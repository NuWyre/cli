package keys

import (
	"errors"
	"testing"
	"time"
)

func TestKeyForBundleSelectsByBundleType(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	// example-demo → dev key
	dev, err := KeyForBundle("example-demo", now)
	if err != nil {
		t.Fatalf("expected dev key for example-demo, got error: %v", err)
	}
	if dev.KeyID != "issuer-dev-v1" {
		t.Errorf("expected issuer-dev-v1, got %s", dev.KeyID)
	}
	if dev.KeyRole != KeyRoleDev {
		t.Errorf("expected KeyRoleDev, got %s", dev.KeyRole)
	}
	// Real fingerprint (matches dev-signing-key.pub.json).
	if dev.SPKIFingerprintB64 != "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=" {
		t.Errorf("dev fingerprint drift: %s", dev.SPKIFingerprintB64)
	}

	// sandbox-preview → dev key (Phase 5.5 Session 5.5.5 — sandbox
	// bundles dispatch to the dev key so check 1 passes against the
	// same pinned fingerprint as example-demo; honest "DEVELOPMENT
	// BUNDLE" warning fires on verification).
	sandbox, err := KeyForBundle("sandbox-preview", now)
	if err != nil {
		t.Fatalf("expected dev key for sandbox-preview, got error: %v", err)
	}
	if sandbox.KeyID != "issuer-dev-v1" {
		t.Errorf("expected issuer-dev-v1 for sandbox-preview, got %s", sandbox.KeyID)
	}
	if sandbox.KeyRole != KeyRoleDev {
		t.Errorf("expected KeyRoleDev for sandbox-preview, got %s", sandbox.KeyRole)
	}

	// customer-export → prod key (placeholder)
	prod, err := KeyForBundle("customer-export", now)
	if err != nil {
		t.Fatalf("expected prod key for customer-export, got error: %v", err)
	}
	if prod.KeyID != "issuer-prod-v1" {
		t.Errorf("expected issuer-prod-v1, got %s", prod.KeyID)
	}
	if prod.KeyRole != KeyRoleProd {
		t.Errorf("expected KeyRoleProd, got %s", prod.KeyRole)
	}
	// Placeholder is intentionally non-base64 so production-bundle
	// fingerprint comparison against it fails. V1 binaries reject
	// all customer-export bundles by design.
	if prod.SPKIFingerprintB64 == "" {
		t.Error("placeholder must be non-empty so comparison can occur")
	}
	if prod.SPKIFingerprintB64 == "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=" {
		t.Error("prod placeholder must NOT equal the dev key fingerprint (security regression)")
	}
}

func TestKeyForBundleFailSecureOnUnknownType(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	// Unknown bundle_type defaults to KeyRoleProd (fail-secure: a
	// tampered bundle that omits or malforms bundle_type gets the
	// strict verification path).
	for _, bt := range []string{"", "unknown", "future-bundle-type"} {
		k, err := KeyForBundle(bt, now)
		if err != nil {
			t.Fatalf("bundle_type=%q: expected fail-secure prod default, got error: %v", bt, err)
		}
		if k.KeyRole != KeyRoleProd {
			t.Errorf("bundle_type=%q: expected KeyRoleProd default, got %s", bt, k.KeyRole)
		}
	}
}

func TestKeyForBundleErrIfNoActiveKey(t *testing.T) {
	t.Parallel()
	// Exercise the no-active-key branch via the testable internal
	// dispatch (keyForBundleIn). Synthetic key set: one prod key
	// effective only after 2030; a request with generatedAt=2025
	// finds no matching key.
	syntheticKeys := []IssuerKey{
		{
			KeyID:              "future-prod-key",
			KeyRole:            KeyRoleProd,
			EffectiveAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			EffectiveBefore:    time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
			SPKIFingerprintB64: "future-key-placeholder",
		},
	}
	earlyTime := time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC)
	k, err := keyForBundleIn(syntheticKeys, "customer-export", earlyTime)
	if !errors.Is(err, ErrNoIssuerKey) {
		t.Errorf("expected ErrNoIssuerKey for pre-effective time, got err=%v key=%v", err, k)
	}
	// And the same key set with a request inside the effective
	// window should succeed.
	inWindow := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	k, err = keyForBundleIn(syntheticKeys, "customer-export", inWindow)
	if err != nil {
		t.Errorf("expected match in window, got error: %v", err)
	}
	if k == nil || k.KeyID != "future-prod-key" {
		t.Errorf("expected future-prod-key, got %v", k)
	}
}

func TestPinnedIssuerKeysHaveDistinctIDs(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for _, k := range PinnedIssuerKeys {
		if seen[k.KeyID] {
			t.Errorf("duplicate pinned KeyID: %s", k.KeyID)
		}
		seen[k.KeyID] = true
	}
}

func TestPinnedIssuerKeysHaveDisjointEffectivePeriodsPerRole(t *testing.T) {
	t.Parallel()
	// Per role, pinned keys must have disjoint [EffectiveAfter,
	// EffectiveBefore] periods so KeyForBundle's dispatch picks a
	// unique key per generated_at. Compile-time invariant enforced
	// for the embedded data here; the check works at N=1 (vacuous)
	// and fails loudly when N>1 with overlap. When Phase 5+ adds
	// a second prod key the operator MUST set EffectiveBefore on
	// the previous key + EffectiveAfter on the new key; this test
	// catches a missed update.
	byRole := make(map[KeyRole][]IssuerKey)
	for _, k := range PinnedIssuerKeys {
		byRole[k.KeyRole] = append(byRole[k.KeyRole], k)
	}
	for role, keys := range byRole {
		// Pairwise overlap check. Treats EffectiveAfter zero as
		// "−∞" and EffectiveBefore zero as "+∞" (matching the
		// dispatch logic's interpretation of zero values).
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if periodsOverlap(keys[i], keys[j]) {
					t.Errorf("role %s: keys %s and %s have overlapping effective periods",
						role, keys[i].KeyID, keys[j].KeyID)
				}
			}
		}
	}
}

// periodsOverlap reports whether two pinned keys' effective windows
// overlap. Used by the disjoint-periods test. Zero EffectiveAfter
// means "active from −∞"; zero EffectiveBefore means "active to +∞".
func periodsOverlap(a, b IssuerKey) bool {
	// a's window: [aFrom, aTo); b's window: [bFrom, bTo). Overlap
	// iff aFrom < bTo AND bFrom < aTo.
	aFrom := a.EffectiveAfter
	aTo := a.EffectiveBefore
	bFrom := b.EffectiveAfter
	bTo := b.EffectiveBefore

	// aFrom < bTo? If bTo is zero (+∞), trivially yes.
	if !bTo.IsZero() && !aFrom.IsZero() && !aFrom.Before(bTo) {
		return false
	}
	// bFrom < aTo? If aTo is zero (+∞), trivially yes.
	if !aTo.IsZero() && !bFrom.IsZero() && !bFrom.Before(aTo) {
		return false
	}
	return true
}

func TestPinnedTSARootsHaveDistinctNames(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for _, r := range PinnedTSARoots {
		if seen[r.RootName] {
			t.Errorf("duplicate pinned TSA RootName: %s", r.RootName)
		}
		seen[r.RootName] = true
	}
}

func TestPinnedTSARootsAllHaveEmbeddedPEMs(t *testing.T) {
	t.Parallel()
	for _, r := range PinnedTSARoots {
		if len(r.PEMBytes) == 0 {
			t.Errorf("pinned TSA root %q has empty PEMBytes (go:embed failed?)", r.RootName)
		}
	}
}

func TestListPinnedReturnsCopies(t *testing.T) {
	t.Parallel()
	// Mutating the returned slice must not affect the package's
	// PinnedIssuerKeys / PinnedTSARoots. Defense against a caller
	// (e.g., `nuwyre keys` formatter) accidentally corrupting the
	// embedded data.
	keys := ListPinnedIssuerKeys()
	originalLen := len(PinnedIssuerKeys)
	if len(keys) > 0 {
		keys[0].KeyID = "MUTATED"
	}
	if PinnedIssuerKeys[0].KeyID == "MUTATED" {
		t.Error("ListPinnedIssuerKeys returned a mutable reference (must return a copy)")
	}
	if len(PinnedIssuerKeys) != originalLen {
		t.Error("PinnedIssuerKeys length changed after caller mutation")
	}

	roots := ListPinnedTSARoots()
	if len(roots) > 0 {
		roots[0].RootName = "MUTATED"
	}
	if PinnedTSARoots[0].RootName == "MUTATED" {
		t.Error("ListPinnedTSARoots returned a mutable reference (must return a copy)")
	}

	// Deep-copy contract for PEMBytes: a caller mutating
	// roots[i].PEMBytes[0] must NOT corrupt the embedded data
	// globally (a shallow copy would let it). Check explicitly.
	if len(roots) > 0 && len(roots[0].PEMBytes) > 0 {
		originalFirstByte := PinnedTSARoots[0].PEMBytes[0]
		roots[0].PEMBytes[0] = 0xFF
		if PinnedTSARoots[0].PEMBytes[0] != originalFirstByte {
			t.Error("ListPinnedTSARoots returned a shallow PEMBytes reference (caller mutation reached embedded data)")
		}
	}
}

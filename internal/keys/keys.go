// Package keys embeds the issuer signing keys + TSA root certificates
// the verifier pins. All keys are compile-time embedded via go:embed
// — the binary contains every key it needs and never reads any key
// material from environment / filesystem at runtime.
//
// Phase 4 Session 1 lands the type definitions + KeyForBundle dispatch
// + ListPinnedTSARoots. Issuer-keys.go and tsa-roots.go (in this same
// package) wire the actual embedded data.
package keys

import (
	"errors"
	"time"
)

// IssuerKey describes one pinned issuer signing key. The CLI carries
// multiple pinned keys per role (with EffectiveAfter timestamps) so
// older bundles continue to verify against the key active at their
// generated_at; key rotation accumulates entries here without
// dropping the previous one.
type IssuerKey struct {
	// KeyID is the stable identifier (e.g., "issuer-prod-v1",
	// "issuer-dev-v1"). Matches manifest.signing.key_id when the
	// manifest declares it; otherwise the verifier dispatches via
	// bundle_type → KeyRole.
	KeyID string

	// KeyRole selects the verifier path: "prod" for customer-export
	// bundles; "dev" for example-demo bundles.
	KeyRole KeyRole

	// EffectiveAfter is the earliest UTC time this key signs valid
	// bundles. Pre-rotation bundles MUST verify against the
	// previous key whose effective period covered their
	// generated_at. Zero value means "active from issuance" with
	// no lower bound.
	EffectiveAfter time.Time

	// EffectiveBefore is the latest UTC time this key signs valid
	// bundles. Post-rotation bundles MUST NOT verify against a key
	// whose effective period has ended. Zero value means "active
	// indefinitely" (current key).
	EffectiveBefore time.Time

	// SPKIFingerprintB64 is the base64-encoded SubjectPublicKeyInfo
	// (SPKI) DER of the public key. Pinned at compile time; matched
	// against manifest.signing.key_fingerprint_spki_b64.
	//
	// **Naming note:** the field is called "Fingerprint" for
	// historical TS-side parity (the manifest field has the same
	// name) but the value is the FULL SPKI DER, NOT a SHA-256 of
	// it. For Ed25519 the SPKI DER is 44 bytes; base64 of those is
	// 60 characters. This is the wire format the writer emits and
	// the verifier parses via x509.ParsePKIXPublicKey. A future
	// refactor may rename this to SPKIB64 for clarity; until then
	// the field name and contents are intentional inconsistencies
	// pinned to TS-side compatibility.
	SPKIFingerprintB64 string

	// Description is a human-readable note shown by `nuwyre keys`.
	Description string
}

// KeyRole disambiguates production vs development signing keys.
// bundle_type field selects the role the verifier expects.
type KeyRole string

const (
	KeyRoleProd KeyRole = "prod"
	KeyRoleDev  KeyRole = "dev"
)

// TSARoot describes one pinned TSA root certificate. The verifier
// chains an RFC 3161 timestamp token's signing certificate up
// through its embedded .chain.pem to a publicly-known root CA.
// System trust store is tried first; pinned roots here cover
// cases where the user's system store doesn't include a particular
// timestamping root (TSA-specific roots aren't always default).
type TSARoot struct {
	// RootName is the stable identifier (e.g., "freetsa-root",
	// "sectigo-rsa-tsa-2020"). Used in `nuwyre keys` listing.
	RootName string

	// Description is a human-readable note shown by `nuwyre keys`.
	Description string

	// EffectiveAfter is the cert's NotBefore (UTC). Verifier uses
	// this to reject pre-issuance timestamps.
	EffectiveAfter time.Time

	// EffectiveBefore is the cert's NotAfter (UTC). Verifier uses
	// this to reject post-expiration timestamps. Zero value means
	// "no enforced upper bound" (set the cert's NotAfter when
	// embedding).
	EffectiveBefore time.Time

	// PEMBytes is the embedded PEM-encoded root certificate.
	// go:embed pulls these from internal/keys/roots/*.pem at
	// compile time.
	PEMBytes []byte
}

// ErrNoIssuerKey is returned by KeyForBundle when no pinned key
// matches the bundle_type / generated_at combination.
var ErrNoIssuerKey = errors.New("no pinned issuer key matches the bundle's bundle_type and generated_at")

// KeyForBundle selects the appropriate pinned issuer key for a
// bundle's metadata. Thin wrapper around keyForBundleIn so unit
// tests can exercise the dispatch logic against synthetic key sets
// without mutating the embedded PinnedIssuerKeys.
//
// Dispatch:
//
//   - bundle_type = "customer-export"   → KeyRoleProd
//   - bundle_type = "example-demo"      → KeyRoleDev
//   - bundle_type = "sandbox-preview"   → KeyRoleDev (Phase 5.5 Session
//     5.5.5; sandbox bundles are non-production demonstration artifacts
//     signed with the dev key so check 1 passes against the same pinned
//     fingerprint as example-demo. Surfaces the "DEVELOPMENT BUNDLE"
//     warning honestly — sandbox is demo data, not production-trusted.)
//   - bundle_type = "audit-log-export"  → KeyRoleDev (Phase 7.D session
//     88 — BACKLOG 1.48 A.1.1 closure; audit-log conformance fixture
//     extension). V1 audit-log-export bundles in production also use
//     dev-key signing because the production deploy-bootstrap (Phase
//     5+) has not yet added a KMS-backed audit-log-export prod key
//     role. When that lands, this dispatch arm flips to KeyRoleProd
//     OR a new KeyRoleAuditLog role distinct from KeyRoleProd (per
//     Pre-Phase 6 Item 1 two-key topology — separate ARNs for event-
//     signing vs manifest-signing). For now, audit-log-export fixtures
//     verify under --allow-dev-key with the same DEVELOPMENT BUNDLE
//     warning as example-demo + sandbox-preview.
//   - any other / missing               → KeyRoleProd (fail-secure
//     default; tampered bundles that omit or malform bundle_type
//     get the strict verification path)
//
// generatedAt selects the active key within that role: the unique
// key whose [EffectiveAfter, EffectiveBefore] period contains the
// bundle's generated_at. Multiple pinned keys with overlapping
// effective periods are a compile-time invariant violation; tests
// in keys_test.go assert disjoint periods per role.
func KeyForBundle(bundleType string, generatedAt time.Time) (*IssuerKey, error) {
	return keyForBundleIn(PinnedIssuerKeys, bundleType, generatedAt)
}

// keyForBundleIn is the testable internal dispatch — same logic as
// KeyForBundle but operates on a caller-supplied key slice rather
// than the package's PinnedIssuerKeys global. Used by keys_test.go
// to exercise the no-active-key branch + future rotation scenarios.
func keyForBundleIn(keys []IssuerKey, bundleType string, generatedAt time.Time) (*IssuerKey, error) {
	role := KeyRoleProd
	if bundleType == "example-demo" || bundleType == "sandbox-preview" || bundleType == "audit-log-export" {
		role = KeyRoleDev
	}
	for i := range keys {
		k := &keys[i]
		if k.KeyRole != role {
			continue
		}
		if !k.EffectiveAfter.IsZero() && generatedAt.Before(k.EffectiveAfter) {
			continue
		}
		if !k.EffectiveBefore.IsZero() && !generatedAt.Before(k.EffectiveBefore) {
			continue
		}
		return k, nil
	}
	return nil, ErrNoIssuerKey
}

// ListPinnedIssuerKeys returns a copy of the embedded key slice.
// Used by `nuwyre keys` (Phase 4 Session 4) to print pinned keys.
func ListPinnedIssuerKeys() []IssuerKey {
	out := make([]IssuerKey, len(PinnedIssuerKeys))
	copy(out, PinnedIssuerKeys)
	return out
}

// ListPinnedTSARoots returns a deep copy of the embedded TSA roots
// slice. Used by `nuwyre keys` (Phase 4 Session 4). Deep copy of
// PEMBytes is load-bearing — a shallow copy would let a caller
// mutating roots[i].PEMBytes corrupt the embedded data globally.
// (TestListPinnedReturnsCopies asserts this contract.)
func ListPinnedTSARoots() []TSARoot {
	out := make([]TSARoot, len(PinnedTSARoots))
	for i := range PinnedTSARoots {
		out[i] = PinnedTSARoots[i]
		// Deep-copy the PEMBytes slice so caller mutations don't
		// reach the embedded var. The struct copy above shares the
		// slice header; the explicit make+copy duplicates the
		// backing array.
		pem := make([]byte, len(PinnedTSARoots[i].PEMBytes))
		copy(pem, PinnedTSARoots[i].PEMBytes)
		out[i].PEMBytes = pem
	}
	return out
}

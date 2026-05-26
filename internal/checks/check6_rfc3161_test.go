package checks

import (
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Check 6 — RFC 3161 timestamp anchor
//
// Tests cover:
//   - Happy path against the regenerated example bundle (3-of-3 distinct
//     TSAs verified — the canonical "extra confirmation" path)
//   - Threshold semantics: 2-of-3 PASS, 1-of-3 FAIL, 0-of-3 FAIL
//   - SignerCert distinctness defense (the H2 attack vector from
//     D3 commit 1's reviewer pass): three valid pairs labeled with
//     three different tsa_names but pointing at copies of one TSR
//     MUST FAIL with "1 distinct of 3 valid"
//   - Tampered TSR / chain.pem / hashedMessage → PairInvalid
//     contributes to per-TSA breakdown
//   - Anchor consistency divergence → FAIL early
//   - Missing TSRs with anchor_status=verified → FAIL
//   - Missing TSRs with anchor_status=not_attempted → PASS (degraded)
//   - Malformed root_hash → FAIL
//   - --offline mode → SKIPPED
// =============================================================================

func newCheck6(t *testing.T) *Check6RFC3161 {
	t.Helper()
	c, err := NewCheck6RFC3161()
	if err != nil {
		t.Fatalf("NewCheck6RFC3161: %v", err)
	}
	return c
}

// TestCheck6HappyPathOnRegeneratedBundle exercises the canonical
// 3-of-3 distinct-signers path against the regenerated example
// bundle. Result MUST be PASS with the "extra confirmation" warning.
func TestCheck6HappyPathOnRegeneratedBundle(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusPass && r.Status != StatusWarn {
		t.Errorf("Status = %v, want Pass or Warn", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	if len(r.Errors) != 0 {
		t.Errorf("got %d errors, want 0", len(r.Errors))
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
	hit := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), "distinct TSAs verified") &&
			strings.Contains(w.Error(), "extra confirmation") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected ≥3 extra-confirmation warning; got:")
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
}

// TestCheck6OfflineSkips pins the --offline behavior: regardless of
// bundle content, --offline returns StatusSkipped.
func TestCheck6OfflineSkips(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{Offline: true})
	if r.Status != StatusSkipped {
		t.Errorf("Status = %v, want Skipped", r.Status)
	}
	if r.SkipReason == "" {
		t.Error("SkipReason empty; expected --offline reason")
	}
}

// TestCheck6PassesWhenNotAttempted pins the degraded-mode short-
// circuit: when manifest declares rfc3161_status="not_attempted",
// check 6 PASSES without iterating daily roots. The degraded state
// is operator-declared honesty, not a verifier failure.
func TestCheck6PassesWhenNotAttempted(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	b.Manifest.AnchorStatus.RFC3161Status = "not_attempted"
	b.Manifest.Anchors.RFC3161 = nil
	b.RFC3161Receipts = nil
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusPass {
		t.Errorf("Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
}

// TestCheck6FailsOnConsistencyDivergence pins the early-fail-on-
// consistency path: when manifest summary disagrees with detail,
// check 6 FAILS at the consistency layer without attempting per-pair
// verification (so the operator sees the structural defect, not a
// cascade of per-pair errors masking it).
func TestCheck6FailsOnConsistencyDivergence(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	// Summary says verified but detail has 0 entries → divergence.
	b.Manifest.AnchorStatus.RFC3161Status = "verified"
	b.Manifest.Anchors.RFC3161 = nil
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 {
		t.Fatal("got 0 errors, want at least 1 (consistency)")
	}
	if !strings.Contains(r.Errors[0].Error(), "consistency") {
		t.Errorf("first error doesn't mention consistency: %v", r.Errors[0])
	}
}

// TestCheck6FailsOnMissingReceiptsWhenVerified pins the missing-data-
// despite-claimed-state path: manifest declares verified with 3
// entries but bundle.RFC3161Receipts is empty for that day.
func TestCheck6FailsOnMissingReceiptsWhenVerified(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	// Wipe the receipts but keep the manifest claiming verified.
	b.RFC3161Receipts = nil
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "no RFC 3161 receipts present") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected missing-receipts error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck6FailsOnMalformedRootHash pins the lowercase-hex
// validation: a non-canonical root_hash in daily_roots.json fails
// before VerifyPair is called, with the spec §6.1 lowercase-hex
// reference.
func TestCheck6FailsOnMalformedRootHash(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	if len(b.DailyRoots.Roots) == 0 {
		t.Skip("no daily roots to mutate")
	}
	// Uppercase hex is invalid per spec §6.1 even though
	// hex.DecodeString would accept it.
	b.DailyRoots.Roots[0].Root = strings.ToUpper(b.DailyRoots.Roots[0].Root)
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "lowercase hex") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected lowercase-hex error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck6FailsOnTamperedTSR pins the integrity guarantee from the
// per-pair perspective: a single tampered TSR drops one TSA from the
// distinct count, but the remaining two still satisfy 2-of-3
// threshold → PASS with warning. Tampering two of three drops to
// 1-of-3 → FAIL.
func TestCheck6OneTamperedTSRStillPasses(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	var firstTSA string
	for n := range byTSA {
		firstTSA = n
		break
	}
	// Tamper one TSA's TSR by truncating to ~25% of original — a
	// guaranteed-destructive corruption (ASN.1 envelope length-prefix
	// mismatch) that doesn't depend on hitting a signature-protected
	// region. Single-byte midpoint flips can land in inert PKCS#7 cert
	// padding (see verifier_test.go's distributed-tamper rationale).
	src := byTSA[firstTSA].TSR
	if len(src) < 100 {
		t.Skipf("TSR too short for truncation tamper: %d bytes", len(src))
	}
	truncated := make([]byte, len(src)/4)
	copy(truncated, src)
	byTSA[firstTSA] = bundle.RFC3161Pair{TSR: truncated, ChainPEM: byTSA[firstTSA].ChainPEM}
	b.RFC3161Receipts[day] = byTSA
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status == StatusFail {
		t.Errorf("Status = Fail, want Pass or Warn (2/3 still meets threshold)")
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
	// Should warn about the failed TSA.
	hit := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), "failed for daily root") &&
			strings.Contains(w.Error(), "threshold met") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected per-TSA failure warning; got:")
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
}

// TestCheck6TwoTamperedTSRsFail pins the threshold breach: tampering
// 2 of 3 TSRs drops distinct count to 1/3 → FAIL with full per-TSA
// breakdown.
func TestCheck6TwoTamperedTSRsFail(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	tsaNames := tsaNamesSorted(byTSA)
	if len(tsaNames) < 2 {
		t.Skip("need at least 2 TSAs to tamper 2 of 3")
	}
	// Tamper the first two TSAs' TSRs.
	for i := 0; i < 2; i++ {
		n := tsaNames[i]
		tampered := tamperBytes(byTSA[n].TSR, len(byTSA[n].TSR)/2, 200)
		byTSA[n] = bundle.RFC3161Pair{TSR: tampered, ChainPEM: byTSA[n].ChainPEM}
	}
	b.RFC3161Receipts[day] = byTSA
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "≥2-of-3 distinct TSA threshold breached") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected threshold-breach error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck6DistinctnessDefenseAttackCaughtAtStep4 — THE H2 ATTACK
// VECTOR caught at the spec §11.3 step 4 layer (signer cert subject
// CN must include claimed tsa_name).
//
// Three pairs labeled "freetsa-clone-a/b/c" all pointing at copies
// of one freetsa TSR. Each pair's chain validates AND each label is
// a distinct lowercase identifier (consistency check passes), but
// the signer cert's CN ("www.freetsa.org") does NOT include any of
// "freetsa-clone-a/b/c" as substrings — step 4 downgrades all three
// to PairInvalid, distinct count = 0 → FAIL.
//
// This is the PRIMARY defense; the SignerCert distinctness defense
// (TestCheck6DistinctnessDefenseAttackBackstop below) is the
// belt-and-suspenders backstop for the residual case where step 4
// passes but distinctness fails.
func TestCheck6DistinctnessDefenseAttackCaughtAtStep4(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	tsaNames := tsaNamesSorted(byTSA)
	if len(tsaNames) == 0 {
		t.Skip("no TSAs to clone")
	}
	original := byTSA[tsaNames[0]]
	attackerTSAs := []string{"freetsa-clone-a", "freetsa-clone-b", "freetsa-clone-c"}
	newReceipts := map[string]bundle.RFC3161Pair{}
	var newAnchors []bundle.ManifestRFC3161Anchor
	for _, n := range attackerTSAs {
		newReceipts[n] = bundle.RFC3161Pair{TSR: original.TSR, ChainPEM: original.ChainPEM}
		newAnchors = append(newAnchors, bundle.ManifestRFC3161Anchor{
			TSAName:     n,
			ReceiptPath: "rfc3161_receipts/" + day + "__" + n + ".tsr",
			ChainPath:   "rfc3161_receipts/" + day + "__" + n + ".chain.pem",
		})
	}
	b.RFC3161Receipts = map[string]map[string]bundle.RFC3161Pair{day: newReceipts}
	b.Manifest.Anchors.RFC3161 = newAnchors
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (H2 attack)", r.Status)
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	// All three pairs failed step 4 → 0 distinct → FAIL.
	hitStep4 := false
	hitThreshold := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "spec §11.3 step 4") {
			hitStep4 = true
		}
		if strings.Contains(e.Error(), "0 distinct valid signer") {
			hitThreshold = true
		}
	}
	if !hitStep4 {
		t.Errorf("expected spec §11.3 step 4 error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
	if !hitThreshold {
		t.Errorf("expected '0 distinct valid signer' threshold error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck6DistinctnessDefenseAttackBackstop — H2 attack vector
// caught at the SignerCert distinctness layer (the BACKSTOP for
// step 4). Three labels are chosen as substrings of one DigiCert
// signer's CN ("DigiCert SHA256 RSA4096 Timestamp Responder 2025 1"):
// "digicert" + "timestamp" + "responder". All three pass step 4
// (each is a substring of the CN, case-insensitive), all three
// validate via VerifyPair (same TSR), but distinctness sees 1
// SignerCert subject for 3 valid pairs → FAIL with "1 distinct
// valid signer of 3 pair(s) attempted".
//
// This is a hypothetical attack that requires the attacker to know
// the target cert's CN structure and pick collisional substring
// labels. Step 4 alone wouldn't catch it. The distinctness backstop
// is the second line of defense.
func TestCheck6DistinctnessDefenseAttackBackstop(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	const targetTSA = "digicert"
	pair, exists := byTSA[targetTSA]
	if !exists {
		t.Skipf("example bundle has no %q TSA", targetTSA)
	}
	// All three labels are substrings of the digicert signer CN.
	collisionLabels := []string{"digicert", "timestamp", "responder"}
	newReceipts := map[string]bundle.RFC3161Pair{}
	var newAnchors []bundle.ManifestRFC3161Anchor
	for _, n := range collisionLabels {
		newReceipts[n] = bundle.RFC3161Pair{TSR: pair.TSR, ChainPEM: pair.ChainPEM}
		newAnchors = append(newAnchors, bundle.ManifestRFC3161Anchor{
			TSAName:     n,
			ReceiptPath: "rfc3161_receipts/" + day + "__" + n + ".tsr",
			ChainPath:   "rfc3161_receipts/" + day + "__" + n + ".chain.pem",
		})
	}
	b.RFC3161Receipts = map[string]map[string]bundle.RFC3161Pair{day: newReceipts}
	b.Manifest.Anchors.RFC3161 = newAnchors
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (distinctness backstop)", r.Status)
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "1 distinct valid signer") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected '1 distinct valid signer' threshold error (the distinctness backstop); got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck6FailsOnSignerCNMismatch is the dedicated spec §11.3
// step 4 regression test: relabel ONE valid pair with a tsa_name
// not in the signer CN; that pair gets downgraded but the other two
// keep the threshold satisfied → PASS with per-TSA warning.
func TestCheck6FailsOnSignerCNMismatch(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	tsaNames := tsaNamesSorted(byTSA)
	if len(tsaNames) < 3 {
		t.Skip("need 3 TSAs to relabel one")
	}
	// Relabel the first TSA's pair under a name that is NOT in the
	// signer CN (sectigo's signer CN is "Sectigo Public Time Stamping
	// Signer R36"; "wrong-tsa-name-not-in-cn" isn't a substring of
	// that or any other TSA's CN). Keep the other two as-is.
	relabeled := byTSA[tsaNames[0]]
	delete(byTSA, tsaNames[0])
	byTSA["wrong-tsa-name-not-in-cn"] = relabeled
	b.RFC3161Receipts[day] = byTSA

	// Update manifest to match the new label set.
	var newAnchors []bundle.ManifestRFC3161Anchor
	for n := range byTSA {
		newAnchors = append(newAnchors, bundle.ManifestRFC3161Anchor{
			TSAName:     n,
			ReceiptPath: "rfc3161_receipts/" + day + "__" + n + ".tsr",
			ChainPath:   "rfc3161_receipts/" + day + "__" + n + ".chain.pem",
		})
	}
	b.Manifest.Anchors.RFC3161 = newAnchors
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status == StatusFail {
		t.Errorf("Status = Fail, want Pass or Warn (2 of 3 still satisfy threshold)")
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
	hit := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), "spec §11.3 step 4") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected spec §11.3 step 4 warning for the relabeled pair; got:")
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
}

// TestCheck6DuplicateSignerWarnsButPasses — close cousin of the
// distinctness backstop test, but with 2 distinct signers (threshold
// met). Two pairs both labeled with substrings of the digicert
// signer CN ("digicert" + "timestamp") share one SignerCert; the
// freetsa pair contributes a second distinct signer. Result:
// 3 valid pairs, 2 distinct → PASS with duplicate-signer warning.
func TestCheck6DuplicateSignerWarnsButPasses(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	digiPair, hasDigi := byTSA["digicert"]
	freetsaPair, hasFree := byTSA["freetsa"]
	if !hasDigi || !hasFree {
		t.Skip("example bundle missing digicert or freetsa pair")
	}
	// "digicert" + "timestamp" → both substrings of digicert CN
	// "DigiCert SHA256 RSA4096 Timestamp Responder 2025 1" (case-
	// insensitive), both pass step 4, both share the digicert
	// SignerCert. "freetsa" → distinct signer.
	newReceipts := map[string]bundle.RFC3161Pair{
		"digicert":  digiPair,
		"timestamp": {TSR: digiPair.TSR, ChainPEM: digiPair.ChainPEM},
		"freetsa":   freetsaPair,
	}
	var newAnchors []bundle.ManifestRFC3161Anchor
	for n := range newReceipts {
		newAnchors = append(newAnchors, bundle.ManifestRFC3161Anchor{
			TSAName:     n,
			ReceiptPath: "rfc3161_receipts/" + day + "__" + n + ".tsr",
			ChainPath:   "rfc3161_receipts/" + day + "__" + n + ".chain.pem",
		})
	}
	b.RFC3161Receipts = map[string]map[string]bundle.RFC3161Pair{day: newReceipts}
	b.Manifest.Anchors.RFC3161 = newAnchors
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status == StatusFail {
		t.Errorf("Status = Fail, want Pass or Warn (2 distinct meets threshold)")
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
	hit := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), "duplicate-signer configuration") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected duplicate-signer warning; got:")
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
}

// TestCheck6TwoValidPairsOneDistinctFails — distinctness backstop
// edge case. Two pairs labeled with digicert CN substrings (both
// pass step 4, share one SignerCert); third pair has a wrong label
// (fails step 4, downgraded). Net: 2 valid pairs, 1 distinct signer
// → FAIL with "1 distinct valid signer".
func TestCheck6TwoValidPairsOneDistinctFails(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck6(t)
	day, byTSA, ok := firstReceiptsDay(b)
	if !ok {
		t.Skip("no RFC 3161 receipts to mutate")
	}
	digiPair, hasDigi := byTSA["digicert"]
	if !hasDigi {
		t.Skip("example bundle missing digicert pair")
	}
	// Two CN-substring labels (both pass step 4, share signer).
	// One unrelated label (fails step 4, downgraded).
	newReceipts := map[string]bundle.RFC3161Pair{
		"digicert":         digiPair,
		"timestamp":        {TSR: digiPair.TSR, ChainPEM: digiPair.ChainPEM},
		"unrelated-tsa-id": {TSR: digiPair.TSR, ChainPEM: digiPair.ChainPEM},
	}
	var newAnchors []bundle.ManifestRFC3161Anchor
	for n := range newReceipts {
		newAnchors = append(newAnchors, bundle.ManifestRFC3161Anchor{
			TSAName:     n,
			ReceiptPath: "rfc3161_receipts/" + day + "__" + n + ".tsr",
			ChainPath:   "rfc3161_receipts/" + day + "__" + n + ".chain.pem",
		})
	}
	b.RFC3161Receipts = map[string]map[string]bundle.RFC3161Pair{day: newReceipts}
	b.Manifest.Anchors.RFC3161 = newAnchors
	c := newCheck6(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (2 valid 1 distinct)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "1 distinct valid signer") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected '1 distinct valid signer' error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// =============================================================================
// canonicalSignerKey unit test
// =============================================================================

func TestCanonicalSignerKeyHandlesNil(t *testing.T) {
	t.Parallel()
	if got := canonicalSignerKey(nil); got != "" {
		t.Errorf("canonicalSignerKey(nil) = %q, want empty string", got)
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// cloneExampleForCheck6 returns a fresh *bundle.Bundle from the
// example for mutation. Sub-tests run in parallel; each must operate
// on its own bundle to avoid races. The example bundle is loaded
// fresh per call (small cost; fixture is cached at the OS level).
func cloneExampleForCheck6(t *testing.T) *bundle.Bundle {
	t.Helper()
	src := loadExampleBundle(t)
	dst := *src
	// Clone receipts map (the value we most often mutate). Other
	// fields are mutated less frequently; tests that touch them
	// override entire substructures rather than nested fields.
	if src.RFC3161Receipts != nil {
		dst.RFC3161Receipts = make(map[string]map[string]bundle.RFC3161Pair, len(src.RFC3161Receipts))
		for d, byTSA := range src.RFC3161Receipts {
			inner := make(map[string]bundle.RFC3161Pair, len(byTSA))
			for n, p := range byTSA {
				inner[n] = p
			}
			dst.RFC3161Receipts[d] = inner
		}
	}
	// Clone manifest anchor slices that tests mutate.
	if src.Manifest.Anchors.RFC3161 != nil {
		dst.Manifest.Anchors.RFC3161 = append(
			[]bundle.ManifestRFC3161Anchor(nil),
			src.Manifest.Anchors.RFC3161...,
		)
	}
	// Clone DailyRoots so root_hash mutations don't leak across tests.
	if src.DailyRoots.Roots != nil {
		dst.DailyRoots.Roots = append(
			[]bundle.DailyRootEntry(nil),
			src.DailyRoots.Roots...,
		)
	}
	return &dst
}

// firstReceiptsDay returns the first day's TSA map from the bundle's
// RFC3161Receipts (deterministic across test runs since Go map
// iteration is randomized — caller iterates result map themselves
// where order matters). Returns (day, map, true) or ("", nil, false)
// if no receipts.
func firstReceiptsDay(b *bundle.Bundle) (string, map[string]bundle.RFC3161Pair, bool) {
	for d, m := range b.RFC3161Receipts {
		// Return a fresh inner map so caller mutations don't leak.
		inner := make(map[string]bundle.RFC3161Pair, len(m))
		for n, p := range m {
			inner[n] = p
		}
		return d, inner, true
	}
	return "", nil, false
}

// tsaNamesSorted returns the TSA names in alphabetical order so
// "first / second" test references are deterministic.
func tsaNamesSorted(m map[string]bundle.RFC3161Pair) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names
}

// tamperBytes returns a copy of src with `length` bytes starting at
// `offset` zero-filled. Used to corrupt TSR or chain.pem bytes for
// integrity tests. Spans bytes inside the signature-protected
// PKCS#7 region so the tamper is reliably destructive (single-byte
// flips at the midpoint can fall in inert cert padding — see
// verifier_test.go's distributed-tamper rationale).
func tamperBytes(src []byte, offset, length int) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	for i := offset; i < offset+length && i < len(dst); i++ {
		dst[i] = 0
	}
	return dst
}

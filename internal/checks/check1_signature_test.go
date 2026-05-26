package checks

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/keys"
)

// =============================================================================
// Check 1: manifest signature — happy path against the regenerated
// example bundle. AllowDevKey=true is required because the example
// bundle is signed with the dev key.
// =============================================================================

func TestCheck1HappyPath(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusWarn {
		// Warn (not Pass) because the dev-key informational warning
		// is always surfaced — see step 10 of Check1Signature.Run.
		t.Errorf("happy path: Status = %v, want Warn (dev-key informational warning is always emitted)", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	// One warning expected: the dev-key informational.
	if len(r.Warnings) != 1 {
		t.Errorf("dev-key warning count = %d, want 1", len(r.Warnings))
	}
	if len(r.Errors) != 0 {
		t.Errorf("happy path errors: got %d, want 0", len(r.Errors))
	}
}

// TestCheck1DevKeyWarningMatchesSpecText pins the EXACT spec-mandated
// warning string. Spec §5 line 308 + build plan line 1083 mandate
// "DEVELOPMENT BUNDLE — verified with dev key, not for production
// trust" (with em-dash U+2014). External tooling greps for this exact
// substring; this test catches drift. H1+H2 from commit-2 reviewer
// pass.
func TestCheck1DevKeyWarningMatchesSpecText(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if len(r.Warnings) == 0 {
		t.Fatal("expected at least one warning (dev-key informational)")
	}
	// The exact spec-mandated phrase. Em-dash matters; hyphen
	// substitution would break external tooling that greps for this.
	const specMandated = "DEVELOPMENT BUNDLE — verified with dev key, not for production trust"
	found := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), specMandated) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("dev-key warning doesn't contain spec-mandated phrase %q\ngot warnings:", specMandated)
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
	// Defense against hyphen substitution: explicitly check that
	// the em-dash (not regular hyphen) is present.
	if found {
		hasEmDash := false
		for _, w := range r.Warnings {
			if strings.Contains(w.Error(), " — ") {
				hasEmDash = true
				break
			}
		}
		if !hasEmDash {
			t.Error("dev-key warning uses regular hyphen instead of em-dash; spec mandates U+2014")
		}
	}
}

// TestCheck1RejectsExampleBundleWithoutAllowDevKey verifies the
// fail-secure default: example-demo bundles are NOT verified unless
// the operator explicitly opts in.
func TestCheck1RejectsExampleBundleWithoutAllowDevKey(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check1Signature{}.Run(b, CheckOptions{}) // AllowDevKey defaults to false
	if r.Status != StatusFail {
		t.Errorf("AllowDevKey=false: Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 {
		t.Fatal("expected at least one error mentioning --allow-dev-key")
	}
	if !strings.Contains(r.Errors[0].Error(), "--allow-dev-key") {
		t.Errorf("error doesn't mention --allow-dev-key: %v", r.Errors[0])
	}
}

// TestCheck1RejectsTamperedManifestBytes verifies the load-bearing
// integrity property: the verifier signs over RAW BYTES, so a single-
// byte change in ManifestRaw must fail the signature check.
func TestCheck1RejectsTamperedManifestBytes(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.ManifestRaw) == 0 {
		t.Fatal("ManifestRaw empty; loader didn't preserve raw bytes")
	}
	// Flip the very first byte. Manifest starts with `{`; flipping
	// produces invalid JSON, but check 1 doesn't re-parse — it
	// verifies the SIGNATURE over bytes regardless of structural
	// validity.
	b.ManifestRaw[0] ^= 0x01
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("tampered manifest: Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Error(), "Ed25519 verification failed") {
		t.Errorf("expected Ed25519 verification error; got: %v", r.Errors)
	}
}

// TestCheck1RejectsTamperedSignatureBytes verifies that flipping a
// byte in signature_b64 fails verification.
func TestCheck1RejectsTamperedSignatureBytes(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	original := b.Signature.SignatureB64
	defer func() { b.Signature.SignatureB64 = original }()
	if len(b.Signature.SignatureB64) > 0 {
		first := b.Signature.SignatureB64[0]
		var replacement byte
		if first == 'A' {
			replacement = 'B'
		} else {
			replacement = 'A'
		}
		b.Signature.SignatureB64 = string(replacement) + b.Signature.SignatureB64[1:]
	}
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("tampered signature: Status = %v, want Fail", r.Status)
	}
}

// TestCheck1RejectsAllZeroSignature verifies a common forgery attempt:
// 64 bytes of zeros pass the length check, then ed25519.Verify
// rejects on cryptographic grounds. Pins the verify path against
// future regressions (e.g., a maintainer accidentally short-circuiting
// verify on all-zero input).
func TestCheck1RejectsAllZeroSignature(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	original := b.Signature.SignatureB64
	defer func() { b.Signature.SignatureB64 = original }()
	b.Signature.SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, 64))
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("all-zero signature: Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Error(), "Ed25519 verification failed") {
		t.Errorf("expected Ed25519 verification error; got: %v", r.Errors)
	}
}

// TestCheck1RejectsWrongLengthSignature verifies the spec §5 length
// check: Ed25519 signatures are 64 bytes; any other length fails
// before ed25519.Verify is called.
func TestCheck1RejectsWrongLengthSignature(t *testing.T) {
	t.Parallel()
	cases := []int{0, 32, 63, 65, 128}
	for _, length := range cases {
		t.Run(string(rune('a'+length%26)), func(t *testing.T) {
			b := loadExampleBundle(t)
			b.Signature.SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, length))
			r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
			if r.Status != StatusFail {
				t.Errorf("length=%d: Status = %v, want Fail", length, r.Status)
			}
		})
	}
}

// TestCheck1RejectsBadAlgorithm verifies spec §5: signature.sig.algorithm
// MUST be "ed25519". A bundle declaring a different algorithm fails
// fast before any cryptographic verification.
func TestCheck1RejectsBadAlgorithm(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.Signature.Algorithm = "rsa-pss"
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("bad algorithm: Status = %v, want Fail", r.Status)
	}
	if !strings.Contains(r.Errors[0].Error(), "ed25519") {
		t.Errorf("error doesn't mention ed25519: %v", r.Errors[0])
	}
}

// TestCheck1RejectsBadManifestAlgorithm verifies the spec §5 cross-
// check: manifest.signing.algorithm MUST also be "ed25519". Catches
// inconsistent bundles where signature.sig and manifest disagree on
// algorithm. Security L1 from commit-2 reviewer.
func TestCheck1RejectsBadManifestAlgorithm(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.Manifest.Signing.Algorithm = "rsa-pss"
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("bad manifest.signing.algorithm: Status = %v, want Fail", r.Status)
	}
	if !strings.Contains(r.Errors[0].Error(), "manifest.json") {
		t.Errorf("error doesn't reference manifest.json: %v", r.Errors[0])
	}
}

// TestCheck1RejectsBadSchemaVersion verifies the spec §5 pin:
// signature.sig.schema_version MUST be 1. M2 from commit-2 reviewer.
func TestCheck1RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.Signature.SchemaVersion = 2
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("schema_version=2: Status = %v, want Fail", r.Status)
	}
	if !strings.Contains(r.Errors[0].Error(), "schema_version") {
		t.Errorf("error doesn't mention schema_version: %v", r.Errors[0])
	}
}

// TestCheck1RejectsBadSignedArtifact verifies spec §5: signed_artifact
// MUST be "manifest.json".
func TestCheck1RejectsBadSignedArtifact(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.Signature.SignedArtifact = "other-file.json"
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("bad signed_artifact: Status = %v, want Fail", r.Status)
	}
}

// TestCheck1RejectsKeyFingerprintMismatch verifies that a bundle
// declaring a different SPKI than the pinned key fails before
// signature verification.
func TestCheck1RejectsKeyFingerprintMismatch(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Manifest.Signing.KeyFingerprintB64) > 0 {
		first := b.Manifest.Signing.KeyFingerprintB64[0]
		var replacement byte
		if first == 'A' {
			replacement = 'B'
		} else {
			replacement = 'A'
		}
		b.Manifest.Signing.KeyFingerprintB64 = string(replacement) + b.Manifest.Signing.KeyFingerprintB64[1:]
	}
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("key fingerprint mismatch: Status = %v, want Fail", r.Status)
	}
	if !strings.Contains(r.Errors[0].Error(), "does not match pinned") {
		t.Errorf("error doesn't mention pinned-key mismatch: %v", r.Errors[0])
	}
}

// TestCheck1RejectsManifestVsSignatureKeyDisagreement verifies the
// spec §5 cross-check: signature.sig.key_fingerprint_spki_b64 MUST
// match manifest.signing.key_fingerprint_spki_b64.
func TestCheck1RejectsManifestVsSignatureKeyDisagreement(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Signature.KeyFingerprintB64) > 0 {
		first := b.Signature.KeyFingerprintB64[0]
		var replacement byte
		if first == 'A' {
			replacement = 'B'
		} else {
			replacement = 'A'
		}
		b.Signature.KeyFingerprintB64 = string(replacement) + b.Signature.KeyFingerprintB64[1:]
	}
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("manifest/signature key disagreement: Status = %v, want Fail", r.Status)
	}
	if !strings.Contains(r.Errors[0].Error(), "disagrees") {
		t.Errorf("error doesn't mention disagreement: %v", r.Errors[0])
	}
}

// TestCheck1FailsCustomerExportAgainstPlaceholderProdKey verifies the
// V1 binary's reality: customer-export bundles cannot be verified
// against the placeholder prod key. The verifier emits both a Warn
// (telling the operator about the placeholder) AND a Fail (because
// no real verification can occur).
func TestCheck1FailsCustomerExportAgainstPlaceholderProdKey(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.Manifest.BundleType = "customer-export"
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: false})
	if r.Status != StatusFail {
		t.Errorf("customer-export against placeholder: Status = %v, want Fail", r.Status)
	}
	allMessages := []string{}
	for _, e := range r.Errors {
		allMessages = append(allMessages, e.Error())
	}
	for _, w := range r.Warnings {
		allMessages = append(allMessages, w.Error())
	}
	combined := strings.Join(allMessages, "\n")
	if !strings.Contains(combined, "placeholder") {
		t.Errorf("expected placeholder warning, got messages:\n%s", combined)
	}
	if !strings.Contains(combined, "deploy-bootstrap") {
		t.Errorf("expected Phase 5 deploy-bootstrap mention, got messages:\n%s", combined)
	}
}

// TestCheck1RejectsTamperedBundleType covers bundle_type tampering:
// empty string and unknown value both fail-secure dispatch to prod
// (which then hits the placeholder fail in V1).
func TestCheck1RejectsTamperedBundleType(t *testing.T) {
	t.Parallel()
	cases := []string{"", "root", "unknown-future-type"}
	for _, bt := range cases {
		t.Run(bt, func(t *testing.T) {
			b := loadExampleBundle(t)
			b.Manifest.BundleType = bt
			r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
			if r.Status != StatusFail {
				t.Errorf("bundle_type=%q: Status = %v, want Fail", bt, r.Status)
			}
		})
	}
}

// TestCheck1RejectsMalformedGeneratedAt covers the M3 commit-2
// reviewer fix: malformed generated_at is a tampering signal, not a
// degraded-fallback case.
func TestCheck1RejectsMalformedGeneratedAt(t *testing.T) {
	t.Parallel()
	cases := []string{"", "not-a-date", "2026-13-99T99:99:99Z"}
	for _, ts := range cases {
		t.Run(ts, func(t *testing.T) {
			b := loadExampleBundle(t)
			b.Manifest.GeneratedAt = ts
			r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
			if r.Status != StatusFail {
				t.Errorf("generated_at=%q: Status = %v, want Fail", ts, r.Status)
			}
			if len(r.Errors) > 0 && !strings.Contains(r.Errors[0].Error(), "generated_at") {
				t.Errorf("generated_at=%q: error doesn't mention generated_at: %v", ts, r.Errors[0])
			}
		})
	}
}

// TestCheck1Slug verifies the Slug() matches the package convention.
// Defends against typo regressions in CLI matcher form.
func TestCheck1Slug(t *testing.T) {
	t.Parallel()
	c := Check1Signature{}
	if c.ID() != 1 {
		t.Errorf("ID() = %d, want 1", c.ID())
	}
	if c.Name() != "manifest signature" {
		t.Errorf("Name() = %q, want %q", c.Name(), "manifest signature")
	}
	if c.Slug() != "manifest-signature" {
		t.Errorf("Slug() = %q, want %q", c.Slug(), "manifest-signature")
	}
}

// TestCheck1NilManifestRawFailsLoudly defends against a future loader
// regression where ManifestRaw isn't preserved. The check should NOT
// silently succeed against zero bytes.
func TestCheck1NilManifestRawFailsLoudly(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.ManifestRaw = []byte{}
	r := Check1Signature{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("empty ManifestRaw: Status = %v, want Fail", r.Status)
	}
	// Crypto L4: assert the SPECIFIC error, not just Fail. A regression
	// that fails for the wrong reason (e.g., short-circuiting earlier)
	// would not be detected without this assertion.
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Error(), "Ed25519 verification failed") {
		t.Errorf("expected Ed25519 verification error; got: %v", r.Errors)
	}
}

// =============================================================================
// Sanity: the pinned dev key really is what's in the example bundle.
// If this test fails, the pinned dev key has drifted from what the
// example bundle's writer produces, and check 1's happy path will
// fail in confusing ways.
// =============================================================================

func TestCheck1ExampleBundleUsesPinnedDevKey(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	const expectedDevKeyFingerprint = "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE="
	if b.Manifest.Signing.KeyFingerprintB64 != expectedDevKeyFingerprint {
		t.Errorf("example bundle's signing key has drifted: got %q, want %q",
			b.Manifest.Signing.KeyFingerprintB64, expectedDevKeyFingerprint)
		t.Errorf("update apps/cli/internal/keys/issuer-keys.go and re-run")
	}
}

// TestCheck1PlaceholderConstantSingleSourceOfTruth pins the security-
// auditor L3 fix: PlaceholderProdFingerprint is in keys/issuer-keys.go
// (single source of truth); check1 imports it. A maintainer who
// changes one site without the other would silently desync; this test
// asserts both sides agree.
func TestCheck1PlaceholderConstantSingleSourceOfTruth(t *testing.T) {
	t.Parallel()
	if keys.PlaceholderProdFingerprint != "PROD_KEY_FINGERPRINT_PENDING_PHASE_5_DEPLOY_BOOTSTRAP" {
		t.Errorf("PlaceholderProdFingerprint drift: %q", keys.PlaceholderProdFingerprint)
	}
	// And confirm the pinned prod key actually carries this constant.
	for _, k := range keys.PinnedIssuerKeys {
		if k.KeyID == "issuer-prod-v1" {
			if k.SPKIFingerprintB64 != keys.PlaceholderProdFingerprint {
				t.Errorf("issuer-prod-v1 SPKI fingerprint = %q, want PlaceholderProdFingerprint constant", k.SPKIFingerprintB64)
			}
		}
	}
}

// =============================================================================
// truncate helper unit tests (M5 from commit-2 crypto reviewer + M1
// from security-auditor: defensive output-size bounding).
// =============================================================================

func TestTruncateShortString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in  string
		n   int
		out string
	}{
		{"", 12, ""},
		{"abc", 12, "abc"},
		{"exactly12345", 12, "exactly12345"},
		{"too-long-thirteen", 12, "too-long-thi"},
		{"MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=", 24, "MCowBQYDK2VwAyEAIdvXBrE7"},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.n); got != c.out {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.out)
		}
	}
}

// TestTruncateAlwaysBoundedRegardlessOfBytes verifies the security M1
// fix: truncate must NEVER return a string longer than n, regardless
// of byte content. An attacker-controlled fingerprint with control
// bytes used to cause the OLD truncate to return the FULL string;
// the new implementation always truncates.
func TestTruncateAlwaysBoundedRegardlessOfBytes(t *testing.T) {
	t.Parallel()
	cases := []string{
		"\x00\x01\x02control-bytes-then-text",
		"\x1b[31mANSI-escape-injection\x1b[0m",
		"valid-base64-but-then-junk\xff\xfe\xfd",
	}
	for _, s := range cases {
		got := truncate(s, 12)
		if len(got) > 12 {
			t.Errorf("truncate(%q, 12) returned %d bytes (want <= 12) — possible output-injection vector", s, len(got))
		}
	}
}

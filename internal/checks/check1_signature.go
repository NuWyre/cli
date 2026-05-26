package checks

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/keys"
)

// Check1Signature verifies the manifest.json Ed25519 signature against
// a pinned issuer key selected by bundle_type. Per spec §5:
//
//   - signature.sig.schema_version MUST be 1
//   - signature.sig.algorithm MUST be "ed25519"
//   - manifest.signing.algorithm MUST be "ed25519" (cross-check)
//   - signature.sig.signed_artifact MUST be "manifest.json"
//   - signature.sig.signature_b64 verifies over the raw bytes of
//     manifest.json under the pinned issuer key for bundle_type
//   - manifest.signing.key_fingerprint_spki_b64 MUST match the
//     pinned key's SPKI (the field name says "fingerprint" but the
//     value is actually the SPKI DER itself, base64-encoded; this
//     is a TS-side naming inheritance — production bundles emit the
//     full SPKI here, NOT a SHA-256 of the SPKI)
//   - signature.sig.key_fingerprint_spki_b64 MUST agree with
//     manifest.signing.key_fingerprint_spki_b64 (cross-check)
//
// Dispatch:
//   - bundle_type="customer-export" → issuer-prod-v1
//   - bundle_type="example-demo"    → issuer-dev-v1
//   - any other / missing            → issuer-prod-v1 (fail-secure)
//
// Special outcomes:
//   - issuer-prod-v1 + placeholder fingerprint → Warn + Fail (V1
//     binary reality: production deploy-bootstrap replaces the
//     placeholder in Phase 5; until then, customer-export bundles
//     are unverifiable by design and the verifier surfaces this
//     loudly)
//   - bundle_type=example-demo + AllowDevKey=false → Fail (production
//     verifier shouldn't trust dev-signed bundles by default)
//
// Step ordering rationale: structural checks (algorithm, signed_artifact,
// schema_version) fire FIRST so a bundle with structurally-wrong
// signature.sig surfaces a clear "wrong format" error before any
// dispatch logic runs. Bundle_type → key dispatch THEN, then policy
// gates (AllowDevKey, placeholder), THEN cryptographic checks
// (fingerprint equality, SPKI parse, signature.Verify). Cross-checks
// (manifest vs signature.sig key_fingerprint_spki_b64) happen between
// policy and crypto so the operator gets the most actionable error
// first.
type Check1Signature struct{}

func (Check1Signature) ID() int      { return 1 }
func (Check1Signature) Name() string { return "manifest signature" }
func (Check1Signature) Slug() string { return "manifest-signature" }

func (c Check1Signature) Run(b *bundle.Bundle, opts CheckOptions) CheckResult {
	// Phase 7.F.3 2026-05-21: dispatch on bundle_format per spec §§18.1-18.10.
	// v2 path runs runV2DualSignature; v1 path preserves the existing
	// single-Ed25519 verification verbatim.
	// Phase 7.F.4 promotion gate session 102 2026-05-22 code-rev H1
	// closure: use bundle.BundleFormatV2 constant rather than the bare
	// string literal — single source of truth for the spec-pinned
	// bundle_format value. Recurring-defect-class memory n=22+ first
	// instance ("writer-side authority on closed-vocabulary spec-pinned
	// fields where a single string is the contract").
	if b.Manifest.BundleFormat == bundle.BundleFormatV2 {
		return c.runV2DualSignature(b, opts)
	}
	return c.runV1Signature(b, opts)
}

// runV1Signature is the legacy v1 single-Ed25519 verification path
// (unchanged from pre-Phase-7.F baseline; preserved byte-verbatim).
func (c Check1Signature) runV1Signature(b *bundle.Bundle, opts CheckOptions) CheckResult {
	const id = 1
	const name = "manifest signature"
	const slug = "manifest-signature"

	var errs []error
	var warnings []error

	// 1a. signature.sig.schema_version pin per spec §5. M2 from
	// commit-2 reviewer pass: a bundle declaring schema_version=2 in
	// signature.sig must NOT be accepted by a v1 verifier.
	if b.Signature.SchemaVersion != 1 {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("schema_version = %d, expected 1", b.Signature.SchemaVersion),
			SpecRefSignature, "schema_version pinned to 1 for v1 bundles"))
		return Result(id, name, slug, errs, warnings)
	}

	// 1b. signature.sig.algorithm pin.
	if b.Signature.Algorithm != "ed25519" {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("algorithm = %q, expected %q", b.Signature.Algorithm, "ed25519"),
			SpecRefSignature, "Ed25519 algorithm pinned"))
		return Result(id, name, slug, errs, warnings)
	}

	// 1c. manifest.signing.algorithm cross-check (security L1). The
	// manifest carries its own copy of the algorithm; spec §5
	// "verifiers cross-check" framing applies here too. A bundle
	// where signature.sig says ed25519 but manifest says rsa-pss is
	// internally inconsistent and gets rejected before any
	// cryptographic verification.
	if b.Manifest.Signing.Algorithm != "ed25519" {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.algorithm = %q, expected %q", b.Manifest.Signing.Algorithm, "ed25519"),
			SpecRefSignature, "Ed25519 algorithm pinned for v1 bundles"))
		return Result(id, name, slug, errs, warnings)
	}

	// 1d. signature.sig.signed_artifact pin.
	if b.Signature.SignedArtifact != "manifest.json" {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signed_artifact = %q, expected %q", b.Signature.SignedArtifact, "manifest.json"),
			SpecRefSignature, "signature signs manifest.json"))
		return Result(id, name, slug, errs, warnings)
	}

	// 2. Bundle_type → KeyRole dispatch. M3 from commit-2 reviewer:
	// a tampered manifest with malformed generated_at is a tampering
	// signal; fail loudly rather than fall back silently. Future
	// rotation scenarios (Phase 5+) where generatedAt selects between
	// keys with overlapping windows would silently dispatch to the
	// wrong key under the previous fallback semantics.
	generatedAt, ok := parseGeneratedAt(b.Manifest.GeneratedAt)
	if !ok {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("generated_at = %q is not a valid RFC 3339 timestamp", b.Manifest.GeneratedAt),
			SpecRefManifestFields, "generated_at is RFC 3339 / ISO-8601 UTC"))
		return Result(id, name, slug, errs, warnings)
	}
	pinned, err := keys.KeyForBundle(b.Manifest.BundleType, generatedAt)
	if err != nil {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("no pinned issuer key for bundle_type=%q at generated_at=%q (%v)",
				b.Manifest.BundleType, b.Manifest.GeneratedAt, err),
			SpecRefSignature, "verifier expects a pinned key for the bundle's bundle_type"))
		return Result(id, name, slug, errs, warnings)
	}

	// 3. AllowDevKey gate. The dev key has a real fingerprint and
	// will Ed25519-verify dev-signed bundles correctly; this gate
	// is a *policy* check (operator must opt in), distinct from the
	// *cryptographic* check. Defense-in-depth alongside the spec §5
	// dispatch.
	if pinned.KeyRole == keys.KeyRoleDev && !opts.AllowDevKey {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("bundle_type=%q dispatches to development key %q; refusing to verify without --allow-dev-key",
				b.Manifest.BundleType, pinned.KeyID),
			SpecRefSignature, "production verifier rejects dev-signed bundles by default"))
		return Result(id, name, slug, errs, warnings)
	}

	// 4. Placeholder prod-key check. If we dispatched to issuer-prod-
	// v1 and that key still carries the placeholder fingerprint, the
	// V1 binary cannot meaningfully verify any production bundle —
	// surface as Warn with explicit "production deploy-bootstrap
	// required" guidance and SHORT-CIRCUIT (don't try to parse the
	// placeholder string as base64 SPKI; it isn't).
	//
	// keys.PlaceholderProdFingerprint is the single source of truth
	// (security-auditor L3 from commit-2 review).
	if pinned.SPKIFingerprintB64 == keys.PlaceholderProdFingerprint {
		warnings = append(warnings, Warnf(id, name, "",
			fmt.Sprintf("CLI built with placeholder %q fingerprint; production deploy-bootstrap (Phase 5) replaces this with the real KMS-backed key's SPKI before customer-export bundles can be verified",
				pinned.KeyID),
			SpecRefSignature, "production binaries embed the real prod-key SPKI"))
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("cannot verify customer-export bundle: this binary's pinned %s key is a placeholder, not yet replaced by deploy-bootstrap",
				pinned.KeyID),
			SpecRefSignature, "production binaries embed the real prod-key SPKI"))
		return Result(id, name, slug, errs, warnings)
	}

	// 5. Fingerprint equality check. The manifest declares the SPKI
	// it was signed under; the verifier rejects if it doesn't match
	// the pinned SPKI.
	if b.Manifest.Signing.KeyFingerprintB64 != pinned.SPKIFingerprintB64 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("manifest.signing.key_fingerprint_spki_b64 (%s…) does not match pinned %s SPKI (%s…)",
				truncate(b.Manifest.Signing.KeyFingerprintB64, 24),
				pinned.KeyID,
				truncate(pinned.SPKIFingerprintB64, 24)),
			SpecRefSignature, "manifest.signing.key_fingerprint_spki_b64 equals the pinned issuer key's SPKI"))
		return Result(id, name, slug, errs, warnings)
	}

	// 6. Cross-check: signature.sig also carries the SPKI; spec §5
	// lets verifiers cross-check. Mismatch between manifest's
	// declared signing block and signature.sig is a tampering signal.
	if b.Signature.KeyFingerprintB64 != b.Manifest.Signing.KeyFingerprintB64 {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signature.sig.key_fingerprint_spki_b64 (%s…) disagrees with manifest.signing.key_fingerprint_spki_b64 (%s…)",
				truncate(b.Signature.KeyFingerprintB64, 24),
				truncate(b.Manifest.Signing.KeyFingerprintB64, 24)),
			SpecRefSignature, "signature.sig and manifest agree on the signing key"))
		return Result(id, name, slug, errs, warnings)
	}

	// 7. Parse SPKI DER → ed25519.PublicKey.
	spkiDER, err := base64.StdEncoding.DecodeString(pinned.SPKIFingerprintB64)
	if err != nil {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s SPKI is not valid base64: %v", pinned.KeyID, err),
			SpecRefSignature, "pinned issuer key's SPKI is base64-encoded DER"))
		return Result(id, name, slug, errs, warnings)
	}
	pubAny, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s SPKI parse failed: %v", pinned.KeyID, err),
			SpecRefSignature, "pinned issuer key's SPKI is a valid PKIX SubjectPublicKeyInfo DER"))
		return Result(id, name, slug, errs, warnings)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s public key is %T, not ed25519.PublicKey", pinned.KeyID, pubAny),
			SpecRefSignature, "pinned issuer key is Ed25519"))
		return Result(id, name, slug, errs, warnings)
	}

	// 8. Decode signature_b64. Ed25519 signatures are 64 bytes; any
	// other length is malformed.
	sig, err := base64.StdEncoding.DecodeString(b.Signature.SignatureB64)
	if err != nil {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signature_b64 base64-decode failed: %v", err),
			SpecRefSignature, "signature_b64 is base64-encoded Ed25519 signature"))
		return Result(id, name, slug, errs, warnings)
	}
	if len(sig) != ed25519.SignatureSize {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signature_b64 decoded to %d bytes, expected %d", len(sig), ed25519.SignatureSize),
			SpecRefSignature, "Ed25519 signatures are 64 bytes"))
		return Result(id, name, slug, errs, warnings)
	}

	// 9. Verify Ed25519 signature over manifest raw bytes (NOT
	// re-serialized struct contents — bytes-as-loaded posture per
	// the package doc).
	if !ed25519.Verify(pub, b.ManifestRaw, sig) {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("Ed25519 verification failed against pinned %s key", pinned.KeyID),
			SpecRefSignature, "the signature verifies over manifest.json bytes"))
		return Result(id, name, slug, errs, warnings)
	}

	// 10. Dev-key informational warning. Spec §5 line 308 mandates
	// the EXACT phrase: "DEVELOPMENT BUNDLE — verified with dev key,
	// not for production trust" (with em-dash U+2014). External
	// tooling greps for this exact substring; diverging breaks the
	// contract. H1+H2 from commit-2 reviewer pass.
	//
	// **Spec §14.4 (v1.0.7):** the structured WarnCategory field
	// (rather than substring matching) is the canonical fold-decision
	// input for the aggregator. We populate it here. The warning text
	// remains stable per the spec §5 line 308 contract above.
	devKeyEmitted := false
	if pinned.KeyRole == keys.KeyRoleDev {
		warnings = append(warnings, Warnf(id, name, "",
			"DEVELOPMENT BUNDLE — verified with dev key, not for production trust",
			SpecRefSignature, "development bundles bear an informational warning even on Pass"))
		devKeyEmitted = true
	}

	if devKeyEmitted {
		return ResultWithCategory(id, name, slug, errs, warnings, WarnCategoryDevKey)
	}
	return Result(id, name, slug, errs, warnings)
}

// parseGeneratedAt parses an RFC 3339 / ISO-8601 timestamp from the
// manifest's generated_at field. Returns ok=false on malformed input;
// callers (Check1) emit Fail in that case rather than fall back
// silently — a malformed generated_at is a tampering signal and the
// verifier's diagnostic surface should name it specifically.
func parseGeneratedAt(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, false
		}
	}
	return t.UTC(), true
}

// truncate returns s truncated to n chars (for log-friendly fingerprint
// display in error messages). Always truncates when len(s) > n,
// regardless of byte content. Base64 input is pure ASCII printable;
// if a tampered manifest carries non-ASCII bytes in the field, this
// helper still returns a bounded prefix rather than echoing the
// full attacker-controlled string into the error log (security M1
// from commit-2 reviewer pass — output-injection prevention).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

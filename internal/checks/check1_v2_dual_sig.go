package checks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/keys"
)

// KeyPurposeEd25519V2 + KeyPurposeMlDsa65V2 are the spec §18.1 line
// 2243 pinned literal strings for v2 manifest.signing.signatures[i].
// key_purpose. Verifiers MUST byte-equal manifest values against
// these literals (recurring-defect-class memory n=18+ + spec-
// conformance H4 + code-reviewer H1 closure 2026-05-22).
// Writer-side authority: apps/api production signing path + the v2
// test fixture buildMinimalV2Manifest helper.
const (
	KeyPurposeEd25519V2 = "Ed25519 manifest signature; v2.0.0-rc1+ dual-sig topology"
	KeyPurposeMlDsa65V2 = "ML-DSA-65 manifest signature; v2.0.0-rc1+ dual-sig topology"
)

// **Phase 7.F.3 Tier A 5-reviewer heavy-bookmarks (2026-05-22)** for
// next-session closure (not session-97 deploy-blockers):
//
//   - **v2 conformance fixtures** (spec-conf M2 + crypto-int M2 +
//     sec-aud C1's coverage-gap component): docs/spec/fixtures/
//     bundle-format-v1/ lacks any valid-v2-* fixture. The Go
//     TestConformanceFixtures framework should be extended in
//     Phase 7.F.4 to include valid-v2-example-demo +
//     valid-v2-customer-export + at least one v2 tamper variant per
//     spec §14.4 PLANNED row. Cross-language byte-equivalence is
//     empirically untested until this lands; the v2 tests at
//     check1_v2_dual_sig_test.go use Go-only in-memory round-trip.
//
//   - **AlgorithmName + AlgorithmStatus typed enums** (code-rev L4):
//     replace the free `string` fields in AlgorithmVerdict with
//     typed enums matching the spec §18.4 + §18.10 closed vocabulary.
//     Catches typos at compile time. Aligns with keys.KeyRole pattern.
//
//   - **Lowercase pinned key globals** (code-rev M3): convert
//     PinnedIssuerKeys + PinnedEd25519V2IssuerKeys +
//     PinnedMlDsa65IssuerKeys to lowercase package-private vars +
//     expose only ListPinned* + KeyForBundle* + a test-only
//     WithPinnedKeysForTest helper. Eliminates the test-globals
//     parallel-safety concern (sec-aud L1 + code-rev M1).
//
//   - **Tampered-test byte-position coverage** (crypto-int M1):
//     parameterize TamperedEd25519 + TamperedMlDsa65 with positions
//     [0, len/2, len-1] x mutation patterns [^=0x01, ^=0xFF, =0x00]
//     for byte-position-comprehensive coverage. Current tests cover
//     only last-byte ^=0x01.
//
//   - **v1/v2 code duplication** (code-rev L5): runV1Signature +
//     runV2DualSignature share substantial structure. Acceptable for
//     spec-§5-vs-§18 separation today; reconsider at next surface
//     change if the duplication becomes a maintenance drag.

// runV2DualSignature is the v2.0.0-rc1 (Phase 7.F.3) dual-signature
// verification path for bundles where manifest.bundle_format ==
// "nuwyre-bundle/v2". Per spec §§18.1-18.10:
//
//   - signature.sig.schema_version MUST be 2
//   - signature.sig.signed_artifact MUST be "manifest.json"
//   - signature.sig.signatures[] has cardinality EXACTLY 2 with
//     positional ordering signatures[0]=ed25519, signatures[1]=ml-dsa-65
//   - manifest.signing.schema_version MUST be 1 (the signing-block
//     schema, distinct from the bundle_format version)
//   - manifest.signing.signatures[] mirrors signature.sig.signatures[]
//     with the same positional algorithm ordering
//   - v1 single-signature fields at both signature.sig and
//     manifest.signing MUST be absent (zero-valued in the Go decoder
//     under omitempty)
//   - For each i in {0,1}: signature.sig.signatures[i].
//     key_fingerprint_spki_b64 MUST equal manifest.signing.
//     signatures[i].key_fingerprint_spki_b64 AND signatures[i].key_id
//     MUST equal (cross-tampering defense per spec §18.7 step 2)
//   - Cross-environment-slot coherence (spec §18.6): both Ed25519 and
//     ML-DSA-65 pinned keys MUST belong to the SAME slot (both prod XOR
//     both dev). A mixed-slot bundle is rejected at schema-cross-check
//     BEFORE any cryptographic operation.
//   - Both signatures verify over manifest raw bytes (bytes-as-loaded
//     posture per package doc): Ed25519 + ML-DSA-65 with empty context
//     per FIPS 204 deterministic-variant pinned at spec §18.3.
//   - Per-algorithm verdict surface (spec §18.10): AlgorithmVerdicts is
//     populated with BOTH verdicts regardless of which fails first —
//     no short-circuit on first failure. Operators consuming `--json`
//     output observe both verdicts even on Check 1 fail; this is the
//     dispute-investigation surface required by spec §18.10.
//
// Step ordering rationale matches v1 (runV1Signature): structural
// schema checks fire FIRST (so a malformed v2 bundle surfaces "wrong
// format" before any dispatch); positional-ordering invariant THEN;
// THEN cross-check + slot-coherence + policy gates (AllowDevKey,
// placeholder); cryptographic verification LAST. Within crypto
// verification, BOTH algorithms run unconditionally so per-algorithm
// verdicts populate even when Ed25519 passes + ML-DSA-65 fails (or
// vice versa).
//
// Recurring-defect-class memory (n=18+): writer-side authority on
// closed-vocabulary spec-pinned fields — the v2 dispatch fires off
// manifest.bundle_format at the entry point (check1_signature.go:64),
// NOT off field-presence. A v1 bundle with stray .signatures field
// would route to runV1Signature; a v2 bundle missing the .signatures
// array would surface as a schema fail HERE, not as a v1-fallback.
func (c Check1Signature) runV2DualSignature(b *bundle.Bundle, opts CheckOptions) CheckResult {
	const id = 1
	const name = "manifest signature"
	const slug = "manifest-signature"

	var errs []error
	var warnings []error

	// failV2 builds a CheckResult with both algorithm_verdicts entries
	// set to "fail" — required even on schema-cross-check short-circuits
	// per spec §18.10 "Conformance contract scope" (the algorithm_verdicts
	// field is load-bearing for cross-implementation structural conformance
	// and MUST emit with cardinality 2 + closed-enum status values for
	// every v2 Check 1 result, including early-fail at schema validation).
	// security-auditor M3 closure 2026-05-22.
	failV2 := func() CheckResult {
		r := Result(id, name, slug, errs, warnings)
		r.AlgorithmVerdicts = []AlgorithmVerdict{
			{Algorithm: "ed25519", Status: "fail"},
			{Algorithm: "ml-dsa-65", Status: "fail"},
		}
		return r
	}

	// Spec §18.2/§18.7 step 1 pin signature.sig.schema_version to 1
	// (NOT 2 — the bundle.schema_version is 2; the signing-container
	// schema is 1). Writer-side authority: packages/evidence/src/
	// generate-bundle.ts:1277 emits schema_version: 1 (recurring-defect-
	// class n=18+: closed-vocabulary spec-pinned fields, writer-side
	// authority). spec-conformance M1 closure 2026-05-22.
	if b.Signature.SchemaVersion != 1 {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("schema_version = %d, expected 1 for v2 bundles", b.Signature.SchemaVersion),
			SpecRefDualSignatureSig, "schema_version pinned to 1 for v2 bundles (signing-container schema; distinct from bundle.schema_version=2)"))
		return failV2()
	}

	if b.Signature.SignedArtifact != "manifest.json" {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signed_artifact = %q, expected %q", b.Signature.SignedArtifact, "manifest.json"),
			SpecRefDualSignatureSig, "signature signs manifest.json"))
		return failV2()
	}

	// v1 single-signature fields MUST be absent at v2. Their presence
	// at non-zero is a v1/v2 mixing signal.
	if b.Signature.Algorithm != "" || b.Signature.KeyFingerprintB64 != "" || b.Signature.SignatureB64 != "" {
		errs = append(errs, Errorf(id, name, "signature.sig",
			"v1 single-signature fields (algorithm, key_fingerprint_spki_b64, signature_b64) MUST be absent at v2 bundles",
			SpecRefDualSignatureSig, "v2 bundles emit only the signatures[] array"))
		return failV2()
	}

	if len(b.Signature.Signatures) != 2 {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[] has %d entries, expected EXACTLY 2", len(b.Signature.Signatures)),
			SpecRefDualSignatureSig, "v2 bundles carry exactly 2 entries (Ed25519 + ML-DSA-65)"))
		return failV2()
	}
	if b.Signature.Signatures[0].Algorithm != "ed25519" {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[0].algorithm = %q, expected %q", b.Signature.Signatures[0].Algorithm, "ed25519"),
			SpecRefDualSignatureOrdering, "signatures[0] MUST be ed25519"))
		return failV2()
	}
	if b.Signature.Signatures[1].Algorithm != "ml-dsa-65" {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[1].algorithm = %q, expected %q", b.Signature.Signatures[1].Algorithm, "ml-dsa-65"),
			SpecRefDualSignatureOrdering, "signatures[1] MUST be ml-dsa-65"))
		return failV2()
	}

	if b.Manifest.Signing.SchemaVersion != 1 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.schema_version = %d, expected 1", b.Manifest.Signing.SchemaVersion),
			SpecRefDualSignatureManifest, "signing.schema_version is 1 for v2 bundles"))
		return failV2()
	}

	// v1 single-signature fields at manifest.signing MUST be absent at v2.
	if b.Manifest.Signing.Algorithm != "" || b.Manifest.Signing.KeyFingerprintB64 != "" || b.Manifest.Signing.KeyPurpose != "" {
		errs = append(errs, Errorf(id, name, "manifest.json",
			"v1 signing fields (algorithm, key_fingerprint_spki_b64, key_purpose) MUST be absent at v2 bundles",
			SpecRefDualSignatureManifest, "v2 bundles emit only the signing.signatures[] array"))
		return failV2()
	}

	if len(b.Manifest.Signing.Signatures) != 2 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[] has %d entries, expected EXACTLY 2", len(b.Manifest.Signing.Signatures)),
			SpecRefDualSignatureManifest, "v2 bundles carry exactly 2 entries (Ed25519 + ML-DSA-65)"))
		return failV2()
	}
	if b.Manifest.Signing.Signatures[0].Algorithm != "ed25519" {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[0].algorithm = %q, expected %q", b.Manifest.Signing.Signatures[0].Algorithm, "ed25519"),
			SpecRefDualSignatureOrdering, "signing.signatures[0] MUST be ed25519"))
		return failV2()
	}
	if b.Manifest.Signing.Signatures[1].Algorithm != "ml-dsa-65" {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[1].algorithm = %q, expected %q", b.Manifest.Signing.Signatures[1].Algorithm, "ml-dsa-65"),
			SpecRefDualSignatureOrdering, "signing.signatures[1] MUST be ml-dsa-65"))
		return failV2()
	}

	// Spec §18.1 line 2243: verifiers MUST byte-equal key_purpose
	// against the pinned literal strings at Check 1 step 2 schema-
	// cross-check (recurring-defect-class n=18+: writer-side authority
	// on closed-vocabulary spec-pinned fields).
	// spec-conformance H4 + code-reviewer H1 closure 2026-05-22.
	if b.Manifest.Signing.Signatures[0].KeyPurpose != KeyPurposeEd25519V2 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[0].key_purpose = %q, expected pinned literal", b.Manifest.Signing.Signatures[0].KeyPurpose),
			SpecRefDualSignatureManifest, fmt.Sprintf("signing.signatures[0].key_purpose MUST be %q", KeyPurposeEd25519V2)))
		return failV2()
	}
	if b.Manifest.Signing.Signatures[1].KeyPurpose != KeyPurposeMlDsa65V2 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[1].key_purpose = %q, expected pinned literal", b.Manifest.Signing.Signatures[1].KeyPurpose),
			SpecRefDualSignatureManifest, fmt.Sprintf("signing.signatures[1].key_purpose MUST be %q", KeyPurposeMlDsa65V2)))
		return failV2()
	}

	// 2. Bundle_type → dual-key dispatch. Parse generated_at first
	// (mirror of v1 step 2). A malformed generated_at is a tampering
	// signal; fail loudly.
	generatedAt, ok := parseGeneratedAt(b.Manifest.GeneratedAt)
	if !ok {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("generated_at = %q is not a valid RFC 3339 timestamp", b.Manifest.GeneratedAt),
			SpecRefManifestFields, "generated_at is RFC 3339 / ISO-8601 UTC"))
		return failV2()
	}
	// crypto-integrity C1 closure 2026-05-22: use the v2-specific
	// Ed25519 pinned-key table (PinnedEd25519V2IssuerKeys), NOT the v1
	// table (PinnedIssuerKeys). Spec §18.6 mandates distinct v2 KeyIDs
	// (issuer-{prod,dev}-v2-ed25519); using KeyForBundle would
	// resolve to v1 keys + leak wrong KeyID into error messages.
	pinnedEd25519, err := keys.KeyForBundleEd25519V2(b.Manifest.BundleType, generatedAt)
	if err != nil {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("no pinned v2 Ed25519 issuer key for bundle_type=%q at generated_at=%q (%v)",
				b.Manifest.BundleType, b.Manifest.GeneratedAt, err),
			SpecRefDualSignatureVerify, "verifier expects a pinned v2 Ed25519 key for the bundle's bundle_type"))
		return failV2()
	}
	pinnedMlDsa65, err := keys.KeyForBundleMlDsa65(b.Manifest.BundleType, generatedAt)
	if err != nil {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("no pinned ML-DSA-65 issuer key for bundle_type=%q at generated_at=%q (%v)",
				b.Manifest.BundleType, b.Manifest.GeneratedAt, err),
			SpecRefDualSignatureVerify, "verifier expects a pinned ML-DSA-65 key for the bundle's bundle_type"))
		return failV2()
	}

	// 3. Cross-environment-slot coherence (spec §18.6). Both keys MUST
	// belong to the same slot: both prod XOR both dev. A bundle
	// mixing prod-Ed25519 with dev-ML-DSA-65 (or vice versa) is
	// rejected BEFORE any cryptographic operation — this is the
	// schema-layer defense against an attacker who has only one
	// algorithm's signing key and tries to pair it with a public key
	// from the other slot.
	if pinnedEd25519.KeyRole != pinnedMlDsa65.KeyRole {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("cross-environment-slot violation: Ed25519 dispatches to %s (role=%s) but ML-DSA-65 dispatches to %s (role=%s); both MUST be same slot",
				pinnedEd25519.KeyID, pinnedEd25519.KeyRole,
				pinnedMlDsa65.KeyID, pinnedMlDsa65.KeyRole),
			SpecRefDualSignatureSlot, "both signature algorithms belong to the SAME environment slot (prod XOR dev)"))
		return failV2()
	}

	// 4. AllowDevKey gate (mirror of v1 step 3). Both keys are in the
	// same slot (verified at step 3); a single check on either suffices.
	if pinnedEd25519.KeyRole == keys.KeyRoleDev && !opts.AllowDevKey {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("bundle_type=%q dispatches to development keys (%s, %s); refusing to verify without --allow-dev-key",
				b.Manifest.BundleType, pinnedEd25519.KeyID, pinnedMlDsa65.KeyID),
			SpecRefDualSignatureVerify, "production verifier rejects dev-signed bundles by default"))
		return failV2()
	}

	// 5. Placeholder prod-key check. At v2.0.0-rc1 the ML-DSA-65 prod
	// key is a placeholder pending Phase 7.F.4 deploy-bootstrap;
	// customer-export v2 bundles are unverifiable by design until the
	// real HSM-equivalent key is wired. Surface as Warn + Fail with
	// explicit guidance, short-circuit before crypto parse.
	//
	// Recurring-defect-class memory n=20+ closure (Phase 7.F.4 promotion
	// gate session 102 2026-05-22): the Ed25519 check now accepts EITHER
	// the v1 placeholder constant (PlaceholderProdFingerprint, legacy
	// path) OR the v2 placeholder constant (PlaceholderProdEd25519V2
	// Fingerprint, current v2 prod dispatch). Pre-closure: only v1 was
	// checked, so v2 prod Ed25519 placeholder bypassed step 5 silently
	// when ML-DSA-65 also happened to be placeholder (cascading
	// detection accident); if v2 prod Ed25519 deployed before v2 prod
	// ML-DSA-65 at Phase 7.F.4+, the Ed25519 step would silently bypass
	// → step 6 catches with less-clear error.
	//
	// **Defense-in-depth note (crypto-int M3 closure 2026-05-22)**: the
	// v1 placeholder branch is STRUCTURALLY UNREACHABLE here because
	// KeyForBundleEd25519V2 only returns v2 keys (issuer-{prod,dev}-v2-
	// ed25519, never v1). Kept as defense against future dispatcher
	// consolidation that might collapse v1+v2 tables — if simplifying
	// to the v2-only branch, ensure keys_test.go has a regression test
	// pinning the v2-only-dispatch invariant.
	if pinnedEd25519.SPKIFingerprintB64 == keys.PlaceholderProdFingerprint ||
		pinnedEd25519.SPKIFingerprintB64 == keys.PlaceholderProdEd25519V2Fingerprint {
		warnings = append(warnings, Warnf(id, name, "",
			fmt.Sprintf("CLI built with placeholder %q fingerprint; production deploy-bootstrap replaces this with the real KMS-backed key's SPKI before v2 customer-export bundles can be verified",
				pinnedEd25519.KeyID),
			SpecRefDualSignatureVerify, "production binaries embed the real prod-key SPKI"))
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("cannot verify v2 customer-export bundle: this binary's pinned %s key is a placeholder, not yet replaced by deploy-bootstrap",
				pinnedEd25519.KeyID),
			SpecRefDualSignatureVerify, "production binaries embed the real prod-key SPKI"))
		return failV2()
	}
	if pinnedMlDsa65.SPKIFingerprintB64 == keys.PlaceholderProdMlDsa65Fingerprint {
		warnings = append(warnings, Warnf(id, name, "",
			fmt.Sprintf("CLI built with placeholder %q fingerprint; Phase 7.F.4 deploy-bootstrap replaces this with the real HSM-equivalent ML-DSA-65 key's SPKI before v2 customer-export bundles can be verified",
				pinnedMlDsa65.KeyID),
			SpecRefDualSignatureVerify, "production binaries embed the real prod-key SPKI"))
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("cannot verify v2 customer-export bundle: this binary's pinned %s key is a placeholder, not yet replaced by deploy-bootstrap",
				pinnedMlDsa65.KeyID),
			SpecRefDualSignatureVerify, "production binaries embed the real prod-key SPKI"))
		return failV2()
	}

	// 6. Fingerprint equality check at manifest.signing.signatures[].
	// The manifest declares which SPKIs it was signed under; the
	// verifier rejects if either disagrees with the pinned SPKI.
	if b.Manifest.Signing.Signatures[0].KeyFingerprintB64 != pinnedEd25519.SPKIFingerprintB64 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[0].key_fingerprint_spki_b64 (%s…) does not match pinned %s SPKI (%s…)",
				truncate(b.Manifest.Signing.Signatures[0].KeyFingerprintB64, 24),
				pinnedEd25519.KeyID,
				truncate(pinnedEd25519.SPKIFingerprintB64, 24)),
			SpecRefDualSignatureManifest, "signing.signatures[0].key_fingerprint_spki_b64 equals the pinned Ed25519 issuer key's SPKI"))
		return failV2()
	}
	if b.Manifest.Signing.Signatures[1].KeyFingerprintB64 != pinnedMlDsa65.SPKIFingerprintB64 {
		errs = append(errs, Errorf(id, name, "manifest.json",
			fmt.Sprintf("signing.signatures[1].key_fingerprint_spki_b64 (%s…) does not match pinned %s SPKI (%s…)",
				truncate(b.Manifest.Signing.Signatures[1].KeyFingerprintB64, 24),
				pinnedMlDsa65.KeyID,
				truncate(pinnedMlDsa65.SPKIFingerprintB64, 24)),
			SpecRefDualSignatureManifest, "signing.signatures[1].key_fingerprint_spki_b64 equals the pinned ML-DSA-65 issuer key's SPKI"))
		return failV2()
	}

	// 7. Cross-check per spec §18.7 step 2:
	//   (a) signature.sig.signatures[i].algorithm equals manifest.signing.signatures[i].algorithm
	//       (defensive against future schema where positional pin alone is insufficient;
	//       spec-conformance H1 closure 2026-05-22).
	//   (b) signature.sig.signatures[i].key_fingerprint_spki_b64 equals manifest.signing equivalent
	//   (c) signature.sig.signatures[i].key_id equals manifest.signing equivalent
	//   (d) signature.sig.signatures[i].key_id equals pinnedKey.KeyID
	//       (security-auditor M1 closure 2026-05-22: attacker who pairs a valid SPKI
	//       with arbitrary key_id passed all prior checks; pinned cross-check closes
	//       the gap so attacker-supplied key_id can't surface in operator dashboards).
	pinnedKeys := [2]*keys.IssuerKey{pinnedEd25519, pinnedMlDsa65}
	for i := 0; i < 2; i++ {
		if b.Signature.Signatures[i].Algorithm != b.Manifest.Signing.Signatures[i].Algorithm {
			errs = append(errs, Errorf(id, name, "signature.sig",
				fmt.Sprintf("signatures[%d].algorithm %q disagrees with manifest.signing.signatures[%d].algorithm %q",
					i, b.Signature.Signatures[i].Algorithm,
					i, b.Manifest.Signing.Signatures[i].Algorithm),
				SpecRefDualSignatureVerify, "signature.sig and manifest agree on the algorithm per position"))
			return failV2()
		}
		if b.Signature.Signatures[i].KeyFingerprintB64 != b.Manifest.Signing.Signatures[i].KeyFingerprintB64 {
			errs = append(errs, Errorf(id, name, "signature.sig",
				fmt.Sprintf("signatures[%d].key_fingerprint_spki_b64 (%s…) disagrees with manifest.signing.signatures[%d].key_fingerprint_spki_b64 (%s…)",
					i, truncate(b.Signature.Signatures[i].KeyFingerprintB64, 24),
					i, truncate(b.Manifest.Signing.Signatures[i].KeyFingerprintB64, 24)),
				SpecRefDualSignatureVerify, "signature.sig and manifest agree on the signing key per algorithm"))
			return failV2()
		}
		if b.Signature.Signatures[i].KeyID != b.Manifest.Signing.Signatures[i].KeyID {
			errs = append(errs, Errorf(id, name, "signature.sig",
				fmt.Sprintf("signatures[%d].key_id %q disagrees with manifest.signing.signatures[%d].key_id %q",
					i, b.Signature.Signatures[i].KeyID,
					i, b.Manifest.Signing.Signatures[i].KeyID),
				SpecRefDualSignatureVerify, "signature.sig and manifest agree on the key_id per algorithm"))
			return failV2()
		}
		if b.Manifest.Signing.Signatures[i].KeyID != pinnedKeys[i].KeyID {
			errs = append(errs, Errorf(id, name, "manifest.json",
				fmt.Sprintf("signing.signatures[%d].key_id %q does not match pinned %q",
					i, b.Manifest.Signing.Signatures[i].KeyID, pinnedKeys[i].KeyID),
				SpecRefDualSignatureVerify, "signing.signatures[i].key_id equals the pinned issuer key's KeyID"))
			return failV2()
		}
	}

	// 8. Parse Ed25519 SPKI DER + verify. Failures populate
	// AlgorithmVerdicts entry 0 without short-circuiting; ML-DSA-65
	// still runs at step 9 so the operator sees both verdicts.
	ed25519Verdict := AlgorithmVerdict{Algorithm: "ed25519", Status: "pass"}
	ed25519Errs := verifyEd25519Leg(b, pinnedEd25519, id, name)
	if len(ed25519Errs) > 0 {
		ed25519Verdict.Status = "fail"
		errs = append(errs, ed25519Errs...)
	}

	// 9. Parse ML-DSA-65 SPKI DER + verify. Spec §18.3 pins the
	// FIPS 204 deterministic-variant (randomized=false, empty context).
	mldsaVerdict := AlgorithmVerdict{Algorithm: "ml-dsa-65", Status: "pass"}
	mldsaErrs := verifyMlDsa65Leg(b, pinnedMlDsa65, id, name)
	if len(mldsaErrs) > 0 {
		mldsaVerdict.Status = "fail"
		errs = append(errs, mldsaErrs...)
	}

	// 10. Dev-key handling. Two paths per spec §18.6:
	//   (a) Informational warning per spec §5 line 308 exact phrase
	//       (external tooling greps for the exact substring). Slot
	//       coherence at step 3 guarantees both keys are dev-slot
	//       when this fires. Foldable via --allow-dev-key per
	//       spec §14.4 dev_key category.
	//   (b) **Elevated FAIL** for bundle_type=audit-log-export +
	//       bundle_subtype=operator-only + dev-slot dispatch per spec
	//       §18.6 audit-log clause + security-auditor H1 closure.
	//       Operator-only audit-log carries SOC 2 + regulatory-
	//       inquiry-response evidence weight per §16.1; a dev-slot
	//       signature on operator-only evidence is a red flag for a
	//       leaked-dev-key-claiming-prod-evidence attack scenario.
	//       NOT foldable via --allow-dev-key (intentional asymmetry
	//       vs path (a)). Recurring-defect-class memory n=21+
	//       inverse-direction closure (Phase 7.F.4 promotion gate
	//       session 102 2026-05-22).
	devKeyEmitted := false
	// Defense-in-depth: explicitly assert BOTH key roles are Dev
	// (crypto-int M2 closure 2026-05-22). Slot coherence at step 3
	// guarantees this transitively today, but a future refactor that
	// relaxes slot-coherence to "warn-not-fail" would leak a mixed-
	// slot (ed25519=dev + mldsa=prod) into this branch and incorrectly
	// elevate. Explicit AND makes the elevation condition robust against
	// such reorderings.
	if pinnedEd25519.KeyRole == keys.KeyRoleDev && pinnedMlDsa65.KeyRole == keys.KeyRoleDev {
		// Empty BundleSubtype on audit-log-export treated as operator-only
		// equivalent for elevation purposes (sec-aud M2 closure 2026-05-22):
		// the verifier cannot prove a missing-subtype bundle is customer-
		// scoped, so default to the elevated discipline. Check 9 catches
		// missing-subtype at the audit-log-merkle layer as well, but
		// defense-in-depth at Check 1 keeps the policy-layer rejection
		// path single-step.
		isOperatorOnlyAuditLog := b.Manifest.BundleType == "audit-log-export" &&
			(b.Manifest.BundleSubtype == "operator-only" || b.Manifest.BundleSubtype == "")
		if isOperatorOnlyAuditLog {
			// Path (b) — elevated FAIL per spec §18.6 audit-log clause.
			// Top-of-message diagnostic per code-rev M1 closure 2026-05-22:
			// explicitly state "crypto verified but policy rejected" so the
			// operator's incident-response narrative is unambiguous. The
			// crypto verdicts (algorithm_verdicts cardinality 2 + both
			// pass) co-exist alongside Check 1 fail; this is the spec-
			// §18.10 dispute-investigation surface working correctly.
			errs = append(errs, Errorf(id, name, "manifest.json",
				"CRYPTO VERIFIED BUT POLICY REJECTED: operator-only audit-log-export bundle signed with development keys; spec §18.6 audit-log clause + security-auditor H1 closure REQUIRE production-slot keys for operator-only subtype (SOC 2 + regulatory-inquiry-response evidence weight per §16.1; dev-slot signature on operator-only evidence is a leaked-dev-key-claiming-prod-evidence attack signal)",
				SpecRefDualSignatureSlot, "operator-only audit-log-export bundles MUST be signed with production-slot keys; dev-slot dispatch elevates to fail + NOT foldable via --allow-dev-key"))
		} else {
			// Path (a) — informational warn (foldable via --allow-dev-key).
			warnings = append(warnings, Warnf(id, name, "",
				"DEVELOPMENT BUNDLE — verified with dev key, not for production trust",
				SpecRefDualSignatureVerify, "development bundles bear an informational warning even on Pass"))
			devKeyEmitted = true
		}
	}

	// 11. Assemble result with AlgorithmVerdicts populated per spec
	// §18.10. Both verdicts surface regardless of pass/fail outcome.
	var r CheckResult
	if devKeyEmitted {
		r = ResultWithCategory(id, name, slug, errs, warnings, WarnCategoryDevKey)
	} else {
		r = Result(id, name, slug, errs, warnings)
	}
	r.AlgorithmVerdicts = []AlgorithmVerdict{ed25519Verdict, mldsaVerdict}
	return r
}

// verifyEd25519Leg runs the Ed25519 leg of the v2 dual-signature
// verification: parse pinned SPKI DER → ed25519.PublicKey, decode
// signature_b64, verify length, verify signature over manifest raw
// bytes. Returns []error populated on failure (empty slice on pass).
//
// Pulled into a helper so step 8 can populate the AlgorithmVerdicts
// entry without short-circuiting on Ed25519 failure (spec §18.10
// requires both verdicts emit even on first-failure).
func verifyEd25519Leg(b *bundle.Bundle, pinned *keys.IssuerKey, id int, name string) []error {
	var errs []error
	spkiDER, err := base64.StdEncoding.DecodeString(pinned.SPKIFingerprintB64)
	if err != nil {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s SPKI is not valid base64: %v", pinned.KeyID, err),
			SpecRefDualSignatureAlgo, "pinned Ed25519 issuer key's SPKI is base64-encoded DER"))
		return errs
	}
	pubAny, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s SPKI parse failed: %v", pinned.KeyID, err),
			SpecRefDualSignatureAlgo, "pinned Ed25519 issuer key's SPKI is a valid PKIX SubjectPublicKeyInfo DER"))
		return errs
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s public key is %T, not ed25519.PublicKey", pinned.KeyID, pubAny),
			SpecRefDualSignatureAlgo, "pinned Ed25519 issuer key is Ed25519"))
		return errs
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature.Signatures[0].SignatureB64)
	if err != nil {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[0].signature_b64 base64-decode failed: %v", err),
			SpecRefDualSignatureAlgo, "signature_b64 is base64-encoded Ed25519 signature"))
		return errs
	}
	if len(sig) != ed25519.SignatureSize {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[0].signature_b64 decoded to %d bytes, expected %d", len(sig), ed25519.SignatureSize),
			SpecRefDualSignatureAlgo, "Ed25519 signatures are 64 bytes"))
		return errs
	}
	if !ed25519.Verify(pub, b.ManifestRaw, sig) {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("Ed25519 verification failed against pinned %s key", pinned.KeyID),
			SpecRefDualSignatureAlgo, "the Ed25519 signature verifies over manifest.json bytes"))
		return errs
	}
	return errs
}

// verifyMlDsa65Leg runs the ML-DSA-65 leg of the v2 dual-signature
// verification. Spec §18.3 pins the FIPS 204 deterministic-variant
// with empty context — cloudflare/circl's mldsa65.Verify takes the
// context as an explicit []byte arg; passing nil is byte-equivalent
// to passing []byte{} per the implementation (verified at cloudflare/
// circl v1.6.3). The writer-side ML-DSA-65 primitive (Phase 7.F.2-A
// at packages/evidence/src/ml-dsa-65-signer.ts) signs with the
// matching empty context.
//
// Signature size: 3309 bytes raw → 4412 chars base64 with NO padding
// (3309 mod 3 == 0) per crypto-integrity L1 closure.
// SPKI size: 1974 bytes raw DER → 2632 chars base64 with NO padding.
func verifyMlDsa65Leg(b *bundle.Bundle, pinned *keys.IssuerKey, id int, name string) []error {
	var errs []error
	spkiDER, err := base64.StdEncoding.DecodeString(pinned.SPKIFingerprintB64)
	if err != nil {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s SPKI is not valid base64: %v", pinned.KeyID, err),
			SpecRefDualSignatureAlgo, "pinned ML-DSA-65 issuer key's SPKI is base64-encoded DER"))
		return errs
	}
	pub, err := parseMlDsa65SPKI(spkiDER)
	if err != nil {
		errs = append(errs, Errorf(id, name, "",
			fmt.Sprintf("internal: pinned %s SPKI parse failed: %v", pinned.KeyID, err),
			SpecRefDualSignatureAlgo, "pinned ML-DSA-65 issuer key's SPKI is a valid PKIX SubjectPublicKeyInfo DER"))
		return errs
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature.Signatures[1].SignatureB64)
	if err != nil {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[1].signature_b64 base64-decode failed: %v", err),
			SpecRefDualSignatureAlgo, "signature_b64 is base64-encoded ML-DSA-65 signature"))
		return errs
	}
	if len(sig) != mldsa65.SignatureSize {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("signatures[1].signature_b64 decoded to %d bytes, expected %d", len(sig), mldsa65.SignatureSize),
			SpecRefDualSignatureAlgo, "ML-DSA-65 signatures are 3309 bytes per FIPS 204"))
		return errs
	}
	// FIPS 204 deterministic variant with empty context per spec §18.3.
	// Explicit []byte{} (NOT nil) matches the spec's "empty byte string"
	// wording verbatim + defends against future cloudflare/circl
	// semantic divergence on nil-vs-empty (spec-conformance H2 closure
	// 2026-05-22; current v1.6.3 treats both identically per its
	// Verify(pub, msg, ctx, sig) implementation).
	if !mldsa65.Verify(pub, b.ManifestRaw, []byte{}, sig) {
		errs = append(errs, Errorf(id, name, "signature.sig",
			fmt.Sprintf("ML-DSA-65 verification failed against pinned %s key", pinned.KeyID),
			SpecRefDualSignatureAlgo, "the ML-DSA-65 signature verifies over manifest.json bytes"))
		return errs
	}
	return errs
}

// parseMlDsa65SPKI extracts an ML-DSA-65 public key from a 1974-byte
// PKIX SubjectPublicKeyInfo DER per spec §18.4. Go's stdlib
// x509.ParsePKIXPublicKey does NOT recognize ML-DSA-65 OIDs (FIPS 204
// post-dates stdlib's PKIX OID table).
//
// Strict-validation posture (consolidated closure 2026-05-22 of
// spec-conformance H3 + crypto-integrity H1 + code-reviewer H2/L3 +
// security-auditor H1): validates the full 22-byte canonical prefix
// against keys.MlDsa65SPKIPrefix (writer-side authority from
// packages/evidence/src/ml-dsa-65.ts:90). An attacker who supplies a
// 1974-byte DER with a different AlgorithmIdentifier OID is rejected
// here; without this check, the raw 1952 trailing bytes would be
// passed to cloudflare/circl as if they were a legitimate ML-DSA-65
// public key (algorithm-confusion surface).
//
// Recurring-defect-class memory (n=18+, writer-side authority on
// closed-vocabulary spec-pinned fields): the prefix bytes ARE the
// closed vocabulary; byte-equality is the only safe validation.
func parseMlDsa65SPKI(der []byte) (*mldsa65.PublicKey, error) {
	if len(der) != keys.MlDsa65SPKISize {
		return nil, fmt.Errorf("SPKI DER length = %d bytes, expected exactly %d (spec §18.4)",
			len(der), keys.MlDsa65SPKISize)
	}
	if !bytes.Equal(der[:keys.MlDsa65SPKIPrefixSize], keys.MlDsa65SPKIPrefix) {
		// Find the first mismatching byte for an actionable error
		// message (operator-localized: pinpoints AlgorithmIdentifier
		// substitution attacks at the byte level).
		for i := 0; i < keys.MlDsa65SPKIPrefixSize; i++ {
			if der[i] != keys.MlDsa65SPKIPrefix[i] {
				return nil, fmt.Errorf("SPKI DER prefix mismatch at byte %d: expected 0x%02x, got 0x%02x (spec §18.4 canonical construction; possible algorithm-confusion)",
					i, keys.MlDsa65SPKIPrefix[i], der[i])
			}
		}
		// Unreachable (bytes.Equal returned false but byte-by-byte
		// found no diff — defensive).
		return nil, fmt.Errorf("SPKI DER prefix mismatch (length-equal but bytes.Equal disagreed; internal verifier error)")
	}
	rawPub := der[keys.MlDsa65SPKIPrefixSize:]
	pub := new(mldsa65.PublicKey)
	if err := pub.UnmarshalBinary(rawPub); err != nil {
		return nil, fmt.Errorf("ml-dsa-65 public-key unmarshal failed: %w", err)
	}
	return pub, nil
}

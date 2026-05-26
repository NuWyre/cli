package checks

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/keys"
)

// TestCheck1V2DispatchHappyPath constructs a minimal v2 bundle.zip
// in-memory using cloudflare/circl + crypto/ed25519, then runs the
// Check 1 v2 dual-signature dispatch against it. Asserts:
//   - Pass overall (with dev-key Warn)
//   - AlgorithmVerdicts has exactly 2 entries: [ed25519, ml-dsa-65]
//   - Both algorithm verdicts are "pass"
//   - WarnCategory is "dev_key" (per spec §14.4 fold)
//
// This is the Go-side round-trip lock-in test for Phase 7.F.3
// v2.0.0-rc1 (per n=18+ recurring-defect-class memory: byte-precise
// code needs byte-precise round-trip coverage).
//
// **Cross-language byte-equivalence**: heavy-bookmarked for Tier A
// 5-reviewer follow-up. Cloudflare/circl + @noble/post-quantum are
// both FIPS 204 conformant per their respective documentation;
// inter-library interop is a documented invariant. A TS-emitted
// bundle.zip → Go-CLI verification round-trip lives at the
// conformance-fixture pipeline (docs/spec/fixtures/bundle-format-v1/)
// extension — pending session 98+.
func TestCheck1V2DispatchHappyPath(t *testing.T) {
	// Generate matching keypairs for both algorithms.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ml-dsa-65 keygen: %v", err)
	}

	// Build SPKI for both keys.
	edSpkiDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("ed25519 SPKI marshal: %v", err)
	}
	edSpkiB64 := base64.StdEncoding.EncodeToString(edSpkiDER)

	mldsaSpkiDER := wrapMlDsa65SPKI(t, mldsaPub)
	mldsaSpkiB64 := base64.StdEncoding.EncodeToString(mldsaSpkiDER)
	mldsaSpkiB64 = strings.TrimRight(mldsaSpkiB64, "=") // 1974 mod 3 == 0; no padding per spec §18.4

	// Construct a minimal v2 manifest. Field order alphabetical for
	// determinism (RFC 8785 JCS posture); the v2 dispatch only reads
	// bundle_format + bundle_type + generated_at + signing.*, so
	// other fields can be omitted at this Check-1-only test level.
	manifestJSON := buildMinimalV2Manifest(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
	)
	manifestBytes := []byte(manifestJSON)

	// Sign with both algorithms over the raw manifest bytes (bytes-as-
	// loaded posture: the writer canonicalizes manifest BEFORE signing,
	// so this test's "raw bytes" are equivalent to the canonical bytes).
	edSig := ed25519.Sign(edPriv, manifestBytes)
	mldsaSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(mldsaPriv, manifestBytes, nil, false, mldsaSig); err != nil {
		t.Fatalf("mldsa65.SignTo: %v", err)
	}

	signatureJSON := buildMinimalV2SignatureSig(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
		edSig, mldsaSig,
	)

	// Construct a minimal in-memory bundle.Bundle with raw bytes.
	b := &bundle.Bundle{
		ManifestRaw:  manifestBytes,
		SignatureRaw: []byte(signatureJSON),
	}
	if err := decodeManifest(b, manifestBytes); err != nil {
		t.Fatalf("manifest decode: %v", err)
	}
	if err := decodeSignature(b, []byte(signatureJSON)); err != nil {
		t.Fatalf("signature decode: %v", err)
	}

	// Swap in test-only pinned keys matching the freshly-generated
	// keys. We cannot mutate package globals safely under -parallel,
	// so this test runs serially via Go's default test posture.
	originalEdV2 := keys.PinnedEd25519V2IssuerKeys
	originalMl := keys.PinnedMlDsa65IssuerKeys
	defer func() {
		keys.PinnedEd25519V2IssuerKeys = originalEdV2
		keys.PinnedMlDsa65IssuerKeys = originalMl
	}()
	keys.PinnedEd25519V2IssuerKeys = []keys.IssuerKey{
		{
			KeyID:              "issuer-dev-v2-ed25519",
			KeyRole:            keys.KeyRoleDev,
			SPKIFingerprintB64: edSpkiB64,
			Description:        "test-only dev Ed25519 key for v2 round-trip",
		},
	}
	keys.PinnedMlDsa65IssuerKeys = []keys.IssuerKey{
		{
			KeyID:              "issuer-dev-v2-ml-dsa-65",
			KeyRole:            keys.KeyRoleDev,
			SPKIFingerprintB64: mldsaSpkiB64,
			Description:        "test-only dev ML-DSA-65 key for v2 round-trip",
		},
	}

	check := Check1Signature{}
	r := check.Run(b, CheckOptions{AllowDevKey: true})

	// Assert: Pass overall (with dev-key warn).
	if r.Status != StatusWarn {
		t.Errorf("v2 happy-path: expected StatusWarn (dev-key fold), got %s; errors=%v warnings=%v",
			r.Status, r.Errors, r.Warnings)
	}
	if r.WarnCategory != WarnCategoryDevKey {
		t.Errorf("v2 happy-path: expected WarnCategory=%q, got %q", WarnCategoryDevKey, r.WarnCategory)
	}
	if len(r.Errors) != 0 {
		t.Errorf("v2 happy-path: expected 0 errors, got %d: %v", len(r.Errors), r.Errors)
	}

	// Assert: AlgorithmVerdicts populated per spec §18.10.
	if len(r.AlgorithmVerdicts) != 2 {
		t.Fatalf("v2 happy-path: expected 2 AlgorithmVerdicts, got %d", len(r.AlgorithmVerdicts))
	}
	if r.AlgorithmVerdicts[0].Algorithm != "ed25519" {
		t.Errorf("v2 happy-path: AlgorithmVerdicts[0].Algorithm = %q, expected %q",
			r.AlgorithmVerdicts[0].Algorithm, "ed25519")
	}
	if r.AlgorithmVerdicts[0].Status != "pass" {
		t.Errorf("v2 happy-path: AlgorithmVerdicts[0].Status = %q, expected %q",
			r.AlgorithmVerdicts[0].Status, "pass")
	}
	if r.AlgorithmVerdicts[1].Algorithm != "ml-dsa-65" {
		t.Errorf("v2 happy-path: AlgorithmVerdicts[1].Algorithm = %q, expected %q",
			r.AlgorithmVerdicts[1].Algorithm, "ml-dsa-65")
	}
	if r.AlgorithmVerdicts[1].Status != "pass" {
		t.Errorf("v2 happy-path: AlgorithmVerdicts[1].Status = %q, expected %q",
			r.AlgorithmVerdicts[1].Status, "pass")
	}
}

// TestCheck1V2DispatchTamperedEd25519 mutates the Ed25519 signature
// bytes after signing. Asserts: Fail overall + AlgorithmVerdicts[0]
// status="fail" + AlgorithmVerdicts[1] status="pass" (per spec §18.10
// no-short-circuit: ML-DSA-65 verdict still emits even after Ed25519
// fail).
func TestCheck1V2DispatchTamperedEd25519(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ml-dsa-65 keygen: %v", err)
	}

	edSpkiDER, _ := x509.MarshalPKIXPublicKey(edPub)
	edSpkiB64 := base64.StdEncoding.EncodeToString(edSpkiDER)
	mldsaSpkiDER := wrapMlDsa65SPKI(t, mldsaPub)
	mldsaSpkiB64 := strings.TrimRight(base64.StdEncoding.EncodeToString(mldsaSpkiDER), "=")

	manifestBytes := []byte(buildMinimalV2Manifest(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
	))

	edSig := ed25519.Sign(edPriv, manifestBytes)
	// TAMPER: flip the last byte of the Ed25519 signature.
	edSig[len(edSig)-1] ^= 0x01
	mldsaSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(mldsaPriv, manifestBytes, nil, false, mldsaSig); err != nil {
		t.Fatalf("mldsa65.SignTo: %v", err)
	}

	signatureJSON := buildMinimalV2SignatureSig(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
		edSig, mldsaSig,
	)

	b := &bundle.Bundle{ManifestRaw: manifestBytes, SignatureRaw: []byte(signatureJSON)}
	if err := decodeManifest(b, manifestBytes); err != nil {
		t.Fatalf("manifest decode: %v", err)
	}
	if err := decodeSignature(b, []byte(signatureJSON)); err != nil {
		t.Fatalf("signature decode: %v", err)
	}

	originalEdV2 := keys.PinnedEd25519V2IssuerKeys
	originalMl := keys.PinnedMlDsa65IssuerKeys
	defer func() {
		keys.PinnedEd25519V2IssuerKeys = originalEdV2
		keys.PinnedMlDsa65IssuerKeys = originalMl
	}()
	keys.PinnedEd25519V2IssuerKeys = []keys.IssuerKey{{
		KeyID: "issuer-dev-v2-ed25519", KeyRole: keys.KeyRoleDev,
		SPKIFingerprintB64: edSpkiB64,
	}}
	keys.PinnedMlDsa65IssuerKeys = []keys.IssuerKey{{
		KeyID: "issuer-dev-v2-ml-dsa-65", KeyRole: keys.KeyRoleDev,
		SPKIFingerprintB64: mldsaSpkiB64,
	}}

	check := Check1Signature{}
	r := check.Run(b, CheckOptions{AllowDevKey: true})

	if r.Status != StatusFail {
		t.Errorf("tampered-ed25519: expected Fail, got %s", r.Status)
	}
	if len(r.AlgorithmVerdicts) != 2 {
		t.Fatalf("tampered-ed25519: expected 2 AlgorithmVerdicts (no short-circuit), got %d", len(r.AlgorithmVerdicts))
	}
	if r.AlgorithmVerdicts[0].Status != "fail" {
		t.Errorf("tampered-ed25519: AlgorithmVerdicts[0].Status = %q, expected fail", r.AlgorithmVerdicts[0].Status)
	}
	if r.AlgorithmVerdicts[1].Status != "pass" {
		t.Errorf("tampered-ed25519: AlgorithmVerdicts[1].Status = %q, expected pass (ML-DSA-65 still valid)", r.AlgorithmVerdicts[1].Status)
	}
}

// TestCheck1V2DispatchTamperedMlDsa65 mirrors TamperedEd25519 at the
// ML-DSA-65 leg. Asserts: Fail overall + AlgorithmVerdicts[0]=pass +
// AlgorithmVerdicts[1]=fail (per spec §18.10).
func TestCheck1V2DispatchTamperedMlDsa65(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ml-dsa-65 keygen: %v", err)
	}

	edSpkiDER, _ := x509.MarshalPKIXPublicKey(edPub)
	edSpkiB64 := base64.StdEncoding.EncodeToString(edSpkiDER)
	mldsaSpkiDER := wrapMlDsa65SPKI(t, mldsaPub)
	mldsaSpkiB64 := strings.TrimRight(base64.StdEncoding.EncodeToString(mldsaSpkiDER), "=")

	manifestBytes := []byte(buildMinimalV2Manifest(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
	))

	edSig := ed25519.Sign(edPriv, manifestBytes)
	mldsaSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(mldsaPriv, manifestBytes, nil, false, mldsaSig); err != nil {
		t.Fatalf("mldsa65.SignTo: %v", err)
	}
	// TAMPER: flip a byte of the ML-DSA-65 signature.
	mldsaSig[len(mldsaSig)-1] ^= 0x01

	signatureJSON := buildMinimalV2SignatureSig(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
		edSig, mldsaSig,
	)

	b := &bundle.Bundle{ManifestRaw: manifestBytes, SignatureRaw: []byte(signatureJSON)}
	if err := decodeManifest(b, manifestBytes); err != nil {
		t.Fatalf("manifest decode: %v", err)
	}
	if err := decodeSignature(b, []byte(signatureJSON)); err != nil {
		t.Fatalf("signature decode: %v", err)
	}

	originalEdV2 := keys.PinnedEd25519V2IssuerKeys
	originalMl := keys.PinnedMlDsa65IssuerKeys
	defer func() {
		keys.PinnedEd25519V2IssuerKeys = originalEdV2
		keys.PinnedMlDsa65IssuerKeys = originalMl
	}()
	keys.PinnedEd25519V2IssuerKeys = []keys.IssuerKey{{
		KeyID: "issuer-dev-v2-ed25519", KeyRole: keys.KeyRoleDev,
		SPKIFingerprintB64: edSpkiB64,
	}}
	keys.PinnedMlDsa65IssuerKeys = []keys.IssuerKey{{
		KeyID: "issuer-dev-v2-ml-dsa-65", KeyRole: keys.KeyRoleDev,
		SPKIFingerprintB64: mldsaSpkiB64,
	}}

	check := Check1Signature{}
	r := check.Run(b, CheckOptions{AllowDevKey: true})

	if r.Status != StatusFail {
		t.Errorf("tampered-ml-dsa-65: expected Fail, got %s", r.Status)
	}
	if len(r.AlgorithmVerdicts) != 2 {
		t.Fatalf("tampered-ml-dsa-65: expected 2 AlgorithmVerdicts (no short-circuit), got %d", len(r.AlgorithmVerdicts))
	}
	if r.AlgorithmVerdicts[0].Status != "pass" {
		t.Errorf("tampered-ml-dsa-65: AlgorithmVerdicts[0].Status = %q, expected pass (Ed25519 still valid)", r.AlgorithmVerdicts[0].Status)
	}
	if r.AlgorithmVerdicts[1].Status != "fail" {
		t.Errorf("tampered-ml-dsa-65: AlgorithmVerdicts[1].Status = %q, expected fail", r.AlgorithmVerdicts[1].Status)
	}
}

// TestCheck1V2SlotCoherence asserts cross-environment-slot coherence
// per spec §18.6: a v2 bundle whose Ed25519 key dispatches to prod
// but ML-DSA-65 key dispatches to dev (or vice versa) is rejected at
// the schema-cross-check BEFORE any cryptographic operation.
//
// **Genuinely unreachable under current dispatch** (Phase 7.F.3 Tier A
// reviewer follow-up 2026-05-22): the dispatch helpers KeyForBundleEd25519V2
// + KeyForBundleMlDsa65 BOTH call keyForBundleIn (keys.go:149), which
// derives the target role from bundle_type via identical logic at
// keys.go:151 + filters returned keys by `k.KeyRole == role`. By
// construction, both dispatches return keys with matching KeyRoles —
// the runV2DualSignature step 3 slot-check at
// check1_v2_dual_sig.go:188 is pure defense-in-depth dead code under
// current dispatch.
//
// Triggering the slot-check requires structural changes that bypass
// the role-derivation logic — e.g., per-algorithm bundle_type→role
// override tables, or directly invoking runV2DualSignature with
// pre-resolved pinned keys via test injection. Both are out-of-scope
// for v2.0.0-rc1; the slot-check stays as forward-compat insurance
// against a future v2.x amendment that introduces algorithm-specific
// dispatch divergence.
//
// **Heavy-bookmarked for Phase 7.F.4**: when KAT-vector tests land
// at the conformance-fixture pipeline, the slot-check should be
// directly testable via a v2 fixture with mismatched key_ids that
// resolves through pinned-key injection at the fixture layer.
func TestCheck1V2SlotCoherence(t *testing.T) {
	t.Skip("slot-coherence path is forward-compat insurance (defense-in-depth); reachable only via dispatch-bypass test infrastructure deferred to Phase 7.F.4 KAT fixtures")
}

// TestCheck1V2InternalFingerprintCrossCheck exercises the spec §18.7
// step 2 cross-check (signature.sig.signatures[i].
// key_fingerprint_spki_b64 == manifest.signing.signatures[i].
// key_fingerprint_spki_b64) by tampering the ML-DSA-65 fingerprint
// in signature.sig only. Expected: Fail before any cryptographic
// operation (short-circuit at schema cross-check; no AlgorithmVerdicts).
func TestCheck1V2InternalFingerprintCrossCheck(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ml-dsa-65 keygen: %v", err)
	}

	edSpkiDER, _ := x509.MarshalPKIXPublicKey(edPub)
	edSpkiB64 := base64.StdEncoding.EncodeToString(edSpkiDER)
	mldsaSpkiDER := wrapMlDsa65SPKI(t, mldsaPub)
	mldsaSpkiB64 := strings.TrimRight(base64.StdEncoding.EncodeToString(mldsaSpkiDER), "=")

	manifestBytes := []byte(buildMinimalV2Manifest(
		edSpkiB64, mldsaSpkiB64,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
	))
	edSig := ed25519.Sign(edPriv, manifestBytes)
	mldsaSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(mldsaPriv, manifestBytes, nil, false, mldsaSig); err != nil {
		t.Fatalf("mldsa65.SignTo: %v", err)
	}

	// TAMPER: emit signature.sig with a different ML-DSA-65 fingerprint
	// than what manifest.signing carries (last 4 chars of the fingerprint
	// flipped). manifest.signing still carries the real fingerprint that
	// matches the pinned key (step 6 passes), but the manifest-vs-
	// signature cross-check at step 7 fails.
	tamperedMldsaSpki := mldsaSpkiB64[:len(mldsaSpkiB64)-4] + "AAAA"
	signatureJSON := buildMinimalV2SignatureSig(
		edSpkiB64, tamperedMldsaSpki,
		"issuer-dev-v2-ed25519", "issuer-dev-v2-ml-dsa-65",
		edSig, mldsaSig,
	)

	b := &bundle.Bundle{ManifestRaw: manifestBytes, SignatureRaw: []byte(signatureJSON)}
	if err := decodeManifest(b, manifestBytes); err != nil {
		t.Fatalf("manifest decode: %v", err)
	}
	if err := decodeSignature(b, []byte(signatureJSON)); err != nil {
		t.Fatalf("signature decode: %v", err)
	}

	originalEdV2 := keys.PinnedEd25519V2IssuerKeys
	originalMl := keys.PinnedMlDsa65IssuerKeys
	defer func() {
		keys.PinnedEd25519V2IssuerKeys = originalEdV2
		keys.PinnedMlDsa65IssuerKeys = originalMl
	}()
	keys.PinnedEd25519V2IssuerKeys = []keys.IssuerKey{{
		KeyID: "issuer-dev-v2-ed25519", KeyRole: keys.KeyRoleDev,
		SPKIFingerprintB64: edSpkiB64,
	}}
	keys.PinnedMlDsa65IssuerKeys = []keys.IssuerKey{{
		KeyID: "issuer-dev-v2-ml-dsa-65", KeyRole: keys.KeyRoleDev,
		SPKIFingerprintB64: mldsaSpkiB64,
	}}

	check := Check1Signature{}
	r := check.Run(b, CheckOptions{AllowDevKey: true})

	if r.Status != StatusFail {
		t.Errorf("cross-check: expected Fail, got %s", r.Status)
	}
	// Spec §18.10 + security-auditor M3 closure 2026-05-22: v2 Check 1
	// MUST emit algorithm_verdicts with cardinality 2 even on schema
	// cross-check fails. Both verdicts populate as "fail" via failV2.
	if len(r.AlgorithmVerdicts) != 2 {
		t.Fatalf("cross-check: expected 2 AlgorithmVerdicts (spec §18.10 conformance contract), got %d", len(r.AlgorithmVerdicts))
	}
	if r.AlgorithmVerdicts[0].Algorithm != "ed25519" || r.AlgorithmVerdicts[0].Status != "fail" {
		t.Errorf("cross-check: AlgorithmVerdicts[0] = %+v, expected {ed25519, fail}", r.AlgorithmVerdicts[0])
	}
	if r.AlgorithmVerdicts[1].Algorithm != "ml-dsa-65" || r.AlgorithmVerdicts[1].Status != "fail" {
		t.Errorf("cross-check: AlgorithmVerdicts[1] = %+v, expected {ml-dsa-65, fail}", r.AlgorithmVerdicts[1])
	}
	foundCrossErr := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "disagrees with") || strings.Contains(e.Error(), "§18.7") {
			foundCrossErr = true
			break
		}
	}
	if !foundCrossErr {
		t.Errorf("cross-check: expected error referencing 'disagrees with' or §18.7; got %v", r.Errors)
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// buildMinimalV2Manifest constructs a deterministic example-demo v2
// manifest with the minimum fields the Check 1 v2 dispatch reads.
// Field order is alphabetical (RFC 8785 JCS posture) so the output
// is byte-stable across runs.
func buildMinimalV2Manifest(edSpki, mldsaSpki, edKeyID, mldsaKeyID string) string {
	return fmt.Sprintf(`{"bundle_format":"nuwyre-bundle/v2","bundle_type":"example-demo","generated_at":"%s","schema_version":2,"signing":{"schema_version":1,"signatures":[{"algorithm":"ed25519","key_fingerprint_spki_b64":"%s","key_id":"%s","key_purpose":"Ed25519 manifest signature; v2.0.0-rc1+ dual-sig topology"},{"algorithm":"ml-dsa-65","key_fingerprint_spki_b64":"%s","key_id":"%s","key_purpose":"ML-DSA-65 manifest signature; v2.0.0-rc1+ dual-sig topology"}]}}`,
		time.Now().UTC().Format(time.RFC3339),
		edSpki, edKeyID,
		mldsaSpki, mldsaKeyID,
	)
}

// buildMinimalV2SignatureSig constructs a v2 signature.sig JSON with
// the §18.2 schema (cardinality-2 signatures[] array, positional
// ordering, alphabetical field order within each entry per RFC 8785).
// schema_version pinned to 1 per spec §18.2 + §18.7 step 1 (the
// signing-container schema; distinct from bundle.schema_version=2).
// Matches writer-side authority at packages/evidence/src/generate-bundle.ts:1277.
func buildMinimalV2SignatureSig(edSpki, mldsaSpki, edKeyID, mldsaKeyID string, edSig, mldsaSig []byte) string {
	edSigB64 := base64.StdEncoding.EncodeToString(edSig)
	mldsaSigB64 := strings.TrimRight(base64.StdEncoding.EncodeToString(mldsaSig), "=")
	return fmt.Sprintf(`{"schema_version":1,"signatures":[{"algorithm":"ed25519","key_fingerprint_spki_b64":"%s","key_id":"%s","signature_b64":"%s"},{"algorithm":"ml-dsa-65","key_fingerprint_spki_b64":"%s","key_id":"%s","signature_b64":"%s"}],"signed_artifact":"manifest.json"}`,
		edSpki, edKeyID, edSigB64,
		mldsaSpki, mldsaKeyID, mldsaSigB64,
	)
}

// wrapMlDsa65SPKI wraps a 1952-byte ML-DSA-65 public key into the
// canonical 1974-byte RFC 5280 SubjectPublicKeyInfo DER per spec §18.4.
// Mirrors the TS-side wrapPublicKeySpki at packages/evidence/src/
// ml-dsa-65.ts:118 (byte-identical output for the same input).
//
// SPKI prefix (22 bytes): outer SEQUENCE + AlgorithmIdentifier
// (id-ml-dsa-65 OID 2.16.840.1.101.3.4.3.18) + BIT STRING header +
// unused-bits-byte 0x00. Followed by the raw 1952-byte public key.
func wrapMlDsa65SPKI(t *testing.T, pub *mldsa65.PublicKey) []byte {
	t.Helper()
	prefix := []byte{
		0x30, 0x82, 0x07, 0xb2, // outer SEQUENCE: tag 0x30 + long-form length 0x82 0x07 0xB2 (1970 content)
		0x30, 0x0b, // AlgorithmIdentifier SEQUENCE: tag 0x30 + short-form length 0x0B (11 content)
		0x06, 0x09, // OID: tag 0x06 + length 0x09 (9 content)
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, // OID content: 2.16.840.1.101.3.4.3.18
		0x03, 0x82, 0x07, 0xa1, // BIT STRING: tag 0x03 + long-form length 0x82 0x07 0xA1 (1953 content)
		0x00, // unused-bits octet (0 unused bits)
	}
	rawPub, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("ml-dsa-65 pubkey marshal: %v", err)
	}
	if len(rawPub) != mldsa65.PublicKeySize {
		t.Fatalf("ml-dsa-65 pubkey: got %d bytes, expected %d", len(rawPub), mldsa65.PublicKeySize)
	}
	spki := make([]byte, 0, len(prefix)+len(rawPub))
	spki = append(spki, prefix...)
	spki = append(spki, rawPub...)
	if len(spki) != 1974 {
		t.Fatalf("ml-dsa-65 SPKI: got %d bytes, expected 1974", len(spki))
	}
	return spki
}

// decodeManifest populates b.Manifest from manifestBytes using the
// same encoding/json decoder the production loader uses (load.go:184).
func decodeManifest(b *bundle.Bundle, manifestBytes []byte) error {
	return json.Unmarshal(manifestBytes, &b.Manifest)
}

// decodeSignature populates b.Signature from signatureBytes using the
// same encoding/json decoder the production loader uses (load.go:196).
func decodeSignature(b *bundle.Bundle, signatureBytes []byte) error {
	return json.Unmarshal(signatureBytes, &b.Signature)
}

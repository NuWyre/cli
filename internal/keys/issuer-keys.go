package keys

import "time"

// PlaceholderProdFingerprint is the V1 placeholder for the production
// signing key's SPKI. Production deploy-bootstrap (Phase 5) replaces
// this with the real KMS-backed key's SPKI before V1 binaries can
// verify customer-export bundles.
//
// Single source of truth — Check 1 imports this constant rather than
// redeclaring the literal, so a typo or rename in one site can't
// silently desync from the value pinned in PinnedIssuerKeys below
// (security-auditor L3 from Phase 4 Session 2 commit-2 review).
//
// The string is intentionally non-base64 (contains underscores) so
// any real production bundle's fingerprint comparison against it
// fails immediately AND any downstream attempt to parse it as base64
// SPKI fails too — two-layer fail-secure.
const PlaceholderProdFingerprint = "PROD_KEY_FINGERPRINT_PENDING_PHASE_5_DEPLOY_BOOTSTRAP"

// PinnedIssuerKeys is the compile-time embedded set of pinned
// issuer signing keys. The CLI ships with both a placeholder
// production-key entry (replaced at production deploy-bootstrap
// time) and a real development-key entry (pinned to the SPKI
// fingerprint of the dev signing key in
// packages/example-bundle/dev-keys/dev-signing-key.pub.json).
//
// Phase 4 verification dispatch (per build plan v3.1.11 §Phase 4
// Step 2):
//
//   - bundle_type="customer-export" → match against issuer-prod-v1
//   - bundle_type="example-demo"    → match against issuer-dev-v1
//   - any other / missing            → fail-secure: customer-export
//                                      path; placeholder fingerprint
//                                      mismatches anything real, so
//                                      tampered bundles that omit
//                                      bundle_type fail loudly
//
// The placeholder for issuer-prod-v1 is INTENTIONALLY a non-base64
// string so any real production bundle's fingerprint comparison
// against it fails immediately. Production deploy-bootstrap (Phase 5)
// replaces this entry with the real KMS-backed key's SPKI
// fingerprint; the production CLI ships with the real fingerprint
// pinned in the binary.
var PinnedIssuerKeys = []IssuerKey{
	{
		KeyID:           "issuer-prod-v1",
		KeyRole:         KeyRoleProd,
		EffectiveAfter:  time.Time{}, // active from issuance
		EffectiveBefore: time.Time{}, // active indefinitely (current key)
		// PLACEHOLDER. Production deploy-bootstrap (Phase 5) replaces
		// this with the real KMS-backed key's SPKI fingerprint. The
		// non-base64 format ensures any comparison against a real
		// bundle's fingerprint fails — fail-secure default for the
		// V1 binary distribution.
		SPKIFingerprintB64: PlaceholderProdFingerprint,
		Description: "Production signing key for customer-export bundles. PLACEHOLDER — Phase 5 deploy-bootstrap replaces with real KMS-backed key's SPKI fingerprint. V1 binaries reject all customer-export bundles by design (no real fingerprint matches the placeholder).",
	},
	{
		KeyID:           "issuer-dev-v1",
		KeyRole:         KeyRoleDev,
		EffectiveAfter:  time.Time{}, // active from issuance
		EffectiveBefore: time.Time{}, // active indefinitely (V1; no rotation yet)
		// SPKI fingerprint matches packages/example-bundle/dev-keys/
		// dev-signing-key.pub.json. Verified against
		// apps/marketing/public/examples/nuwyre_export_cypress-derm_
		// 2026-04-22.manifest.json's signing.key_fingerprint_spki_b64
		// at the time of this commit.
		SPKIFingerprintB64: "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=",
		Description: "Development signing key for example-demo bundles. The committed dev key in packages/example-bundle/dev-keys/. CLI emits a 'DEVELOPMENT BUNDLE — verified with dev key, not for production trust' warning even on success.",
	},
}

// =============================================================================
// v2.0.0-rc1 Ed25519 pinned issuer keys (Phase 7.F.3 2026-05-22)
// =============================================================================
//
// crypto-integrity C1 closure: v2 bundles carry distinct Ed25519
// key_ids ("issuer-prod-v2-ed25519" / "issuer-dev-v2-ed25519") per
// spec §18.6. Keeping v1 + v2 catalogs separate ensures the v2
// dispatch helper cannot accidentally resolve to a v1 key (and vice
// versa). Symmetric to PinnedMlDsa65IssuerKeys.

// PlaceholderProdEd25519V2Fingerprint is the v2.0.0-rc1 placeholder
// for the production v2 Ed25519 signing key's SPKI. Production
// deploy-bootstrap (Phase 7.F.4+) replaces this with the real KMS-
// backed v2 Ed25519 key's SPKI before v2.0.0-rc1+ binaries can verify
// v2 customer-export bundles. Non-base64 prefix matches the v1 +
// ML-DSA-65 placeholder posture (two-layer fail-secure).
const PlaceholderProdEd25519V2Fingerprint = "PROD_ED25519_V2_KEY_FINGERPRINT_PENDING_PHASE_7F4_KMS_DEPLOY_BOOTSTRAP"

// PinnedEd25519V2IssuerKeys is the compile-time embedded set of pinned
// v2 Ed25519 issuer signing keys per spec §18.6. Phase 7.F.3 v2.0.0-rc1
// addition.
//
// V2 dispatch (per spec §18.6):
//   - bundle_format="nuwyre-bundle/v2" + bundle_type="customer-export"
//     → match against issuer-prod-v2-ed25519 (placeholder pending
//     Phase 7.F.4 deploy-bootstrap)
//   - bundle_format="nuwyre-bundle/v2" + bundle_type="example-demo"
//     → match against issuer-dev-v2-ed25519 (real dev key; SPKI
//     reused from packages/example-bundle/dev-keys/dev-signing-key.pub.json
//     since the dev Ed25519 keypair is the same artifact across v1+v2 dev tooling)
//   - bundle_format="nuwyre-bundle/v2" + bundle_type="audit-log-export"
//     → match against issuer-dev-v2-ed25519 (audit-log dispatches to
//     dev role per keys.go bundle_type→role mapping)
var PinnedEd25519V2IssuerKeys = []IssuerKey{
	{
		KeyID:              "issuer-prod-v2-ed25519",
		KeyRole:            KeyRoleProd,
		EffectiveAfter:     time.Time{},
		EffectiveBefore:    time.Time{},
		SPKIFingerprintB64: PlaceholderProdEd25519V2Fingerprint,
		Description:        "Production v2 Ed25519 signing key for v2 customer-export bundles. PLACEHOLDER — Phase 7.F.4 deploy-bootstrap replaces with real KMS-backed v2 Ed25519 key's SPKI fingerprint. v2.0.0-rc1 binaries reject all v2 customer-export bundles by design.",
	},
	{
		KeyID:           "issuer-dev-v2-ed25519",
		KeyRole:         KeyRoleDev,
		EffectiveAfter:  time.Time{},
		EffectiveBefore: time.Time{},
		// SPKI matches packages/example-bundle/dev-keys/dev-signing-key.pub.json
		// — same SPKI as v1 dev key (issuer-dev-v1). The v1 vs v2
		// distinction is in the KeyID + dispatch table, not the
		// cryptographic material. Future v2.x amendments MAY rotate.
		SPKIFingerprintB64: "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=",
		Description:        "Development v2 Ed25519 signing key for example-demo + audit-log-export v2 bundles. Shares SPKI with v1 dev key (KeyID distinguishes). CLI emits a 'DEVELOPMENT BUNDLE — verified with dev key, not for production trust' warning even on success.",
	},
}

// KeyForBundleEd25519V2 selects the appropriate pinned v2 Ed25519
// issuer key for a v2 bundle's bundle_type, generated_at, and active
// key rotation window. Symmetric to KeyForBundle (v1) + KeyForBundleMlDsa65.
func KeyForBundleEd25519V2(bundleType string, generatedAt time.Time) (*IssuerKey, error) {
	return keyForBundleIn(PinnedEd25519V2IssuerKeys, bundleType, generatedAt)
}

// ListPinnedEd25519V2IssuerKeys returns a copy of the embedded v2
// Ed25519 issuer keys (for `nuwyre keys` listing + audit tooling).
func ListPinnedEd25519V2IssuerKeys() []IssuerKey {
	out := make([]IssuerKey, len(PinnedEd25519V2IssuerKeys))
	copy(out, PinnedEd25519V2IssuerKeys)
	return out
}

// =============================================================================
// v2.0.0-rc1 ML-DSA-65 pinned issuer keys (Phase 7.F.3 2026-05-21)
// =============================================================================

// PlaceholderProdMlDsa65Fingerprint is the v2.0.0-rc1 placeholder for
// the production ML-DSA-65 signing key's SPKI. Production deploy-
// bootstrap (Phase 7.F.4+) replaces this with the real HSM-equivalent
// (or KMS-backed, pending AWS KMS exposing `rnd` parameter per spec
// §18.3) ML-DSA-65 key's SPKI before v2.0.0-rc1+ binaries can verify
// v2 customer-export bundles. Non-base64 prefix so any comparison
// against a real bundle's fingerprint fails immediately — two-layer
// fail-secure matching the Ed25519 placeholder pattern at line 19.
const PlaceholderProdMlDsa65Fingerprint = "PROD_ML_DSA_65_KEY_FINGERPRINT_PENDING_PHASE_7F4_HSM_DEPLOY_BOOTSTRAP"

// PinnedMlDsa65IssuerKeys is the compile-time embedded set of pinned
// ML-DSA-65 issuer signing keys per spec §18.4. Phase 7.F.3 v2.0.0-rc1
// addition — supports Check 1 v2 dual-signature verification path.
//
// V2 dispatch (per spec §18.7):
//   - bundle_format="nuwyre-bundle/v2" + bundle_type="customer-export"
//     → match against issuer-prod-v2-ml-dsa-65 (placeholder pending
//     Phase 7.F.4 deploy-bootstrap)
//   - bundle_format="nuwyre-bundle/v2" + bundle_type="example-demo"
//     → match against issuer-dev-v2-ml-dsa-65 (real dev key from
//     packages/example-bundle/dev-keys/dev-ml-dsa-65-seed.pub.json)
//
// **Cross-environment-slot coherence (spec §18.6 line 2402)**: Check 1
// step 2 ensures both Ed25519 + ML-DSA-65 keys belong to the SAME env
// slot (both prod XOR both dev). Mixed-slot bundles fail at the schema-
// cross-check BEFORE pinned-directory lookup.
var PinnedMlDsa65IssuerKeys = []IssuerKey{
	{
		KeyID:              "issuer-prod-v2-ml-dsa-65",
		KeyRole:            KeyRoleProd,
		EffectiveAfter:     time.Time{}, // active from issuance
		EffectiveBefore:    time.Time{}, // active indefinitely (current key)
		SPKIFingerprintB64: PlaceholderProdMlDsa65Fingerprint,
		Description:        "Production ML-DSA-65 signing key for v2 customer-export bundles. PLACEHOLDER — Phase 7.F.4 deploy-bootstrap replaces with real HSM-equivalent (or KMS-backed when AWS KMS exposes rnd parameter per spec §18.3) ML-DSA-65 key's SPKI fingerprint. v2.0.0-rc1 binaries reject all v2 customer-export bundles by design.",
	},
	{
		KeyID:           "issuer-dev-v2-ml-dsa-65",
		KeyRole:         KeyRoleDev,
		EffectiveAfter:  time.Time{}, // active from issuance
		EffectiveBefore: time.Time{}, // active indefinitely
		// SPKI fingerprint matches packages/example-bundle/dev-keys/
		// dev-ml-dsa-65-seed.pub.json (Phase 7.F.2-B dev key
		// generation). 1974-byte SPKI DER → 2632 chars base64 with NO
		// padding per spec §18.4 + crypto-integrity L1 closure
		// (1974 mod 3 == 0).
		SPKIFingerprintB64: "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",
		Description:        "Development ML-DSA-65 signing key for example-demo + v2 dev-slot bundles. From packages/example-bundle/dev-keys/dev-ml-dsa-65-seed.pub.json. CLI emits a 'DEVELOPMENT BUNDLE — verified with dev key, not for production trust' warning even on success.",
	},
}

// KeyForBundleMlDsa65 selects the appropriate pinned ML-DSA-65 issuer
// key for a v2 bundle's bundle_type, generated_at, and active key
// rotation window. Symmetric to KeyForBundle (Ed25519) at the v1 path.
//
// Returns ErrNoIssuerKey if no pinned key matches the bundle_type +
// time window.
func KeyForBundleMlDsa65(bundleType string, generatedAt time.Time) (*IssuerKey, error) {
	return keyForBundleIn(PinnedMlDsa65IssuerKeys, bundleType, generatedAt)
}

// ListPinnedMlDsa65IssuerKeys returns the pinned ML-DSA-65 issuer
// keys (for `nuwyre keys` listing + audit tooling).
func ListPinnedMlDsa65IssuerKeys() []IssuerKey {
	out := make([]IssuerKey, len(PinnedMlDsa65IssuerKeys))
	copy(out, PinnedMlDsa65IssuerKeys)
	return out
}

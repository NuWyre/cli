package checks

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/keys"
)

// Check8EphemeralSession verifies the sandbox session-scoped ephemeral
// signing keys per spec §6.5 (v1.0.9 amendment; Pre-Phase 6 Item 2
// closure 2026-05-15).
//
// **Conditionally executed.** Check 8 runs when
// `manifest.signing.topology == "ephemeral-sessions"`. Otherwise it
// returns StatusSkipped with skip_reason explaining single-key topology.
//
// **Sandbox-only at v1.0.9.** The topology/bundle_type discipline (spec
// §5 v1.0.9 amendment table) restricts ephemeral-sessions to
// `bundle_type = "sandbox-preview"`. Any other bundle_type combined with
// `topology = "ephemeral-sessions"` fails Check 8 with a specific
// mismatch error.
//
// **Ordering.** Check 8 runs BEFORE Check 3 in the registry. Check 3's
// per-event signature step depends on the session_id → ephemeral_pubkey
// map Check 8 builds. The verifier orchestrator wires the dependency
// via bundle.EphemeralPubkeyByID (populated as a side effect of Check
// 8's successful run); Check 3's topology-aware branch reads from that
// map under ephemeral-sessions topology.
//
// **Six tenants framing**:
//   - T3 (security/privacy) load-bearing — the per-session attestation
//     binds each ephemeral SPKI to the pinned KMS issuer key's Ed25519
//     signature over a canonical seed. Any tampering with seed bytes,
//     attestation bytes, or the manifest's declared ephemeral SPKI
//     fails verification.
//   - T2 (quality/reliability) — cross-language byte-equivalence with
//     the TS reference impl via the apps/api/src/lib/__tests__/
//     session-signing.test.ts cross-lang fixture (read by check
//     8's test file).
//   - T5 (customer trust) — the bundle's ephemeral key chain of trust
//     is fully reconstructible by an external verifier from the
//     bundle bytes alone (no NuWyre runtime required).
type Check8EphemeralSession struct{}

// Check8 ID + slug per spec §14.6 v1.0.9 amendment.
func (Check8EphemeralSession) ID() int      { return 8 }
func (Check8EphemeralSession) Name() string { return "ephemeral session" }
func (Check8EphemeralSession) Slug() string { return "ephemeral-session" }

// hkdfInfoV109 — spec §6.5.3 domain separator. MUST be exactly these
// 35 UTF-8 bytes; mirrors apps/api/src/lib/session-signing.ts
// HKDF_INFO_V1_0_9. A cross-language test fixture asserts byte-for-byte
// equivalence.
const hkdfInfoV109 = "nuwyre/v1.0.9-ephemeral-session-key"

// ephemeralSeedLength = 32 (Ed25519 seed length per RFC 8032 §5.1.5).
const ephemeralSeedLength = 32

// Run executes Check 8 per spec §6.5.6.
func (c Check8EphemeralSession) Run(b *bundle.Bundle, _ CheckOptions) CheckResult {
	const id = 8
	const checkName = "ephemeral session"
	const slug = "ephemeral-session"

	// Topology gate: skip when single-key topology (legacy bundles +
	// customer-export + example-demo + pre-v1.0.9 sandbox).
	topology := b.Manifest.Signing.Topology
	if topology == "" || topology == "single-key" {
		// Reset the per-bundle ephemeral pubkey map: a fresh run on
		// a single-key bundle MUST NOT see stale state from a prior
		// ephemeral-sessions bundle run in the same process.
		b.EphemeralPubkeyByID = nil
		return Skipped(
			id, checkName, slug,
			"bundle uses single-key signing topology; ephemeral-session attestation not applicable",
		)
	}
	if topology != "ephemeral-sessions" {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					fmt.Sprintf("signing.topology=%q is not in the v1.0.9 closed vocabulary {single-key, ephemeral-sessions}", topology),
					SpecRefSignature,
					"signing.topology is closed vocabulary per spec §5 v1.0.9 amendment",
				),
			},
			nil,
		)
	}

	// Topology/bundle_type discipline per spec §5 v1.0.9 amendment
	// table. v1.0.9 restricts ephemeral-sessions to sandbox-preview.
	if b.Manifest.BundleType != "sandbox-preview" {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					fmt.Sprintf("topology=%q is permitted only with bundle_type=\"sandbox-preview\" at v1.0.9 (got bundle_type=%q)",
						topology, b.Manifest.BundleType),
					SpecRefSignature,
					"v1.0.9 restricts ephemeral-sessions topology to sandbox-preview bundles per spec §5 topology-vs-bundle_type table",
				),
			},
			nil,
		)
	}

	// Cardinality: non-empty array; v1.0.9 = exactly one entry.
	sessions := b.Manifest.Signing.EphemeralSessions
	if len(sessions) == 0 {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					"signing.ephemeral_sessions is empty but topology=ephemeral-sessions",
					SpecRefSignature,
					"ephemeral_sessions[] is non-empty when topology is ephemeral-sessions per spec §5 + §6.5",
				),
			},
			nil,
		)
	}
	if len(sessions) != 1 {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					fmt.Sprintf("signing.ephemeral_sessions has %d entries; v1.0.9 requires exactly 1", len(sessions)),
					SpecRefSignature,
					"v1.0.9 sandbox-preview bundles carry exactly one ephemeral session per spec §6.5",
				),
			},
			nil,
		)
	}

	// Dispatch the pinned KMS issuer key the same way Check 1 does:
	// bundle_type → KeyRole → effective-period lookup. Under
	// ephemeral-sessions topology the manifest.signing.key_fingerprint_spki_b64
	// is the pinned KMS issuer key SPKI (the attesting key, NOT a
	// per-event signing key). Cross-check it matches the pinned SPKI
	// before consuming.
	generatedAt, ok := parseGeneratedAt(b.Manifest.GeneratedAt)
	if !ok {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					fmt.Sprintf("generated_at = %q is not a valid RFC 3339 timestamp", b.Manifest.GeneratedAt),
					SpecRefManifestFields,
					"generated_at is RFC 3339 / ISO-8601 UTC",
				),
			},
			nil,
		)
	}
	pinned, err := keys.KeyForBundle(b.Manifest.BundleType, generatedAt)
	if err != nil {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					fmt.Sprintf("no pinned issuer key for bundle_type=%q at generated_at=%q (%v)",
						b.Manifest.BundleType, b.Manifest.GeneratedAt, err),
					SpecRefSignature,
					"verifier expects a pinned key for the bundle's bundle_type",
				),
			},
			nil,
		)
	}
	if pinned.SPKIFingerprintB64 == keys.PlaceholderProdFingerprint {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "",
					fmt.Sprintf("cannot verify ephemeral session attestations: this binary's pinned %s key is a placeholder (Phase 5 deploy-bootstrap pending)", pinned.KeyID),
					SpecRefSignature,
					"production binaries embed the real prod-key SPKI",
				),
			},
			nil,
		)
	}
	// Cross-check manifest's declared SPKI equals the pinned SPKI
	// (Check 1 already does this; we repeat here so Check 8 is
	// self-contained — a check 1 failure would block check 8 from
	// running, but in case of partial-run scenarios we still gate).
	if b.Manifest.Signing.KeyFingerprintB64 != pinned.SPKIFingerprintB64 {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "manifest.json",
					fmt.Sprintf("manifest.signing.key_fingerprint_spki_b64 (%s…) does not match pinned %s SPKI (%s…)",
						truncate(b.Manifest.Signing.KeyFingerprintB64, 24),
						pinned.KeyID,
						truncate(pinned.SPKIFingerprintB64, 24)),
					SpecRefSignature,
					"manifest.signing.key_fingerprint_spki_b64 equals the pinned issuer key's SPKI",
				),
			},
			nil,
		)
	}
	pinnedKmsPubkey, err := parseEd25519SPKI(pinned.SPKIFingerprintB64)
	if err != nil {
		return Result(
			id, checkName, slug,
			[]error{
				Errorf(id, checkName, "",
					fmt.Sprintf("internal: pinned %s SPKI parse failed: %v", pinned.KeyID, err),
					SpecRefSignature,
					"pinned issuer key is Ed25519",
				),
			},
			nil,
		)
	}

	// Iterate per-session verification per spec §6.5.6.
	var errs []error
	ephemeralMap := make(map[string]ed25519.PublicKey, len(sessions))
	for i, s := range sessions {
		loc := fmt.Sprintf("manifest.signing.ephemeral_sessions[%d]", i)

		// Schema version pin.
		if s.SchemaVersion != 1 {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("schema_version = %d, expected 1", s.SchemaVersion),
				SpecRefSignature,
				"ephemeral session schema_version pinned to 1 for v1.0.9 bundles",
			))
			break
		}

		// Decode seed bytes.
		seedBytes, err := base64.StdEncoding.DecodeString(s.SessionSeedBytesB64)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("session_seed_bytes_b64 base64-decode failed: %v", err),
				SpecRefSignature,
				"session_seed_bytes_b64 is base64 of canonical JCS seed bytes per spec §6.5.1",
			))
			break
		}
		if len(seedBytes) == 0 {
			errs = append(errs, Errorf(id, checkName, loc,
				"session_seed_bytes_b64 decoded to 0 bytes",
				SpecRefSignature,
				"session seed bytes are the canonical JCS object bytes per spec §6.5.1",
			))
			break
		}

		// Decode KMS attestation. Per RFC 8032, Ed25519 signature is
		// 64 bytes.
		attestation, err := base64.StdEncoding.DecodeString(s.KmsAttestationB64)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("kms_attestation_b64 base64-decode failed: %v", err),
				SpecRefSignature,
				"kms_attestation_b64 is base64 of an Ed25519 signature per spec §6.5.2",
			))
			break
		}
		if len(attestation) != ed25519.SignatureSize {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("kms_attestation_b64 decoded to %d bytes, expected %d",
					len(attestation), ed25519.SignatureSize),
				SpecRefSignature,
				"Ed25519 signatures are 64 bytes",
			))
			break
		}

		// Verify KMS attestation against the pinned KMS public key
		// over the seed bytes (spec §6.5.2). Failure means seed bytes
		// or attestation have been tampered with.
		if !ed25519.Verify(pinnedKmsPubkey, seedBytes, attestation) {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("KMS attestation Ed25519 verification failed against pinned %s key over the session seed bytes", pinned.KeyID),
				SpecRefSignature,
				"kms_attestation_b64 verifies over session_seed_bytes under the pinned KMS issuer public key per spec §6.5.2",
			))
			break
		}

		// HKDF-SHA-256 derivation per spec §6.5.3.
		// ikm = seed_bytes ‖ attestation
		// salt = "" (zero-byte salt)
		// info = hkdfInfoV109
		// L = 32 (Ed25519 seed length)
		ikm := make([]byte, 0, len(seedBytes)+len(attestation))
		ikm = append(ikm, seedBytes...)
		ikm = append(ikm, attestation...)
		hkdfReader := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoV109))
		ephemeralSeed := make([]byte, ephemeralSeedLength)
		if _, err := io.ReadFull(hkdfReader, ephemeralSeed); err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("HKDF-SHA-256 expansion failed: %v", err),
				SpecRefSignature,
				"HKDF-SHA-256 derivation per spec §6.5.3",
			))
			break
		}

		// Ed25519 keypair derivation from 32-byte seed per RFC 8032
		// §5.1.5. Go's crypto/ed25519.NewKeyFromSeed does exactly this.
		ephemeralPrivKey := ed25519.NewKeyFromSeed(ephemeralSeed)
		ephemeralPubKey := ephemeralPrivKey.Public().(ed25519.PublicKey)

		// Wrap raw 32-byte pubkey in SPKI DER per RFC 8410. The
		// SPKI DER for Ed25519 is a fixed 12-byte prefix + 32 raw
		// public-key bytes. We construct the bytes directly rather
		// than going through x509.MarshalPKIXPublicKey to keep the
		// dependency surface minimal.
		recomputedSpkiDer := append(
			[]byte{
				0x30, 0x2a, // SEQUENCE, 42 bytes
				0x30, 0x05, // SEQUENCE, 5 bytes (algorithm)
				0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
				0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused
			},
			ephemeralPubKey...,
		)
		recomputedSpkiB64 := base64.StdEncoding.EncodeToString(recomputedSpkiDer)

		// Cross-check recomputed SPKI byte-equals manifest's claimed
		// SPKI per spec §6.5.6 step 6.
		if recomputedSpkiB64 != s.EphemeralSpkiB64 {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("ephemeral_spki_b64 mismatch: declared=%s… recomputed=%s… (tampering signal: the writer may have substituted a different ephemeral key whose attestation appears valid for an unrelated session)",
					truncate(s.EphemeralSpkiB64, 24),
					truncate(recomputedSpkiB64, 24)),
				SpecRefSignature,
				"ephemeral SPKI is HKDF-derived from (seed ‖ attestation) per spec §6.5.3-§6.5.4",
			))
			break
		}

		// Populate the verifier-internal map for Check 3's per-event
		// signature routing.
		ephemeralMap[s.SessionID] = ephemeralPubKey
	}

	if len(errs) > 0 {
		// Reset map to avoid Check 3 routing through a partially-
		// populated state on a failed Check 8.
		b.EphemeralPubkeyByID = nil
		return Result(id, checkName, slug, errs, nil)
	}

	// Publish the map for Check 3's topology-aware branch.
	b.EphemeralPubkeyByID = ephemeralMap
	return Result(id, checkName, slug, nil, nil)
}

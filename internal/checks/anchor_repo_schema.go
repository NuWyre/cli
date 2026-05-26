package checks

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Anchor-repo root.json schema parser. Phase 4 Session 3 D4 commit 1.
//
// Mirrors the v3.1.8 root.json schema with the Phase 4 prereq
// Session A per-org extension as documented in spec §12.2 and
// implemented by packages/evidence/src/anchor-schema.ts. Each anchor
// commit places one root.json file at:
//
//	daily-roots/<organization_id>/<date>/root.json
//
// The verifier (check 7's anchored cross-check, currently stubbed
// in D4 commit 2) cross-checks every field in this object against
// the bundle's own claims. A mismatch on any cross-checked field
// is a load-bearing tampering signal — the bundle and the anchor
// repo MUST agree byte-for-byte on the cryptographic anchors per
// spec §12.4.
//
// **Five-tenant attribution:**
//
//   - Tenant 1 (long-term value). Schema version is enforced at
//     parse time; future schema_version=2 bundles will be rejected
//     by THIS verifier rather than silently accepted (forward-
//     compat refusal). Operators who upgrade the verifier get
//     correct verdicts on new-format bundles; operators who don't
//     get an explicit upgrade prompt instead of silent fall-through.
//
//   - Tenant 3 (security/privacy). DisallowUnknownFields is set on
//     the JSON decoder. An attacker who tries to inject an
//     additional field into a tampered root.json (e.g.,
//     "alternative_root_hash" hoping the verifier helpfully checks
//     the wrong one) hits a parse-time rejection. Strict-allowlist,
//     not allow-and-ignore.
//
//   - Tenant 4 (simplicity). One canonical schema, one parser. No
//     dispatch on bundle_format_version (spec §12.2 documents
//     v1.0 only; future v1.x bundles use the same schema with
//     tolerated unknown fields per the spec's forward-compat
//     posture, but root.json is anchor-side metadata and MUST
//     remain canonical).
//
//   - Tenant 5 (customer trust). Validation errors name the
//     specific field + the rule violated, so an operator reading
//     the diagnostic understands both what failed and why. No
//     opaque "schema validation error" without context.

// RootJsonV2 mirrors the spec §12.2 root.json schema (v3.1.8
// canonical + Phase 4 prereq Session A per-org extension).
//
// JSON tags MUST match spec §12.2 verbatim — the schema is anchor-
// repo public contract, not internal Go state.
type RootJsonV2 struct {
	SchemaVersion       int             `json:"schema_version"`
	BundleFormatVersion int             `json:"bundle_format_version"`
	Date                string          `json:"date"`
	OrganizationID      string          `json:"organization_id"`
	ProducedBy          string          `json:"produced_by"`
	RootHash            string          `json:"root_hash"`
	EventCount          int             `json:"event_count"`
	Merkle              RootJsonMerkle  `json:"merkle"`
	Anchors             RootJsonAnchors `json:"anchors"`
	ComputedAt          string          `json:"computed_at"`
	Issuer              RootJsonIssuer  `json:"issuer"`
}

// RootJsonMerkle is the merkle metadata sub-object.
type RootJsonMerkle struct {
	LeafCount       int    `json:"leaf_count"`
	PaddedLeafCount int    `json:"padded_leaf_count"`
	HashAlgorithm   string `json:"hash_algorithm"`
}

// RootJsonAnchors is the per-leg anchor metadata sub-object. Per
// spec §12.2: opentimestamps + rfc3161 (no github sub-leg here —
// root.json IS the github anchor's content; recursive github
// reference would be circular).
type RootJsonAnchors struct {
	OpenTimestamps RootJsonOTS       `json:"opentimestamps"`
	RFC3161        []RootJsonRFC3161 `json:"rfc3161"`
}

// RootJsonOTS mirrors anchors.opentimestamps in the anchor-repo
// schema. Note: receipt_path is bare filename (e.g., "2026-04-22.ots"),
// distinct from the bundle's "ots_receipts/2026-04-22.ots" path.
// See spec §12.2 path-discipline-divergence note.
type RootJsonOTS struct {
	ReceiptPath   string `json:"receipt_path"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	SubmittedAt   string `json:"submitted_at"`
}

// RootJsonRFC3161 mirrors one entry in anchors.rfc3161[]. Same
// path-divergence note as RootJsonOTS — receipt_path + chain_path
// are bare filenames.
type RootJsonRFC3161 struct {
	TSAName       string `json:"tsa_name"`
	ReceiptPath   string `json:"receipt_path"`
	ChainPath     string `json:"chain_path"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	ChainSHA256   string `json:"chain_sha256"`
	TSATime       string `json:"tsa_time"`
}

// RootJsonIssuer mirrors the issuer sub-object.
type RootJsonIssuer struct {
	KeyFingerprintSPKIB64 string `json:"key_fingerprint_spki_b64"`
	KeyPurpose            string `json:"key_purpose"`
}

// MaxRootJsonBytes caps caller-supplied root.json input. Production
// root.json files are <2 KB (one OTS + 3 RFC 3161 + metadata); 256 KiB
// covers any plausible legitimate size with massive headroom while
// foreclosing memory-DoS via a malicious endpoint streaming a multi-
// MB response. D1's HTTPClient.MaxResponseBytes (4 MiB) is the
// upstream cap; this is a tighter local cap at the schema parser.
const MaxRootJsonBytes = 256 * 1024

// Per-field caps, applied during ParseRootJsonV2 validation. Each
// closes a wide-array / large-string DoS amplification surface
// inside the 256 KiB byte cap (security-auditor M1 + M2 from
// D4 commit 1 review). Tenant 3: defense-in-depth at every layer.
const (
	// MaxRFC3161Entries caps anchors.rfc3161[] length. Production
	// uses 3 TSAs (FreeTSA + Sectigo + DigiCert); 16 is generous
	// over any plausible production expansion.
	MaxRFC3161Entries = 16
	// MaxFreeTextLen caps free-text fields (produced_by, key_purpose,
	// receipt_path, chain_path, tsa_name). Production values are
	// <50 chars; 256 covers legitimate identifiers + slack.
	MaxFreeTextLen = 256
	// MaxFingerprintB64Len caps base64-encoded SPKI. The SPKI is
	// the full DER public key (Ed25519: 44 bytes → 60 b64 chars;
	// RSA-2048: ~294 bytes → ~392 b64 chars; RSA-4096: ~550 bytes
	// → ~736 b64 chars). 1024 chars covers any plausible key
	// algorithm with slack.
	MaxFingerprintB64Len = 1024
	// MinFingerprintB64Len rejects clearly-truncated values.
	// 32 b64 chars decode to 24 raw bytes; nothing useful is
	// shorter than that.
	MinFingerprintB64Len = 32
)

// validateBareFilename enforces "no path-separators" per spec §12.2's
// path-discipline-divergence note. Anchor-repo receipt_path /
// chain_path are bare filenames (e.g., "2026-04-22__freetsa.tsr"),
// distinct from bundle-side paths. Mirrors TS composer's
// BARE_FILENAME_RE (anchor-schema.ts) — crypto-integrity-reviewer
// M3 cross-language parity.
func validateBareFilename(s string) error {
	if s == "" {
		return errors.New("empty")
	}
	if len(s) > MaxFreeTextLen {
		return fmt.Errorf("exceeds max len %d (got %d)", MaxFreeTextLen, len(s))
	}
	if strings.ContainsAny(s, "/\\") {
		return errors.New("path-separator characters not allowed in bare filename")
	}
	if s == "." || s == ".." {
		return fmt.Errorf("path-traversal token %q", s)
	}
	return nil
}

// validateIsoNoFraction enforces RFC 3339 UTC timestamp WITHOUT
// fractional seconds. Per spec §4 line 271: "No fractional seconds
// in any ISO 8601 timestamp anywhere in the bundle (including ...
// anchor-repo root.json)." TS composer enforces this; the Go reader
// MUST match — crypto-integrity-reviewer M4 cross-language parity.
//
// Format: "YYYY-MM-DDTHH:MM:SSZ" (exactly 20 chars, trailing 'Z' for
// UTC, no offset, no .NNN fractional).
func validateIsoNoFraction(s string) error {
	const want = "2006-01-02T15:04:05Z"
	if len(s) != len(want) {
		return fmt.Errorf("ISO 8601 UTC must be %d chars without fractional (got %d)", len(want), len(s))
	}
	// Position-by-position check against the canonical shape.
	for i := 0; i < len(s); i++ {
		expectChar := want[i]
		actual := s[i]
		switch expectChar {
		case '-', 'T', ':', 'Z':
			if actual != expectChar {
				return fmt.Errorf("position %d expected %q, got %q", i, expectChar, actual)
			}
		default:
			if actual < '0' || actual > '9' {
				return fmt.Errorf("position %d must be digit (got %q)", i, actual)
			}
		}
	}
	return nil
}

// validateFreeTextLen caps a field's length and rejects empty.
// Used for produced_by / key_purpose / tsa_name where the spec
// requires non-empty + bounded content.
func validateFreeTextLen(field, s string) error {
	if s == "" {
		return fmt.Errorf("%s empty", field)
	}
	if len(s) > MaxFreeTextLen {
		return fmt.Errorf("%s exceeds max len %d (got %d)", field, MaxFreeTextLen, len(s))
	}
	return nil
}

// validateSPKIFingerprintB64 enforces base64-decodable + length-
// bounded. Per spec: the field carries the FULL SPKI DER (not a
// hash) base64-encoded. The DER size depends on the key algorithm
// (Ed25519 → 44 bytes; RSA-2048 → ~294 bytes; RSA-4096 → ~550 bytes),
// so the length range is permissive. The validator's job is to
// reject malformed shapes (non-base64, truncated, oversized) at
// parse time so an attacker can't smuggle log-injection or memory-
// amplification content through this field. Security-auditor M3.
func validateSPKIFingerprintB64(s string) error {
	if len(s) < MinFingerprintB64Len {
		return fmt.Errorf("SPKI fingerprint too short (got %d, min %d chars)", len(s), MinFingerprintB64Len)
	}
	if len(s) > MaxFingerprintB64Len {
		return fmt.Errorf("SPKI fingerprint too long (got %d, max %d chars)", len(s), MaxFingerprintB64Len)
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return fmt.Errorf("SPKI fingerprint base64 decode failed: %w", err)
	}
	return nil
}

// ParseRootJsonV2 parses + validates root.json bytes against the
// spec §12.2 schema. Returns a populated *RootJsonV2 on success or
// a descriptive error on any validation failure.
//
// **Strict validation** (Tenant 3):
//   - DisallowUnknownFields is set on the decoder; unknown fields
//     fail the parse rather than being silently dropped. The
//     forward-compat tolerance documented in spec §1 applies to
//     the BUNDLE'S JSON files (manifest, events, etc.) but NOT to
//     root.json — the anchor repo's content is canonical, written
//     by NuWyre's own pipeline, and any deviation is suspicious.
//   - schema_version MUST equal 1; future versions require the
//     verifier to be upgraded.
//   - bundle_format_version MUST equal 1; same forward-compat-refusal
//     posture as schema_version.
//   - organization_id MUST be canonical lowercase UUID
//     (validateOrgIDCanonical). Path-traversal characters
//     (/, \, ., ..) are caught here even before URL construction.
//   - root_hash MUST be 64-char lowercase hex (matches spec §6.1
//     daily root canonicalization).
//   - date MUST be strict YYYY-MM-DD (validateUTCDayStrict).
//
// Defense-in-depth: every cross-checked field is shape-validated
// here BEFORE check 7's per-field comparison runs. A malformed
// field surfaces at parse with a specific error rather than at the
// comparison with a confusing mismatch error.
func ParseRootJsonV2(data []byte) (*RootJsonV2, error) {
	if len(data) == 0 {
		return nil, errors.New("root.json: empty bytes")
	}
	if len(data) > MaxRootJsonBytes {
		return nil, fmt.Errorf("root.json: exceeds max bytes (%d > %d)", len(data), MaxRootJsonBytes)
	}

	var rj RootJsonV2
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rj); err != nil {
		return nil, fmt.Errorf("root.json: JSON decode failed: %w", err)
	}
	// Reject trailing data — strict-single-object semantics.
	if dec.More() {
		return nil, errors.New("root.json: trailing data after JSON object")
	}

	// Forward-compat refusal: future schema_version requires verifier
	// upgrade, not silent fall-through.
	if rj.SchemaVersion != 1 {
		return nil, fmt.Errorf("root.json: schema_version %d not supported (this verifier handles schema_version=1; upgrade verifier for newer formats)", rj.SchemaVersion)
	}
	if rj.BundleFormatVersion != 1 {
		return nil, fmt.Errorf("root.json: bundle_format_version %d not supported (this verifier handles bundle_format_version=1; upgrade verifier for newer formats)", rj.BundleFormatVersion)
	}

	// Required field shape validation.
	if err := validateUTCDayStrict(rj.Date); err != nil {
		return nil, fmt.Errorf("root.json: invalid date: %w", err)
	}
	if err := validateOrgIDCanonical(rj.OrganizationID); err != nil {
		return nil, fmt.Errorf("root.json: invalid organization_id: %w", err)
	}
	if err := validateLowercaseHexLen(rj.RootHash, 64); err != nil {
		return nil, fmt.Errorf("root.json: invalid root_hash: %w", err)
	}
	if err := validateFreeTextLen("produced_by", rj.ProducedBy); err != nil {
		return nil, fmt.Errorf("root.json: %w", err)
	}
	if rj.EventCount < 0 {
		return nil, fmt.Errorf("root.json: event_count must be non-negative (got %d)", rj.EventCount)
	}

	// Merkle sub-object validation.
	if rj.Merkle.LeafCount < 0 {
		return nil, fmt.Errorf("root.json: merkle.leaf_count must be non-negative (got %d)", rj.Merkle.LeafCount)
	}
	if rj.Merkle.PaddedLeafCount < rj.Merkle.LeafCount {
		return nil, fmt.Errorf("root.json: merkle.padded_leaf_count (%d) < leaf_count (%d)",
			rj.Merkle.PaddedLeafCount, rj.Merkle.LeafCount)
	}
	if rj.Merkle.HashAlgorithm != "sha256" {
		return nil, fmt.Errorf("root.json: merkle.hash_algorithm must be 'sha256' (got %q)", rj.Merkle.HashAlgorithm)
	}

	// Anchors sub-object: cross-language strictness parity per
	// crypto-integrity-reviewer M2-M4 — Go reader matches TS
	// composer's assertHex64 / assertBareFilename / assertIsoNoFraction
	// strictness on every field rather than punting empty-string
	// handling to the consumer (D4 commit 2 anchored cross-check).
	if err := validateLowercaseHexLen(rj.Anchors.OpenTimestamps.ReceiptSHA256, 64); err != nil {
		return nil, fmt.Errorf("root.json: invalid anchors.opentimestamps.receipt_sha256: %w", err)
	}
	if err := validateBareFilename(rj.Anchors.OpenTimestamps.ReceiptPath); err != nil {
		return nil, fmt.Errorf("root.json: invalid anchors.opentimestamps.receipt_path: %w", err)
	}
	if err := validateIsoNoFraction(rj.Anchors.OpenTimestamps.SubmittedAt); err != nil {
		return nil, fmt.Errorf("root.json: invalid anchors.opentimestamps.submitted_at: %w", err)
	}

	// Per security-auditor M1: cap RFC 3161 array length to bound
	// allocation. Production has 3 entries; 16 is generous.
	if len(rj.Anchors.RFC3161) > MaxRFC3161Entries {
		return nil, fmt.Errorf("root.json: anchors.rfc3161 has %d entries (max %d)", len(rj.Anchors.RFC3161), MaxRFC3161Entries)
	}
	for i, tsa := range rj.Anchors.RFC3161 {
		if err := validateFreeTextLen(fmt.Sprintf("anchors.rfc3161[%d].tsa_name", i), tsa.TSAName); err != nil {
			return nil, fmt.Errorf("root.json: %w", err)
		}
		// M1 fix (security reviewer, dedicated SSH session commit 3):
		// enforce lowercase tsa_name to match the bundle-side
		// discipline (validateRFC3161Consistency in
		// anchor_consistency.go). Without this, a root.json with
		// "FreeTSA" + a bundle with "freetsa" would mismatch at
		// the cross-check lookup step with a confusing "no
		// matching receipt" error rather than a precise
		// case-normalization diagnostic at parse time.
		if strings.ToLower(tsa.TSAName) != tsa.TSAName {
			return nil, fmt.Errorf("root.json: anchors.rfc3161[%d].tsa_name = %q is not lowercase; spec §3 requires lowercase identifier (cross-language strictness parity with bundle-side enforcement)", i, tsa.TSAName)
		}
		if err := validateBareFilename(tsa.ReceiptPath); err != nil {
			return nil, fmt.Errorf("root.json: invalid anchors.rfc3161[%d].receipt_path: %w", i, err)
		}
		if err := validateBareFilename(tsa.ChainPath); err != nil {
			return nil, fmt.Errorf("root.json: invalid anchors.rfc3161[%d].chain_path: %w", i, err)
		}
		if err := validateLowercaseHexLen(tsa.ReceiptSHA256, 64); err != nil {
			return nil, fmt.Errorf("root.json: invalid anchors.rfc3161[%d].receipt_sha256: %w", i, err)
		}
		if err := validateLowercaseHexLen(tsa.ChainSHA256, 64); err != nil {
			return nil, fmt.Errorf("root.json: invalid anchors.rfc3161[%d].chain_sha256: %w", i, err)
		}
		if err := validateIsoNoFraction(tsa.TSATime); err != nil {
			return nil, fmt.Errorf("root.json: invalid anchors.rfc3161[%d].tsa_time: %w", i, err)
		}
	}

	// Issuer sub-object — security-auditor M3: shape-validate the
	// SPKI fingerprint as base64 of expected length, not just non-
	// empty.
	if err := validateSPKIFingerprintB64(rj.Issuer.KeyFingerprintSPKIB64); err != nil {
		return nil, fmt.Errorf("root.json: invalid issuer.key_fingerprint_spki_b64: %w", err)
	}
	if err := validateFreeTextLen("issuer.key_purpose", rj.Issuer.KeyPurpose); err != nil {
		return nil, fmt.Errorf("root.json: %w", err)
	}

	// computed_at — strict ISO 8601 UTC no-fraction.
	if err := validateIsoNoFraction(rj.ComputedAt); err != nil {
		return nil, fmt.Errorf("root.json: invalid computed_at: %w", err)
	}

	return &rj, nil
}

// validateLowercaseHexLen enforces "lowercase hex string of exactly
// n chars". Used for SHA-256 (64-char) and shorter fingerprints.
// Mirrors the discipline in check 4's isLowercaseHex64 but
// parameterized on length so root.json's various hex fields share
// a single validator.
func validateLowercaseHexLen(s string, n int) error {
	if len(s) != n {
		return fmt.Errorf("expected %d-char hex (got %d)", n, len(s))
	}
	for i, r := range s {
		ok := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !ok {
			return fmt.Errorf("position %d must be lowercase hex (got %q)", i, r)
		}
	}
	return nil
}

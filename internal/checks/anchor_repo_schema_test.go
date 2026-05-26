package checks

import (
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// RootJsonV2 schema tests (Phase 4 Session 3 D4 commit 1)
// =============================================================================

const validRootJsonExample = `{
  "schema_version": 1,
  "bundle_format_version": 1,
  "date": "2026-04-22",
  "organization_id": "00000000-0000-4000-8000-000000000001",
  "produced_by": "nuwyre-example-bundle-generator/3.1",
  "root_hash": "ce905ca84827dec683202c9790119955e77b24762cdafb384fd4f6125b5cea93",
  "event_count": 37,
  "merkle": {
    "leaf_count": 37,
    "padded_leaf_count": 64,
    "hash_algorithm": "sha256"
  },
  "anchors": {
    "opentimestamps": {
      "receipt_path": "2026-04-22.ots",
      "receipt_sha256": "fdb776104abb4947f0b16d25b057af59d5d5747ccebd4b54224147d00a41a62b",
      "submitted_at": "2026-05-10T17:00:29Z"
    },
    "rfc3161": [
      {
        "tsa_name": "freetsa",
        "receipt_path": "2026-04-22__freetsa.tsr",
        "chain_path": "2026-04-22__freetsa.chain.pem",
        "receipt_sha256": "71d10204d780e667c152104c9088a9b32b8f346ec726c6f15af7afabf6c33d42",
        "chain_sha256": "1175041e9e8144c42b3b10bfee84e2e850434cdb5b4ec9f35384f1112f2aed7b",
        "tsa_time": "2026-05-10T17:00:29Z"
      }
    ]
  },
  "computed_at": "2026-04-22T23:59:59Z",
  "issuer": {
    "key_fingerprint_spki_b64": "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=",
    "key_purpose": "DEMO ONLY"
  }
}`

func TestParseRootJsonV2HappyPath(t *testing.T) {
	t.Parallel()
	rj, err := ParseRootJsonV2([]byte(validRootJsonExample))
	if err != nil {
		t.Fatalf("ParseRootJsonV2: %v", err)
	}
	if rj.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", rj.SchemaVersion)
	}
	if rj.OrganizationID != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("OrganizationID = %q", rj.OrganizationID)
	}
	if rj.RootHash != "ce905ca84827dec683202c9790119955e77b24762cdafb384fd4f6125b5cea93" {
		t.Errorf("RootHash = %q", rj.RootHash)
	}
	if len(rj.Anchors.RFC3161) != 1 {
		t.Errorf("RFC3161 len = %d, want 1", len(rj.Anchors.RFC3161))
	}
	if rj.Anchors.RFC3161[0].TSAName != "freetsa" {
		t.Errorf("TSAName = %q", rj.Anchors.RFC3161[0].TSAName)
	}
	if rj.Merkle.HashAlgorithm != "sha256" {
		t.Errorf("HashAlgorithm = %q", rj.Merkle.HashAlgorithm)
	}
}

// =============================================================================
// Strict-allowlist tests (Tenant 3: DisallowUnknownFields)
// =============================================================================

func TestParseRootJsonV2RejectsUnknownTopLevelField(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"schema_version": 1,`,
		`"schema_version": 1,
  "alternative_root_hash": "deadbeef",`,
		1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted unknown top-level field; want strict-allowlist rejection")
	}
	if !strings.Contains(err.Error(), "alternative_root_hash") {
		t.Errorf("error doesn't name the unknown field: %v", err)
	}
}

func TestParseRootJsonV2RejectsUnknownNestedField(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"hash_algorithm": "sha256"`,
		`"hash_algorithm": "sha256",
    "alternative_algorithm": "md5"`,
		1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted unknown nested field; want strict-allowlist rejection")
	}
}

func TestParseRootJsonV2RejectsTrailingData(t *testing.T) {
	t.Parallel()
	withTrailing := validRootJsonExample + `{"second":"object"}`
	_, err := ParseRootJsonV2([]byte(withTrailing))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted trailing data; want rejection")
	}
}

// =============================================================================
// Forward-compat refusal (Tenant 1)
// =============================================================================

func TestParseRootJsonV2RejectsFutureSchemaVersion(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"schema_version": 1,`,
		`"schema_version": 2,`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted schema_version=2; want forward-compat refusal")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error %q missing schema_version reference", err.Error())
	}
}

func TestParseRootJsonV2RejectsFutureBundleFormatVersion(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"bundle_format_version": 1,`,
		`"bundle_format_version": 2,`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted bundle_format_version=2; want forward-compat refusal")
	}
}

// =============================================================================
// Field-shape validation
// =============================================================================

func TestParseRootJsonV2RejectsPathTraversalOrgID(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"organization_id": "00000000-0000-4000-8000-000000000001"`,
		`"organization_id": "../../etc/passwd-deadbeef-deadbeef-dead"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted path-traversal organization_id; want rejection")
	}
	if !strings.Contains(err.Error(), "organization_id") {
		t.Errorf("error %q missing organization_id reference", err.Error())
	}
}

func TestParseRootJsonV2RejectsUppercaseOrgID(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"00000000-0000-4000-8000-000000000001"`,
		`"00000000-0000-4000-8000-00000000000A"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted uppercase organization_id; want canonical-lowercase rejection")
	}
}

func TestParseRootJsonV2RejectsUppercaseRootHash(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"ce905ca84827dec683202c9790119955e77b24762cdafb384fd4f6125b5cea93"`,
		`"CE905CA84827DEC683202C9790119955E77B24762CDAFB384FD4F6125B5CEA93"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted uppercase root_hash; want lowercase rejection")
	}
}

func TestParseRootJsonV2RejectsMalformedDate(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"date": "2026-04-22"`,
		`"date": "2026/04/22"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted slash-separated date; want hyphen rejection")
	}
}

func TestParseRootJsonV2RejectsNegativeEventCount(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"event_count": 37`,
		`"event_count": -1`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted negative event_count; want non-negative rejection")
	}
}

func TestParseRootJsonV2RejectsMerkleInversion(t *testing.T) {
	t.Parallel()
	// padded_leaf_count < leaf_count is structurally impossible
	bad := strings.Replace(validRootJsonExample,
		`"leaf_count": 37,
    "padded_leaf_count": 64,`,
		`"leaf_count": 64,
    "padded_leaf_count": 37,`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted padded < leaf; want inversion rejection")
	}
}

func TestParseRootJsonV2RejectsNonSHA256MerkleAlgorithm(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"hash_algorithm": "sha256"`,
		`"hash_algorithm": "md5"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted md5 hash_algorithm; want sha256-only rejection")
	}
}

func TestParseRootJsonV2RejectsBadOTSReceiptSHA(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"receipt_sha256": "fdb776104abb4947f0b16d25b057af59d5d5747ccebd4b54224147d00a41a62b"`,
		`"receipt_sha256": "FDB776104abb4947f0b16d25b057af59d5d5747ccebd4b54224147d00a41a62b"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted uppercase OTS receipt_sha256; want lowercase rejection")
	}
}

func TestParseRootJsonV2RejectsBadRFC3161ChainSHA(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"chain_sha256": "1175041e9e8144c42b3b10bfee84e2e850434cdb5b4ec9f35384f1112f2aed7b"`,
		`"chain_sha256": "tooshort"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted short chain_sha256; want length rejection")
	}
}

func TestParseRootJsonV2RejectsRFC3161WithoutTSAName(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"tsa_name": "freetsa"`,
		`"tsa_name": ""`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted empty tsa_name; want rejection")
	}
}

// =============================================================================
// Edge cases
// =============================================================================

func TestParseRootJsonV2RejectsEmpty(t *testing.T) {
	t.Parallel()
	_, err := ParseRootJsonV2(nil)
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted nil bytes")
	}
	_, err = ParseRootJsonV2([]byte{})
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted empty bytes")
	}
}

func TestParseRootJsonV2RejectsOversized(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, MaxRootJsonBytes+1)
	_, err := ParseRootJsonV2(oversized)
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted oversized bytes; want size-cap rejection")
	}
	if !strings.Contains(err.Error(), "exceeds max bytes") {
		t.Errorf("error doesn't mention size cap: %v", err)
	}
}

func TestParseRootJsonV2RejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	_, err := ParseRootJsonV2([]byte("not valid json"))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted invalid JSON")
	}
}

// =============================================================================
// validateLowercaseHexLen
// =============================================================================

// =============================================================================
// New tightening validators (D4 commit 1 reviewer-fix pass)
// =============================================================================

func TestValidateBareFilename(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"canonical TSR filename", "2026-04-22__freetsa.tsr", false},
		{"canonical OTS filename", "2026-04-22.ots", false},
		{"empty", "", true},
		{"forward slash", "subdir/file.tsr", true},
		{"backslash (Windows)", "subdir\\file.tsr", true},
		{"single dot", ".", true},
		{"double dot", "..", true},
		{"leading dot ok", ".gitattributes", false},
		{"path traversal in middle", "subdir/../leak.tsr", true},
		{"oversized", strings.Repeat("a", 257), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateBareFilename(c.in)
			if c.wantErr && err == nil {
				t.Errorf("validateBareFilename(%q) accepted; want error", c.in)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateBareFilename(%q) rejected: %v", c.in, err)
			}
		})
	}
}

func TestValidateIsoNoFraction(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"canonical UTC", "2026-04-22T23:59:59Z", false},
		{"midnight UTC", "2026-04-22T00:00:00Z", false},
		{"with fractional seconds (rejected)", "2026-04-22T23:59:59.123Z", true},
		{"no Z (offset)", "2026-04-22T23:59:59+00:00", true},
		{"local time (no Z)", "2026-04-22T23:59:59", true},
		{"empty", "", true},
		{"too short", "2026-04-22T23:59:5Z", true},
		{"too long", "2026-04-22T23:59:59Z0", true},
		{"date only", "2026-04-22", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateIsoNoFraction(c.in)
			if c.wantErr && err == nil {
				t.Errorf("validateIsoNoFraction(%q) accepted; want error", c.in)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateIsoNoFraction(%q) rejected: %v", c.in, err)
			}
		})
	}
}

func TestValidateSPKIFingerprintB64(t *testing.T) {
	t.Parallel()
	// Ed25519 SPKI: 44 bytes → 60 b64 chars.
	ed25519SPKI := "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE="
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"canonical Ed25519 SPKI", ed25519SPKI, false},
		{"empty", "", true},
		{"too short", "MCowBQ==", true},
		{"too long (>1024 chars)", strings.Repeat("A", 1025), true},
		{"non-base64 chars", "not-b64!@#$%^&*()not-b64!@#$%^&*()", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateSPKIFingerprintB64(c.in)
			if c.wantErr && err == nil {
				t.Errorf("validateSPKIFingerprintB64(%q) accepted; want error", c.in)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateSPKIFingerprintB64(%q) rejected: %v", c.in, err)
			}
		})
	}
}

// =============================================================================
// New ParseRootJsonV2 tightening tests
// =============================================================================

func TestParseRootJsonV2RejectsFractionalTimestamp(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"computed_at": "2026-04-22T23:59:59Z"`,
		`"computed_at": "2026-04-22T23:59:59.123Z"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted fractional-second timestamp; want spec §4 line 271 rejection")
	}
}

func TestParseRootJsonV2RejectsBareFilenameWithSlash(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"receipt_path": "2026-04-22__freetsa.tsr"`,
		`"receipt_path": "../../etc/passwd"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted path-traversal in receipt_path; want bare-filename rejection")
	}
}

func TestParseRootJsonV2RejectsRFC3161OverCap(t *testing.T) {
	t.Parallel()
	// Construct a synthetic root.json with MaxRFC3161Entries+1 entries.
	var sb strings.Builder
	sb.WriteString(`{
  "schema_version": 1,
  "bundle_format_version": 1,
  "date": "2026-04-22",
  "organization_id": "00000000-0000-4000-8000-000000000001",
  "produced_by": "test/1.0",
  "root_hash": "ce905ca84827dec683202c9790119955e77b24762cdafb384fd4f6125b5cea93",
  "event_count": 0,
  "merkle": { "leaf_count": 0, "padded_leaf_count": 0, "hash_algorithm": "sha256" },
  "anchors": {
    "opentimestamps": { "receipt_path": "2026-04-22.ots", "receipt_sha256": "fdb776104abb4947f0b16d25b057af59d5d5747ccebd4b54224147d00a41a62b", "submitted_at": "2026-05-10T17:00:29Z" },
    "rfc3161": [`)
	for i := 0; i < MaxRFC3161Entries+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"tsa_name":"tsa%d","receipt_path":"x.tsr","chain_path":"x.chain.pem","receipt_sha256":"%s","chain_sha256":"%s","tsa_time":"2026-05-10T17:00:29Z"}`,
			i, strings.Repeat("a", 64), strings.Repeat("b", 64))
	}
	sb.WriteString(`]
  },
  "computed_at": "2026-04-22T23:59:59Z",
  "issuer": { "key_fingerprint_spki_b64": "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=", "key_purpose": "test" }
}`)
	_, err := ParseRootJsonV2([]byte(sb.String()))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted >MaxRFC3161Entries; want array-cap rejection")
	}
	if !strings.Contains(err.Error(), "max") {
		t.Errorf("error missing cap reference: %v", err)
	}
}

func TestParseRootJsonV2RejectsOversizedProducedBy(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"produced_by": "nuwyre-example-bundle-generator/3.1"`,
		fmt.Sprintf(`"produced_by": %q`, strings.Repeat("a", MaxFreeTextLen+1)), 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted oversized produced_by; want length rejection")
	}
}

func TestParseRootJsonV2RejectsBadSPKIFingerprint(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validRootJsonExample,
		`"key_fingerprint_spki_b64": "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE="`,
		`"key_fingerprint_spki_b64": "not-base64-content!"`, 1)
	_, err := ParseRootJsonV2([]byte(bad))
	if err == nil {
		t.Fatal("ParseRootJsonV2 accepted non-base64 SPKI fingerprint; want decode rejection")
	}
}

// =============================================================================
// Pre-existing tests continue below
// =============================================================================

func TestValidateLowercaseHexLen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		n       int
		wantErr bool
	}{
		{"sha256 happy", strings.Repeat("a", 64), 64, false},
		{"sha1 happy", strings.Repeat("a", 40), 40, false},
		{"mixed digit + hex", "0123456789abcdef", 16, false},
		{"too short", strings.Repeat("a", 63), 64, true},
		{"too long", strings.Repeat("a", 65), 64, true},
		{"uppercase rejected", strings.Repeat("A", 64), 64, true},
		{"non-hex char", strings.Repeat("a", 63) + "g", 64, true},
		{"empty when n>0", "", 64, true},
		{"empty when n==0", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateLowercaseHexLen(c.in, c.n)
			if c.wantErr && err == nil {
				t.Errorf("validateLowercaseHexLen(%q, %d) accepted; want error", c.in, c.n)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateLowercaseHexLen(%q, %d) rejected: %v", c.in, c.n, err)
			}
		})
	}
}

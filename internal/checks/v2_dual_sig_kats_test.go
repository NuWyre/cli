package checks

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/nuwyre/cli/internal/keys"
)

// Phase 7.F.5 session 103 closure: KAT golden vector consumer tests
// for v2.0.0 dual-signature cross-language byte-equivalence. Vectors
// are pinned at testdata/v2_dual_sig_kats_v1.json (Go-readable form);
// SOURCE OF TRUTH is packages/evidence/src/v2-dual-sig-kats.test.ts.
//
// **Standards-Track Posture** (tenants T1+T2+T5): a third-party
// implementer reading the spec alone MUST produce a conformant
// implementation whose KAT outputs match these hex strings byte-for-
// byte. Drift between TS and Go is a SHIPPED CONFORMANCE DEFECT —
// investigate the root cause; do NOT snapshot-update.
//
// **Cryptographic invariants pinned** (per spec §§18.3 + 18.4):
//   - KAT-V2-1: ML-DSA-65 keygen-from-32-byte-seed (FIPS 204 §6.2
//     deterministic) produces byte-identical raw public key + SPKI
//     across TS (@noble/post-quantum) + Go (cloudflare/circl).
//   - KAT-V2-2: ML-DSA-65 deterministic-variant sign (FIPS 204 §6.2 +
//     spec §18.3 pin; rnd=32 zero bytes; ctx=empty) produces byte-
//     identical 3309-byte signature across TS + Go.
//   - KAT-V2-3: Ed25519 RFC 8032 §5.1.6 deterministic sign produces
//     byte-identical 64-byte signature across TS (Node createPrivateKey
//     PKCS8 + cryptoSign) + Go (ed25519.NewKeyFromSeed + ed25519.Sign).

type v2DualSigKATFile struct {
	SpecVersionPinnedAt string `json:"spec_version_pinned_at"`
	PinnedInputs        struct {
		TestSeedHex    string `json:"test_seed_hex"`
		TestMessageHex string `json:"test_message_hex"`
	} `json:"pinned_inputs"`
	Vectors struct {
		KATV21 struct {
			Description                  string `json:"description"`
			Input                        struct {
				SeedHex string `json:"seed_hex"`
			} `json:"input"`
			ExpectedRawPubSha256         string `json:"expected_raw_pub_sha256"`
			ExpectedRawPubByteLength     int    `json:"expected_raw_pub_byte_length"`
			ExpectedSpkiSha256           string `json:"expected_spki_sha256"`
			ExpectedSpkiByteLength       int    `json:"expected_spki_byte_length"`
			ExpectedSpkiPrefixFirst22Hex string `json:"expected_spki_prefix_first22_hex"`
		} `json:"KAT-V2-1"`
		KATV22 struct {
			Description           string `json:"description"`
			Input                 struct {
				SeedHex    string `json:"seed_hex"`
				MessageHex string `json:"message_hex"`
			} `json:"input"`
			ExpectedSigSha256     string `json:"expected_sig_sha256"`
			ExpectedSigByteLength int    `json:"expected_sig_byte_length"`
		} `json:"KAT-V2-2"`
		KATV23 struct {
			Description           string `json:"description"`
			Input                 struct {
				SeedHex    string `json:"seed_hex"`
				MessageHex string `json:"message_hex"`
			} `json:"input"`
			ExpectedPubSpkiHex    string `json:"expected_pub_spki_hex"`
			ExpectedSigHex        string `json:"expected_sig_hex"`
			ExpectedSigSha256     string `json:"expected_sig_sha256"`
			ExpectedSigByteLength int    `json:"expected_sig_byte_length"`
		} `json:"KAT-V2-3"`
	} `json:"vectors"`
}

func loadV2DualSigKATs(t *testing.T) v2DualSigKATFile {
	t.Helper()
	path := filepath.Join("testdata", "v2_dual_sig_kats_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read v2 KAT file: %v", err)
	}
	var k v2DualSigKATFile
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("unmarshal v2 KAT file: %v", err)
	}
	return k
}

func hexDecodeOrFatal(t *testing.T, h string, label string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("%s: hex decode: %v", label, err)
	}
	return b
}

// TestV2KAT1_MlDsa65KeygenFromSeed asserts that cloudflare/circl's
// mldsa65.NewKeyFromSeed produces a byte-identical SPKI to TS's
// @noble/post-quantum keygenFromSeed + wrapPublicKeySpki when given
// the same 32-byte seed. Cross-language SPKI byte-equivalence is the
// load-bearing v2.0.0 spec §18.4 invariant.
func TestV2KAT1_MlDsa65KeygenFromSeed(t *testing.T) {
	k := loadV2DualSigKATs(t)
	seedBytes := hexDecodeOrFatal(t, k.Vectors.KATV21.Input.SeedHex, "KAT-V2-1 seed")
	if len(seedBytes) != mldsa65.SeedSize {
		t.Fatalf("KAT-V2-1: seed length %d != mldsa65.SeedSize %d", len(seedBytes), mldsa65.SeedSize)
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)

	pub, _ := mldsa65.NewKeyFromSeed(&seed)
	rawPub, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("KAT-V2-1: pub.MarshalBinary: %v", err)
	}
	if len(rawPub) != keys.MlDsa65PublicKeySize {
		t.Fatalf("KAT-V2-1: raw pub length %d != %d", len(rawPub), keys.MlDsa65PublicKeySize)
	}
	// Crypto-int L1 closure session 103: cross-check raw pub byte length
	// against the JSON-pinned expected (currently 1952 per FIPS 204 §4
	// Table 1). The Go-side keys.MlDsa65PublicKeySize constant + the
	// JSON-pinned expected MUST agree — if not, the JSON is source-of-
	// truth (spec authority) and Go must reconcile.
	if len(rawPub) != k.Vectors.KATV21.ExpectedRawPubByteLength {
		t.Errorf("KAT-V2-1: raw pub length %d != JSON-pinned expected %d (cross-language byte-size invariant per spec §18.4)",
			len(rawPub), k.Vectors.KATV21.ExpectedRawPubByteLength)
	}

	rawPubHash := sha256.Sum256(rawPub)
	gotRawPubSha256 := hex.EncodeToString(rawPubHash[:])
	if gotRawPubSha256 != k.Vectors.KATV21.ExpectedRawPubSha256 {
		t.Errorf("KAT-V2-1 raw_pub SHA-256: got=%s expected=%s — CROSS-LANGUAGE DRIFT vs TS @noble/post-quantum keygenFromSeed",
			gotRawPubSha256, k.Vectors.KATV21.ExpectedRawPubSha256)
	}

	// Wrap with the canonical SPKI prefix (mirror of TS wrapPublicKeySpki).
	spki := make([]byte, 0, keys.MlDsa65SPKISize)
	spki = append(spki, keys.MlDsa65SPKIPrefix...)
	spki = append(spki, rawPub...)
	if len(spki) != keys.MlDsa65SPKISize {
		t.Fatalf("KAT-V2-1: SPKI length %d != %d", len(spki), keys.MlDsa65SPKISize)
	}
	if len(spki) != k.Vectors.KATV21.ExpectedSpkiByteLength {
		t.Errorf("KAT-V2-1: SPKI length %d != JSON-pinned expected %d", len(spki), k.Vectors.KATV21.ExpectedSpkiByteLength)
	}

	spkiHash := sha256.Sum256(spki)
	gotSpkiSha256 := hex.EncodeToString(spkiHash[:])
	if gotSpkiSha256 != k.Vectors.KATV21.ExpectedSpkiSha256 {
		t.Errorf("KAT-V2-1 SPKI SHA-256: got=%s expected=%s — CROSS-LANGUAGE DRIFT vs TS wrapPublicKeySpki",
			gotSpkiSha256, k.Vectors.KATV21.ExpectedSpkiSha256)
	}

	// Defensive: verify the 22-byte prefix matches the pinned expected hex
	// (catches drift between keys.MlDsa65SPKIPrefix and the spec §18.4
	// worked-construction prefix bytes).
	gotPrefixHex := hex.EncodeToString(spki[:22])
	if gotPrefixHex != k.Vectors.KATV21.ExpectedSpkiPrefixFirst22Hex {
		t.Errorf("KAT-V2-1 SPKI prefix first 22 bytes: got=%s expected=%s — drift between keys.MlDsa65SPKIPrefix and spec §18.4",
			gotPrefixHex, k.Vectors.KATV21.ExpectedSpkiPrefixFirst22Hex)
	}
}

// TestV2KAT2_MlDsa65DeterministicSign asserts that cloudflare/circl's
// deterministic-variant signature (SignTo with randomized=false) over
// the pinned test message produces a byte-identical 3309-byte signature
// to TS's @noble/post-quantum signDeterministic. Spec §18.3 invariant.
func TestV2KAT2_MlDsa65DeterministicSign(t *testing.T) {
	k := loadV2DualSigKATs(t)
	seedBytes := hexDecodeOrFatal(t, k.Vectors.KATV22.Input.SeedHex, "KAT-V2-2 seed")
	msg := hexDecodeOrFatal(t, k.Vectors.KATV22.Input.MessageHex, "KAT-V2-2 message")
	if len(seedBytes) != mldsa65.SeedSize {
		t.Fatalf("KAT-V2-2: seed length %d != mldsa65.SeedSize", len(seedBytes))
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)

	_, sk := mldsa65.NewKeyFromSeed(&seed)

	sig := make([]byte, mldsa65.SignatureSize)
	// FIPS 204 §6.2 deterministic variant: randomized=false, ctx=nil.
	// Matches the v2 verifier path at check1_v2_dual_sig.go verifyMlDsa65Leg
	// which calls mldsa65.Verify(pub, msg, []byte{}, sig). Crypto-int H1
	// closure session 103: assign + assert the error return to catch any
	// future ctx-too-long regression (today ctx==nil so unreachable; a
	// spec §18.3 ctx-binding amendment introducing non-empty ctx would
	// silently sign with residual sig bytes + pass the SHA-256 assertion
	// otherwise).
	if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatalf("KAT-V2-2: mldsa65.SignTo error: %v", err)
	}

	if len(sig) != k.Vectors.KATV22.ExpectedSigByteLength {
		t.Fatalf("KAT-V2-2 sig length: got=%d expected=%d", len(sig), k.Vectors.KATV22.ExpectedSigByteLength)
	}

	sigHash := sha256.Sum256(sig)
	gotSigSha256 := hex.EncodeToString(sigHash[:])
	if gotSigSha256 != k.Vectors.KATV22.ExpectedSigSha256 {
		t.Errorf("KAT-V2-2 sig SHA-256: got=%s expected=%s — CROSS-LANGUAGE DRIFT vs TS signDeterministic; FIPS 204 deterministic-variant byte-equivalence BROKEN",
			gotSigSha256, k.Vectors.KATV22.ExpectedSigSha256)
	}
}

// TestV2KAT3_Ed25519DeterministicSign asserts that crypto/ed25519's
// NewKeyFromSeed + Sign produces a byte-identical 64-byte signature
// to TS's Node createPrivateKey PKCS8 + cryptoSign. RFC 8032 §5.1.6
// deterministic invariant.
func TestV2KAT3_Ed25519DeterministicSign(t *testing.T) {
	k := loadV2DualSigKATs(t)
	seedBytes := hexDecodeOrFatal(t, k.Vectors.KATV23.Input.SeedHex, "KAT-V2-3 seed")
	msg := hexDecodeOrFatal(t, k.Vectors.KATV23.Input.MessageHex, "KAT-V2-3 message")
	if len(seedBytes) != ed25519.SeedSize {
		t.Fatalf("KAT-V2-3: seed length %d != ed25519.SeedSize %d", len(seedBytes), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seedBytes)
	sig := ed25519.Sign(priv, msg)

	if len(sig) != k.Vectors.KATV23.ExpectedSigByteLength {
		t.Fatalf("KAT-V2-3 sig length: got=%d expected=%d", len(sig), k.Vectors.KATV23.ExpectedSigByteLength)
	}

	gotSigHex := hex.EncodeToString(sig)
	if gotSigHex != k.Vectors.KATV23.ExpectedSigHex {
		t.Errorf("KAT-V2-3 sig hex: got=%s expected=%s — CROSS-LANGUAGE DRIFT vs TS Ed25519; RFC 8032 deterministic-sign byte-equivalence BROKEN",
			gotSigHex, k.Vectors.KATV23.ExpectedSigHex)
	}

	sigHash := sha256.Sum256(sig)
	gotSigSha256 := hex.EncodeToString(sigHash[:])
	if gotSigSha256 != k.Vectors.KATV23.ExpectedSigSha256 {
		t.Errorf("KAT-V2-3 sig SHA-256 redundancy check: got=%s expected=%s", gotSigSha256, k.Vectors.KATV23.ExpectedSigSha256)
	}

}

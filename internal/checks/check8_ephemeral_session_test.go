package checks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// Cross-language conformance test for spec §6.5 ephemeral session
// signing. Reads the fixture emitted by
// apps/api/src/lib/__tests__/session-signing.test.ts and asserts:
//
//   1. The HKDF-SHA-256 derivation produces the byte-identical Ed25519
//      seed when given (session_seed_bytes ‖ kms_attestation).
//   2. The Ed25519 keypair derived from that seed produces a 32-byte
//      public key whose SPKI DER wrapping matches the
//      `expected_ephemeral_spki_b64` field byte-for-byte.
//   3. The KMS attestation verifies against the pinned KMS public key
//      over the seed bytes.
//   4. The sample per-event signature verifies against the recomputed
//      ephemeral public key over the sample event_hash bytes.
//
// Mismatch on any axis fails CI on the Go side. The TS test fails CI
// on its side via the in-process verifier round-trip at fixture-emit
// time. Together the two tests pin the byte-equivalence contract for
// the entire spec §6.5 protocol.

const crossLangFixturePath = "../../../../docs/spec/fixtures/bundle-format-v1/cross-lang-ephemeral.json"

type crossLangFixture struct {
	Comment                  string `json:"$comment"`
	HKDFInfo                 string `json:"hkdf_info"`
	SessionSeedBytesB64      string `json:"session_seed_bytes_b64"`
	KmsAttestationB64        string `json:"kms_attestation_b64"`
	PinnedKmsPublicKeyB64    string `json:"pinned_kms_public_key_b64"`
	PinnedKmsSpkiB64         string `json:"pinned_kms_spki_b64"`
	ExpectedEphemeralSpkiB64 string `json:"expected_ephemeral_spki_b64"`
	SampleEventHashB64       string `json:"sample_event_hash_b64"`
	SampleEventSignatureB64  string `json:"sample_event_signature_b64"`
}

func loadCrossLangFixture(t *testing.T) crossLangFixture {
	t.Helper()
	// Resolve fixture path relative to this test file's package directory.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	absPath := filepath.Join(wd, crossLangFixturePath)
	bytes, err := os.ReadFile(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("cross-lang fixture not found at %s; re-run `pnpm --filter @nuwyre/api test session-signing` to emit it", absPath)
		}
		t.Fatalf("read fixture %s: %v", absPath, err)
	}
	var fixture crossLangFixture
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatalf("parse fixture %s: %v", absPath, err)
	}
	return fixture
}

func TestCheck8CrossLangHKDFInfoString(t *testing.T) {
	fixture := loadCrossLangFixture(t)
	if fixture.HKDFInfo != hkdfInfoV109 {
		t.Errorf("hkdf_info mismatch: TS=%q Go=%q (spec §6.5.3 mandates the exact 35-byte literal)",
			fixture.HKDFInfo, hkdfInfoV109)
	}
	if len(fixture.HKDFInfo) != 35 {
		t.Errorf("hkdf_info length = %d, expected 35 (spec §6.5.3)", len(fixture.HKDFInfo))
	}
}

func TestCheck8CrossLangPinnedKmsAttestationVerifies(t *testing.T) {
	fixture := loadCrossLangFixture(t)
	pinnedPubkey, err := base64.StdEncoding.DecodeString(fixture.PinnedKmsPublicKeyB64)
	if err != nil {
		t.Fatalf("decode pinned_kms_public_key_b64: %v", err)
	}
	if len(pinnedPubkey) != ed25519.PublicKeySize {
		t.Fatalf("pinned KMS pubkey %d bytes, expected %d", len(pinnedPubkey), ed25519.PublicKeySize)
	}
	seedBytes, err := base64.StdEncoding.DecodeString(fixture.SessionSeedBytesB64)
	if err != nil {
		t.Fatalf("decode session_seed_bytes_b64: %v", err)
	}
	attestation, err := base64.StdEncoding.DecodeString(fixture.KmsAttestationB64)
	if err != nil {
		t.Fatalf("decode kms_attestation_b64: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pinnedPubkey), seedBytes, attestation) {
		t.Errorf("Ed25519.Verify(pinned_kms_pub, seed_bytes, attestation) returned false (spec §6.5.2 attestation must verify under the pinned KMS public key)")
	}
}

func TestCheck8CrossLangHKDFAndEphemeralSPKIRecompute(t *testing.T) {
	fixture := loadCrossLangFixture(t)
	seedBytes, err := base64.StdEncoding.DecodeString(fixture.SessionSeedBytesB64)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	attestation, err := base64.StdEncoding.DecodeString(fixture.KmsAttestationB64)
	if err != nil {
		t.Fatalf("decode attestation: %v", err)
	}
	expectedSpkiB64 := fixture.ExpectedEphemeralSpkiB64

	// HKDF-SHA-256(seed ‖ attestation, salt="", info=hkdfInfoV109, L=32)
	ikm := append([]byte{}, seedBytes...)
	ikm = append(ikm, attestation...)
	reader := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoV109))
	ephemeralSeed := make([]byte, 32)
	if _, err := io.ReadFull(reader, ephemeralSeed); err != nil {
		t.Fatalf("HKDF read: %v", err)
	}
	// Ed25519 keypair derivation per RFC 8032 §5.1.5.
	privKey := ed25519.NewKeyFromSeed(ephemeralSeed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	// SPKI DER wrapping per RFC 8410. Same 12-byte prefix layout as the
	// TS reference impl's `createPublicKey({jwk}).export('spki', 'der')`.
	spkiDer := append(
		[]byte{
			0x30, 0x2a,
			0x30, 0x05,
			0x06, 0x03, 0x2b, 0x65, 0x70,
			0x03, 0x21, 0x00,
		},
		pubKey...,
	)
	recomputedSpkiB64 := base64.StdEncoding.EncodeToString(spkiDer)
	if recomputedSpkiB64 != expectedSpkiB64 {
		t.Errorf("ephemeral SPKI mismatch — TS expected %q, Go recomputed %q (spec §6.5.4 cross-language byte-equivalence)",
			expectedSpkiB64, recomputedSpkiB64)
	}
}

func TestCheck8CrossLangPerEventSignatureVerifies(t *testing.T) {
	fixture := loadCrossLangFixture(t)
	seedBytes, _ := base64.StdEncoding.DecodeString(fixture.SessionSeedBytesB64)
	attestation, _ := base64.StdEncoding.DecodeString(fixture.KmsAttestationB64)
	eventHash, err := base64.StdEncoding.DecodeString(fixture.SampleEventHashB64)
	if err != nil {
		t.Fatalf("decode sample_event_hash_b64: %v", err)
	}
	if len(eventHash) != 32 {
		t.Fatalf("sample_event_hash %d bytes, expected 32", len(eventHash))
	}
	sig, err := base64.StdEncoding.DecodeString(fixture.SampleEventSignatureB64)
	if err != nil {
		t.Fatalf("decode sample_event_signature_b64: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sample_event_signature %d bytes, expected %d", len(sig), ed25519.SignatureSize)
	}

	// Recompute ephemeral public key + verify the TS-side signature
	// against it. End-to-end: TS sign() → Go ed25519.Verify().
	ikm := append([]byte{}, seedBytes...)
	ikm = append(ikm, attestation...)
	reader := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoV109))
	ephemeralSeed := make([]byte, 32)
	io.ReadFull(reader, ephemeralSeed)
	pubKey := ed25519.NewKeyFromSeed(ephemeralSeed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pubKey, eventHash, sig) {
		t.Errorf("Go-side Ed25519.Verify of TS-side signature failed (spec §6.5.5 per-event signing primitive)")
	}

	// Sanity: the SPKI DER bytes from the recomputed pubkey match the
	// fixture's expected SPKI bytes.
	spkiDer := append(
		[]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00},
		pubKey...,
	)
	expectedSpki, _ := base64.StdEncoding.DecodeString(fixture.ExpectedEphemeralSpkiB64)
	if !bytes.Equal(spkiDer, expectedSpki) {
		t.Errorf("SPKI byte-comparison failed (recomputed %x vs expected %x)", spkiDer, expectedSpki)
	}
}

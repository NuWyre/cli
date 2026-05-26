package checks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nuwyre/cli/internal/keys"
)

// =============================================================================
// SSH signature verification tests (Phase 4 dedicated SSH session)
//
// Tests cover:
//   - Real signed commit fixtures from NuWyre/anchors (1a1635b3 + ade149b2)
//   - Pinned-key-matches-extracted-key regression (catches drift if the
//     hand-pinned literal ever desyncs from the actual commit signer key)
//   - Synthetic generated-key + signed-payload happy path
//   - Tampered signature: SSHInvalid
//   - Tampered payload: SSHInvalid (signature no longer covers reconstructed input)
//   - Mismatched signer (signed by non-pinned key): SSHInvalid
//   - Malformed armored signature (missing markers, garbage base64): SSHInvalid
//   - Empty/nil inputs: SSHInvalid (defense-in-depth)
//   - parseSafe coverage on every library boundary
// =============================================================================

// =============================================================================
// Real-commit signatures from NuWyre/anchors (extracted via gh CLI). Both
// commits are signed by the same ssh-ed25519 key — the NuWyre Anchors Bot
// role identity (post-2026-05-26 migration off the founder's personal key) —
// matching the value pinned in keys.PinnedSSHIssuerKeys.
// =============================================================================

const (
	// fixtureCommit1A1635B3Signature is the armored SSH signature from
	// NuWyre/anchors commit 3d5ea93a41ea426a43462ab0531248c483683551 (the
	// .gitattributes commit). The var name keeps its historical label; the
	// bot-identity migration + subsequent rotation to an operator-generated
	// key rebuilt the commit under the dedicated NuWyre Anchors Bot key
	// (new SHA above).
	// Signature ONLY — the signed commit payload is not reproduced here (this
	// public test source stays identity-free). The signature embeds the bot's
	// ssh-ed25519 public key, which is all TestExtractedKeyMatchesPinned needs
	// to validate the pinned key against the real anchor signer. Verify/tamper
	// coverage uses generated, bot-authored fixtures (see nameFreeFixture).
	fixtureCommit1A1635B3Signature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgtZ7qhBjMkbWTK8LgR7QnqgMzkR
9KM3esKPHTjUl3LhIAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQA3YR4tdz3EkdhCglrQJK1y6Ouu02esfi8F4R5Tlx3Q3UgvhlGCcX05cMChJtLYy13
A3KITXDFdLq9scoGO2lg0=
-----END SSH SIGNATURE-----`

	// fixtureCommitADE149B2Signature is the armored SSH signature from
	// NuWyre/anchors commit 886f5fbd7ae62d57f5f3169a27db221ccb7d0591 (the
	// 2026-04-22 daily root anchor, rebuilt under the rotated bot key).
	// Signature only — same rationale as above.
	fixtureCommitADE149B2Signature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgtZ7qhBjMkbWTK8LgR7QnqgMzkR
9KM3esKPHTjUl3LhIAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQCv1ZZio9tT6jVQ0cGFgwHsPS/guh2vsm/XlxOkmuVF2fb1NJ5nCEcmPWlPNSLicK6
IstuwdXZs257Gn9t5Vswc=
-----END SSH SIGNATURE-----`
)

// nameFreeFixture builds a bot-authored, generated-key-signed commit fixture
// for the verify/tamper tests below. It carries no personal identity (the
// public verifier repo must not embed one), while exercising the exact same
// SSHSIG verification path the real anchor commits do. Returns the signed
// payload, its armored SSHSIG, and a pinned issuer key for the generated
// signer so VerifyCommit's pubkey-match check passes.
func nameFreeFixture(t *testing.T) (payload []byte, armoredSig string, pinned *keys.SSHIssuerKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	payload = []byte("tree 0000000000000000000000000000000000000000\n" +
		"author NuWyre Anchors Bot <support@nuwyre.com> 1778210285 -0400\n" +
		"committer NuWyre Anchors Bot <support@nuwyre.com> 1778210285 -0400\n\n" +
		"anchor: example daily root\n")
	armoredSig, err = synthesizeSSHSig(pub, priv, "git", "sha512", payload)
	if err != nil {
		t.Fatalf("synthesizeSSHSig: %v", err)
	}
	pinned = &keys.SSHIssuerKey{
		KeyID:               "test-generated-anchor-signer",
		KeyRole:             keys.KeyRoleDev,
		AuthorizedKeyFormat: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(buildEd25519AuthorizedKeyWire(pub)),
	}
	return payload, armoredSig, pinned
}

// devKey returns the pinned dev SSH issuer key for tests.
func devKey(t *testing.T) *keys.SSHIssuerKey {
	t.Helper()
	for i := range keys.PinnedSSHIssuerKeys {
		k := &keys.PinnedSSHIssuerKeys[i]
		if k.KeyRole == keys.KeyRoleDev {
			return k
		}
	}
	t.Fatal("no dev SSH issuer key in PinnedSSHIssuerKeys")
	return nil
}

// =============================================================================
// Pinned-key extraction regression
// =============================================================================

// TestExtractedKeyMatchesPinned re-derives the SSH public key from
// each fixture commit's signature blob + asserts the derivation
// produces the same authorized_keys-format value pinned in
// keys.PinnedSSHIssuerKeys. Catches drift if either:
//   - The hand-pinned literal in ssh-issuer-keys.go gets edited away
//     from the real signer key.
//   - The signer key on NuWyre/anchors gets rotated without updating
//     the pinned literal.
//
// Re-derivation workflow per ssh-issuer-keys.go's pin-discipline
// comment.
func TestExtractedKeyMatchesPinned(t *testing.T) {
	t.Parallel()
	pinned := devKey(t)
	pinnedPubKey, err := parsePinnedSSHKey(pinned.AuthorizedKeyFormat)
	if err != nil {
		t.Fatalf("parsing pinned key failed: %v", err)
	}
	pinnedMarshal := pinnedPubKey.Marshal()

	cases := []struct {
		name       string
		armoredSig string
	}{
		{"3d5ea93a (.gitattributes)", fixtureCommit1A1635B3Signature},
		{"886f5fbd (anchor 2026-04-22)", fixtureCommitADE149B2Signature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blob, err := decodeArmoredSSHSig(c.armoredSig)
			if err != nil {
				t.Fatalf("decode armored: %v", err)
			}
			parsed, err := parseSSHSigBlob(blob)
			if err != nil {
				t.Fatalf("parse SSHSIG: %v", err)
			}
			extractedMarshal := parsed.embeddedPubKey.Marshal()
			if !bytes.Equal(extractedMarshal, pinnedMarshal) {
				t.Errorf("extracted key from %s does NOT match pinned key:\n  pinned:    %s\n  extracted: ssh-ed25519 %s",
					c.name,
					pinned.AuthorizedKeyFormat,
					base64.StdEncoding.EncodeToString(extractedMarshal),
				)
			}
		})
	}
}

// =============================================================================
// Happy path (a valid signature verifies against its pinned signer key)
// =============================================================================

func TestVerifyCommitValidSignature(t *testing.T) {
	t.Parallel()
	payload, armoredSig, pinned := nameFreeFixture(t)
	v := NewSSHSignatureVerifier(pinned)
	r := v.VerifyCommit(armoredSig, payload)
	if r.Verdict != SSHValid {
		t.Errorf("Verdict = %v, want SSHValid; ErrorReason: %s", r.Verdict, r.ErrorReason)
	}
	if !strings.HasPrefix(r.SignerKeyFingerprint, "SHA256:") {
		t.Errorf("SignerKeyFingerprint = %q, want prefix 'SHA256:'", r.SignerKeyFingerprint)
	}
}

// =============================================================================
// Tamper detection (load-bearing integrity guarantees)
// =============================================================================

// TestVerifyCommitTamperedPayload pins the integrity guarantee:
// modifying ANY byte of the payload (the signed commit object)
// produces SSHInvalid. The signature was computed over the SHA-512
// hash of the original payload; flipping a byte changes the hash,
// invalidating the signature.
func TestVerifyCommitTamperedPayload(t *testing.T) {
	t.Parallel()
	payload, armoredSig, pinned := nameFreeFixture(t)
	v := NewSSHSignatureVerifier(pinned)
	tampered := make([]byte, len(payload))
	copy(tampered, payload)
	tampered[0] ^= 0x01 // flip one bit at the start
	r := v.VerifyCommit(armoredSig, tampered)
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid (tampered payload)", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "signature verification failed") {
		t.Errorf("ErrorReason missing signature-verify diagnostic: %q", r.ErrorReason)
	}
}

// TestVerifyCommitTamperedSignatureBlob pins that flipping bytes
// in the SSHSIG signature struct produces SSHInvalid. Tamper inside
// the signature blob (after the public key field) so we exercise
// signature-bytes corruption rather than parse-time rejection.
func TestVerifyCommitTamperedSignatureBlob(t *testing.T) {
	t.Parallel()
	payload, armoredSig, pinned := nameFreeFixture(t)
	v := NewSSHSignatureVerifier(pinned)
	// Decode → modify byte deep in the signature region → re-encode.
	blob, err := decodeArmoredSSHSig(armoredSig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Find the last 32 bytes (within the Ed25519 signature) and
	// flip one bit. The Ed25519 signature is the last ~64 bytes of
	// the SSHSIG blob.
	tamperedBlob := make([]byte, len(blob))
	copy(tamperedBlob, blob)
	tamperedBlob[len(tamperedBlob)-10] ^= 0x01
	tamperedArmored := "-----BEGIN SSH SIGNATURE-----\n" +
		base64.StdEncoding.EncodeToString(tamperedBlob) +
		"\n-----END SSH SIGNATURE-----"
	r := v.VerifyCommit(tamperedArmored, payload)
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid (tampered signature)", r.Verdict)
	}
	// Crypto-integrity reviewer M2 (dedicated SSH session commit 1
	// review): pin the failure mode. A regression that shifted the
	// flipped byte to a length-prefix region would still produce
	// SSHInvalid but at the parse layer, not the signature-verify
	// layer the test claims to exercise.
	if !strings.Contains(r.ErrorReason, "signature verification failed") {
		t.Errorf("ErrorReason = %q, want signature-verify failure path", r.ErrorReason)
	}
}

// TestVerifyCommitMismatchedSigner pins the cross-issuer forgery
// defense: a signature signed by a DIFFERENT Ed25519 key (still
// well-formed SSHSIG, just signed by an attacker's key) MUST be
// rejected at the public-key-mismatch check, before any signature
// verification path runs.
func TestVerifyCommitMismatchedSigner(t *testing.T) {
	t.Parallel()
	// Generate a random Ed25519 key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	// Synthesize an SSHSIG blob signed by that key over an arbitrary
	// payload.
	payload := []byte("attacker-controlled payload")
	armored, err := synthesizeSSHSig(pub, priv, "git", "sha512", payload)
	if err != nil {
		t.Fatalf("synthesizeSSHSig: %v", err)
	}
	// Verify against the pinned dev key — should fail at the
	// pubkey-mismatch check.
	v := NewSSHSignatureVerifier(devKey(t))
	r := v.VerifyCommit(armored, payload)
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid (mismatched signer)", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "signer public key does not match pinned issuer SSH key") {
		t.Errorf("ErrorReason missing mismatch diagnostic: %q", r.ErrorReason)
	}
	if !strings.Contains(r.ErrorReason, "cross-issuer forgery OR operator key-rotation timing") {
		t.Errorf("ErrorReason missing operator-actionable framing: %q", r.ErrorReason)
	}
}

// TestVerifyCommitNamespaceCrossProtocolReplay — load-bearing
// regression for crypto-integrity reviewer C1 (Critical). An
// attacker who has any other SSH-signed message under the same key
// (e.g., `ssh-keygen -Y sign -n file ...` for a text file) could
// lift that signature, present it as a "git commit signature" via
// the GitHub API surface, and the verifier MUST reject it because
// the SSHSIG namespace differs from the expected "git" value.
//
// Constructs an SSHSIG with namespace="file" using a freshly
// generated key. Pin the verifier with that same key so the
// pubkey-match check passes — the namespace check MUST be the
// load-bearing rejection.
func TestVerifyCommitNamespaceCrossProtocolReplay(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	payload := []byte("a text file an attacker also signed under -n file")
	armored, err := synthesizeSSHSig(pub, priv, "file", "sha512", payload)
	if err != nil {
		t.Fatalf("synthesizeSSHSig: %v", err)
	}

	// Pin the verifier with the SAME key so the pubkey-match check
	// passes — the namespace check MUST be the rejection layer.
	pinnedAuthorizedKey := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(
		buildEd25519AuthorizedKeyWire(pub),
	)
	pinned := &keys.SSHIssuerKey{
		KeyID:               "test-pinned-matches-attacker-key",
		KeyRole:             keys.KeyRoleDev,
		AuthorizedKeyFormat: pinnedAuthorizedKey,
	}
	v := NewSSHSignatureVerifier(pinned)
	r := v.VerifyCommit(armored, payload)
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid (namespace mismatch)", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "namespace") {
		t.Errorf("ErrorReason missing namespace diagnostic: %q", r.ErrorReason)
	}
	if !strings.Contains(r.ErrorReason, "cross-protocol signature replay") {
		t.Errorf("ErrorReason missing cross-protocol-replay framing: %q", r.ErrorReason)
	}
}

// buildEd25519AuthorizedKeyWire constructs the SSH wire-format
// public-key bytes for an Ed25519 key (the bytes that base64-encode
// to the value after "ssh-ed25519 " in authorized_keys form).
func buildEd25519AuthorizedKeyWire(pub ed25519.PublicKey) []byte {
	var wire []byte
	wire = appendSSHString(wire, []byte("ssh-ed25519"))
	wire = appendSSHString(wire, pub)
	return wire
}

// =============================================================================
// Defensive input validation
// =============================================================================

func TestVerifyCommitNilPinnedKey(t *testing.T) {
	t.Parallel()
	v := NewSSHSignatureVerifier(nil)
	r := v.VerifyCommit(fixtureCommit1A1635B3Signature, []byte("commit payload"))
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "nil pinned") {
		t.Errorf("ErrorReason missing nil-pinned diagnostic: %q", r.ErrorReason)
	}
}

func TestVerifyCommitEmptyArmoredSig(t *testing.T) {
	t.Parallel()
	v := NewSSHSignatureVerifier(devKey(t))
	r := v.VerifyCommit("", []byte("payload"))
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "empty SSH signature") {
		t.Errorf("ErrorReason missing empty-sig diagnostic: %q", r.ErrorReason)
	}
}

func TestVerifyCommitEmptyPayload(t *testing.T) {
	t.Parallel()
	v := NewSSHSignatureVerifier(devKey(t))
	r := v.VerifyCommit(fixtureCommit1A1635B3Signature, nil)
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "empty signed payload") {
		t.Errorf("ErrorReason missing empty-payload diagnostic: %q", r.ErrorReason)
	}
}

// TestVerifyCommitWithPlaceholderProdKey pins fail-secure on the
// production placeholder: even with valid signature bytes, the
// pinned-key parse fails because the placeholder isn't a valid
// authorized_keys line. Result: SSHInvalid, not silent acceptance.
func TestVerifyCommitWithPlaceholderProdKey(t *testing.T) {
	t.Parallel()
	prod := &keys.SSHIssuerKey{
		KeyID:               "issuer-ssh-prod-v1",
		KeyRole:             keys.KeyRoleProd,
		AuthorizedKeyFormat: keys.PlaceholderProdSSHAuthorizedKey,
	}
	v := NewSSHSignatureVerifier(prod)
	r := v.VerifyCommit(fixtureCommit1A1635B3Signature, []byte("commit payload"))
	if r.Verdict != SSHInvalid {
		t.Errorf("Verdict = %v, want SSHInvalid (placeholder key fail-secure)", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "failed to parse pinned issuer SSH key") {
		t.Errorf("ErrorReason missing pinned-key-parse diagnostic: %q", r.ErrorReason)
	}
}

// =============================================================================
// Malformed armored signature variants (parse-error paths)
// =============================================================================

func TestDecodeArmoredSSHSigVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"missing BEGIN", "no markers here", "missing BEGIN"},
		{"missing END", "-----BEGIN SSH SIGNATURE-----\nU1NI", "missing END"},
		{"reversed markers", "-----END SSH SIGNATURE-----\n-----BEGIN SSH SIGNATURE-----", "before BEGIN"},
		{"non-base64 body", "-----BEGIN SSH SIGNATURE-----\nnot!@#$%base64\n-----END SSH SIGNATURE-----", "base64 decode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeArmoredSSHSig(c.input)
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q missing %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestParseSSHSigBlobVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		blob    []byte
		wantErr string
	}{
		{"empty", []byte{}, "blob too short"},
		{"wrong magic", []byte("BADMAGIC\x00\x00\x00\x01"), "invalid magic"},
		{"truncated short", []byte("SSHSIG\x00"), "blob too short"},
		{"truncated mid-version", []byte("SSHSIG\x00\x00\x00\x01\x00"), "truncated"},
		{"version 99", []byte("SSHSIG\x00\x00\x00\x63"), "unsupported SSHSIG version 99"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseSSHSigBlob(c.blob)
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q missing %q", err.Error(), c.wantErr)
			}
		})
	}
}

// TestParseSSHSigBlobRejectsNonEmptyReserved — security-auditor L3
// regression. The OpenSSH PROTOCOL.sshsig v1 spec requires the
// reserved field to be the empty string; a non-empty reserved is a
// spec violation that the verifier rejects at parse time with a
// precise diagnostic (rather than letting it through to surface
// later as the generic "signature verification failed").
//
// Constructs a valid SSHSIG with a non-empty reserved field by
// taking a known-valid signature blob, locating + replacing the
// reserved field, and re-encoding. Simpler approach: synthesize a
// fresh blob with a forged reserved field directly.
func TestParseSSHSigBlobRejectsNonEmptyReserved(t *testing.T) {
	t.Parallel()
	// Synthesize a fresh signed payload, then mutate the resulting
	// SSHSIG blob to have non-empty reserved.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	armored, err := synthesizeSSHSig(pub, priv, "git", "sha512", []byte("payload"))
	if err != nil {
		t.Fatalf("synthesizeSSHSig: %v", err)
	}
	blob, err := decodeArmoredSSHSig(armored)
	if err != nil {
		t.Fatalf("decodeArmoredSSHSig: %v", err)
	}
	// Walk the blob until reserved field, replace its 4-byte length
	// from 0 to 1 + insert one byte.
	const magicLen = 6
	rest := blob[magicLen+4:] // skip magic + version
	pubKeyBytes, rest, err := readSSHString(rest)
	if err != nil {
		t.Fatalf("walking blob (publickey): %v", err)
	}
	namespaceBytes, rest, err := readSSHString(rest)
	if err != nil {
		t.Fatalf("walking blob (namespace): %v", err)
	}
	// 'rest' now starts at the reserved field's length prefix.
	// Reconstruct the blob with non-empty reserved:
	prefixLen := magicLen + 4 + 4 + len(pubKeyBytes) + 4 + len(namespaceBytes)
	if len(blob) < prefixLen+4 {
		t.Fatalf("blob layout unexpected: prefix beyond blob")
	}
	tampered := make([]byte, 0, len(blob)+1)
	tampered = append(tampered, blob[:prefixLen]...) // up to reserved-length
	// Append non-empty reserved (length 1, byte 0xAB)
	tampered = append(tampered, 0x00, 0x00, 0x00, 0x01, 0xAB)
	tampered = append(tampered, rest[4:]...) // skip the original (zero-length) reserved field's length prefix

	_, err = parseSSHSigBlob(tampered)
	if err == nil {
		t.Fatal("expected non-empty-reserved rejection; got nil")
	}
	if !strings.Contains(err.Error(), "reserved field MUST be empty") {
		t.Errorf("error missing reserved-field diagnostic: %v", err)
	}
}

// TestParseSSHSigBlobRejectsTrailingBytes — security-auditor L4
// coverage gap. The "trailing N bytes after signature field" branch
// in parseSSHSigBlob (defense against attacker-padded blobs) had no
// direct test. Constructs a valid blob, appends garbage bytes, and
// asserts the rejection.
func TestParseSSHSigBlobRejectsTrailingBytes(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	armored, err := synthesizeSSHSig(pub, priv, "git", "sha512", []byte("payload"))
	if err != nil {
		t.Fatalf("synthesizeSSHSig: %v", err)
	}
	blob, err := decodeArmoredSSHSig(armored)
	if err != nil {
		t.Fatalf("decodeArmoredSSHSig: %v", err)
	}
	tampered := append(blob, 0xff, 0xff)
	_, err = parseSSHSigBlob(tampered)
	if err == nil {
		t.Fatal("expected trailing-bytes rejection; got nil")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error missing trailing-bytes diagnostic: %v", err)
	}
}

// =============================================================================
// parseSafe coverage — synthetic inputs that exercise each library
// boundary's panic-recovery path. None of these should panic in
// practice (the libraries are documented as panic-free), but the
// wrappers exist per D2's calibration discipline against
// undocumented edge cases + future library changes.
// =============================================================================

func TestParseSafeWrappersDoNotPanicOnGarbage(t *testing.T) {
	t.Parallel()

	// parsePinnedSSHKey on garbage
	_, err := parsePinnedSSHKey("not a valid authorized_keys line at all")
	if err == nil {
		t.Error("parsePinnedSSHKey accepted garbage; want error")
	}

	// parseSSHWireFormatPublicKeySafe on empty / random bytes
	_, err = parseSSHWireFormatPublicKeySafe(nil)
	if err == nil {
		t.Error("parseSSHWireFormatPublicKeySafe accepted nil; want error")
	}
	_, err = parseSSHWireFormatPublicKeySafe([]byte{0xff, 0xff, 0xff, 0xff, 0x01})
	if err == nil {
		t.Error("parseSSHWireFormatPublicKeySafe accepted random bytes; want error")
	}

	// parseSSHWireFormatSignatureSafe on garbage
	_, err = parseSSHWireFormatSignatureSafe(nil)
	if err == nil {
		t.Error("parseSSHWireFormatSignatureSafe accepted nil; want error")
	}
}

// =============================================================================
// Hash algorithm dispatch — sha256 + sha512 supported, others rejected
// =============================================================================

func TestBuildSSHSigSigningInputAlgorithms(t *testing.T) {
	t.Parallel()
	payload := []byte("test payload")

	out256, err := buildSSHSigSigningInput("git", "sha256", payload)
	if err != nil {
		t.Fatalf("sha256: %v", err)
	}
	out512, err := buildSSHSigSigningInput("git", "sha512", payload)
	if err != nil {
		t.Fatalf("sha512: %v", err)
	}
	if bytes.Equal(out256, out512) {
		t.Error("sha256 + sha512 outputs equal; expected different lengths")
	}

	if _, err := buildSSHSigSigningInput("git", "md5", payload); err == nil {
		t.Error("md5 accepted; want unsupported-algorithm rejection")
	}
	if _, err := buildSSHSigSigningInput("git", "", payload); err == nil {
		t.Error("empty algorithm accepted; want rejection")
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// synthesizeSSHSig constructs a valid armored SSHSIG signature for
// the given payload using the given Ed25519 key pair. Used by tests
// that need to generate signatures (e.g., mismatched-signer test).
//
// Implements the same SSHSIG protocol the verifier parses, but in
// reverse: synthesize signing input → sign → wrap in SSHSIG blob.
//
// Security-auditor L2 (dedicated SSH session commit 1 review):
// returns an explicit error on unsupported hash algorithm rather
// than silently emitting empty armored bytes. A future test that
// passes "sha256" (which the verifier supports but this helper
// doesn't yet) gets a clear t.Fatal at the helper call rather than
// a misleading "empty SSH signature" downstream.
func synthesizeSSHSig(pub ed25519.PublicKey, priv ed25519.PrivateKey, namespace, hashAlgorithm string, payload []byte) (string, error) {
	// Construct signing input.
	var hashed []byte
	switch hashAlgorithm {
	case "sha512":
		h := sha512.Sum512(payload)
		hashed = h[:]
	default:
		return "", fmt.Errorf("synthesizeSSHSig: unsupported hash algorithm %q (test helper supports sha512 only — extend if needed)", hashAlgorithm)
	}
	var signingInput []byte
	signingInput = append(signingInput, []byte("SSHSIG")...)
	signingInput = appendSSHString(signingInput, []byte(namespace))
	signingInput = appendSSHString(signingInput, []byte(""))
	signingInput = appendSSHString(signingInput, []byte(hashAlgorithm))
	signingInput = appendSSHString(signingInput, hashed)

	// Sign.
	rawSig := ed25519.Sign(priv, signingInput)

	// Wrap signature in SSH wire format signature struct:
	// string format ("ssh-ed25519") + string blob (raw signature)
	var sigStruct []byte
	sigStruct = appendSSHString(sigStruct, []byte("ssh-ed25519"))
	sigStruct = appendSSHString(sigStruct, rawSig)

	// Encode public key in SSH wire format.
	var pubKeyWire []byte
	pubKeyWire = appendSSHString(pubKeyWire, []byte("ssh-ed25519"))
	pubKeyWire = appendSSHString(pubKeyWire, pub)

	// Build SSHSIG blob.
	var blob []byte
	blob = append(blob, []byte("SSHSIG")...)
	var verBuf [4]byte
	binary.BigEndian.PutUint32(verBuf[:], 1)
	blob = append(blob, verBuf[:]...)
	blob = appendSSHString(blob, pubKeyWire)
	blob = appendSSHString(blob, []byte(namespace))
	blob = appendSSHString(blob, []byte(""))
	blob = appendSSHString(blob, []byte(hashAlgorithm))
	blob = appendSSHString(blob, sigStruct)

	armored := "-----BEGIN SSH SIGNATURE-----\n" +
		base64.StdEncoding.EncodeToString(blob) +
		"\n-----END SSH SIGNATURE-----"
	return armored, nil
}

// (Compile-time sanity check: ssh.PublicKey.Marshal is the
// reference for byte-equality public-key comparison.)
var _ = ssh.MarshalAuthorizedKey

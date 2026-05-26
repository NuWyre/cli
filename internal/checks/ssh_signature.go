package checks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nuwyre/cli/internal/keys"
)

// SSH signature verification for git anchor commits. Phase 4
// dedicated SSH signature session.
//
// Implements the OpenSSH SSHSIG protocol (PROTOCOL.sshsig in the
// OpenSSH source) for verifying SSH-signed git commits. Used by
// check 7's anchored cross-check to validate the signature on
// commits to the anchor repo against pinned SSH issuer keys.
//
// **Why hand-rolled** (Tenant 4 simplicity): golang.org/x/crypto/ssh
// provides primitives (PublicKey.Verify, FingerprintSHA256, wire-
// format Marshal/Unmarshal) but no built-in SSHSIG parser. The
// protocol is well-defined in ~150 lines; adding a third-party
// SSHSIG dependency for that surface is over-engineered. The
// parser uses x/crypto/ssh's wire-format primitives where
// applicable + crypto/ed25519 stdlib for the actual signature
// verification.
//
// **SSHSIG protocol summary** (per OpenSSH PROTOCOL.sshsig):
//
//	Armored SSHSIG blob (in commit's gpgsig header):
//	  -----BEGIN SSH SIGNATURE-----
//	  base64-encoded SSHSIG_BINARY
//	  -----END SSH SIGNATURE-----
//
//	SSHSIG_BINARY:
//	  byte[6]    "SSHSIG"
//	  uint32     version (1)
//	  string     publickey         (SSH wire format)
//	  string     namespace         (e.g., "git" for git commits)
//	  string     reserved          (typically empty)
//	  string     hash_algorithm    (e.g., "sha256", "sha512")
//	  string     signature         (SSH wire format signature struct)
//
//	Signing input (what's actually signed):
//	  byte[6]    "SSHSIG"
//	  string     namespace
//	  string     reserved
//	  string     hash_algorithm
//	  string     H(message)         (hash of payload bytes)
//
// **GitHub API integration**: GitHub exposes both
// `verification.signature` (the armored SSHSIG blob) AND
// `verification.payload` (the raw bytes that were signed — for git
// commits, this is the canonical commit object minus the gpgsig
// header). The verifier consumes both directly without
// reconstructing canonical commit form, eliminating an entire
// canonicalization-drift surface.
//
// **Five-tenant attribution:**
//   - Tenant 1: implementation outlasts library version + git
//     version + key rotation; the SSHSIG protocol is stable.
//   - Tenant 2: parseSafe wrappers per D2's library-boundary
//     discipline; every ssh.* call wrapped.
//   - Tenant 3: pinned-key-only (no system trust); fail-secure on
//     every ambiguous state; no bypass paths.
//   - Tenant 4: hand-rolled parser ~150 lines vs third-party
//     dependency; cross-language reproducibility.
//   - Tenant 5: signer fingerprint surfaced per anchored
//     verification for forensic transparency.

// SSHVerdict is the per-commit SSH signature verification outcome.
type SSHVerdict int

const (
	// SSHValid — signature parses, embedded public key matches the
	// pinned issuer SSH key, signature verifies over the payload.
	SSHValid SSHVerdict = iota
	// SSHInvalid — at least one verification step failed.
	// ErrorReason names the specific failure for forensic debugging.
	SSHInvalid
)

// SSHVerifyResult is the structured verdict for one commit's SSH
// signature verification. Carries enough information for check 7's
// anchored path to surface SSH verification status in operator
// output (Tenant 5 transparency).
type SSHVerifyResult struct {
	// Verdict is SSHValid or SSHInvalid.
	Verdict SSHVerdict
	// ErrorReason is populated on SSHInvalid; empty on SSHValid.
	// Forensic-debugging-grade: names the specific failed step
	// (armored decode, SSHSIG parse, public key mismatch,
	// signature verify) and the underlying error.
	ErrorReason string
	// SignerKeyFingerprint is the SHA-256 fingerprint of the
	// embedded public key (the key that actually signed the
	// commit). Populated on SSHValid. Format matches OpenSSH's
	// `ssh-keygen -lf` output: "SHA256:<base64-sha256>".
	SignerKeyFingerprint string
}

// SSHSignatureVerifier verifies SSH signatures on git commits
// against a pinned SSH issuer key. Constructed per check 7 anchored
// invocation with the issuer key dispatched by bundle_type.
type SSHSignatureVerifier struct {
	pinnedKey *keys.SSHIssuerKey
}

// NewSSHSignatureVerifier constructs a verifier with the given
// pinned SSH issuer key. The key's AuthorizedKeyFormat is parsed
// once at first VerifyCommit call (lazy parse with caching would
// require synchronization; eager parse at construction is simpler
// per Tenant 4).
func NewSSHSignatureVerifier(pinnedKey *keys.SSHIssuerKey) *SSHSignatureVerifier {
	return &SSHSignatureVerifier{pinnedKey: pinnedKey}
}

// VerifyCommit verifies an armored SSHSIG signature on signed
// payload bytes against the pinned issuer SSH key. Returns
// SSHVerifyResult with the verdict + forensic detail.
//
// armoredSig: the "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH
// SIGNATURE-----\n" string from GitHub API's verification.signature
// (returned as a UTF-8 string, NOT base64-encoded — the "armored"
// PEM-style wrapper is the format GitHub returns).
//
// payload: the BASE64-DECODED raw bytes that were signed (per
// crypto-integrity reviewer M1 clarification, dedicated SSH session
// commit 1 review: GitHub API's `commit.verification.payload` field
// is itself returned as raw bytes embedded in the JSON response,
// representing the canonical git commit object minus the gpgsig
// header. The check 7 caller passes these bytes through directly;
// no base64 decode at this layer).
//
// **Verification steps:**
//  1. Strip armored markers + base64-decode → SSHSIG binary blob.
//  2. Parse SSHSIG binary blob → version + embedded public key +
//     namespace + hash_algorithm + signature.
//  3. Verify embedded public key matches the pinned issuer SSH key
//     (compare via SSH wire format byte-equality). Defense against
//     cross-issuer forgery: the signature might verify against a
//     non-pinned key, but the pinned-key match check rejects
//     before that point.
//  4. Compute signing input: "SSHSIG" + namespace + reserved +
//     hash_algorithm + H(payload).
//  5. Verify signature against signing input using the embedded
//     public key.
//
// **Library-boundary parseSafe discipline** per D2: every ssh.*
// library call wrapped with parseSafe per D2's recurring pattern.
// The libraries are documented as panic-free in their happy paths
// but parseSafe is cheap insurance against undocumented edge cases
// + future library changes.
func (v *SSHSignatureVerifier) VerifyCommit(armoredSig string, payload []byte) SSHVerifyResult {
	result := SSHVerifyResult{Verdict: SSHInvalid}

	if v.pinnedKey == nil {
		result.ErrorReason = "internal: nil pinned SSH issuer key"
		return result
	}
	if armoredSig == "" {
		result.ErrorReason = "empty SSH signature (commit not SSH-signed)"
		return result
	}
	if len(payload) == 0 {
		result.ErrorReason = "empty signed payload"
		return result
	}

	// 1. Parse pinned key (defense-in-depth: catch placeholder /
	// unparseable pinned values at verify time so the operator
	// gets a clear error rather than silent acceptance).
	pinnedPubKey, err := parsePinnedSSHKey(v.pinnedKey.AuthorizedKeyFormat)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("failed to parse pinned issuer SSH key %q: %v", v.pinnedKey.KeyID, err)
		return result
	}

	// 2. Strip armored markers + base64-decode.
	sigBlob, err := decodeArmoredSSHSig(armoredSig)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("armored SSH signature decode failed: %v", err)
		return result
	}

	// 3. Parse SSHSIG binary blob.
	sshSig, err := parseSSHSigBlob(sigBlob)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("SSHSIG blob parse failed: %v", err)
		return result
	}

	// 4. SSHSIG namespace MUST be "git" (the OpenSSH-defined
	// namespace for git commit signatures). Per the OpenSSH
	// PROTOCOL.sshsig spec: "Namespaces are arbitrary strings...
	// They are not signed but ARE used as inputs to the signature,
	// so the verifier MUST require a particular namespace value to
	// provide cryptographic isolation between different
	// applications."
	//
	// **Cross-protocol replay defense** (crypto-integrity reviewer
	// C1, dedicated SSH session commit 1 review). Without this
	// check, an attacker who has any other SSH-signed message
	// under the same key (e.g., `ssh-keygen -Y sign -n file ...`
	// for a text file) could lift that signature, present it as a
	// "git commit signature" via the GitHub API surface, and the
	// verifier would silently accept. The pinned-key match doesn't
	// help here — the same key can legitimately sign in multiple
	// namespaces, and namespace is the ONLY domain-separation
	// mechanism in SSHSIG.
	const expectedNamespace = "git"
	if sshSig.namespace != expectedNamespace {
		result.ErrorReason = fmt.Sprintf(
			"SSHSIG namespace %q does not match expected git-commit namespace %q (cross-protocol signature replay defense per OpenSSH PROTOCOL.sshsig)",
			sshSig.namespace, expectedNamespace,
		)
		return result
	}

	// 5. Embedded public key MUST match pinned key (cross-issuer
	// forgery defense). Compare via SSH wire format byte-equality
	// — both keys serialize to the same Marshal() output if they're
	// the same key.
	if !embeddedKeyMatchesPinned(sshSig.embeddedPubKey, pinnedPubKey) {
		result.ErrorReason = fmt.Sprintf(
			"signer public key does not match pinned issuer SSH key %q (signed by a different key — cross-issuer forgery OR operator key-rotation timing)",
			v.pinnedKey.KeyID,
		)
		return result
	}

	// 6. Construct signing input + verify signature.
	signingInput, err := buildSSHSigSigningInput(sshSig.namespace, sshSig.hashAlgorithm, payload)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("failed to build SSHSIG signing input: %v", err)
		return result
	}
	if err := verifySSHSignatureSafe(sshSig.embeddedPubKey, signingInput, sshSig.signature); err != nil {
		result.ErrorReason = fmt.Sprintf("signature verification failed: %v", err)
		return result
	}

	// All checks passed. Compute fingerprint for forensic output.
	result.Verdict = SSHValid
	result.SignerKeyFingerprint = ssh.FingerprintSHA256(sshSig.embeddedPubKey)
	return result
}

// =============================================================================
// SSHSIG protocol parsing (hand-rolled per OpenSSH PROTOCOL.sshsig)
// =============================================================================

// parsedSSHSig holds the fields extracted from an SSHSIG binary blob.
type parsedSSHSig struct {
	version        uint32
	embeddedPubKey ssh.PublicKey
	namespace      string
	reserved       string
	hashAlgorithm  string
	signature      *ssh.Signature
}

// decodeArmoredSSHSig strips the "-----BEGIN/END SSH SIGNATURE-----"
// markers + whitespace, then base64-decodes the body to recover the
// SSHSIG binary blob.
func decodeArmoredSSHSig(armored string) ([]byte, error) {
	const beginMarker = "-----BEGIN SSH SIGNATURE-----"
	const endMarker = "-----END SSH SIGNATURE-----"

	startIdx := strings.Index(armored, beginMarker)
	if startIdx < 0 {
		return nil, errors.New("missing BEGIN SSH SIGNATURE marker")
	}
	endIdx := strings.Index(armored, endMarker)
	if endIdx < 0 {
		return nil, errors.New("missing END SSH SIGNATURE marker")
	}
	if endIdx < startIdx {
		return nil, errors.New("END marker appears before BEGIN marker")
	}
	body := armored[startIdx+len(beginMarker) : endIdx]
	// Strip whitespace (newlines, spaces, tabs) — the body's base64
	// is line-wrapped per RFC 7468 / OpenSSH armoring.
	body = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, body)
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return decoded, nil
}

// parseSSHSigBlob parses an SSHSIG binary blob per the OpenSSH
// PROTOCOL.sshsig spec. The blob layout:
//
//	byte[6]   "SSHSIG"
//	uint32    version
//	string    publickey         (SSH wire format)
//	string    namespace
//	string    reserved
//	string    hash_algorithm
//	string    signature         (SSH wire format signature struct)
//
// All ssh.* library calls wrapped in parseSafe per D2 discipline.
func parseSSHSigBlob(blob []byte) (*parsedSSHSig, error) {
	const magicLen = 6
	if len(blob) < magicLen+4 {
		return nil, fmt.Errorf("blob too short (%d bytes; need at least 10 for magic + version)", len(blob))
	}
	if string(blob[:magicLen]) != "SSHSIG" {
		return nil, fmt.Errorf("invalid magic: got %q, want SSHSIG", string(blob[:magicLen]))
	}
	rest := blob[magicLen:]

	// Version
	if len(rest) < 4 {
		return nil, errors.New("truncated: missing version")
	}
	version := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if version != 1 {
		return nil, fmt.Errorf("unsupported SSHSIG version %d (this verifier handles version 1)", version)
	}

	// publickey field (SSH wire format)
	pubkeyBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("read publickey: %w", err)
	}
	embeddedPubKey, err := parseSSHWireFormatPublicKeySafe(pubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded publickey: %w", err)
	}

	// namespace
	namespaceBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("read namespace: %w", err)
	}
	namespace := string(namespaceBytes)

	// reserved (per OpenSSH PROTOCOL.sshsig v1: MUST be empty string).
	// Security-auditor L3 (dedicated SSH session commit 1 review):
	// reject non-empty reserved at parse time so the operator gets
	// a precise diagnostic ("spec violation: reserved field MUST be
	// empty") rather than a downstream signature-verify failure
	// with the generic "signature verification failed" message.
	reservedBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("read reserved: %w", err)
	}
	if len(reservedBytes) != 0 {
		return nil, fmt.Errorf("SSHSIG reserved field MUST be empty per OpenSSH PROTOCOL.sshsig v1 (got %d bytes)", len(reservedBytes))
	}
	reserved := ""

	// hash_algorithm
	hashAlgBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("read hash_algorithm: %w", err)
	}
	hashAlgorithm := string(hashAlgBytes)

	// signature (SSH wire format signature struct)
	sigBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing %d bytes after signature field", len(rest))
	}
	signature, err := parseSSHWireFormatSignatureSafe(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded signature: %w", err)
	}

	return &parsedSSHSig{
		version:        version,
		embeddedPubKey: embeddedPubKey,
		namespace:      namespace,
		reserved:       reserved,
		hashAlgorithm:  hashAlgorithm,
		signature:      signature,
	}, nil
}

// readSSHString reads a length-prefixed string from the SSH wire
// format. Returns (value, remainder, error). Length is uint32 big-
// endian.
func readSSHString(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, fmt.Errorf("truncated: need 4 bytes for length, have %d", len(buf))
	}
	length := binary.BigEndian.Uint32(buf[:4])
	rest := buf[4:]
	if uint32(len(rest)) < length {
		return nil, nil, fmt.Errorf("truncated: declared length %d but only %d bytes remain", length, len(rest))
	}
	return rest[:length], rest[length:], nil
}

// buildSSHSigSigningInput constructs the byte sequence the SSH
// signature actually covers per the SSHSIG spec:
//
//	byte[6]   "SSHSIG"
//	string    namespace
//	string    reserved
//	string    hash_algorithm
//	string    H(message)
//
// Where H is the hash specified by hash_algorithm.
func buildSSHSigSigningInput(namespace, hashAlgorithm string, message []byte) ([]byte, error) {
	var hashed []byte
	switch hashAlgorithm {
	case "sha256":
		h := sha256.Sum256(message)
		hashed = h[:]
	case "sha512":
		h := sha512.Sum512(message)
		hashed = h[:]
	default:
		return nil, fmt.Errorf("unsupported SSHSIG hash algorithm %q (this verifier handles sha256 + sha512)", hashAlgorithm)
	}

	var buf []byte
	buf = append(buf, []byte("SSHSIG")...)
	buf = appendSSHString(buf, []byte(namespace))
	buf = appendSSHString(buf, []byte("")) // reserved (per spec, empty string)
	buf = appendSSHString(buf, []byte(hashAlgorithm))
	buf = appendSSHString(buf, hashed)
	return buf, nil
}

// appendSSHString appends a length-prefixed string (uint32 BE
// length + bytes) to buf and returns the extended slice.
func appendSSHString(buf, s []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, s...)
	return buf
}

// embeddedKeyMatchesPinned reports whether the embedded public key
// in the SSHSIG matches the pinned issuer SSH key. Compares via SSH
// wire format byte-equality (Marshal output). Two keys are the same
// iff they marshal to the same bytes.
//
// Constant-time comparison is unnecessary here: both keys are public
// material, no secret data is being compared.
func embeddedKeyMatchesPinned(embedded, pinned ssh.PublicKey) bool {
	if embedded == nil || pinned == nil {
		return false
	}
	return bytes.Equal(embedded.Marshal(), pinned.Marshal())
}

// =============================================================================
// parseSafe wrappers per D2 library-boundary discipline
// =============================================================================

// parsePinnedSSHKey wraps ssh.ParseAuthorizedKey for the pinned-key
// load path. parseSafe-equivalent: the library is documented as
// panic-free but the wrapper is cheap insurance per D2 calibration.
func parsePinnedSSHKey(authorizedKey string) (pubKey ssh.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			pubKey = nil
			err = fmt.Errorf("ssh.ParseAuthorizedKey panic (likely malformed pinned-key value): %v", r)
		}
	}()
	if authorizedKey == "" {
		return nil, errors.New("empty authorized_key string")
	}
	pubKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(authorizedKey))
	return pubKey, err
}

// parseSSHWireFormatPublicKeySafe wraps ssh.ParsePublicKey with
// parseSafe per D2 library-boundary discipline. ssh.ParsePublicKey
// expects SSH wire format bytes (the same encoding as the body of
// an authorized_keys entry, AFTER the algorithm prefix).
func parseSSHWireFormatPublicKeySafe(wireBytes []byte) (pubKey ssh.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			pubKey = nil
			err = fmt.Errorf("ssh.ParsePublicKey panic (likely malformed wire-format key bytes): %v", r)
		}
	}()
	if len(wireBytes) == 0 {
		return nil, errors.New("empty SSH wire-format public key bytes")
	}
	return ssh.ParsePublicKey(wireBytes)
}

// parseSSHWireFormatSignatureSafe wraps the SSH wire-format
// signature struct unmarshal. The SSH wire format for a signature
// is: string format + string blob; ssh.Unmarshal parses this into
// an ssh.Signature struct.
func parseSSHWireFormatSignatureSafe(wireBytes []byte) (sig *ssh.Signature, err error) {
	defer func() {
		if r := recover(); r != nil {
			sig = nil
			err = fmt.Errorf("ssh.Unmarshal signature panic (likely malformed wire-format signature bytes): %v", r)
		}
	}()
	if len(wireBytes) == 0 {
		return nil, errors.New("empty SSH wire-format signature bytes")
	}
	var parsed ssh.Signature
	if err := ssh.Unmarshal(wireBytes, &parsed); err != nil {
		return nil, fmt.Errorf("ssh.Unmarshal: %w", err)
	}
	// Defense-in-depth: empty Format or Blob indicates a malformed
	// signature even if Unmarshal didn't error.
	if parsed.Format == "" {
		return nil, errors.New("parsed signature has empty Format field")
	}
	if len(parsed.Blob) == 0 {
		return nil, errors.New("parsed signature has empty Blob field")
	}
	return &parsed, nil
}

// verifySSHSignatureSafe wraps ssh.PublicKey.Verify with parseSafe.
// The Verify call internally checks the signature against the
// public key over the data; an unsupported algorithm or malformed
// signature surface as errors (or, in pathological library cases,
// panics).
func verifySSHSignatureSafe(pubKey ssh.PublicKey, data []byte, sig *ssh.Signature) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ssh.PublicKey.Verify panic (likely malformed signature for the key's algorithm): %v", r)
		}
	}()
	if pubKey == nil {
		return errors.New("nil public key")
	}
	if sig == nil {
		return errors.New("nil signature")
	}
	return pubKey.Verify(data, sig)
}

// (Compile-time guard: verify ed25519 stdlib is wired even though
// we delegate to ssh.PublicKey.Verify which uses it internally.
// Touching the import keeps the dependency explicit for readers.)
var _ = ed25519.PublicKeySize

package tsa

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// MaxTSRBytes caps caller-supplied .tsr input. Production TSRs are
// <10 KB (typical: 4-7 KB for the full TimeStampResp envelope with
// embedded certs); the cap accommodates legitimate TSRs with
// significant headroom while foreclosing memory-DoS via a malicious
// bundle that ships a multi-MB .tsr (e.g., zip-bombed from a tiny
// compressed entry). The bundle loader's zip-entry size cap is the
// upstream defense; this is local defense-in-depth at the
// verifier-library boundary.
const MaxTSRBytes = 1 * 1024 * 1024 // 1 MiB

// MaxChainPEMBytes caps caller-supplied chain.pem input. Production
// chains are <15 KB (typical: 4-8 KB for 3-cert chains); 256 KiB
// covers any plausible legitimate chain with massive headroom.
const MaxChainPEMBytes = 256 * 1024

// PairVerdict is the per-{tsr, chain.pem} verification outcome.
type PairVerdict int

const (
	// PairValid — token parses, signature verifies, chain validates
	// against trusted root, TSTInfo.HashedMessage matches expected.
	PairValid PairVerdict = iota
	// PairInvalid — at least one verification step failed. ErrorReason
	// names the specific failure for forensic debugging.
	PairInvalid
)

// PairResult is the structured verdict for one TSA's {tsr, chain.pem}
// pair against an expected hashedMessage. Includes the per-TSA
// metadata (genTime, trust source, signer cert) that check 6's CLI
// output surfaces in operator-readable form AND that check 6 uses
// to enforce spec §11.1's "≥2 of 3 distinct TSAs" requirement
// (distinctness is enforced cert-side, not by trusting the
// caller-supplied tsaName parameter).
type PairResult struct {
	// TSAName is the canonical lowercase TSA identifier (e.g.,
	// "freetsa", "sectigo", "digicert") as supplied by the caller
	// from manifest.anchors.rfc3161[].tsa_name. Used for forensic
	// labeling. Distinctness MUST be cross-checked against
	// SignerCert (see below) — see TSA-name-substitution defense.
	TSAName string
	// Verdict is PairValid or PairInvalid.
	Verdict PairVerdict
	// ErrorReason is populated on PairInvalid; empty on PairValid.
	// Forensic-debugging-grade: names the specific failed step
	// (parse, chain validation, hashedMessage mismatch, signature
	// verify) and the underlying error.
	ErrorReason string
	// GenTime is TSTInfo.genTime; populated on PairValid. Surfaced
	// in CLI output so the operator can confirm the timestamping
	// time aligns with the bundle's stated submission window.
	GenTime time.Time
	// TrustSource is "system" (chain validated via system trust
	// store) or "pinned" (chain validated via pinned TSA roots).
	// Populated on PairValid.
	TrustSource string
	// SignerCert is the TSA's signing certificate extracted from
	// the PKCS#7 SignedData (via PKCS#7.GetOnlySigner — TSRs MUST
	// have exactly one signer). Populated on PairValid. Spec §11.3
	// step 4 requires the signer cert subject CN to include the
	// expected TSA name; check 6 (D3 commit 2) consumes this field
	// to enforce the requirement AND to enforce spec §11.1's
	// distinctness defense by comparing SHA-256(SignerCert.Raw)
	// across pairs (an attacker who substitutes three different
	// tsa_name labels onto copies of the same TSA's TSR + chain.pem
	// would be caught here, where label-trust is replaced with
	// cert-content-trust). Nil on PairInvalid.
	SignerCert *x509.Certificate
}

// VerifyPair verifies one TSA's {tsr, chain.pem} pair against an
// expected hashedMessage (the daily root's root_hash decoded from
// hex to 32 bytes). Performs:
//
//  1. Parse chain.pem → []*x509.Certificate. Caller-supplied PEM
//     bytes; tampered PEM is caught at this step.
//  2. Parse .tsr → *timestamp.Timestamp via timestamp.ParseResponse.
//     The .tsr file as written by NuWyre's stamping pipeline is the
//     full TimeStampResp envelope — ParseResponse unwraps it,
//     enforces PKIStatus = Granted (0), and recursively parses the
//     inner TimeStampToken (PKCS#7), verifying the token's signed-
//     attribute hash + the signature against the embedded signing
//     cert. Tampered TSR is caught at this step.
//  3. Verify TSTInfo.HashAlgorithm == SHA-256 AND
//     TSTInfo.HashedMessage equals expectedHashedMessage
//     (byte-exact). The algorithm check closes a substitution
//     surface where a TSA-issued SHA-512 stamp could happen to
//     echo our 32-byte SHA-256 root as a prefix; bytes.Equal alone
//     would accept it. NuWyre's stamping pipeline submits SHA-256
//     requests exclusively (per packages/integrations/src/rfc3161/),
//     so SHA-256 is the only legitimate algorithm.
//  4. Re-parse .tsr's RawToken (extracted by ParseResponse) via
//     pkcs7.Parse to access PKCS#7 structure (the timestamp library
//     doesn't expose a chain-validating verify entry point); call
//     p7.VerifyWithOpts with our TSAPool's trust + chain.pem as
//     intermediates + EKU constraint. Chain validation per spec §11.
//
// **Chain-validity time** (spec §11.2 + methodology §09: bundles
// remain verifiable indefinitely). Chain validation uses
// CurrentTime = ts.Time (the TSA-asserted timestamp, authenticated
// by the signature check in step 2) — NOT time.Now(). The captured
// chain.pem design exists precisely so that bundles validate against
// the cert validity windows that were live when the TSA stamped,
// not against today's wall clock. Using time.Now() would silently
// fail bundles when their TSA's root expires (e.g., DigiCert G4 in
// ~2042) even though the captured chain remains complete and
// cryptographically valid for the asserted ts.Time. Cryptographic
// guarantee: "the cert chain was valid at the moment the TSA
// asserted it stamped" — that moment is ts.Time, and the assertion
// is trustworthy to the same extent the signature is.
//
// Every library call is wrapped in defer-recover (parseSafe
// discipline from D2). The libraries return errors on most
// malformed inputs, but defense-in-depth covers undocumented edge
// cases + future library changes.
//
// **PKIStatus strictness.** ParseResponse accepts only Granted
// (status = 0); GrantedWithMods (1) is rejected. NuWyre's stamping
// pipeline only stores Granted responses, so this is operationally
// equivalent to the TS-side verifier for production bundles.
func VerifyPair(
	tsrBytes []byte,
	chainPEM []byte,
	expectedHashedMessage []byte,
	tsaName string,
	pool *TSAPool,
) PairResult {
	result := PairResult{TSAName: tsaName, Verdict: PairInvalid}

	if pool == nil {
		result.ErrorReason = "internal error: nil TSAPool"
		return result
	}
	if len(expectedHashedMessage) == 0 {
		result.ErrorReason = "internal error: empty expectedHashedMessage"
		return result
	}
	if len(expectedHashedMessage) != 32 {
		result.ErrorReason = fmt.Sprintf(
			"internal error: expectedHashedMessage must be 32 bytes (SHA-256), got %d",
			len(expectedHashedMessage),
		)
		return result
	}
	if len(tsrBytes) == 0 {
		result.ErrorReason = "empty tsr bytes"
		return result
	}
	if len(tsrBytes) > MaxTSRBytes {
		result.ErrorReason = fmt.Sprintf("tsr exceeds max bytes (%d > %d)", len(tsrBytes), MaxTSRBytes)
		return result
	}
	if len(chainPEM) == 0 {
		result.ErrorReason = "empty chain.pem bytes"
		return result
	}
	if len(chainPEM) > MaxChainPEMBytes {
		result.ErrorReason = fmt.Sprintf("chain.pem exceeds max bytes (%d > %d)", len(chainPEM), MaxChainPEMBytes)
		return result
	}

	// 1. Parse chain.pem.
	chainCerts, err := ParseChainPEM(chainPEM)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("chain.pem parse failed: %v", err)
		return result
	}

	// 2. Parse .tsr (timestamp.ParseResponse unwraps the
	// TimeStampResp envelope, enforces PKIStatus = Granted, then
	// internally calls pkcs7.Parse + pkcs7.Verify with no chain on
	// the inner token — verifying signature against embedded signing
	// cert + signed-attribute hash). Wrap with defer-recover.
	ts, err := parseTimestampSafe(tsrBytes)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("TSR parse / signed-attribute verify failed: %v", err)
		return result
	}

	// 3a. Hash algorithm MUST be SHA-256. Closes the substitution
	// surface where a TSA-issued non-SHA-256 stamp could echo bytes
	// that happen to match (a prefix of) our 32-byte SHA-256 root.
	if ts.HashAlgorithm != crypto.SHA256 {
		result.ErrorReason = fmt.Sprintf(
			"TSTInfo.HashAlgorithm mismatch: TSA used %s, NuWyre stamping uses SHA-256 only",
			ts.HashAlgorithm,
		)
		return result
	}

	// 3b. Verify HashedMessage matches expected (byte-exact). This
	// is the load-bearing claim that THIS TSR was issued for OUR
	// daily root, not some other digest.
	if !bytes.Equal(ts.HashedMessage, expectedHashedMessage) {
		result.ErrorReason = fmt.Sprintf(
			"TSTInfo.HashedMessage mismatch: TSR claims %s, expected %s",
			truncateBytes(ts.HashedMessage, 16),
			truncateBytes(expectedHashedMessage, 16),
		)
		return result
	}

	// 4. Re-parse for chain validation. The timestamp library's
	// ParseResponse already called p7.Verify on the inner token (no
	// chain), so signature is verified. We need to add chain.pem
	// certs as intermediates and validate against our trust pool.
	// Use ts.RawToken (the inner PKCS#7 bytes that ParseResponse
	// extracted from the TimeStampResp envelope) — passing the
	// outer .tsr bytes to pkcs7.Parse would fail the same way as
	// passing them to timestamp.Parse.
	if len(ts.RawToken) == 0 {
		result.ErrorReason = "internal error: parsed Timestamp has empty RawToken"
		return result
	}
	p7, err := parsePKCS7Safe(ts.RawToken)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("PKCS#7 re-parse for chain validation failed: %v", err)
		return result
	}

	// Extract the signing cert. TSRs MUST have exactly one signer
	// (RFC 3161); GetOnlySigner returns nil if Signers count != 1.
	signerCert := p7.GetOnlySigner()
	if signerCert == nil {
		result.ErrorReason = fmt.Sprintf(
			"PKCS#7 has %d signers (TSR MUST have exactly 1)",
			len(p7.Signers),
		)
		return result
	}

	// Build intermediates pool from chain.pem entries. Per
	// ParseChainPEM's trust contract: chain.pem-supplied "roots"
	// remain non-trusted (only opts.Roots = system + pinned are
	// trust anchors); chain.pem provides intermediates that help
	// Go's chain-walking algorithm find the path.
	intermediates := IntermediatesPool(chainCerts)

	// Per pool.VerifyChain's contract: try system trust first, fall
	// through to pinned. We can't directly invoke pool.VerifyChain
	// here because PKCS#7's signing cert is embedded inside the
	// token; pkcs7.VerifyWithOpts handles signing-cert extraction
	// + chain validation in one call. Replicate the system-then-
	// pinned dispatch by trying VerifyWithOpts twice.
	//
	// CurrentTime = ts.Time per spec §11.2 indefinite-verifiability
	// (see function-level doc).
	currentTime := ts.Time

	systemErr := verifyPKCS7ChainSafe(p7, x509.VerifyOptions{
		Roots:         pool.systemPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime:   currentTime,
	})
	if systemErr == nil {
		// Chain validated against system trust.
		result.Verdict = PairValid
		result.GenTime = ts.Time
		result.TrustSource = "system"
		result.SignerCert = signerCert
		return result
	}

	pinnedErr := verifyPKCS7ChainSafe(p7, x509.VerifyOptions{
		Roots:         pool.pinnedPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime:   currentTime,
	})
	if pinnedErr == nil {
		// Chain validated against pinned trust.
		result.Verdict = PairValid
		result.GenTime = ts.Time
		result.TrustSource = "pinned"
		result.SignerCert = signerCert
		return result
	}

	// Both failed. Surface the pinned-pool error (more useful
	// diagnostically — system pool may simply not have the TSA's
	// root, while pinned is our own curated set). Distinguish
	// expired-root for forensic clarity.
	if IsExpiredRootError(pinnedErr) {
		result.ErrorReason = fmt.Sprintf(
			"chain validation failed at ts.Time=%s: root certificate expired; chain no longer validates against pinned trust at TSA-asserted time: %v",
			ts.Time.Format(time.RFC3339), pinnedErr,
		)
	} else {
		result.ErrorReason = fmt.Sprintf(
			"chain validation failed at ts.Time=%s against both system trust and pinned TSA roots: %v",
			ts.Time.Format(time.RFC3339), pinnedErr,
		)
	}
	return result
}

// parseTimestampSafe wraps timestamp.ParseResponse with defer-
// recover. ParseResponse expects the full TimeStampResp envelope
// (what NuWyre's stamping pipeline writes to .tsr files), unwraps
// it, enforces PKIStatus = Granted, and parses the inner
// TimeStampToken. The digitorus/timestamp library is more
// disciplined than nbd-wtf/opentimestamps (no panic calls in
// production code per audit) but the wrapper is cheap insurance
// per D2 calibration.
func parseTimestampSafe(tsrBytes []byte) (ts *timestamp.Timestamp, err error) {
	defer func() {
		if r := recover(); r != nil {
			ts = nil
			err = fmt.Errorf("digitorus/timestamp ParseResponse panic (likely malformed TimeStampResp / TSTInfo): %v", r)
		}
	}()
	if len(tsrBytes) == 0 {
		return nil, errors.New("empty tsr bytes")
	}
	return timestamp.ParseResponse(tsrBytes)
}

// parsePKCS7Safe wraps pkcs7.Parse with defer-recover. Same
// discipline as parseTimestampSafe.
func parsePKCS7Safe(tokenBytes []byte) (p7 *pkcs7.PKCS7, err error) {
	defer func() {
		if r := recover(); r != nil {
			p7 = nil
			err = fmt.Errorf("digitorus/pkcs7 Parse panic (likely malformed PKCS#7 structure): %v", r)
		}
	}()
	if len(tokenBytes) == 0 {
		return nil, errors.New("empty token bytes")
	}
	return pkcs7.Parse(tokenBytes)
}

// verifyPKCS7ChainSafe wraps p7.VerifyWithOpts with defer-recover.
// VerifyWithOpts internally calls cert.Verify (Go stdlib, panic-
// free) but the wrapper covers the library's pre-/post-processing.
func verifyPKCS7ChainSafe(p7 *pkcs7.PKCS7, opts x509.VerifyOptions) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("digitorus/pkcs7 VerifyWithOpts panic (likely malformed signer info): %v", r)
		}
	}()
	if p7 == nil {
		return errors.New("nil PKCS7")
	}
	return p7.VerifyWithOpts(opts)
}

// truncateBytes formats up to n bytes of b as hex. Returns the full
// hex string when n >= len(b); otherwise returns the first n bytes
// hex-encoded with a trailing "…" to indicate truncation. Used for
// diagnostic error messages where full hex would be unreadably
// long.
func truncateBytes(b []byte, n int) string {
	if n < 0 {
		n = 0
	}
	if n >= len(b) {
		return fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("%x…", b[:n])
}

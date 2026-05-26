// Package tsa implements RFC 3161 timestamp token verification for
// the Phase 4 verification CLI. Per build plan v3.1.11 §Phase 4 Step
// 4 check 6 + spec §11: each .tsr in the bundle is paired with its
// .chain.pem (full PEM-encoded chain captured at stamping time per
// build plan v3.1.2). Verification chains the token's signing
// certificate up through its embedded chain to a publicly-known
// root CA — system trust store first, falling back to pinned roots
// in internal/keys/. ≥2 of 3 distinct TSAs MUST produce verifying
// {token, chain} pairs per daily root.
//
// **Trust model.** Only roots in the system trust store OR
// internal/keys/PinnedTSARoots are trusted. Chain.pem entries are
// added as INTERMEDIATES only — never as roots. A bundle whose
// chain.pem includes an attacker-controlled root cert MUST fail
// verification because that root is not in either trusted pool.
//
// **Library boundary** (Phase 4 Session 3 D3, post-D2 calibration):
// every digitorus/timestamp + digitorus/pkcs7 + crypto/x509 library
// call is wrapped in parseSafe. The libraries return errors on most
// malformed inputs (better-disciplined than nbd-wtf/opentimestamps),
// but parseSafe is cheap insurance against undocumented edge cases
// + future library changes that could introduce panics.
package tsa

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/nuwyre/cli/internal/keys"
)

// MaxChainCerts caps the number of certificates ParseChainPEM will
// return from a single chain.pem document. Production TSA chains
// have 2-4 certs (signing cert + 1-2 intermediates + root); 100 is
// a generous upper bound that forecloses memory-DoS via a malicious
// chain.pem packed with thousands of CERTIFICATE blocks. Working in
// concert with verifier.go's MaxChainPEMBytes byte cap.
const MaxChainCerts = 100

// TSAPool wraps the layered trust resolution: try system trust store
// first, fall through to pinned TSA roots (FreeTSA, Sectigo current,
// DigiCert per Session 1 D2). The order matters — system trust is
// preferred so verifier behavior aligns with what a third-party
// reviewer would see using their OS's standard trust set; pinned
// CAs cover the case where a TSA's root isn't in the user's system
// store (e.g., FreeTSA's self-signed root, or older Sectigo roots
// that some distros haven't shipped).
type TSAPool struct {
	systemPool *x509.CertPool
	pinnedPool *x509.CertPool
}

// NewTSAPool constructs a pool with system + pinned trust. Returns
// an error if pinned roots fail to load — fail-secure: a partial
// pool (system only, no pinned fallback) would silently reject TSA
// chains whose roots production stamping uses, producing false
// negatives that look like tampering. Better to fail loudly at
// construction.
//
// System trust unavailability (e.g., minimal containers without
// /etc/ssl/certs) is non-fatal: the system pool degrades to empty,
// and verification falls through to the pinned pool.
func NewTSAPool() (*TSAPool, error) {
	sysPool, err := x509.SystemCertPool()
	if err != nil || sysPool == nil {
		// System trust store unavailable — degrade to empty.
		// Verification will rely on pinned pool only.
		sysPool = x509.NewCertPool()
	}

	pinnedPool := x509.NewCertPool()
	for _, root := range keys.PinnedTSARoots {
		if !pinnedPool.AppendCertsFromPEM(root.PEMBytes) {
			return nil, fmt.Errorf("failed to add pinned TSA root %q to pool (PEM may be malformed)", root.RootName)
		}
	}

	return &TSAPool{
		systemPool: sysPool,
		pinnedPool: pinnedPool,
	}, nil
}

// VerifyChain verifies signingCert chains to a trusted root, trying
// the system pool first then the pinned pool. Returns the trust
// source ("system" | "pinned") on success. On failure, returns the
// underlying x509 error from the second (pinned-pool) attempt with
// an annotation that both pools were tried.
//
// **EKU constraint** (TimeStamping). The verifier requires the
// signing cert chain to be authorized for x509.ExtKeyUsageTimeStamping;
// a chain authorized only for ServerAuth or EmailProtection MUST
// fail. Production TSAs always issue their signing certs with the
// TimeStamping EKU; this guard catches a malicious bundle that
// substitutes a non-TSA cert.
//
// **currentTime** is caller-supplied. Per spec §11.2 indefinite-
// verifiability + methodology §09 (bundles MUST remain verifiable
// after NuWyre disappears), production callers pass ts.Time (the
// TSA-asserted timestamp authenticated by the TSR signature),
// NOT time.Now(). The captured chain.pem design exists precisely
// so that a 2026 bundle still validates in 2042 against the 2026
// cert validity windows. Tests inject deterministic values.
// Cryptographic property: "the cert chain was valid at the moment
// the TSA asserted it stamped" — that moment is ts.Time.
func (p *TSAPool) VerifyChain(
	signingCert *x509.Certificate,
	intermediates *x509.CertPool,
	currentTime time.Time,
) (trustSource string, err error) {
	// parseSafe-equivalent: x509.Certificate.Verify is stdlib + does
	// not panic on malformed input (returns error). But wrapping is
	// cheap insurance per D2 calibration discipline.
	defer func() {
		if r := recover(); r != nil {
			trustSource = ""
			err = fmt.Errorf("crypto/x509 Verify panic (likely malformed cert): %v", r)
		}
	}()

	systemOpts := x509.VerifyOptions{
		Roots:         p.systemPool,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, sysErr := signingCert.Verify(systemOpts); sysErr == nil {
		return "system", nil
	}

	pinnedOpts := x509.VerifyOptions{
		Roots:         p.pinnedPool,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, pinErr := signingCert.Verify(pinnedOpts); pinErr == nil {
		return "pinned", nil
	} else {
		// Annotate that both pools were attempted. The pinned-pool
		// error is more useful diagnostically since it's the
		// fallback — if pinned fails, the verifier doesn't know
		// the root.
		return "", fmt.Errorf("chain validation failed against both system trust and pinned TSA roots: %w", pinErr)
	}
}

// IsExpiredRootError reports whether err indicates the chain's root
// or intermediate certificate has expired (rather than another kind
// of chain validation failure like missing intermediate, wrong EKU,
// or signature mismatch). Used by callers to surface the
// expired-specific error message ("chain's root certificate
// expired; chain no longer validates against current trust") which
// is forensically distinct from generic chain-validation failures.
func IsExpiredRootError(err error) bool {
	if err == nil {
		return false
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return invalidErr.Reason == x509.Expired
	}
	return false
}

// ParseChainPEM splits the .chain.pem bytes into certificates.
// Returns the FULL list — caller decides which are intermediates
// vs leaf. Per spec §11.2 (chain.pem captured at stamping time),
// the .chain.pem typically contains [intermediate(s), root] OR
// [signing cert, intermediate(s), root] depending on TSA. Caller
// adds all to intermediates pool; the root is also a member of
// the trusted pool (if it's in system or pinned), so x509.Verify
// finds it via opts.Roots regardless of also being in
// intermediates.
//
// **Trust contract.** Even though chain.pem certs go into the
// intermediates pool, the chain validation uses opts.Roots
// (system + pinned) as the trust anchor. A chain.pem-supplied
// "root" that isn't in either trusted pool will NOT be trusted
// — Go's x509.Verify only walks up to roots in opts.Roots, never
// to intermediates-pool entries.
func ParseChainPEM(chainPEM []byte) (certs []*x509.Certificate, err error) {
	defer func() {
		if r := recover(); r != nil {
			certs = nil
			err = fmt.Errorf("PEM/x509 parse panic (likely malformed chain.pem): %v", r)
		}
	}()

	rest := chainPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// Skip non-certificate blocks (some chain.pem files have
			// PRIVATE KEY or other blocks; chain validation only
			// cares about certs).
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("chain.pem certificate parse failed at block %d: %w", len(certs)+1, parseErr)
		}
		certs = append(certs, cert)
		if len(certs) > MaxChainCerts {
			return nil, fmt.Errorf("chain.pem has more than %d CERTIFICATE blocks (likely malformed/malicious)", MaxChainCerts)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("chain.pem has no CERTIFICATE blocks")
	}
	return certs, nil
}

// IntermediatesPool builds an x509.CertPool containing all
// chain.pem entries. Caller passes this as opts.Intermediates to
// x509.Verify. Per ParseChainPEM's contract, chain.pem-supplied
// "roots" remain non-trusted (they're not in opts.Roots) but their
// presence in the intermediates pool helps Go's chain-walking
// algorithm find the path from the signing cert to the trusted
// root.
func IntermediatesPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

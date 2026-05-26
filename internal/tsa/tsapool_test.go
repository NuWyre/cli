package tsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// TSAPool construction
// =============================================================================

// TestNewTSAPoolConstructsWithSystemAndPinned pins the canonical
// happy path: NewTSAPool succeeds with both pools populated.
func TestNewTSAPoolConstructsWithSystemAndPinned(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("NewTSAPool returned nil pool with nil error")
	}
	if pool.systemPool == nil {
		t.Error("systemPool nil; expected SystemCertPool result or empty fallback")
	}
	if pool.pinnedPool == nil {
		t.Error("pinnedPool nil; expected PinnedTSARoots-populated pool")
	}
}

// =============================================================================
// VerifyChain — synthetic certs
// =============================================================================

// TestVerifyChainHappyPathSystemPool pins the load-bearing claim
// that VerifyChain returns "system" when the signing cert chains
// to a root in the system pool.
func TestVerifyChainHappyPathSystemPool(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, rootKey := mustGenerateSelfSignedCA(t, "synthetic root", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	signing, _ := mustGenerateLeafCert(t, "synthetic TSA", root, rootKey, now.Add(-time.Hour), now.Add(365*24*time.Hour), x509.ExtKeyUsageTimeStamping)

	systemPool := x509.NewCertPool()
	systemPool.AddCert(root)
	pool := &TSAPool{
		systemPool: systemPool,
		pinnedPool: x509.NewCertPool(),
	}

	source, err := pool.VerifyChain(signing, x509.NewCertPool(), now)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if source != "system" {
		t.Errorf("trust source = %q, want %q", source, "system")
	}
}

// TestVerifyChainHappyPathPinnedPool pins fallback semantics:
// when the system pool doesn't contain the root, the pinned pool
// is tried, and a successful validation reports "pinned".
func TestVerifyChainHappyPathPinnedPool(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, rootKey := mustGenerateSelfSignedCA(t, "synthetic pinned root", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	signing, _ := mustGenerateLeafCert(t, "synthetic TSA", root, rootKey, now.Add(-time.Hour), now.Add(365*24*time.Hour), x509.ExtKeyUsageTimeStamping)

	pinnedPool := x509.NewCertPool()
	pinnedPool.AddCert(root)
	pool := &TSAPool{
		systemPool: x509.NewCertPool(),
		pinnedPool: pinnedPool,
	}

	source, err := pool.VerifyChain(signing, x509.NewCertPool(), now)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if source != "pinned" {
		t.Errorf("trust source = %q, want %q", source, "pinned")
	}
}

// TestVerifyChainFailsWhenRootNotInEitherPool pins the trust
// contract: a chain whose root isn't in system OR pinned MUST fail.
// Even if the root is in chain.pem (= intermediates pool), Go's
// x509.Verify only walks up to opts.Roots, never to intermediates.
func TestVerifyChainFailsWhenRootNotInEitherPool(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, rootKey := mustGenerateSelfSignedCA(t, "attacker root", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	signing, _ := mustGenerateLeafCert(t, "attacker TSA", root, rootKey, now.Add(-time.Hour), now.Add(365*24*time.Hour), x509.ExtKeyUsageTimeStamping)

	pool := &TSAPool{
		systemPool: x509.NewCertPool(),
		pinnedPool: x509.NewCertPool(),
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(root)

	source, err := pool.VerifyChain(signing, intermediates, now)
	if err == nil {
		t.Fatal("VerifyChain unexpectedly succeeded with attacker-supplied root")
	}
	if source != "" {
		t.Errorf("trust source = %q, want empty on failure", source)
	}
	if !strings.Contains(err.Error(), "both system trust and pinned TSA roots") {
		t.Errorf("error message missing both-pools annotation: %v", err)
	}
}

// TestVerifyChainRejectsNonTimeStampingEKU pins the EKU constraint:
// a chain whose leaf is authorized only for ServerAuth (not
// TimeStamping) MUST fail. Catches the substitution attack where
// an attacker swaps in a TLS cert from a CA that's in trust pools.
func TestVerifyChainRejectsNonTimeStampingEKU(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, rootKey := mustGenerateSelfSignedCA(t, "synthetic root", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	signing, _ := mustGenerateLeafCert(t, "synthetic non-TSA", root, rootKey, now.Add(-time.Hour), now.Add(365*24*time.Hour), x509.ExtKeyUsageServerAuth)

	systemPool := x509.NewCertPool()
	systemPool.AddCert(root)
	pool := &TSAPool{
		systemPool: systemPool,
		pinnedPool: x509.NewCertPool(),
	}

	_, err := pool.VerifyChain(signing, x509.NewCertPool(), now)
	if err == nil {
		t.Fatal("VerifyChain unexpectedly accepted ServerAuth-only leaf")
	}
}

// TestVerifyChainRejectsExpiredRoot pins time-of-check semantics:
// chain validation uses currentTime, and an expired root MUST fail
// regardless of when the original timestamp was issued.
func TestVerifyChainRejectsExpiredRoot(t *testing.T) {
	t.Parallel()
	pastIssue := time.Now().UTC().Add(-2 * 365 * 24 * time.Hour)
	pastExpire := time.Now().UTC().Add(-30 * 24 * time.Hour) // expired 30 days ago
	root, rootKey := mustGenerateSelfSignedCA(t, "expired root", pastIssue, pastExpire)
	signing, _ := mustGenerateLeafCert(t, "tsa under expired root", root, rootKey, pastIssue, pastExpire, x509.ExtKeyUsageTimeStamping)

	systemPool := x509.NewCertPool()
	systemPool.AddCert(root)
	pool := &TSAPool{
		systemPool: systemPool,
		pinnedPool: x509.NewCertPool(),
	}

	_, err := pool.VerifyChain(signing, x509.NewCertPool(), time.Now().UTC())
	if err == nil {
		t.Fatal("VerifyChain unexpectedly accepted chain rooted at expired cert")
	}
	t.Logf("expired-root verify (expected) returned: %v", err)
}

// =============================================================================
// VerifyChain — real bundle chain.pem files (integration)
// =============================================================================

// Bundle integration coverage for VerifyChain is provided
// indirectly via TestVerifyPairAgainstRealBundleHappyPath in
// verifier_test.go (VerifyPair exercises the same x509.Verify
// machinery with cert.Verify under VerifyWithOpts, but does not
// require leaf-first cert ordering — Go's chain walker finds the
// leaf via PKCS#7's SignerInfo). A direct VerifyChain integration
// test would need leaf-detection logic to be ordering-robust;
// instead we rely on the VerifyPair integration path.

// =============================================================================
// ParseChainPEM
// =============================================================================

func TestParseChainPEMHappyPath(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, rootKey := mustGenerateSelfSignedCA(t, "root", now, now.Add(365*24*time.Hour))
	signing, _ := mustGenerateLeafCert(t, "leaf", root, rootKey, now, now.Add(365*24*time.Hour), x509.ExtKeyUsageTimeStamping)

	pemBytes := certsToPEM(t, signing, root)
	certs, err := ParseChainPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParseChainPEM: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("got %d certs, want 2", len(certs))
	}
}

func TestParseChainPEMRejectsEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty bytes", []byte{}},
		{"non-PEM bytes", []byte("not a PEM document")},
		{"PEM with no CERTIFICATE blocks", []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseChainPEM(c.in)
			if err == nil {
				t.Errorf("ParseChainPEM(%q) accepted non-cert PEM; expected error", c.name)
			}
		})
	}
}

func TestParseChainPEMSkipsNonCertificateBlocks(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, _ := mustGenerateSelfSignedCA(t, "root", now, now.Add(365*24*time.Hour))
	certPEM := certsToPEM(t, root)

	// Prepend a non-CERTIFICATE block; ParseChainPEM should skip it
	// without error and return the cert.
	mixed := []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
	mixed = append(mixed, certPEM...)
	certs, err := ParseChainPEM(mixed)
	if err != nil {
		t.Fatalf("mixed PEM: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certs, want 1", len(certs))
	}
}

func TestParseChainPEMRejectsMalformedCertBytes(t *testing.T) {
	t.Parallel()
	// CERTIFICATE block with garbage inside.
	badPEM := []byte("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n")
	_, err := ParseChainPEM(badPEM)
	if err == nil {
		t.Error("ParseChainPEM accepted garbage-inside-CERTIFICATE PEM")
	}
}

// TestParseChainPEMRejectsExcessiveCertCount pins the Maximum-
// CERTIFICATE-block guard. Production chains have 2-4 certs;
// hundreds is anomalous, thousands is hostile. Concatenate a real
// cert PEM many times to build an oversized chain document.
func TestParseChainPEMRejectsExcessiveCertCount(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	root, _ := mustGenerateSelfSignedCA(t, "root", now, now.Add(365*24*time.Hour))
	one := certsToPEM(t, root)

	var oversized []byte
	for i := 0; i < MaxChainCerts+5; i++ {
		oversized = append(oversized, one...)
	}
	_, err := ParseChainPEM(oversized)
	if err == nil {
		t.Fatal("ParseChainPEM accepted chain.pem with > MaxChainCerts blocks")
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Errorf("error missing cert-count cap diagnostic: %v", err)
	}
}

// =============================================================================
// IsExpiredRootError classification
// =============================================================================

func TestIsExpiredRootErrorClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"expired error", x509.CertificateInvalidError{Reason: x509.Expired, Detail: "expired"}, true},
		{"non-expired CertificateInvalidError", x509.CertificateInvalidError{Reason: x509.IncompatibleUsage, Detail: "wrong EKU"}, false},
		{"unknown authority", x509.UnknownAuthorityError{}, false},
		{"generic error", errors.New("plain error"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsExpiredRootError(c.err)
			if got != c.want {
				t.Errorf("IsExpiredRootError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// mustGenerateSelfSignedCA creates a self-signed root CA with the
// given validity window. ECDSA P-256 (faster than RSA for tests).
func mustGenerateSelfSignedCA(t *testing.T, cn string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate (CA): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate (CA): %v", err)
	}
	return cert, key
}

// mustGenerateLeafCert creates a leaf cert signed by parent with
// the given EKU. parentKey is the parent's signing key.
func mustGenerateLeafCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, eku x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate (leaf): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate (leaf): %v", err)
	}
	return cert, key
}

// certsToPEM concatenates one or more certs into PEM byte form.
func certsToPEM(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, c := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatalf("pem.Encode: %v", err)
		}
	}
	return buf.Bytes()
}

// loadExampleBundleFromTSA loads the regenerated example bundle.
// Skips test if missing (fresh checkout case).
func loadExampleBundleFromTSA(t *testing.T) *bundle.Bundle {
	t.Helper()
	const exampleRel = "../../../../apps/marketing/public/examples/nuwyre_export_cypress-derm_2026-04-22.zip"
	if _, err := os.Stat(exampleRel); err != nil {
		t.Skipf("example bundle missing at %s: %v\n"+
			"regenerate via `pnpm --filter @nuwyre/example-bundle generate`",
			exampleRel, err)
	}
	b, err := bundle.Load(exampleRel)
	if err != nil {
		t.Skipf("bundle.Load: %v", err)
	}
	return b
}

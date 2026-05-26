package tsa

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// =============================================================================
// VerifyPair — argument validation (defensive)
// =============================================================================

func TestVerifyPairRejectsNilPool(t *testing.T) {
	t.Parallel()
	r := VerifyPair([]byte{0x30, 0x00}, []byte("dummy"), bytes.Repeat([]byte{0xab}, 32), "test", nil)
	if r.Verdict != PairInvalid {
		t.Errorf("Verdict = %v, want PairInvalid for nil pool", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "nil TSAPool") {
		t.Errorf("ErrorReason missing nil-pool diagnostic: %q", r.ErrorReason)
	}
	if r.TSAName != "test" {
		t.Errorf("TSAName = %q, want %q", r.TSAName, "test")
	}
}

func TestVerifyPairRejectsEmptyExpectedHashedMessage(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	r := VerifyPair([]byte{0x30, 0x00}, []byte("dummy"), nil, "test", pool)
	if r.Verdict != PairInvalid {
		t.Errorf("Verdict = %v, want PairInvalid for empty hashedMessage", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "empty expectedHashedMessage") {
		t.Errorf("ErrorReason missing empty-hash diagnostic: %q", r.ErrorReason)
	}
}

func TestVerifyPairRejectsNon32ByteExpectedHashedMessage(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	cases := []struct {
		name string
		hash []byte
	}{
		{"16 bytes (SHA-1)", bytes.Repeat([]byte{0xab}, 16)},
		{"20 bytes", bytes.Repeat([]byte{0xab}, 20)},
		{"31 bytes (one short)", bytes.Repeat([]byte{0xab}, 31)},
		{"33 bytes (one over)", bytes.Repeat([]byte{0xab}, 33)},
		{"64 bytes (SHA-512)", bytes.Repeat([]byte{0xab}, 64)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := VerifyPair([]byte{0x30, 0x00}, []byte("dummy"), c.hash, "test", pool)
			if r.Verdict != PairInvalid {
				t.Errorf("Verdict = %v, want PairInvalid", r.Verdict)
			}
			if !strings.Contains(r.ErrorReason, "must be 32 bytes") {
				t.Errorf("ErrorReason missing 32-byte diagnostic: %q", r.ErrorReason)
			}
		})
	}
}

func TestVerifyPairRejectsEmptyTSR(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	r := VerifyPair(nil, []byte("dummy"), bytes.Repeat([]byte{0xab}, 32), "test", pool)
	if r.Verdict != PairInvalid {
		t.Errorf("Verdict = %v, want PairInvalid for nil tsr", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "empty tsr") {
		t.Errorf("ErrorReason missing empty-tsr diagnostic: %q", r.ErrorReason)
	}
}

func TestVerifyPairRejectsEmptyChainPEM(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	r := VerifyPair([]byte{0x30, 0x00}, nil, bytes.Repeat([]byte{0xab}, 32), "test", pool)
	if r.Verdict != PairInvalid {
		t.Errorf("Verdict = %v, want PairInvalid for nil chain.pem", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "empty chain.pem") {
		t.Errorf("ErrorReason missing empty-chain diagnostic: %q", r.ErrorReason)
	}
}

func TestVerifyPairRejectsOversizedInputs(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	hash := bytes.Repeat([]byte{0xab}, 32)

	t.Run("oversized tsr", func(t *testing.T) {
		oversized := make([]byte, MaxTSRBytes+1)
		r := VerifyPair(oversized, []byte("dummy"), hash, "test", pool)
		if r.Verdict != PairInvalid {
			t.Errorf("Verdict = %v, want PairInvalid", r.Verdict)
		}
		if !strings.Contains(r.ErrorReason, "tsr exceeds max bytes") {
			t.Errorf("ErrorReason missing tsr-cap diagnostic: %q", r.ErrorReason)
		}
	})
	t.Run("oversized chain.pem", func(t *testing.T) {
		oversized := make([]byte, MaxChainPEMBytes+1)
		r := VerifyPair([]byte{0x30, 0x00}, oversized, hash, "test", pool)
		if r.Verdict != PairInvalid {
			t.Errorf("Verdict = %v, want PairInvalid", r.Verdict)
		}
		if !strings.Contains(r.ErrorReason, "chain.pem exceeds max bytes") {
			t.Errorf("ErrorReason missing chain-cap diagnostic: %q", r.ErrorReason)
		}
	})
}

// =============================================================================
// VerifyPair — parseSafe coverage (library boundary defenses)
//
// Per Phase 4 Session 2 D2 calibration C1: every library-call site
// must be exercised at least once with malformed input so the
// defer-recover wrappers actually run. These tests don't expect
// panics — they expect "library returned an error, wrapped, surfaced
// as ErrorReason" — but if any future library change introduces a
// panic, these are the canaries.
// =============================================================================

func TestVerifyPairChainPEMParseFailureIsReported(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	r := VerifyPair(
		[]byte{0x30, 0x00},
		[]byte("not a PEM document at all"),
		bytes.Repeat([]byte{0xab}, 32),
		"test",
		pool,
	)
	if r.Verdict != PairInvalid {
		t.Errorf("Verdict = %v, want PairInvalid for malformed chain.pem", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "chain.pem parse failed") {
		t.Errorf("ErrorReason missing chain-parse diagnostic: %q", r.ErrorReason)
	}
}

func TestVerifyPairTSRParseFailureIsReported(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	// Use real chain.pem so we get past step 1, then garbage TSR.
	chainPEM := loadAnyChainPEM(t)
	r := VerifyPair(
		[]byte("garbage tsr bytes - not ASN.1 at all"),
		chainPEM,
		bytes.Repeat([]byte{0xab}, 32),
		"test",
		pool,
	)
	if r.Verdict != PairInvalid {
		t.Errorf("Verdict = %v, want PairInvalid for malformed TSR", r.Verdict)
	}
	if !strings.Contains(r.ErrorReason, "TSR parse") {
		t.Errorf("ErrorReason missing TSR-parse diagnostic: %q", r.ErrorReason)
	}
}

// TestVerifyPairTSRParseDoesNotPanicOnRandomBytes is the parseSafe
// canary: feeds raw bytes that are most likely to trip a library
// panic if defer-recover were absent. The test asserts the outer
// process doesn't crash; ErrorReason content is incidental.
func TestVerifyPairTSRParseDoesNotPanicOnRandomBytes(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	chainPEM := loadAnyChainPEM(t)
	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0xff, 0xff, 0xff, 0xff},
		bytes.Repeat([]byte{0x30}, 1024), // looks like ASN.1 SEQUENCE prefix
		bytes.Repeat([]byte{0x80}, 256),  // indefinite-length octets
	}
	for i, in := range cases {
		// Defensive defer: if a library panic escapes parseSafe, the
		// recover here logs it (test still fails via t.Errorf below).
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("case %d panic escaped parseSafe wrapper: %v", i, r)
			}
		}()
		r := VerifyPair(in, chainPEM, bytes.Repeat([]byte{0xab}, 32), "test", pool)
		if r.Verdict != PairInvalid {
			t.Errorf("case %d: Verdict = %v, want PairInvalid for garbage TSR", i, r.Verdict)
		}
	}
}

// =============================================================================
// VerifyPair — real bundle integration
// =============================================================================

// TestVerifyPairAgainstRealBundleHappyPath asserts that for every
// {day, tsa} pair in the regenerated example bundle, VerifyPair
// returns PairValid against the bundle's actual daily_root.
// Load-bearing: production stamping produced these TSRs; the
// verifier MUST validate them or real bundles will fail check 6.
func TestVerifyPairAgainstRealBundleHappyPath(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	b := loadExampleBundleFromTSA(t)
	if len(b.RFC3161Receipts) == 0 {
		t.Skip("example bundle has no RFC 3161 receipts")
	}
	if len(b.DailyRoots.Roots) == 0 {
		t.Skip("example bundle has no daily roots")
	}

	// Build day → expected hashedMessage (decoded hex root bytes).
	expectedByDay := map[string][]byte{}
	for _, e := range b.DailyRoots.Roots {
		hashBytes, err := hex.DecodeString(e.Root)
		if err != nil {
			t.Fatalf("daily_roots[%s].root not hex: %v", e.Date, err)
		}
		if len(hashBytes) != 32 {
			t.Fatalf("daily_roots[%s].root has %d bytes, want 32", e.Date, len(hashBytes))
		}
		expectedByDay[e.Date] = hashBytes
	}

	for day, byTSA := range b.RFC3161Receipts {
		expected, ok := expectedByDay[day]
		if !ok {
			t.Errorf("RFC3161 receipt for %s but no daily root for that day", day)
			continue
		}
		for tsaName, pair := range byTSA {
			day := day
			tsaName := tsaName
			pair := pair
			expected := expected
			t.Run(day+"/"+tsaName, func(t *testing.T) {
				t.Parallel()
				r := VerifyPair(pair.TSR, pair.ChainPEM, expected, tsaName, pool)
				if r.Verdict != PairValid {
					t.Errorf("VerifyPair returned PairInvalid: %s", r.ErrorReason)
					return
				}
				if r.TSAName != tsaName {
					t.Errorf("TSAName = %q, want %q", r.TSAName, tsaName)
				}
				if r.TrustSource != "system" && r.TrustSource != "pinned" {
					t.Errorf("TrustSource = %q, want system or pinned", r.TrustSource)
				}
				if r.GenTime.IsZero() {
					t.Error("GenTime is zero; expected populated TSTInfo.genTime")
				}
				if r.ErrorReason != "" {
					t.Errorf("ErrorReason should be empty on PairValid: %q", r.ErrorReason)
				}
				if r.SignerCert == nil {
					t.Error("SignerCert is nil; expected populated PKCS#7.GetOnlySigner result")
				} else if r.SignerCert.Subject.CommonName == "" {
					t.Error("SignerCert.Subject.CommonName empty; production TSA signing certs should have a CN")
				}
				t.Logf("genTime=%s trustSource=%s signerCN=%q",
					r.GenTime.Format("2006-01-02T15:04:05Z"),
					r.TrustSource,
					r.SignerCert.Subject.CommonName,
				)
			})
		}
	}
}

// TestVerifyPairAgainstRealBundleHashedMessageMismatch asserts
// that swapping the expected hashedMessage to a different 32-byte
// value MUST flip the verdict to PairInvalid with the
// "HashedMessage mismatch" diagnostic. This is the load-bearing
// replay defense: a TSR for a different daily root MUST fail.
func TestVerifyPairAgainstRealBundleHashedMessageMismatch(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	b := loadExampleBundleFromTSA(t)
	if len(b.RFC3161Receipts) == 0 {
		t.Skip("no RFC 3161 receipts")
	}

	wrongHash := bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 8) // 32 bytes != real root

	for day, byTSA := range b.RFC3161Receipts {
		for tsaName, pair := range byTSA {
			day := day
			tsaName := tsaName
			pair := pair
			t.Run(day+"/"+tsaName, func(t *testing.T) {
				t.Parallel()
				r := VerifyPair(pair.TSR, pair.ChainPEM, wrongHash, tsaName, pool)
				if r.Verdict != PairInvalid {
					t.Errorf("VerifyPair unexpectedly returned PairValid for wrong hashedMessage")
					return
				}
				if !strings.Contains(r.ErrorReason, "HashedMessage mismatch") {
					t.Errorf("ErrorReason missing mismatch diagnostic: %q", r.ErrorReason)
				}
			})
		}
	}
}

// TestVerifyPairAgainstRealBundleTamperedTSR tampers the TSR at
// several positions and asserts that AT LEAST HALF of distributed
// tampers produce PairInvalid. PKCS#7 SignedData contains certs
// (large) and signature payload (small); the signature-protected
// scope is TSTInfo + signed attributes + the signing cert chain
// path. Tampering bytes inside non-path certs in p7.Certificates,
// or inside cert fields that aren't part of the validated chain,
// can produce a false negative because the verifier finds an
// alternate valid path (e.g., system trust supplies intermediates).
//
// The 50% threshold is the realistic integrity guarantee: enough
// bytes are cryptographically protected that a random tamper
// usually fails, but the precise rate depends on TSA-specific
// PKCS#7 structure. Targeted tampers (hashedMessage, signature)
// are covered by separate tests
// (TestVerifyPairAgainstRealBundleHashedMessageMismatch).
func TestVerifyPairAgainstRealBundleTamperedTSR(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	b := loadExampleBundleFromTSA(t)
	if len(b.RFC3161Receipts) == 0 {
		t.Skip("no RFC 3161 receipts")
	}

	expectedByDay := map[string][]byte{}
	for _, e := range b.DailyRoots.Roots {
		h, _ := hex.DecodeString(e.Root)
		expectedByDay[e.Date] = h
	}

	for day, byTSA := range b.RFC3161Receipts {
		expected := expectedByDay[day]
		for tsaName, pair := range byTSA {
			day := day
			tsaName := tsaName
			pair := pair
			expected := expected
			t.Run(day+"/"+tsaName, func(t *testing.T) {
				t.Parallel()
				if len(pair.TSR) < 500 {
					t.Skipf("TSR too short for distributed tamper: %d bytes", len(pair.TSR))
				}
				// Tamper at 10 evenly-spaced positions. Each tamper
				// is an independent test: copy fresh bytes, flip a
				// 16-byte window, run VerifyPair.
				const positions = 10
				const window = 16
				step := len(pair.TSR) / (positions + 1)
				rejected := 0
				for i := 1; i <= positions; i++ {
					start := step * i
					tampered := make([]byte, len(pair.TSR))
					copy(tampered, pair.TSR)
					for j := start; j < start+window && j < len(tampered); j++ {
						tampered[j] ^= 0xff
					}
					r := VerifyPair(tampered, pair.ChainPEM, expected, tsaName, pool)
					if r.Verdict == PairInvalid {
						rejected++
					}
				}
				// Require ≥50% of positions to fail. False negatives
				// in non-path-cert regions are realistic. Targeted
				// tampers (hashedMessage, signature) covered by
				// other tests.
				const minRejected = 5
				if rejected < minRejected {
					t.Errorf("only %d/%d distributed tampers were rejected; want ≥%d. "+
						"This suggests the TSR has too many tamper-safe regions or "+
						"signature-protected scope is narrower than expected.",
						rejected, positions, minRejected)
				}
				t.Logf("rejected %d/%d distributed tamper positions", rejected, positions)
			})
		}
	}
}

// TestVerifyPairAgainstRealBundleGarbageChainPEM asserts that a
// chain.pem replaced with non-PEM bytes fails fast at the chain-
// parse step. This pins the load-bearing claim that chain.pem MUST
// be syntactically valid; corrupted chain.pem cannot silently
// degrade verification to "use system trust only."
//
// **Note on what is NOT tested here.** Substituting a different-
// but-valid chain.pem (e.g., another TSA's chain) does NOT
// necessarily fail, because the .tsr's embedded PKCS#7 already
// carries the signing cert and may chain via system trust without
// needing chain.pem's intermediates at all. chain.pem is
// supplemental intermediates, not cryptographic binding evidence.
// The binding evidence is the signature inside the TSR.
func TestVerifyPairAgainstRealBundleGarbageChainPEM(t *testing.T) {
	t.Parallel()
	pool, err := NewTSAPool()
	if err != nil {
		t.Fatalf("NewTSAPool: %v", err)
	}
	b := loadExampleBundleFromTSA(t)
	if len(b.RFC3161Receipts) == 0 {
		t.Skip("no RFC 3161 receipts")
	}

	expectedByDay := map[string][]byte{}
	for _, e := range b.DailyRoots.Roots {
		h, _ := hex.DecodeString(e.Root)
		expectedByDay[e.Date] = h
	}

	// Pick the first available pair.
	for day, byTSA := range b.RFC3161Receipts {
		expected := expectedByDay[day]
		for tsaName, pair := range byTSA {
			r := VerifyPair(pair.TSR, []byte("not a PEM document"), expected, tsaName, pool)
			if r.Verdict != PairInvalid {
				t.Errorf("[%s/%s] garbage chain.pem unexpectedly verified as PairValid",
					day, tsaName)
				return
			}
			if !strings.Contains(r.ErrorReason, "chain.pem parse failed") {
				t.Errorf("ErrorReason missing chain-parse diagnostic: %q", r.ErrorReason)
			}
			return
		}
	}
}

// =============================================================================
// Helpers
// =============================================================================

// loadAnyChainPEM returns one chain.pem from the example bundle
// (any day, any TSA). Used by tests that need a real, well-formed
// chain.pem to get past ParseChainPEM in order to test downstream
// failure modes.
func loadAnyChainPEM(t *testing.T) []byte {
	t.Helper()
	b := loadExampleBundleFromTSA(t)
	for _, byTSA := range b.RFC3161Receipts {
		for _, pair := range byTSA {
			if len(pair.ChainPEM) > 0 {
				return pair.ChainPEM
			}
		}
	}
	t.Skip("example bundle has no chain.pem files")
	return nil
}

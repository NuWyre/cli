package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/nbd-wtf/opentimestamps"
	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Check 5 — OpenTimestamps Bitcoin anchor
// =============================================================================

// TestCheck5HappyPathOnRegeneratedBundle exercises the canonical
// pending-state path: the regenerated example bundle's OTS receipt
// is in pending state (manifest declares ots_status="pending"); the
// default --allow-pending-ots posture treats this as Warn (no
// errors, one warning). --strict-ots flips to Fail.
//
// The example bundle's manifest carries `ots_status="pending"` per
// the V1 anchor-pending posture; the receipt itself has calendar
// attestations but no Bitcoin attestation yet (Bitcoin confirmation
// lands ~24h after submission). This is the fixture for both
// happy-path Warn AND --strict-ots Fail testing.
func TestCheck5HappyPathPending(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := NewCheck5OTS(newTestHTTPClient(nil))

	// Default posture: pending receipt → WARN, no errors.
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusWarn {
		t.Errorf("default pending: Status = %v, want Warn", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	if len(r.Errors) != 0 {
		t.Errorf("default pending: %d errors, want 0", len(r.Errors))
	}
	if len(r.Warnings) == 0 {
		t.Errorf("default pending: 0 warnings, want at least 1")
	}
	hit := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), "pending Bitcoin confirmation") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("warning doesn't mention pending Bitcoin confirmation; got:")
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
}

// TestCheck5StrictOTSFailsPending pins the --strict-ots inversion:
// pending state under --strict-ots is FAIL (not Warn).
func TestCheck5StrictOTSFailsPending(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := NewCheck5OTS(newTestHTTPClient(nil))

	r := c.Run(b, CheckOptions{StrictOTS: true})
	if r.Status != StatusFail {
		t.Errorf("strict pending: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "--strict-ots requires Bitcoin attestation") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("strict-ots error doesn't mention requirement; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5OfflineSkipped pins the --offline short-circuit before
// any Bitcoin lookup is attempted.
func TestCheck5OfflineSkipped(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := NewCheck5OTS(newTestHTTPClient(nil))

	r := c.Run(b, CheckOptions{Offline: true})
	if r.Status != StatusSkipped {
		t.Errorf("offline: Status = %v, want Skipped", r.Status)
	}
	if !strings.Contains(r.SkipReason, "offline") {
		t.Errorf("offline SkipReason doesn't mention offline: %q", r.SkipReason)
	}
}

func TestCheck5Slug(t *testing.T) {
	t.Parallel()
	c := Check5OTS{}
	if c.ID() != 5 {
		t.Errorf("ID() = %d, want 5", c.ID())
	}
	if c.Name() != "OpenTimestamps Bitcoin anchor" {
		t.Errorf("Name() = %q, want %q", c.Name(), "OpenTimestamps Bitcoin anchor")
	}
	if c.Slug() != "opentimestamps" {
		t.Errorf("Slug() = %q, want %q", c.Slug(), "opentimestamps")
	}
}

// TestCheck5RejectsConsistencyDivergence pins that the cross-anchor
// consistency check (D1's validateOTSConsistency) runs BEFORE
// per-receipt verification, so a manifest-vs-detail divergence
// surfaces at its native level.
func TestCheck5RejectsConsistencyDivergence(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	originalSummary := b.Manifest.AnchorStatus.OTSStatus
	defer func() { b.Manifest.AnchorStatus.OTSStatus = originalSummary }()
	// Set summary to "confirmed" while detail still says
	// "submitted-pending-bitcoin-confirmation" — H5 from D1
	// reviewer pass (matrix enforced) catches this.
	b.Manifest.AnchorStatus.OTSStatus = "confirmed"

	c := NewCheck5OTS(newTestHTTPClient(nil))
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("consistency divergence: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "anchor consistency failure") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected anchor-consistency error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5RejectsCorruptedReceipt pins parse-failure surface.
// Replaces the OTS receipt bytes with garbage; ReadFromFile errors.
func TestCheck5RejectsCorruptedReceipt(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	// Find any date with a receipt; replace with garbage.
	var dateToCorrupt string
	for date := range b.OTSReceipts {
		dateToCorrupt = date
		break
	}
	if dateToCorrupt == "" {
		t.Skip("example bundle has no OTS receipts")
	}
	original := b.OTSReceipts[dateToCorrupt]
	defer func() { b.OTSReceipts[dateToCorrupt] = original }()
	b.OTSReceipts[dateToCorrupt] = []byte("not a valid OTS receipt")

	c := NewCheck5OTS(newTestHTTPClient(nil))
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("corrupted receipt: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "parse failed") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected parse-failed error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5RejectsDigestMismatch pins the receipt-digest-vs-daily-
// root-hash cross-check. Constructs a synthetic OTS receipt whose
// digest does NOT match the bundle's daily root.
func TestCheck5RejectsDigestMismatch(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	// Find any date with a receipt; replace with a synthetic receipt
	// for a different digest.
	var dateToReplace string
	for date := range b.OTSReceipts {
		dateToReplace = date
		break
	}
	if dateToReplace == "" {
		t.Skip("example bundle has no OTS receipts")
	}
	original := b.OTSReceipts[dateToReplace]
	defer func() { b.OTSReceipts[dateToReplace] = original }()

	// Construct a synthetic pending receipt for the digest
	// SHA-256("wrong-digest"). Even though this receipt is
	// structurally valid, its digest doesn't match our daily root.
	wrongDigest := sha256.Sum256([]byte("wrong-digest"))
	syntheticReceipt := buildSyntheticPendingReceipt(t, wrongDigest[:])
	b.OTSReceipts[dateToReplace] = syntheticReceipt

	c := NewCheck5OTS(newTestHTTPClient(nil))
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("digest mismatch: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "anchors a different digest") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected digest-mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5UpgradedHappyPath uses a synthetic upgraded receipt + a
// mock Bitcoin endpoint (httptest) to exercise the full Sequence.
// Verify path through the library — without making real network
// calls. Degenerate-sequence variant: the receipt has no
// Operations, just a Bitcoin attestation, so Compute returns the
// digest unchanged. Mock returns a block whose merkle_root = digest.
func TestCheck5UpgradedHappyPath(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("nuwyre-test-daily-root"))
	const blockHeight = 12345
	syntheticReceipt := buildSyntheticUpgradedReceipt(t, digest[:], blockHeight)

	header := buildSyntheticBlockHeader(digest[:], time.Now().Unix())
	mockEndpoint := buildMockEsplora(t, blockHeight, header)
	defer mockEndpoint.Close()

	b := buildSyntheticOTSBundle(t, digest, syntheticReceipt, mockEndpoint.SubmittedAt)
	c := NewCheck5OTS(newTestHTTPClient(mockEndpoint.Client))
	c.endpointsForTest(mockEndpoint.URL)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusPass {
		t.Errorf("upgraded happy path: Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
}

// TestCheck5UpgradedHappyPathRealisticOpChain pins H2 from D2
// reviewer pass: the degenerate test above (no Operations) bypasses
// the cryptographic chain through Compute. This test exercises the
// load-bearing path — sequence has [append(suffix), sha256,
// BitcoinAttestation] — Compute's op-application path is exercised
// against the merkle root computed from those ops. If a future
// regression breaks Compute's append or sha256 application, this
// test catches it.
func TestCheck5UpgradedHappyPathRealisticOpChain(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("nuwyre-test-realistic-chain"))
	suffix := []byte("test-merkle-suffix-bytes")
	// Compute the expected merkle root: SHA256(digest || suffix).
	combined := append([]byte{}, digest[:]...)
	combined = append(combined, suffix...)
	expectedMerkleRoot := sha256.Sum256(combined)

	const blockHeight = 22222
	receipt := buildSyntheticUpgradedReceiptWithOps(t, digest[:], suffix, blockHeight)

	header := buildSyntheticBlockHeader(expectedMerkleRoot[:], time.Now().Unix())
	mockEndpoint := buildMockEsplora(t, blockHeight, header)
	defer mockEndpoint.Close()

	b := buildSyntheticOTSBundle(t, digest, receipt, mockEndpoint.SubmittedAt)
	c := NewCheck5OTS(newTestHTTPClient(mockEndpoint.Client))
	c.endpointsForTest(mockEndpoint.URL)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusPass {
		t.Errorf("realistic op-chain: Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
}

// TestCheck5UpgradedFailsOnWrongMerkleRoot pins the load-bearing
// negative case: the library's Verify catches a block whose merkle
// root doesn't match the receipt's claim. This is the canonical
// tampering-detection test.
func TestCheck5UpgradedFailsOnWrongMerkleRoot(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("nuwyre-test-daily-root-2"))
	const blockHeight = 67890
	syntheticReceipt := buildSyntheticUpgradedReceipt(t, digest[:], blockHeight)

	// Mock returns a header with a DIFFERENT merkle root.
	wrongMerkleRoot := sha256.Sum256([]byte("wrong-merkle-root"))
	header := buildSyntheticBlockHeader(wrongMerkleRoot[:], time.Now().Unix())
	mockEndpoint := buildMockEsplora(t, blockHeight, header)
	defer mockEndpoint.Close()

	b := buildSyntheticOTSBundle(t, digest, syntheticReceipt, mockEndpoint.SubmittedAt)
	c := NewCheck5OTS(newTestHTTPClient(mockEndpoint.Client))
	c.endpointsForTest(mockEndpoint.URL)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("wrong merkle root: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "Bitcoin verification failed") &&
			strings.Contains(e.Error(), "merkle root") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected merkle-root-mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5RejectsPoisonedOpTag pins C1 from D2 reviewer pass:
// a malicious .ots file using a "not implemented" op tag (sha1 0x02,
// reverse 0xf2, hexlify 0xf3, keccak256 0x67) panics inside the
// library's Sequence.Compute. verifySequenceSafe wraps the call
// with defer-recover, converting the panic into a clean Fail with
// the receipt's date + spec section reference. Without this
// wrapper, a single tampered receipt becomes a denial-of-
// verification primitive against all subsequent daily roots.
func TestCheck5RejectsPoisonedOpTag(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("nuwyre-test-poisoned-op"))
	const blockHeight = 33333
	// Build a receipt with [reverse op, BitcoinAttestation] — the
	// library will panic inside Compute when it tries to Apply the
	// reverse op (whose Apply func is `panic("reverse not
	// implemented")`).
	receipt := buildSyntheticReceiptWithPoisonedOp(t, digest[:], blockHeight)

	header := buildSyntheticBlockHeader(digest[:], time.Now().Unix())
	mockEndpoint := buildMockEsplora(t, blockHeight, header)
	defer mockEndpoint.Close()

	b := buildSyntheticOTSBundle(t, digest, receipt, mockEndpoint.SubmittedAt)
	c := NewCheck5OTS(newTestHTTPClient(mockEndpoint.Client))
	c.endpointsForTest(mockEndpoint.URL)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("poisoned op tag: Status = %v, want Fail", r.Status)
	}
	// The error should attribute the panic to the specific receipt
	// + sequence, NOT crash the verifier.
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "panic") &&
			strings.Contains(e.Error(), "ots_receipts/2026-04-22.ots") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected panic-recovery-attributed error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5MissingReceiptFails pins the missing-receipt-with-
// attempted-status path. Per spec §4.2, ots_status has no
// "not_attempted" enum value (unlike rfc3161_status / github_status),
// so every daily root MUST have a corresponding receipt. Missing
// is always structural failure.
func TestCheck5MissingReceiptFails(t *testing.T) {
	t.Parallel()
	syntheticBundle := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:  "example-demo",
			GeneratedAt: "2026-04-22T09:00:00Z",
			AnchorStatus: bundle.ManifestAnchorStatus{
				OTSStatus:     "failed",
				RFC3161Status: "not_attempted",
				GithubStatus:  "not_attempted",
			},
			Anchors: bundle.ManifestAnchors{
				OpenTimestamps: bundle.ManifestOTSAnchor{
					Status:      "submission-failed-no-receipt",
					SubmittedAt: time.Now().UTC().Format(time.RFC3339),
				},
			},
		},
		DailyRoots: bundle.DailyRootsJSON{
			Roots: []bundle.DailyRootEntry{
				{Date: "2026-04-22", Root: hex.EncodeToString(make([]byte, 32))},
			},
		},
		OTSReceipts: map[string][]byte{},
	}
	c := NewCheck5OTS(newTestHTTPClient(nil))
	r := c.Run(syntheticBundle, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("missing receipt: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "missing OTS receipt") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected missing-receipt error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck5NetworkUnavailableSkipped pins the transient-error →
// SKIPPED classification. Mock endpoint returns 5xx repeatedly;
// retries exhaust; check 5 returns SKIPPED with "network
// unavailable" reason rather than FAIL.
func TestCheck5NetworkUnavailableSkipped(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("nuwyre-test-network-fail"))
	const blockHeight = 99999
	syntheticReceipt := buildSyntheticUpgradedReceipt(t, digest[:], blockHeight)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewCheck5OTS(&HTTPClient{
		Client:     srv.Client(),
		UserAgent:  "test",
		MaxRetries: 1,
		BaseDelay:  10 * time.Millisecond,
	})
	c.endpointsForTest(srv.URL)

	b := buildSyntheticOTSBundle(t, digest, syntheticReceipt, time.Now())
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusSkipped {
		t.Errorf("network unavailable: Status = %v, want Skipped", r.Status)
	}
	if !strings.Contains(r.SkipReason, "network unavailable") {
		t.Errorf("SkipReason doesn't mention 'network unavailable': %q", r.SkipReason)
	}
}

// =============================================================================
// otsBitcoinAdapter unit tests
// =============================================================================

func TestOTSBitcoinAdapterGetBlockHashSuccess(t *testing.T) {
	t.Parallel()
	// Esplora returns block hash hex (NOT reversed); adapter reverses
	// internally to match chainhash byte order. Verify the round-trip:
	// adapter request for height N → chainhash that, when stringified,
	// matches the original hex.
	mockHashBytes := sha256.Sum256([]byte("test-block-hash"))
	mockHashHex := hex.EncodeToString(mockHashBytes[:])
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/block-height/12345" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(mockHashHex))
	}))
	defer srv.Close()

	c := newTestHTTPClient(srv.Client())
	a := &otsBitcoinAdapter{
		httpClient: c,
		endpoints:  []string{srv.URL},
		ctx:        context.Background(),
	}
	hash, err := a.GetBlockHash(12345)
	if err != nil {
		t.Fatalf("GetBlockHash error: %v", err)
	}
	// chainhash.String() reverses internally to produce human-
	// readable hex. Round-trip should match the original hex.
	if hash.String() != mockHashHex {
		t.Errorf("hash.String() = %s, want %s", hash.String(), mockHashHex)
	}
}

func TestOTSBitcoinAdapterRejectsNegativeHeight(t *testing.T) {
	t.Parallel()
	a := &otsBitcoinAdapter{
		httpClient: newTestHTTPClient(nil),
		endpoints:  []string{"https://example.com"},
		ctx:        context.Background(),
	}
	_, err := a.GetBlockHash(-1)
	if err == nil {
		t.Fatal("negative height accepted")
	}
	var defErr *DefiniteError
	if !errors.As(err, &defErr) {
		t.Errorf("error type %T, want *DefiniteError", err)
	}
}

// =============================================================================
// Test helpers — synthetic OTS receipts + mock Esplora
// =============================================================================

// endpointsForTest swaps the check's adapter endpoint list. Test-
// only seam — see Check5OTS.testEndpoints field in check5_ots.go.
func (c *Check5OTS) endpointsForTest(urls ...string) {
	c.testEndpoints = urls
}

// buildSyntheticPendingReceipt constructs a minimal valid OTS
// receipt with a single calendar attestation (no Bitcoin attestation).
// Used to test parse-success paths without needing a real OTS
// receipt.
func buildSyntheticPendingReceipt(t *testing.T, digest []byte) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("digest length = %d, want 32", len(digest))
	}
	file := opentimestamps.File{
		Digest: digest,
		Sequences: []opentimestamps.Sequence{
			{
				opentimestamps.Instruction{
					Attestation: &opentimestamps.Attestation{
						CalendarServerURL: "https://test.calendar.example.com",
					},
				},
			},
		},
	}
	return file.SerializeToFile()
}

// buildSyntheticUpgradedReceipt constructs a minimal valid OTS
// receipt whose single sequence is just `[Bitcoin attestation at
// height N]` — no operations, so Sequence.Compute(digest) returns
// digest unchanged. Tests pair this with a mock Esplora endpoint
// returning a block whose merkle root equals digest.
func buildSyntheticUpgradedReceipt(t *testing.T, digest []byte, blockHeight uint64) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("digest length = %d, want 32", len(digest))
	}
	file := opentimestamps.File{
		Digest: digest,
		Sequences: []opentimestamps.Sequence{
			{
				opentimestamps.Instruction{
					Attestation: &opentimestamps.Attestation{
						BitcoinBlockHeight: blockHeight,
					},
				},
			},
		},
	}
	return file.SerializeToFile()
}

// buildSyntheticUpgradedReceiptWithOps constructs an OTS receipt
// with a realistic op chain: [append(suffix), sha256, BitcoinAttestation].
// Compute(digest) returns SHA256(digest || suffix). Tests pair this
// with a mock Esplora endpoint returning a block whose merkle root
// equals SHA256(digest || suffix). Pins H2 from D2 reviewer pass:
// exercises the load-bearing Compute op-application chain.
func buildSyntheticUpgradedReceiptWithOps(t *testing.T, digest, suffix []byte, blockHeight uint64) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("digest length = %d, want 32", len(digest))
	}
	// Operation tags: 0xf0 = append, 0x08 = sha256.
	appendOp := &opentimestamps.Operation{
		Name:   "append",
		Tag:    0xf0,
		Binary: true,
		Apply: func(curr, arg []byte) []byte {
			out := make([]byte, len(curr)+len(arg))
			copy(out, curr)
			copy(out[len(curr):], arg)
			return out
		},
	}
	sha256Op := &opentimestamps.Operation{
		Name:   "sha256",
		Tag:    0x08,
		Binary: false,
		Apply: func(curr, arg []byte) []byte {
			h := sha256.Sum256(curr)
			return h[:]
		},
	}
	file := opentimestamps.File{
		Digest: digest,
		Sequences: []opentimestamps.Sequence{
			{
				opentimestamps.Instruction{Operation: appendOp, Argument: suffix},
				opentimestamps.Instruction{Operation: sha256Op},
				opentimestamps.Instruction{
					Attestation: &opentimestamps.Attestation{BitcoinBlockHeight: blockHeight},
				},
			},
		},
	}
	return file.SerializeToFile()
}

// buildSyntheticReceiptWithPoisonedOp constructs an OTS receipt
// with the "reverse" op tag (0xf2), whose Apply func panics
// "reverse not implemented" in the library v0.4.0. Tests use this
// to exercise the verifySequenceSafe defer-recover wrapper (C1
// from D2 reviewer pass).
func buildSyntheticReceiptWithPoisonedOp(t *testing.T, digest []byte, blockHeight uint64) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("digest length = %d, want 32", len(digest))
	}
	reverseOp := &opentimestamps.Operation{
		Name:   "reverse",
		Tag:    0xf2,
		Binary: false,
		Apply: func(curr, arg []byte) []byte {
			// Match the library's panic-on-Apply for unimplemented
			// op. The library's parser accepts tag 0xf2 without
			// filtering (per ots.go:46), so this op rides into
			// Compute and panics there.
			panic("reverse not implemented")
		},
	}
	file := opentimestamps.File{
		Digest: digest,
		Sequences: []opentimestamps.Sequence{
			{
				opentimestamps.Instruction{Operation: reverseOp},
				opentimestamps.Instruction{
					Attestation: &opentimestamps.Attestation{BitcoinBlockHeight: blockHeight},
				},
			},
		},
	}
	return file.SerializeToFile()
}

// buildSyntheticBlockHeader constructs an 80-byte serialized
// Bitcoin block header with the given merkle root + timestamp.
// Used by tests that mock Esplora's /block/<hash>/header endpoint.
func buildSyntheticBlockHeader(merkleRoot []byte, unixTime int64) []byte {
	if len(merkleRoot) != 32 {
		panic(fmt.Sprintf("merkle root length = %d, want 32", len(merkleRoot)))
	}
	var mr chainhash.Hash
	copy(mr[:], merkleRoot)
	header := wire.NewBlockHeader(0, &chainhash.Hash{}, &mr, 0, 0)
	header.Timestamp = time.Unix(unixTime, 0)
	var buf strings.Builder
	w := newHexWriter(&buf)
	if err := header.BtcEncode(w, 0, 0); err != nil {
		panic(err)
	}
	return []byte(buf.String())
}

// hexWriter wraps a strings.Builder to write hex-encoded bytes
// (Esplora's /block/<hash>/header returns hex-encoded header).
type hexWriter struct{ b *strings.Builder }

func newHexWriter(b *strings.Builder) *hexWriter { return &hexWriter{b: b} }
func (w *hexWriter) Write(p []byte) (int, error) {
	w.b.WriteString(hex.EncodeToString(p))
	return len(p), nil
}

// mockEsploraServer wraps httptest.NewTLSServer to respond to the
// adapter's two endpoints (/block-height/<N> + /block/<hash>/header).
// The hash returned for /block-height/<N> is computed from the
// header bytes via wire.BlockHeader.BlockHash() — H1 from D2
// reviewer pass: the adapter cross-checks the returned header's
// hash against the requested hash, so the mock must return a
// consistent (height → hash → header → hash-of-header) tuple.
type mockEsploraServer struct {
	*httptest.Server
	URL          string
	Client       *http.Client
	SubmittedAt  time.Time
	BlockHashHex string
}

func buildMockEsplora(t *testing.T, height uint64, headerHex []byte) *mockEsploraServer {
	t.Helper()
	// Decode the header to compute its actual block hash. The mock's
	// /block-height/<N> response must return a hash that matches
	// header.BlockHash() so the adapter's H1 cross-check passes.
	rawHeader, err := hex.DecodeString(string(headerHex))
	if err != nil {
		t.Fatalf("buildMockEsplora: header hex decode: %v", err)
	}
	header := &wire.BlockHeader{}
	if err := header.BtcDecode(strings.NewReader(string(rawHeader)), 0, 0); err != nil {
		t.Fatalf("buildMockEsplora: header decode: %v", err)
	}
	hash := header.BlockHash()
	hashHex := hash.String()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedHeightPath := fmt.Sprintf("/block-height/%d", height)
		expectedHeaderPath := fmt.Sprintf("/block/%s/header", hashHex)
		switch r.URL.Path {
		case expectedHeightPath:
			// Esplora returns the human-order hex (NOT reversed
			// per chainhash internal order). hash.String()
			// returns the human-order form already.
			_, _ = w.Write([]byte(hashHex))
		case expectedHeaderPath:
			_, _ = w.Write(headerHex)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	return &mockEsploraServer{
		Server:       srv,
		URL:          srv.URL,
		Client:       srv.Client(),
		SubmittedAt:  time.Now().Add(-1 * time.Hour),
		BlockHashHex: hashHex,
	}
}

// buildSyntheticOTSBundle constructs a minimal Bundle with a single
// daily root + matching synthetic OTS receipt + manifest fields
// configured to satisfy the consistency checks.
func buildSyntheticOTSBundle(t *testing.T, digest [32]byte, receiptBytes []byte, submittedAt time.Time) *bundle.Bundle {
	t.Helper()
	const date = "2026-04-22"
	return &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:  "example-demo",
			GeneratedAt: "2026-04-22T09:00:00Z",
			AnchorStatus: bundle.ManifestAnchorStatus{
				OTSStatus:     "confirmed",
				RFC3161Status: "not_attempted",
				GithubStatus:  "not_attempted",
			},
			Anchors: bundle.ManifestAnchors{
				OpenTimestamps: bundle.ManifestOTSAnchor{
					Status:      "confirmed-bitcoin-attestation",
					SubmittedAt: submittedAt.UTC().Format(time.RFC3339),
					ReceiptPath: fmt.Sprintf("ots_receipts/%s.ots", date),
				},
			},
		},
		DailyRoots: bundle.DailyRootsJSON{
			SchemaVersion: 1,
			Roots: []bundle.DailyRootEntry{
				{Date: date, Root: hex.EncodeToString(digest[:]), LeafCount: 1, PaddedLeafCount: 1},
			},
		},
		OTSReceipts: map[string][]byte{date: receiptBytes},
	}
}

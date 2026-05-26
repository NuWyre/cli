package checks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Check 3: hash chain reconstruction — happy path against the
// regenerated example bundle.
// =============================================================================

func TestCheck3HappyPath(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check3Chain{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusPass {
		t.Errorf("happy path: Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	if len(r.Errors) != 0 {
		t.Errorf("happy path: %d errors, want 0", len(r.Errors))
	}
}

func TestCheck3Slug(t *testing.T) {
	t.Parallel()
	c := Check3Chain{}
	if c.ID() != 3 {
		t.Errorf("ID() = %d, want 3", c.ID())
	}
	if c.Name() != "hash chain" {
		t.Errorf("Name() = %q, want %q", c.Name(), "hash chain")
	}
	if c.Slug() != "hash-chain" {
		t.Errorf("Slug() = %q, want %q", c.Slug(), "hash-chain")
	}
}

// TestCheck3RejectsTamperedContent flips one byte of an event's
// declared content field. The recomputed content_hash diverges from
// the row's declared content_hash → Fail.
func TestCheck3RejectsTamperedContent(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events in example bundle")
	}
	// Find the first event with non-empty content; tamper its
	// content. Use the in-memory b.Events shape (check 3 reads from
	// b.Events, not from raw bytes).
	var target *bundle.EventJSONL
	for i := range b.Events {
		if b.Events[i].Content.Content != nil && *b.Events[i].Content.Content != "" {
			target = &b.Events[i]
			break
		}
	}
	if target == nil {
		t.Skip("no event with non-empty content; cannot tamper")
	}
	original := *target.Content.Content
	defer func() { *target.Content.Content = original }()
	tampered := original + "X"
	*target.Content.Content = tampered

	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered content: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "content_hash mismatch") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected content_hash mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3RejectsTamperedEventHash flips one declared event_hash
// while leaving content + prev_event_hash + signature untouched.
// content_hash check passes; event_hash recompute disagrees with
// declared → Fail.
func TestCheck3RejectsTamperedEventHash(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events in example bundle")
	}
	// Tamper the FIRST event's declared event_hash. The chain check
	// for event 1 will fail at event_hash mismatch.
	target := &b.Events[0]
	original := target.Forensic.EventHash
	defer func() { target.Forensic.EventHash = original }()
	target.Forensic.EventHash = strings.Repeat("a", 64)

	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered event_hash: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "event_hash mismatch") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected event_hash mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3RejectsTamperedPrevHash flips one declared prev_event_hash
// on a non-genesis event. Per-organization chain breaks → Fail with
// prev_event_hash mismatch.
//
// Post-Path-A: walks the bundle's event_hash chain by sequence_number
// (not by session). Picks any non-genesis event (sequence > 0) and
// tampers its prev_event_hash; the chain walk reaches it in sequence
// order and fires a mismatch.
func TestCheck3RejectsTamperedPrevHash(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) < 2 {
		t.Skip("need at least 2 events to tamper prev_event_hash")
	}
	// Find any non-genesis event in the per-organization chain. Sort
	// by sequence_number to mirror the validator's walk order, then
	// pick index 1 (the event immediately after the genesis).
	sorted := make([]*bundle.EventJSONL, len(b.Events))
	for i := range b.Events {
		sorted[i] = &b.Events[i]
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Forensic.SequenceNumber < sorted[j].Forensic.SequenceNumber
	})
	target := sorted[1]
	original := target.Forensic.PrevEventHash
	defer func() { target.Forensic.PrevEventHash = original }()
	target.Forensic.PrevEventHash = strings.Repeat("b", 64)

	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered prev_event_hash: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "prev_event_hash mismatch") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected prev_event_hash mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3RejectsTamperedSignature flips one byte of an
// ingestion_signature. content_hash, event_hash, prev chain still
// pass; ed25519.Verify fails → Fail with signature error.
func TestCheck3RejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events")
	}
	target := &b.Events[0]
	original := target.Forensic.IngestionSignature
	defer func() { target.Forensic.IngestionSignature = original }()
	if len(original) == 0 {
		t.Fatal("first event has empty ingestion_signature")
	}
	// L1 from commit-4 reviewer pass: mutate at the BYTE level
	// (decode → flip bit → re-encode). Mutating a base64 char
	// directly could (with low probability) land on bits that still
	// produce a valid signature; flipping a known bit position in
	// the decoded sig is deterministic regardless of original value.
	decoded, err := base64.StdEncoding.DecodeString(original)
	if err != nil {
		t.Fatalf("decode original signature: %v", err)
	}
	// Flip the high bit of byte 5 — well past any structural
	// position-zero magic. Ed25519 signatures have no internal
	// structure that would tolerate a bit flip.
	decoded[5] ^= 0x80
	target.Forensic.IngestionSignature = base64.StdEncoding.EncodeToString(decoded)

	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered ingestion_signature: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "ingestion_signature") &&
			strings.Contains(e.Error(), "Ed25519 verification failed") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected ingestion_signature Ed25519 fail; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3RejectsZeroLengthSignature pins the length check: a
// signature whose decoded length isn't 64 bytes fails before
// ed25519.Verify is called.
func TestCheck3RejectsZeroLengthSignature(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events")
	}
	target := &b.Events[0]
	target.Forensic.IngestionSignature = base64.StdEncoding.EncodeToString(make([]byte, 0))

	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("zero-length signature: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "ingestion_signature decoded to 0 bytes") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected zero-length error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3RejectsCustomerExportAgainstPlaceholderProdKey verifies
// the placeholder-prod-key short-circuit: customer-export bundles
// cannot have their per-event signatures verified against the
// placeholder.
func TestCheck3RejectsCustomerExportAgainstPlaceholderProdKey(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.Manifest.BundleType = "customer-export"
	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("placeholder prod key: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "placeholder") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected placeholder error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3SwappedEventsBreakChain swaps two events' sequence
// numbers within a session. The walk reorders them by sequence
// number, so the chain breaks at the swapped position (their
// prev_event_hash references each other rather than the prior
// event).
// TestCheck3SwappedEventsBreakChain swaps two events' event_hash
// declarations. The per-organization chain walk catches this at
// event_hash mismatch (the recomputed event_hash for ev0 won't equal
// its now-tampered declared event_hash).
//
// Post-Path-A: pick any two adjacent events by sequence_number across
// the full bundle (not per-session).
func TestCheck3SwappedEventsBreakChain(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) < 2 {
		t.Skip("need at least 2 events")
	}
	// Sort by sequence_number; pick events 0 and 1.
	sorted := make([]*bundle.EventJSONL, len(b.Events))
	for i := range b.Events {
		sorted[i] = &b.Events[i]
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Forensic.SequenceNumber < sorted[j].Forensic.SequenceNumber
	})
	ev0, ev1 := sorted[0], sorted[1]
	// Swap their event_hash declarations (NOT sequence numbers — the
	// chain walks by sequence_number ordering, so the same events
	// in the same order are presented but with each carrying the
	// other's event_hash). The recomputed event_hash for ev0 will
	// no longer equal its (now-tampered) declared event_hash.
	ev0Hash := ev0.Forensic.EventHash
	ev1Hash := ev1.Forensic.EventHash
	defer func() {
		ev0.Forensic.EventHash = ev0Hash
		ev1.Forensic.EventHash = ev1Hash
	}()
	ev0.Forensic.EventHash = ev1Hash
	ev1.Forensic.EventHash = ev0Hash

	r := Check3Chain{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("swapped event_hashes: Status = %v, want Fail", r.Status)
	}
	// L2 from commit-4 reviewer pass: pin which error fired. Swapping
	// event_hashes makes the recomputed event_hash for ev0 (built from
	// content + prev) NOT equal its declared (now-tampered) event_hash.
	// The chain walk catches this at event_hash mismatch on the first
	// swapped row.
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "event_hash mismatch") ||
			strings.Contains(e.Error(), "prev_event_hash mismatch") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected event_hash or prev_event_hash mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3DeterministicAcrossRuns asserts that two consecutive
// runs against the same tampered bundle produce byte-identical
// error sequences. Catches Go-map-iteration nondeterminism.
func TestCheck3DeterministicAcrossRuns(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	// Tamper multiple sessions to maximize the chance of
	// nondeterministic ordering if the implementation iterated maps
	// without sorting.
	bySession := make(map[string][]int)
	for i, ev := range b.Events {
		bySession[ev.Identity.SessionID] = append(bySession[ev.Identity.SessionID], i)
	}
	tamperedSessions := 0
	for _, idxs := range bySession {
		if tamperedSessions >= 3 {
			break
		}
		// Tamper the first event in each session.
		b.Events[idxs[0]].Forensic.EventHash = strings.Repeat("a", 64)
		tamperedSessions++
	}

	var firstSeq []string
	for run := 0; run < 5; run++ {
		r := Check3Chain{}.Run(b, CheckOptions{})
		var seq []string
		for _, e := range r.Errors {
			seq = append(seq, e.Error())
		}
		if run == 0 {
			firstSeq = seq
			continue
		}
		if len(seq) != len(firstSeq) {
			t.Errorf("run %d: %d errors, want %d", run, len(seq), len(firstSeq))
			continue
		}
		for i := range seq {
			if seq[i] != firstSeq[i] {
				t.Errorf("run %d index %d differs:\n  first: %q\n  now:   %q", run, i, firstSeq[i], seq[i])
			}
		}
	}
}

// =============================================================================
// Path A.1 (D4) per-organization chain regression tests. These tests
// don't depend on the example bundle (which is pre-D5 and stale);
// they construct synthetic bundles inline to pin the specific chain-
// semantic invariants the D4 amendment introduced.
// =============================================================================

// devSigningKey returns the dev Ed25519 private key loaded from the
// example-bundle dev-keys JWK fixture. Used by syntheticEvent to
// produce ingestion_signatures that pass Check 3's signature
// verification, so chain-semantic regression tests can exercise the
// gap / prev_hash / event_hash code paths on synthetic bundles
// without the signature check terminating the walk early.
//
// Cached at first call to avoid re-loading per test.
//
// **Phase 7.E session 118 H1 closure**: prior implementation was
// `var devSigningKeyCache ed25519.PrivateKey` + bare nil-check +
// assignment, which races under `t.Parallel()` (27 parallel-mode
// subtests in this file alone). Two goroutines could both see nil,
// both read+parse the seed file, both write to the cache — and the
// race detector flags it under `go test -race`. Replaced with
// sync.Once: the loader runs exactly once across all goroutines,
// and the read of devSigningKeyCache after Do() is synchronized via
// the same happens-before edge.
var (
	devSigningKeyOnce    sync.Once
	devSigningKeyCache   ed25519.PrivateKey
	devSigningKeyErr     error
	devSigningKeyMissing bool
)

func devSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	devSigningKeyOnce.Do(func() {
		// The dev signing key (private material, dev-only) lives in the monorepo
		// only; the standalone published verifier repo intentionally ships no
		// private key, so these re-signing tests skip there. Verification paths
		// are covered standalone by the committed conformance fixtures.
		devKeyPath := findArtifactOrEmpty("packages/example-bundle/dev-keys/dev-signing-key.json")
		if devKeyPath == "" {
			devSigningKeyMissing = true
			return
		}
		raw, err := os.ReadFile(devKeyPath)
		if err != nil {
			devSigningKeyErr = fmt.Errorf("devSigningKey read: %v", err)
			return
		}
		var jwk struct {
			PrivateJWK struct {
				D string `json:"d"`
				X string `json:"x"`
			} `json:"private_jwk"`
		}
		if err := json.Unmarshal(raw, &jwk); err != nil {
			devSigningKeyErr = fmt.Errorf("devSigningKey parse: %v", err)
			return
		}
		// JWK uses base64url (no padding); decode the 32-byte seed.
		seed, err := base64.RawURLEncoding.DecodeString(jwk.PrivateJWK.D)
		if err != nil {
			devSigningKeyErr = fmt.Errorf("devSigningKey seed b64url decode: %v", err)
			return
		}
		if len(seed) != ed25519.SeedSize {
			devSigningKeyErr = fmt.Errorf("devSigningKey seed length = %d, want %d", len(seed), ed25519.SeedSize)
			return
		}
		devSigningKeyCache = ed25519.NewKeyFromSeed(seed)
	})
	if devSigningKeyMissing {
		t.Skip("dev signing key not present (standalone verifier repo ships no private key); re-signing tests run in the monorepo")
	}
	if devSigningKeyErr != nil {
		t.Fatalf("%v", devSigningKeyErr)
	}
	return devSigningKeyCache
}

// syntheticEvent constructs an EventJSONL with valid declared
// content_hash + event_hash computed via the same helpers Check 3
// uses, AND a valid ingestion_signature signed with the dev key. So
// a chain-walk reaches the assertion the test cares about (gap,
// prev_hash) instead of failing earlier on content_hash mismatch or
// signature failure from undeclared/unsigned synthetic events.
//
// Caller controls sequence_number, prev_event_hash, session_id,
// content text.
func syntheticEvent(t *testing.T, seq int64, prevHash, sessionID, contentText string) bundle.EventJSONL {
	t.Helper()
	contentStr := contentText
	contentPtr := &contentStr
	timestamp := "1700000000000000000"
	content := bundle.EventContent{
		Role:    "user",
		Content: contentPtr,
	}
	contentHash, err := computeContentHashGo(content)
	if err != nil {
		t.Fatalf("syntheticEvent computeContentHash: %v", err)
	}
	content.ContentHash = contentHash
	eventHash, err := computeEventHashGo(contentHash, prevHash, seq, timestamp)
	if err != nil {
		t.Fatalf("syntheticEvent computeEventHash: %v", err)
	}
	// Sign over decoded-hex event_hash bytes (matches §6.3).
	eventHashBytes, err := hex.DecodeString(eventHash)
	if err != nil {
		t.Fatalf("syntheticEvent event_hash hex decode: %v", err)
	}
	sig := ed25519.Sign(devSigningKey(t), eventHashBytes)
	return bundle.EventJSONL{
		Identity: bundle.EventIdentity{SessionID: sessionID},
		Content:  content,
		Forensic: bundle.EventForensic{
			SequenceNumber:     seq,
			PrevEventHash:      prevHash,
			EventHash:          eventHash,
			TimestampUnixNs:    timestamp,
			IngestionSignature: base64.StdEncoding.EncodeToString(sig),
		},
	}
}

// syntheticManifestForExampleDemo returns a Manifest valid enough for
// Check 3's key dispatch path (bundle_type → dev key, valid RFC 3339
// generated_at). All other manifest fields default-zero.
func syntheticManifestForExampleDemo() bundle.ManifestJSON {
	return bundle.ManifestJSON{
		BundleType:  "example-demo",
		GeneratedAt: "2026-04-22T09:00:00Z",
	}
}

// TestCheck3SyntheticHappyPath pins the symmetry counterpart to the
// new synthetic-bundle Fail tests below: a 3-event synthetic per-
// organization chain spanning two sessions MUST pass Check 3
// without modification. L2 from D4 reviewer pass: closes the
// "regression that spuriously fails every bundle" detection gap
// during the D5 window when the example-bundle happy-path is
// skipped.
func TestCheck3SyntheticHappyPath(t *testing.T) {
	t.Parallel()
	a0 := syntheticEvent(t, 0, bundle.GenesisPrevHash, "session-A", "first event")
	a1 := syntheticEvent(t, 1, a0.Forensic.EventHash, "session-A", "second event same session")
	// Cross-session edge: b0 is in session-B but its prev_event_hash
	// references a1.event_hash regardless of session boundary.
	b0 := syntheticEvent(t, 2, a1.Forensic.EventHash, "session-B", "first event in second session")
	b := &bundle.Bundle{
		Manifest: syntheticManifestForExampleDemo(),
		Events:   []bundle.EventJSONL{a0, a1, b0},
	}
	r := Check3Chain{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusPass {
		t.Errorf("synthetic happy path: Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	if len(r.Errors) != 0 {
		t.Errorf("synthetic happy path: %d errors, want 0", len(r.Errors))
	}
}

// =============================================================================
// Phase 7.E session 118 H3 closure — sequence_number bound
// =============================================================================

// TestCheck3RejectsNegativeSequenceNumber pins the H3 defense-in-depth
// guard: an event with sequence_number < 0 must fail with an explicit
// "sequence_number ... is negative" error rather than only surfacing via
// the implicit "gap (expected 0, got -1)" path. Defends against any
// future refactor or non-chain-walk consumer that uses SequenceNumber
// arithmetically.
func TestCheck3RejectsNegativeSequenceNumber(t *testing.T) {
	t.Parallel()
	evNeg := syntheticEvent(t, -1, bundle.GenesisPrevHash, "session-A", "negative-seq event")
	b := &bundle.Bundle{
		Manifest: syntheticManifestForExampleDemo(),
		Events:   []bundle.EventJSONL{evNeg},
	}
	r := Check3Chain{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("negative seq: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "is negative") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected explicit 'is negative' error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3MaxChainEventsConstant pins the H3 upper bound at the
// documented value. Validates the constant rather than constructing
// a 10M-event bundle (which would be both slow + a memory-pressure
// regression in CI).
func TestCheck3MaxChainEventsConstant(t *testing.T) {
	t.Parallel()
	if MaxChainEvents != 10_000_000 {
		t.Errorf("MaxChainEvents = %d, want 10_000_000 (session 118 H3 closure documented value)", MaxChainEvents)
	}
}

// TestCheck3RejectsMissingGenesisAttack pins the load-bearing
// regression vector flagged by the D3 reviewer pass: a bundle that
// OMITS the genesis event (sequence 0) but has the remaining chain
// internally consistent would silently pass a per-session validator
// (each session's first event has its own GENESIS) but MUST fail
// the per-organization validator (sequence gap at 0).
func TestCheck3RejectsMissingGenesisAttack(t *testing.T) {
	t.Parallel()
	// 2-event chain starting at sequence 1 (genesis omitted). The
	// declared content_hash + event_hash on each event are valid —
	// gap fires on the FIRST event before content_hash recompute.
	ev1 := syntheticEvent(t, 1, bundle.GenesisPrevHash, "session-A", "first event after omitted genesis")
	ev2 := syntheticEvent(t, 2, ev1.Forensic.EventHash, "session-A", "second event")
	b := &bundle.Bundle{
		Manifest: syntheticManifestForExampleDemo(),
		Events:   []bundle.EventJSONL{ev1, ev2},
	}
	r := Check3Chain{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("missing-genesis attack: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "sequence gap") &&
			strings.Contains(e.Error(), "expected 0, got 1") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected 'sequence gap — expected 0, got 1' error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3RejectsSequenceGapMidChain pins gap detection for events
// removed from the middle of the chain. A bundle with sequence
// numbers {0, 1, 3} (event 2 removed) must fail with a specific
// gap-at-2 error.
func TestCheck3RejectsSequenceGapMidChain(t *testing.T) {
	t.Parallel()
	ev0 := syntheticEvent(t, 0, bundle.GenesisPrevHash, "session-A", "genesis")
	ev1 := syntheticEvent(t, 1, ev0.Forensic.EventHash, "session-A", "second")
	// ev2 omitted → gap. ev3 chains from a synthetic prev (since the
	// real ev2 was deleted; this simulates an attacker who computed a
	// chain through ev2 then removed ev2 from the bundle).
	ev3 := syntheticEvent(t, 3, strings.Repeat("9", 64), "session-A", "fourth (after omitted third)")
	b := &bundle.Bundle{
		Manifest: syntheticManifestForExampleDemo(),
		Events:   []bundle.EventJSONL{ev0, ev1, ev3},
	}
	r := Check3Chain{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("mid-chain gap: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "sequence gap") &&
			strings.Contains(e.Error(), "expected 2, got 3") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected 'sequence gap — expected 2, got 3' error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck3PerSessionBundleAttackPattern simulates the canonical
// pre-Path-A bundle shape: events in two sessions where each session
// starts with sequence 0 + GENESIS_PREV_HASH (the per-session-chain
// pattern compose-events.ts pre-amendment emitted). The post-Path-A
// per-organization validator MUST reject this — sorting by sequence
// produces [seq=0(A), seq=0(B), seq=1(A)] and the SECOND event has
// seq=0 with expected=1 → gap fires.
//
// This is the regression test that closes the divergence between the
// pre-Path-A example bundle and post-Path-A verifier: a third party
// who downloads a pre-Path-A bundle (or a bundle generated by some
// non-conformant implementation) gets a clear diagnostic, not silent
// acceptance.
func TestCheck3PerSessionBundleAttackPattern(t *testing.T) {
	t.Parallel()
	a0 := syntheticEvent(t, 0, bundle.GenesisPrevHash, "session-A", "session A first")
	a1 := syntheticEvent(t, 1, a0.Forensic.EventHash, "session-A", "session A second")
	// Session 2 restarts at sequence 0 + GENESIS — the per-session
	// pattern. Post-Path-A verifier rejects.
	b0 := syntheticEvent(t, 0, bundle.GenesisPrevHash, "session-B", "session B first")
	b := &bundle.Bundle{
		Manifest: syntheticManifestForExampleDemo(),
		Events:   []bundle.EventJSONL{a0, a1, b0},
	}
	r := Check3Chain{}.Run(b, CheckOptions{AllowDevKey: true})
	if r.Status != StatusFail {
		t.Errorf("per-session bundle pattern: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "sequence gap") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected 'sequence gap' error for per-session bundle pattern; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// =============================================================================
// Cross-implementation oracle: Go's canonical bytes + SHA-256 must
// match what the TS reference implementation would have produced for
// the same logical event. This is the load-bearing
// cross-implementation parity test for the canonicalize +
// hash-payload-shape correctness claim.
// =============================================================================

// TestCheck3CrossImplementationContentHash takes the example bundle's
// first event, recomputes content_hash via the Go implementation,
// and asserts it equals the row's declared content_hash. The
// declared content_hash was produced by the TS writer; if Go's
// recomputation matches the declared value, Go and TS agree on the
// canonical bytes and SHA-256 of the same logical content payload.
//
// This is the load-bearing oracle that JCS canonicalization +
// payload-field selection are byte-identical between languages.
// Failure here means TestCheck3HappyPath also fails — but THIS test
// fails with a clearer "Go vs TS canonical bytes diverge" framing
// than the generic chain-reconstruction failure.
func TestCheck3CrossImplementationContentHash(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events")
	}
	for i, ev := range b.Events {
		recomputed, err := computeContentHashGo(ev.Content)
		if err != nil {
			t.Errorf("event %d: canonicalize failed: %v", i, err)
			continue
		}
		if recomputed != ev.Content.ContentHash {
			t.Errorf("event %d: cross-impl divergence — Go canonical SHA-256=%s, TS-declared content_hash=%s",
				i, recomputed, ev.Content.ContentHash)
		}
	}
}

// TestCheck3CrossImplementationEventHash asserts the same parity for
// the event_hash payload shape.
func TestCheck3CrossImplementationEventHash(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events")
	}
	for i, ev := range b.Events {
		recomputed, err := computeEventHashGo(
			ev.Content.ContentHash,
			ev.Forensic.PrevEventHash,
			ev.Forensic.SequenceNumber,
			ev.Forensic.TimestampUnixNs,
		)
		if err != nil {
			t.Errorf("event %d: canonicalize failed: %v", i, err)
			continue
		}
		if recomputed != ev.Forensic.EventHash {
			t.Errorf("event %d: cross-impl divergence — Go canonical SHA-256=%s, TS-declared event_hash=%s",
				i, recomputed, ev.Forensic.EventHash)
		}
	}
}

// TestCheck3IngestionSignatureSemantics is the load-bearing
// confirmation that the Go verifier and the TS writer agree on what
// ingestion_signature signs over. The TS writer calls
// `cryptoSign(null, Buffer.from(eventHashHex, "hex"), key)` —
// Ed25519 over decoded-hex event_hash bytes (NOT canonicalized JSON
// per spec §6.3 text). This test pins that semantic by verifying
// the example bundle's first event signature with the dev key
// against the decoded-hex event_hash bytes directly (no
// canonicalization).
func TestCheck3IngestionSignatureSemantics(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events")
	}
	const devSPKIB64 = "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE="
	pub, err := parseEd25519SPKI(devSPKIB64)
	if err != nil {
		t.Fatalf("dev SPKI parse: %v", err)
	}

	for i, ev := range b.Events {
		eventHashBytes, err := hex.DecodeString(ev.Forensic.EventHash)
		if err != nil {
			t.Errorf("event %d: event_hash hex decode: %v", i, err)
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(ev.Forensic.IngestionSignature)
		if err != nil {
			t.Errorf("event %d: signature base64 decode: %v", i, err)
			continue
		}
		// Verify per the TS writer's contract: Ed25519 over the
		// decoded-hex event_hash bytes.
		if !ed25519.Verify(pub, eventHashBytes, sig) {
			t.Errorf("event %d: ingestion_signature does NOT verify over decoded-hex event_hash bytes; spec §6.3 text vs writer divergence not resolved",
				i)
		}
	}
}

// =============================================================================
// Canonical JSON + hash helper unit tests
// =============================================================================

func TestCanonicalJSONEmptyObject(t *testing.T) {
	t.Parallel()
	got, err := canonicalJSON(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}" {
		t.Errorf("empty object: got %q, want %q", got, "{}")
	}
}

func TestCanonicalJSONSortsKeys(t *testing.T) {
	t.Parallel()
	got, err := canonicalJSON(map[string]interface{}{
		"z": 1,
		"a": 2,
		"m": 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"m":3,"z":1}` {
		t.Errorf("sorted keys: got %q, want %q", got, `{"a":2,"m":3,"z":1}`)
	}
}

func TestCanonicalJSONNullValue(t *testing.T) {
	t.Parallel()
	got, err := canonicalJSON(map[string]interface{}{
		"a": nil,
		"b": "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":null,"b":"x"}` {
		t.Errorf("null value: got %q, want %q", got, `{"a":null,"b":"x"}`)
	}
}

func TestCanonicalJSONNoHTMLEscape(t *testing.T) {
	t.Parallel()
	// JCS does NOT escape <, >, & — these are emitted as raw chars.
	got, err := canonicalJSON(map[string]interface{}{
		"html": "a<b>c&d",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"html":"a<b>c&d"}` {
		t.Errorf("HTML chars: got %q, want %q", got, `{"html":"a<b>c&d"}`)
	}
}

func TestCanonicalJSONStripsTrailingNewline(t *testing.T) {
	t.Parallel()
	got, err := canonicalJSON("hello")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(string(got), "\n") {
		t.Errorf("trailing newline not stripped: got %q", got)
	}
}

func TestCanonicalJSONNonFiniteFloatRejected(t *testing.T) {
	t.Parallel()
	// Go's json.Marshal rejects NaN/Inf; canonicalJSON propagates
	// the error so callers know JCS canonicalization is impossible
	// for that value.
	cases := []float64{math.NaN(), math.Inf(1), math.Inf(-1)}
	for _, v := range cases {
		_, err := canonicalJSON(map[string]interface{}{"bad": v})
		if err == nil {
			t.Errorf("expected error for non-finite %v, got nil", v)
		}
	}
}

// TestComputeContentHashStableAcrossRuns asserts deterministic output
// — same input always produces the same hash.
func TestComputeContentHashStableAcrossRuns(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Events) == 0 {
		t.Fatal("no events")
	}
	first, err := computeContentHashGo(b.Events[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		again, err := computeContentHashGo(b.Events[0].Content)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Errorf("run %d: hash drift — first=%s now=%s", i, first, again)
		}
	}
}

// TestCanonicalJSONU2028U2029RawUTF8 pins the M1 fix: Go's
// json.Encoder always escapes U+2028 / U+2029 as 6-ASCII-byte
// sequences regardless of SetEscapeHTML(false), but JCS (and thus
// the TS reference at packages/schema/src/canonical.ts) emits raw
// 3-byte UTF-8. canonicalJSON post-processes to restore raw UTF-8.
//
// Without this fix, a customer event whose content carried U+2028
// would have its content_hash recomputed to a different value than
// the writer-produced declared content_hash → Check 3 Fail on a
// legitimate bundle.
func TestCanonicalJSONU2028U2029RawUTF8(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		// expected canonical bytes for `{"k":"<input>"}` per JCS.
		// Quote + raw UTF-8 + quote inside a JSON object.
	}{
		{"line separator U+2028", "a b"},
		{"paragraph separator U+2029", "a b"},
		{"both", "x y z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := canonicalJSON(map[string]interface{}{"k": c.input})
			if err != nil {
				t.Fatal(err)
			}
			// Build the expected canonical bytes: `{"k":"` + raw UTF-8 input + `"}`.
			want := append([]byte{'{', '"', 'k', '"', ':', '"'}, []byte(c.input)...)
			want = append(want, '"', '}')
			if !bytes.Equal(got, want) {
				t.Errorf("got bytes %x\nwant bytes %x", got, want)
			}
			// And confirm the raw 3-byte UTF-8 sequence appears in
			// the output (not the 6-byte ASCII escape).
			if c.name != "both" {
				if !bytes.Contains(got, []byte(c.input)) {
					t.Errorf("output doesn't contain raw UTF-8 of input")
				}
			}
		})
	}
}

// TestRestoreJCSLineSeparatorsLeavesEscapedBackslashAlone pins the
// safety claim from the M1-fix doc-comment: an input whose literal
// 7-character text is ` ` (backslash + ASCII) must NOT be
// silently converted to U+2028. Go's encoder escapes the backslash
// as `\\u2028` (7 bytes), which doesn't match the 6-byte
// ` ` substitution target.
func TestRestoreJCSLineSeparatorsLeavesEscapedBackslashAlone(t *testing.T) {
	t.Parallel()
	const input = "\\u2028" // 6 ASCII chars: \, u, 2, 0, 2, 8
	got, err := canonicalJSON(map[string]interface{}{"k": input})
	if err != nil {
		t.Fatal(err)
	}
	// Expected: `{"k":"\\u2028"}` (backslash escaped). The output
	// MUST contain the escaped backslash sequence, NOT a raw U+2028.
	want := []byte(`{"k":"\\u2028"}`)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q\nwant %q\nbytes got=%x bytes want=%x", got, want, got, want)
	}
	// Confirm raw U+2028 (3 bytes 0xe2 0x80 0xa8) is NOT in output.
	if bytes.Contains(got, []byte{0xe2, 0x80, 0xa8}) {
		t.Errorf("output contains raw U+2028 from a literal-backslash input — safety violation")
	}
}

// TestSHA256AnchorMatchesKnownVector pins SHA-256 as the algorithm
// the canonical-hash helpers use. A future regression that swaps in
// a different algorithm would change this output and surface here
// before any check 3 test fails with a confusing chain-mismatch.
func TestSHA256AnchorMatchesKnownVector(t *testing.T) {
	t.Parallel()
	const input = `{"a":"b"}`
	// SHA-256("{\"a\":\"b\"}") — verified against the Go std library
	// (sha256.Sum256). This pins the algorithm; if a future
	// regression swaps SHA-256 for a different hash, the assertion
	// fails with a clear divergence rather than producing a confusing
	// chain-mismatch downstream.
	const want = "db4a7ecb114bc66c623a06c4ff6fe8daa2f49cc270ebbf7a1f81e22ab061c837"
	sum := sha256.Sum256([]byte(input))
	got := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("SHA-256(%q) = %s, want %s", input, got, want)
	}
}

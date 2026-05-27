package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Check 7 — GitHub anchor cross-check (D4 commit 2 V1-only scope)
//
// D4 commit 2 implements the V1 anchor-pending + failed/unknown
// mirror_status paths. The "anchored" path is stubbed (FAIL with
// explicit "post-Phase-5 deferred" diagnostic). Tests cover:
//
//   - V1 anchor-pending default: WARN-equivalent FAIL with
//     --allow-anchor-pending opt-in pointer in the error message
//     (real-bundle integration: regenerated example bundle is in
//     anchor-pending state).
//   - V1 anchor-pending with --allow-anchor-pending: PASS with
//     warning. Regression for the opt-in flag.
//   - failed mirror_status: FAIL with operator-actionable framing
//     (writer-declared degradation, not tampering).
//   - anchored stub: FAIL with "post-Phase-5 deferred" diagnostic
//     (the load-bearing fail-secure regression test).
//   - unknown mirror_status: FAIL with spec §11.1 reference.
//   - missing entry under github_status='anchored': FAIL.
//   - missing entry under github_status='not_attempted': PASS.
//   - consistency divergence: FAIL early.
//   - --offline: SKIPPED.
// =============================================================================

func newCheck7(t *testing.T) *Check7Github {
	t.Helper()
	// V1 paths don't dispatch to the fetcher; nil is safe per the
	// constructor doc-comment. The anchored-stub path also returns
	// FAIL before any fetcher dispatch.
	return NewCheck7Github(nil)
}

func cloneExampleForCheck7(t *testing.T) *bundle.Bundle {
	t.Helper()
	src := loadExampleBundle(t)
	dst := *src
	if src.GithubAnchors != nil {
		dst.GithubAnchors = make(map[string]bundle.GithubAnchorJSON, len(src.GithubAnchors))
		for d, a := range src.GithubAnchors {
			dst.GithubAnchors[d] = a
		}
	}
	if src.DailyRoots.Roots != nil {
		dst.DailyRoots.Roots = append([]bundle.DailyRootEntry(nil), src.DailyRoots.Roots...)
	}
	return &dst
}

// =============================================================================
// V1 anchor-pending — the load-bearing real-bundle path
// =============================================================================

// TestCheck7AnchorPendingDefaultFails pins the default V1 behavior:
// the regenerated example bundle is in anchor-pending state, and
// running check 7 without --allow-anchor-pending MUST FAIL with the
// V1 deploy-bootstrap diagnostic AND a pointer to the opt-in flag.
//
// Tenant 5 (customer trust): operators get explicit V1 state visibility
// + actionable opt-in path, not silent acceptance.
func TestCheck7AnchorPendingDefaultFails(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (V1 anchor-pending default)", r.Status)
	}
	if len(r.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
	hitV1 := false
	hitOptIn := false
	for _, e := range r.Errors {
		msg := e.Error()
		if strings.Contains(msg, "anchor-pending") && strings.Contains(msg, "V1 deploy-bootstrap") {
			hitV1 = true
		}
		if strings.Contains(msg, "--allow-anchor-pending") {
			hitOptIn = true
		}
	}
	if !hitV1 {
		t.Errorf("error doesn't mention V1 deploy-bootstrap state")
	}
	if !hitOptIn {
		t.Errorf("error doesn't point operator at --allow-anchor-pending opt-in")
	}
}

// TestCheck7AnchorPendingWithFlagPasses pins the opt-in: the same
// example bundle with --allow-anchor-pending PASSes (with a warning
// surfacing the V1 state to the operator).
func TestCheck7AnchorPendingWithFlagPasses(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{AllowAnchorPending: true})
	// M3 from D4 commit 2 crypto review: pin StatusWarn exactly.
	// The implementation can ONLY produce StatusWarn here (warnings
	// non-empty, errors empty); accepting StatusPass would mask a
	// regression where the warning gets dropped silently.
	if r.Status != StatusWarn {
		t.Errorf("Status = %v, want Warn exactly (--allow-anchor-pending populates warnings, never silent Pass)", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
	if len(r.Errors) != 0 {
		t.Errorf("got %d errors, want 0", len(r.Errors))
	}
	hit := false
	for _, w := range r.Warnings {
		if strings.Contains(w.Error(), "--allow-anchor-pending opt-in") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected warning surfacing --allow-anchor-pending opt-in; got:")
		for _, w := range r.Warnings {
			t.Errorf("  %v", w)
		}
	}
}

// =============================================================================
// --offline + not_attempted
// =============================================================================

func TestCheck7OfflineSkips(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{Offline: true})
	if r.Status != StatusSkipped {
		t.Errorf("Status = %v, want Skipped", r.Status)
	}
}

func TestCheck7PassesWhenNotAttempted(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	b.Manifest.AnchorStatus.GithubStatus = "not_attempted"
	b.GithubAnchors = nil
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusPass {
		t.Errorf("Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
}

// =============================================================================
// Anchored stub (load-bearing fail-secure regression test)
// =============================================================================

// TestCheck7AnchoredPathRejectsNilFetcher pins that handleAnchored
// produces an internal-error FAIL when called with nil fetcher
// (defense against operator misconfiguration: the anchored path
// requires network access; a nil fetcher would panic without the
// explicit guard).
func TestCheck7AnchoredPathRejectsNilFetcher(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	// Mutate the bundle to look anchored on every per-day entry.
	for date, anchor := range b.GithubAnchors {
		anchor.MirrorStatus = "anchored"
		fortyHex := strings.Repeat("a", 40)
		anchor.CommitSha = &fortyHex
		path := "daily-roots/00000000-0000-4000-8000-000000000001/" + date + "/example-demo/root.json"
		anchor.Path = &path
		anchoredAt := "2026-05-10T17:00:29Z"
		anchor.AnchoredAt = &anchoredAt
		b.GithubAnchors[date] = anchor
	}
	b.Manifest.AnchorStatus.GithubStatus = "anchored"
	c := newCheck7(t) // nil fetcher per newCheck7 default

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (anchored requires non-nil fetcher)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "nil fetcher") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected nil-fetcher error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck7AnchoredRejectsBadCommitShaFormat pins per-format
// length validation: format=sha1 with 64-char value, format=sha256
// with 40-char value, format=md5 (unknown).
func TestCheck7AnchoredRejectsBadCommitShaFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		format    string
		commitSha string
		wantInErr string
	}{
		{"sha1 wrong length (64)", "sha1", strings.Repeat("a", 64), "invalid"},
		{"sha256 wrong length (40)", "sha256", strings.Repeat("a", 40), "invalid"},
		{"unknown format md5", "md5", strings.Repeat("a", 40), "unknown commit_sha_format"},
		{"unknown format empty", "", strings.Repeat("a", 40), "unknown commit_sha_format"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := cloneExampleForCheck7(t)
			for date, anchor := range b.GithubAnchors {
				anchor.MirrorStatus = "anchored"
				cs := tc.commitSha
				anchor.CommitSha = &cs
				anchor.CommitShaFormat = tc.format
				path := "daily-roots/00000000-0000-4000-8000-000000000001/" + date + "/example-demo/root.json"
				anchor.Path = &path
				at := "2026-05-10T17:00:29Z"
				anchor.AnchoredAt = &at
				b.GithubAnchors[date] = anchor
			}
			b.Manifest.AnchorStatus.GithubStatus = "anchored"
			fetcher := NewMockGithubFetcher()
			c := NewCheck7Github(fetcher)

			r := c.Run(b, CheckOptions{})
			if r.Status != StatusFail {
				t.Errorf("Status = %v, want Fail", r.Status)
			}
			hit := false
			for _, e := range r.Errors {
				if strings.Contains(e.Error(), tc.wantInErr) {
					hit = true
				}
			}
			if !hit {
				t.Errorf("expected error containing %q; got:", tc.wantInErr)
				for _, e := range r.Errors {
					t.Errorf("  %v", e)
				}
			}
		})
	}
}

// TestCheck7AnchoredRejectsNullCommitSha — anchored mirror_status
// with null/empty commit_sha is structurally inconsistent.
func TestCheck7AnchoredRejectsNullCommitSha(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	for date, anchor := range b.GithubAnchors {
		anchor.MirrorStatus = "anchored"
		anchor.CommitShaFormat = "sha1"
		anchor.CommitSha = nil // null
		path := "daily-roots/00000000-0000-4000-8000-000000000001/" + date + "/example-demo/root.json"
		anchor.Path = &path
		at := "2026-05-10T17:00:29Z"
		anchor.AnchoredAt = &at
		b.GithubAnchors[date] = anchor
	}
	b.Manifest.AnchorStatus.GithubStatus = "anchored"
	fetcher := NewMockGithubFetcher()
	c := NewCheck7Github(fetcher)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (null commit_sha)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "commit_sha is null/empty") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected null-commit_sha error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck7AnchoredExampleDemoRequiresAllowDevKey pins the
// Tenant 3 defense: an example-demo bundle's anchored verification
// requires --allow-dev-key (otherwise check 7 would silently use
// the dev SSH key without the operator's opt-in, splitting policy
// from check 1's manifest signature gate).
//
// Construct a synthetic anchored bundle with a valid sha1 commit_sha
// and mock-fetcher root.json that cross-checks (so we get past steps
// 1-4); then the dev-key gate fires before SSH verification.
func TestCheck7AnchoredExampleDemoRequiresAllowDevKey(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	if b.Manifest.BundleType != "example-demo" {
		t.Skipf("expected example-demo bundle, got %q", b.Manifest.BundleType)
	}
	commitSha := strings.Repeat("a", 40)
	for date, anchor := range b.GithubAnchors {
		anchor.MirrorStatus = "anchored"
		anchor.CommitShaFormat = "sha1"
		anchor.CommitSha = &commitSha
		path := "daily-roots/" + b.Manifest.OrganizationID + "/" + date + "/" + b.Manifest.BundleType + "/root.json"
		anchor.Path = &path
		at := "2026-05-10T17:00:29Z"
		anchor.AnchoredAt = &at
		b.GithubAnchors[date] = anchor
	}
	b.Manifest.AnchorStatus.GithubStatus = "anchored"
	// Mock fetcher with cross-check-matching root.json bytes.
	// Phase 6.2.C session 70 BACKLOG 1.33: mock key now includes
	// bundleType segment (here "example-demo" per cloneExampleForCheck7).
	fetcher := NewMockGithubFetcher()
	for date := range b.GithubAnchors {
		key := b.Manifest.OrganizationID + "/" + date + "/" + b.Manifest.BundleType + "/" + commitSha
		fetcher.RootJsonResponses[key] = makeMockRootJsonForBundle(t, b, date)
	}
	c := NewCheck7Github(fetcher)

	// Without --allow-dev-key: anchored example-demo MUST fail with
	// the dev-key-gate diagnostic.
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (--allow-dev-key gate)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "--allow-dev-key") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected --allow-dev-key gate error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck7AnchoredCustomerExportPlaceholderFastFails pins M3
// fix (crypto reviewer): customer-export anchored bundles surface
// a precise V1-pending diagnostic (not the generic SSH-verify
// failure) when they hit the prod placeholder pinned key.
func TestCheck7AnchoredCustomerExportPlaceholderFastFails(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	// Mutate to look like customer-export with anchored state.
	b.Manifest.BundleType = "customer-export"
	commitSha := strings.Repeat("a", 40)
	for date, anchor := range b.GithubAnchors {
		anchor.MirrorStatus = "anchored"
		anchor.CommitShaFormat = "sha1"
		anchor.CommitSha = &commitSha
		path := "daily-roots/" + b.Manifest.OrganizationID + "/" + date + "/" + b.Manifest.BundleType + "/root.json"
		anchor.Path = &path
		at := "2026-05-10T17:00:29Z"
		anchor.AnchoredAt = &at
		b.GithubAnchors[date] = anchor
	}
	b.Manifest.AnchorStatus.GithubStatus = "anchored"

	// Mock fetcher with cross-check-matching root.json bytes
	// (so we get past steps 1-5). Phase 6.2.C session 70 BACKLOG 1.33:
	// bundleType segment included in mock key (here "customer-export"
	// per the BundleType mutation above).
	fetcher := NewMockGithubFetcher()
	for date := range b.GithubAnchors {
		key := b.Manifest.OrganizationID + "/" + date + "/" + b.Manifest.BundleType + "/" + commitSha
		fetcher.RootJsonResponses[key] = makeMockRootJsonForBundle(t, b, date)
	}
	// Provide commit metadata so we get past step 5 to the SSH key
	// dispatch.
	fetcher.CommitMetadataResponses[commitSha] = &CommitMetadata{
		SHA:              commitSha,
		SignatureArmored: fixtureCommit1A1635B3Signature,
		SignedPayload:    []byte("commit payload"),
	}

	c := NewCheck7Github(fetcher)
	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (V1 prod placeholder fail-fast)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "production SSH issuer key is a placeholder pending Phase 5 deploy-bootstrap") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected V1-pending placeholder diagnostic; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// makeMockRootJsonForBundle constructs a synthetic root.json that
// cross-checks against the bundle's contents for the given date.
// Used by anchored-path tests that need a valid root.json fixture.
func makeMockRootJsonForBundle(t *testing.T, b *bundle.Bundle, date string) []byte {
	t.Helper()
	// Find the daily root for this date.
	var rootHash string
	var leafCount int
	for _, dr := range b.DailyRoots.Roots {
		if dr.Date == date {
			rootHash = dr.Root
			leafCount = dr.LeafCount
			break
		}
	}
	if rootHash == "" {
		t.Fatalf("no daily root for date %s", date)
	}
	// Compute OTS receipt SHA-256.
	otsBytes := b.OTSReceipts[date]
	otsSha := sha256Hex(otsBytes)

	// Build per-TSA entries.
	var rfc3161Entries []string
	for tsaName, pair := range b.RFC3161Receipts[date] {
		tsrSha := sha256Hex(pair.TSR)
		chainSha := sha256Hex(pair.ChainPEM)
		rfc3161Entries = append(rfc3161Entries, fmt.Sprintf(
			`{"tsa_name":%q,"receipt_path":"%s__%s.tsr","chain_path":"%s__%s.chain.pem","receipt_sha256":%q,"chain_sha256":%q,"tsa_time":"2026-05-10T17:00:29Z"}`,
			tsaName, date, tsaName, date, tsaName, tsrSha, chainSha))
	}
	rfc3161Joined := strings.Join(rfc3161Entries, ",")

	rootJson := fmt.Sprintf(`{
  "schema_version": 1,
  "bundle_format_version": 1,
  "date": %q,
  "organization_id": %q,
  "produced_by": "test/1.0",
  "root_hash": %q,
  "event_count": 37,
  "merkle": { "leaf_count": %d, "padded_leaf_count": 64, "hash_algorithm": "sha256" },
  "anchors": {
    "opentimestamps": { "receipt_path": "%s.ots", "receipt_sha256": %q, "submitted_at": "2026-05-10T17:00:29Z" },
    "rfc3161": [%s]
  },
  "computed_at": "2026-04-22T23:59:59Z",
  "issuer": { "key_fingerprint_spki_b64": "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=", "key_purpose": "DEMO" }
}`, date, b.Manifest.OrganizationID, rootHash, leafCount, date, otsSha, rfc3161Joined)
	return []byte(rootJson)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// =============================================================================
// failed mirror_status (writer-declared degradation framing)
// =============================================================================

func TestCheck7FailsOnFailedMirrorStatus(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	for date, anchor := range b.GithubAnchors {
		anchor.MirrorStatus = "failed"
		b.GithubAnchors[date] = anchor
	}
	b.Manifest.AnchorStatus.GithubStatus = "failed"
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		// Operator-actionable framing: writer-declared degradation
		// signal, not tampering signal.
		if strings.Contains(e.Error(), "writer-declared mirror_status") &&
			strings.Contains(e.Error(), "anchor commit attempt did not succeed") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected writer-declared-degradation framing; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// =============================================================================
// Consistency divergence (caught at the consistency layer, before
// per-day verification)
// =============================================================================

func TestCheck7FailsOnConsistencyDivergence(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	// Summary says anchored but per-day entry says anchor-pending.
	b.Manifest.AnchorStatus.GithubStatus = "anchored"
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 {
		t.Fatal("expected error")
	}
	if !strings.Contains(r.Errors[0].Error(), "consistency") {
		t.Errorf("first error doesn't mention consistency: %v", r.Errors[0])
	}
}

// =============================================================================
// Missing per-day entry under various status declarations
// =============================================================================

// TestCheck7FailsOnEmptyGithubAnchorsWhenAnchored exercises the
// CONSISTENCY-check failure path (validateGitHubConsistency rejects
// "summary != not_attempted with zero entries"). For per-day
// missing-entry coverage see TestCheck7PerDayMissingEntry below.
func TestCheck7FailsOnEmptyGithubAnchorsWhenAnchored(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	b.GithubAnchors = nil
	b.Manifest.AnchorStatus.GithubStatus = "anchored"
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		// Should hit the consistency-failure path (top-level error
		// before per-day iteration).
		if strings.Contains(e.Error(), "consistency failure") &&
			strings.Contains(e.Error(), "no github_anchors") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected consistency-failure error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck7PerDayMissingEntry exercises the load-bearing per-day
// missing-entry handler (verifyDailyRoot lines ~140-170): when
// some daily roots have github_anchors entries and others don't,
// consistency passes (entries-present-and-matching) and check 7
// dispatches per-day, FAILing on the missing-entry days with the
// branched diagnostic. M1 from D4 commit 2 crypto review: this
// branch had zero direct test coverage.
func TestCheck7PerDayMissingEntry(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	if len(b.DailyRoots.Roots) == 0 || len(b.GithubAnchors) == 0 {
		t.Skip("example bundle missing required structure")
	}
	// Add a synthetic daily root that has NO matching github_anchors
	// entry. Use a date that's distinct from existing roots.
	syntheticDate := "2026-04-21"
	b.DailyRoots.Roots = append(b.DailyRoots.Roots, bundle.DailyRootEntry{
		Date:      syntheticDate,
		Root:      strings.Repeat("a", 64),
		LeafCount: 0,
	})
	// Manifest status = "anchor-pending" matches the existing example
	// per-day entry. Consistency check passes (per-day entries all
	// declare anchor-pending matching summary), then per-day iteration
	// catches the synthetic date with no github_anchors entry.
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{AllowAnchorPending: true})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (per-day missing entry)", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
	}
	// Per-day missing-entry diagnostic mentions the synthetic date
	// AND uses the "anchored, anchor-pending" branch wording
	// ("manifest declares github_status=...").
	hit := false
	for _, e := range r.Errors {
		msg := e.Error()
		if strings.Contains(msg, syntheticDate) &&
			strings.Contains(msg, "manifest declares github_status") &&
			strings.Contains(msg, "no github_anchors") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected per-day missing-entry error for date %s; got:", syntheticDate)
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck7ConsistencyRejectsNotAttemptedWithEntries exercises the
// M3 (security) symmetric not_attempted+entries check. A bundle
// declaring github_status=not_attempted MUST NOT have any per-day
// entries; the consistency check now rejects this redundant shape.
func TestCheck7ConsistencyRejectsNotAttemptedWithEntries(t *testing.T) {
	t.Parallel()
	b := cloneExampleForCheck7(t)
	if len(b.GithubAnchors) == 0 {
		t.Skip("example bundle missing github_anchors entries")
	}
	// Mutate per-day entries to declare not_attempted, then set
	// summary to not_attempted. Without the M3 fix this would
	// pass; with the fix the consistency check rejects.
	for date, anchor := range b.GithubAnchors {
		anchor.MirrorStatus = "not_attempted"
		b.GithubAnchors[date] = anchor
	}
	b.Manifest.AnchorStatus.GithubStatus = "not_attempted"
	c := newCheck7(t)

	r := c.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("Status = %v, want Fail (not_attempted summary with non-empty entries)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "not_attempted MUST mean zero per-day entries") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected not_attempted+entries consistency error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

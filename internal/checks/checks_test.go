package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Shared test infrastructure for Phase 4 Session 2 checks 1-4.
// Each check has its own _test.go file (check1_signature_test.go,
// check2_artifacts_test.go, etc.) that uses these helpers.
// =============================================================================

// exampleBundleCandidates is the layout-agnostic list of relative paths where
// the example bundle may live: its monorepo home, and the standalone published
// verifier repo's testdata/ (where scripts/export-verifier.mjs places it).
var exampleBundleCandidates = []string{
	filepath.Join("apps", "marketing", "public", "examples", "nuwyre_export_cypress-derm_2026-04-22.zip"),
	filepath.Join("testdata", "example-bundle.zip"),
}

// findArtifactOrEmpty walks up from the test working directory, returning the
// first <ancestor>/<candidate> that exists, or "" if none do.
func findArtifactOrEmpty(candidates ...string) string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := wd
	for {
		for _, rel := range candidates {
			cand := filepath.Join(dir, rel)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// findArtifact is findArtifactOrEmpty with a test-skip when nothing is found,
// so the standalone published repo can choose which optional artifacts to ship
// without failing the suite.
func findArtifact(t *testing.T, candidates ...string) string {
	t.Helper()
	if p := findArtifactOrEmpty(candidates...); p != "" {
		return p
	}
	wd, _ := os.Getwd()
	t.Skipf("artifact not found walking up from %s (looked for %v); ship it under testdata/ to run this test", wd, candidates)
	return ""
}

// loadExampleBundle returns the parsed example bundle. Subtests use this as the
// canonical "well-formed bundle" fixture. Resolved layout-agnostically (monorepo
// path or standalone testdata/); skips if absent.
func loadExampleBundle(t *testing.T) *bundle.Bundle {
	t.Helper()
	b, err := bundle.Load(findArtifact(t, exampleBundleCandidates...))
	if err != nil {
		t.Fatalf("loadExampleBundle: %v", err)
	}
	return b
}

// =============================================================================
// CheckStatus + CheckResult unit tests (no Bundle required).
// =============================================================================

func TestCheckStatusString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    CheckStatus
		want string
	}{
		{StatusPass, "pass"},
		{StatusFail, "fail"},
		{StatusWarn, "warn"},
		{StatusSkipped, "skipped"},
		{CheckStatus(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("CheckStatus(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestResultFactoringOnEmptyLists(t *testing.T) {
	t.Parallel()
	r := Result(1, "test", "test", nil, nil)
	if r.Status != StatusPass {
		t.Errorf("empty errors+warnings: Status = %v, want Pass", r.Status)
	}
	if r.CheckID != 1 || r.CheckName != "test" || r.CheckSlug != "test" {
		t.Errorf("ID/Name/Slug not preserved: %+v", r)
	}
}

func TestResultFactoringOnWarningsOnly(t *testing.T) {
	t.Parallel()
	r := Result(1, "test", "test", nil, []error{errors.New("w1"), errors.New("w2")})
	if r.Status != StatusWarn {
		t.Errorf("warnings only: Status = %v, want Warn", r.Status)
	}
	if len(r.Warnings) != 2 {
		t.Errorf("warnings preserved: got %d, want 2", len(r.Warnings))
	}
}

func TestResultFactoringOnErrorsPresent(t *testing.T) {
	t.Parallel()
	// Errors present → Fail regardless of warnings.
	r := Result(1, "test", "test", []error{errors.New("e1")}, []error{errors.New("w1")})
	if r.Status != StatusFail {
		t.Errorf("errors+warnings: Status = %v, want Fail", r.Status)
	}
	// Warnings still surfaced for diagnostic context.
	if len(r.Warnings) != 1 {
		t.Errorf("warnings not preserved on Fail: got %d, want 1", len(r.Warnings))
	}
}

func TestResultPreservesMultipleErrorsInOrder(t *testing.T) {
	t.Parallel()
	errs := []error{errors.New("first"), errors.New("second"), errors.New("third")}
	r := Result(1, "test", "test", errs, nil)
	if len(r.Errors) != 3 {
		t.Fatalf("len(Errors) = %d, want 3", len(r.Errors))
	}
	for i, want := range []string{"first", "second", "third"} {
		if r.Errors[i].Error() != want {
			t.Errorf("Errors[%d] = %q, want %q", i, r.Errors[i].Error(), want)
		}
	}
}

func TestSkippedPopulatesSkipReasonNotWarnings(t *testing.T) {
	t.Parallel()
	// Skipped's reason MUST land in SkipReason, NOT Warnings.
	// This separation lets reporters distinguish "skipped because
	// --offline" from "warned because pending OTS" without parsing
	// message strings.
	r := Skipped(5, "OpenTimestamps", "opentimestamps", "network disabled by --offline")
	if r.Status != StatusSkipped {
		t.Errorf("Status = %v, want Skipped", r.Status)
	}
	if r.SkipReason != "network disabled by --offline" {
		t.Errorf("SkipReason = %q, want the documented reason", r.SkipReason)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("Skipped result has %d warnings; should have 0 (reason lives in SkipReason)", len(r.Warnings))
	}
	if len(r.Errors) != 0 {
		t.Errorf("Skipped result has %d errors; should have 0", len(r.Errors))
	}
}

// =============================================================================
// Errorf / Warnf format tests.
// =============================================================================

func TestErrorfCanonicalFormat(t *testing.T) {
	t.Parallel()
	err := Errorf(2, "artifact integrity", "events.jsonl",
		"declared SHA-256 abc but computed def",
		"§3", "manifest hash matches artifact bytes")
	want := "check 2 (artifact integrity): events.jsonl: declared SHA-256 abc but computed def; spec §3 requires manifest hash matches artifact bytes"
	if got := err.Error(); got != want {
		t.Errorf("Errorf:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestErrorfOmitsArtifactPathWhenEmpty(t *testing.T) {
	t.Parallel()
	err := Errorf(1, "manifest signature", "",
		"signature decode failed",
		"§5", "signature.sig is base64-encoded Ed25519 signature")
	want := "check 1 (manifest signature): signature decode failed; spec §5 requires signature.sig is base64-encoded Ed25519 signature"
	if got := err.Error(); got != want {
		t.Errorf("Errorf empty path:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestErrorfOmitsSpecRefWhenBothEmpty(t *testing.T) {
	t.Parallel()
	err := Errorf(3, "hash chain", "events.jsonl line 5",
		"unexpected internal error",
		"", "")
	want := "check 3 (hash chain): events.jsonl line 5: unexpected internal error"
	if got := err.Error(); got != want {
		t.Errorf("Errorf no spec:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestErrorfOmitsSpecRefWhenSectionEmptyButRulePresent covers the H4
// reviewer finding: asymmetric (one-empty) input MUST NOT produce a
// malformed message like "...; spec  requires <rule>".
func TestErrorfOmitsSpecRefWhenSectionEmptyButRulePresent(t *testing.T) {
	t.Parallel()
	err := Errorf(3, "hash chain", "events.jsonl",
		"missing spec section",
		"", "manifest hash matches")
	if strings.Contains(err.Error(), "spec  requires") {
		t.Errorf("Errorf double-space malformed: %q", err.Error())
	}
	if strings.Contains(err.Error(), "spec  ") {
		t.Errorf("Errorf with empty section produced malformed output: %q", err.Error())
	}
	// Issue should still be present.
	if !strings.Contains(err.Error(), "missing spec section") {
		t.Errorf("Errorf dropped the issue: %q", err.Error())
	}
}

// TestErrorfOmitsSpecRefWhenRuleEmptyButSectionPresent — the symmetric
// asymmetric case.
func TestErrorfOmitsSpecRefWhenRuleEmptyButSectionPresent(t *testing.T) {
	t.Parallel()
	err := Errorf(3, "hash chain", "events.jsonl",
		"missing spec rule",
		"§5", "")
	if strings.Contains(err.Error(), "spec §5 requires ") {
		// Trailing space + empty rule = malformed.
		if strings.HasSuffix(err.Error(), "requires ") || strings.HasSuffix(err.Error(), "requires") {
			t.Errorf("Errorf trailing-empty-rule malformed: %q", err.Error())
		}
	}
}

// =============================================================================
// RunChecks aggregation — overall status semantics.
// =============================================================================

// stubCheck is a Check whose Run returns a pre-set CheckResult and
// captures the opts received for later assertion. Used by RunChecks
// aggregation tests so we don't depend on the real check
// implementations (which haven't landed yet at the shared-
// infrastructure commit).
type stubCheck struct {
	id     int
	name   string
	slug   string
	result CheckResult
	// captured CheckOptions from the most recent Run call.
	captured *CheckOptions
}

func (s *stubCheck) ID() int      { return s.id }
func (s *stubCheck) Name() string { return s.name }
func (s *stubCheck) Slug() string { return s.slug }
func (s *stubCheck) Run(_ *bundle.Bundle, opts CheckOptions) CheckResult {
	cap := opts
	s.captured = &cap
	return s.result
}

// stubBundle is a non-nil Bundle for tests that don't actually need
// bundle contents. RunChecks rejects nil bundles, so test fixtures
// MUST supply at least an empty Bundle struct.
func stubBundle() *bundle.Bundle {
	return &bundle.Bundle{}
}

func TestRunChecksAggregatesPassWhenAllPass(t *testing.T) {
	t.Parallel()
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	c2 := &stubCheck{id: 2, name: "b", slug: "b", result: CheckResult{Status: StatusPass}}
	_, overall := RunChecks(stubBundle(), CheckOptions{}, c1, c2)
	if overall != StatusPass {
		t.Errorf("all Pass: overall = %v, want Pass", overall)
	}
}

func TestRunChecksAggregatesFailOnAnyFail(t *testing.T) {
	t.Parallel()
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	c2 := &stubCheck{id: 2, name: "b", slug: "b", result: CheckResult{Status: StatusFail}}
	c3 := &stubCheck{id: 3, name: "c", slug: "c", result: CheckResult{Status: StatusWarn}}
	_, overall := RunChecks(stubBundle(), CheckOptions{}, c1, c2, c3)
	if overall != StatusFail {
		t.Errorf("with Fail: overall = %v, want Fail", overall)
	}
}

func TestRunChecksAggregatesWarnWhenWarnButNoFail(t *testing.T) {
	t.Parallel()
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	c2 := &stubCheck{id: 2, name: "b", slug: "b", result: CheckResult{Status: StatusWarn}}
	c3 := &stubCheck{id: 3, name: "c", slug: "c", result: CheckResult{Status: StatusPass}}
	_, overall := RunChecks(stubBundle(), CheckOptions{}, c1, c2, c3)
	if overall != StatusWarn {
		t.Errorf("with Warn (no Fail): overall = %v, want Warn", overall)
	}
}

// TestRunChecksAggregatesSkippedWhenSkippedButNoFail asserts the
// security-auditor H1 fix: spec §14 mandates "All seven checks MUST
// pass for the verifier to report 'verified.'" A run with checks 5/6/7
// Skipped under --offline is partial verification, NOT verified. The
// aggregator surfaces this with overall=Skipped (distinct from Pass).
func TestRunChecksAggregatesSkippedWhenSkippedButNoFail(t *testing.T) {
	t.Parallel()
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	c2 := &stubCheck{id: 2, name: "b", slug: "b", result: CheckResult{Status: StatusSkipped}}
	c3 := &stubCheck{id: 3, name: "c", slug: "c", result: CheckResult{Status: StatusPass}}
	_, overall := RunChecks(stubBundle(), CheckOptions{}, c1, c2, c3)
	if overall != StatusSkipped {
		t.Errorf("Pass+Skipped: overall = %v, want Skipped (spec §14: Skipped is non-Pass)", overall)
	}
}

func TestRunChecksFailOverridesSkipped(t *testing.T) {
	t.Parallel()
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusFail}}
	c2 := &stubCheck{id: 2, name: "b", slug: "b", result: CheckResult{Status: StatusSkipped}}
	_, overall := RunChecks(stubBundle(), CheckOptions{}, c1, c2)
	if overall != StatusFail {
		t.Errorf("Fail+Skipped: overall = %v, want Fail", overall)
	}
}

func TestRunChecksSkippedOverridesWarn(t *testing.T) {
	t.Parallel()
	// Warn + Skipped (no Fail) → overall Skipped, since Skipped is
	// the more-severe non-Pass state per the spec §14 framing.
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusWarn}}
	c2 := &stubCheck{id: 2, name: "b", slug: "b", result: CheckResult{Status: StatusSkipped}}
	_, overall := RunChecks(stubBundle(), CheckOptions{}, c1, c2)
	if overall != StatusSkipped {
		t.Errorf("Warn+Skipped: overall = %v, want Skipped", overall)
	}
}

func TestRunChecksRejectsEmptyRegistry(t *testing.T) {
	t.Parallel()
	// Per the security-auditor M2 finding: zero registered checks
	// is a programmer error; refuse to claim verification.
	results, overall := RunChecks(stubBundle(), CheckOptions{})
	if overall != StatusFail {
		t.Errorf("empty registry: overall = %v, want Fail", overall)
	}
	if len(results) != 1 {
		t.Fatalf("empty registry: %d results, want 1 synthetic Fail", len(results))
	}
	if results[0].Status != StatusFail {
		t.Errorf("synthetic result: Status = %v, want Fail", results[0].Status)
	}
}

func TestRunChecksRejectsNilBundle(t *testing.T) {
	t.Parallel()
	c1 := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	results, overall := RunChecks(nil, CheckOptions{}, c1)
	if overall != StatusFail {
		t.Errorf("nil bundle: overall = %v, want Fail", overall)
	}
	if len(results) != 1 || results[0].Status != StatusFail {
		t.Errorf("nil bundle: %+v, want single synthetic Fail", results)
	}
}

func TestRunChecksPopulatesDuration(t *testing.T) {
	t.Parallel()
	c := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	results, _ := RunChecks(stubBundle(), CheckOptions{}, c)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].DurationMS < 0 {
		t.Errorf("DurationMS negative: %d", results[0].DurationMS)
	}
}

// TestRunChecksDefaultsNowToUTC verifies the H2 reviewer finding fix:
// callers passing zero-valued CheckOptions.Now get a non-zero UTC
// time — actually checked, not just that RunChecks doesn't panic.
// Sessions 3's RFC 3161 chain validation depends on Now being set
// AND in UTC, so a regression test locks this contract.
func TestRunChecksDefaultsNowToUTC(t *testing.T) {
	t.Parallel()
	c := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	_, _ = RunChecks(stubBundle(), CheckOptions{}, c)
	if c.captured == nil {
		t.Fatal("stubCheck did not capture opts")
	}
	if c.captured.Now.IsZero() {
		t.Error("Now defaulted to zero (want non-zero default)")
	}
	if loc := c.captured.Now.Location(); loc != time.UTC {
		t.Errorf("Now location = %v, want UTC", loc)
	}
}

func TestRunChecksPreservesExplicitNow(t *testing.T) {
	t.Parallel()
	c := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	want := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	_, _ = RunChecks(stubBundle(), CheckOptions{Now: want}, c)
	if !c.captured.Now.Equal(want) {
		t.Errorf("Now = %v, want %v (caller-supplied value not preserved)", c.captured.Now, want)
	}
}

// =============================================================================
// Panic-recovery in RunChecks (M1 from commit-1 reviewer pass + M1
// from security-auditor).
// =============================================================================

// panicCheck is a Check whose Run panics. RunChecks must convert
// the panic to a Fail result and continue to subsequent checks.
type panicCheck struct {
	id   int
	name string
	slug string
}

func (p *panicCheck) ID() int      { return p.id }
func (p *panicCheck) Name() string { return p.name }
func (p *panicCheck) Slug() string { return p.slug }
func (p *panicCheck) Run(_ *bundle.Bundle, _ CheckOptions) CheckResult {
	panic("simulated check internal error")
}

func TestRunChecksRecoversPanicsAsFail(t *testing.T) {
	t.Parallel()
	good := &stubCheck{id: 1, name: "a", slug: "a", result: CheckResult{Status: StatusPass}}
	bad := &panicCheck{id: 2, name: "b", slug: "b"}
	after := &stubCheck{id: 3, name: "c", slug: "c", result: CheckResult{Status: StatusPass}}

	results, overall := RunChecks(stubBundle(), CheckOptions{}, good, bad, after)

	if overall != StatusFail {
		t.Errorf("with panic: overall = %v, want Fail", overall)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (panic must not abort subsequent checks)", len(results))
	}
	if results[1].Status != StatusFail {
		t.Errorf("panicked check: Status = %v, want Fail", results[1].Status)
	}
	if len(results[1].Errors) == 0 {
		t.Error("panicked check has no errors; expected internal-error message")
	} else if !strings.Contains(results[1].Errors[0].Error(), "internal verifier error") {
		t.Errorf("panic error doesn't mention 'internal verifier error': %v", results[1].Errors[0])
	}
	// Crucially, the third check ran AFTER the panic.
	if results[2].Status != StatusPass {
		t.Errorf("post-panic check: Status = %v, want Pass (panic must not suppress subsequent checks)", results[2].Status)
	}
}

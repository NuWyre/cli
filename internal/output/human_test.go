package output

import (
	"errors"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/checks"
)

// =============================================================================
// HumanFormatter tests (Phase 4 Session 3 D5 commit 1)
//
// Tests cover:
//   - Happy path: per-check headers + summary + verdict line
//   - With warnings: indented [warn] markers
//   - With errors: indented [fail] markers
//   - With skip reason: indented [skip] marker
//   - Color: ANSI escapes present when color=true; absent when false
//   - PARTIAL VERIFICATION: distinct verdict label rendered
//   - Empty results: graceful summary + verdict
// =============================================================================

func makeResult(id int, name, slug string, status checks.CheckStatus) checks.CheckResult {
	return checks.CheckResult{
		CheckID:   id,
		CheckName: name,
		CheckSlug: slug,
		Status:    status,
	}
}

func TestHumanFormatterAllPass(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false) // no color for stable byte assertions
	results := []checks.CheckResult{
		makeResult(1, "manifest signature", "manifest-signature", checks.StatusPass),
		makeResult(2, "artifact integrity", "artifact-integrity", checks.StatusPass),
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out := f.FormatResults(results, verdict)

	wantSubstrings := []string{
		"Check 1 (manifest signature):",
		"PASS",
		"Check 2 (artifact integrity):",
		"Summary: 2 passed, 0 failed, 0 warned, 0 skipped",
		"Verdict: PASS",
		"Exit code: 0",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestHumanFormatterWithErrors(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false)
	r := checks.CheckResult{
		CheckID:   2,
		CheckName: "artifact integrity",
		CheckSlug: "artifact-integrity",
		Status:    checks.StatusFail,
		Errors: []error{
			errors.New("events.jsonl: declared SHA-256 abc123 but computed def456"),
		},
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	if !strings.Contains(out, "[fail]") {
		t.Errorf("output missing [fail] marker:\n%s", out)
	}
	if !strings.Contains(out, "events.jsonl: declared SHA-256 abc123 but computed def456") {
		t.Errorf("output missing error text:\n%s", out)
	}
	if !strings.Contains(out, "Verdict: FAIL") {
		t.Errorf("output missing FAIL verdict:\n%s", out)
	}
}

func TestHumanFormatterWithWarnings(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false)
	r := checks.CheckResult{
		CheckID:   5,
		CheckName: "OpenTimestamps Bitcoin anchor",
		CheckSlug: "opentimestamps",
		Status:    checks.StatusWarn,
		Warnings: []error{
			errors.New("OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
		},
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	if !strings.Contains(out, "[warn]") {
		t.Errorf("output missing [warn] marker:\n%s", out)
	}
	if !strings.Contains(out, "pending Bitcoin confirmation") {
		t.Errorf("output missing warning text:\n%s", out)
	}
	if !strings.Contains(out, "PARTIAL VERIFICATION") {
		t.Errorf("output missing PARTIAL VERIFICATION verdict:\n%s", out)
	}
}

func TestHumanFormatterWithSkipReason(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false)
	r := checks.CheckResult{
		CheckID:    5,
		CheckName:  "OpenTimestamps Bitcoin anchor",
		CheckSlug:  "opentimestamps",
		Status:     checks.StatusSkipped,
		SkipReason: "anchor verification skipped — --offline mode",
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{Offline: true})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	if !strings.Contains(out, "SKIPPED") {
		t.Errorf("output missing SKIPPED status:\n%s", out)
	}
	if !strings.Contains(out, "[skip]") {
		t.Errorf("output missing [skip] marker:\n%s", out)
	}
	if !strings.Contains(out, "--offline mode") {
		t.Errorf("output missing skip reason text:\n%s", out)
	}
}

// =============================================================================
// Color handling
// =============================================================================

func TestHumanFormatterColorEnabled(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(true)
	results := []checks.CheckResult{
		makeResult(1, "manifest signature", "manifest-signature", checks.StatusPass),
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out := f.FormatResults(results, verdict)

	if !strings.Contains(out, "\x1b[") {
		t.Errorf("color=true should emit ANSI escapes; output had none:\n%s", out)
	}
	if !strings.Contains(out, "\x1b[0m") {
		t.Errorf("color=true should emit reset escapes; output had none:\n%s", out)
	}
}

func TestHumanFormatterColorDisabled(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false)
	results := []checks.CheckResult{
		makeResult(1, "manifest signature", "manifest-signature", checks.StatusPass),
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out := f.FormatResults(results, verdict)

	if strings.Contains(out, "\x1b[") {
		t.Errorf("color=false should emit no ANSI escapes; output had some:\n%s", out)
	}
}

// =============================================================================
// Determinism (Tenant 2)
// =============================================================================

func TestHumanFormatterDeterministic(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false)
	results := []checks.CheckResult{
		makeResult(1, "manifest signature", "manifest-signature", checks.StatusPass),
		makeResult(2, "artifact integrity", "artifact-integrity", checks.StatusFail),
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out1 := f.FormatResults(results, verdict)
	out2 := f.FormatResults(results, verdict)
	if out1 != out2 {
		t.Errorf("non-deterministic output:\n--- out1 ---\n%s\n--- out2 ---\n%s", out1, out2)
	}
}

// =============================================================================
// Empty results — graceful handling
// =============================================================================

func TestHumanFormatterEmptyResults(t *testing.T) {
	t.Parallel()
	f := NewHumanFormatter(false)
	verdict := checks.AggregateVerdict(nil, checks.CheckOptions{})
	out := f.FormatResults(nil, verdict)
	// Even with no checks, summary + verdict line MUST render.
	if !strings.Contains(out, "Summary:") {
		t.Errorf("empty results should still render summary line:\n%s", out)
	}
	if !strings.Contains(out, "Verdict: FAIL") {
		t.Errorf("empty results verdict should be FAIL:\n%s", out)
	}
	if !strings.Contains(out, "no checks executed") {
		t.Errorf("empty results reason should explain:\n%s", out)
	}
}

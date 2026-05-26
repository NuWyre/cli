package output

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/checks"
)

// =============================================================================
// JSONFormatter tests (Phase 4 Session 3 D5 commit 1)
//
// Tests cover:
//   - Happy path: schema matches; output_format_version="1" present
//   - Errors / warnings serialized as []string with .Error() text
//   - Status / verdict labels match canonical lowercase enum forms
//   - Indented vs non-indented output both parseable
//   - Determinism: same input → same bytes
//   - Empty results gracefully serialized (Tenant 3 fail-secure)
//   - Skip reason serialized only when present (omitempty)
// =============================================================================

func TestJSONFormatterHappyPath(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	results := []checks.CheckResult{
		{
			CheckID:    1,
			CheckName:  "manifest signature",
			CheckSlug:  "manifest-signature",
			Status:     checks.StatusPass,
			DurationMS: 12,
		},
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out := f.FormatResults(results, verdict)

	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output not parseable JSON: %v\n%s", err, out)
	}
	if parsed.OutputFormatVersion != "1" {
		t.Errorf("OutputFormatVersion = %q, want %q", parsed.OutputFormatVersion, "1")
	}
	if parsed.Verdict != "pass" {
		t.Errorf("Verdict = %q, want %q", parsed.Verdict, "pass")
	}
	if parsed.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", parsed.ExitCode)
	}
	if len(parsed.Checks) != 1 {
		t.Fatalf("Checks len = %d, want 1", len(parsed.Checks))
	}
	c := parsed.Checks[0]
	if c.CheckID != 1 || c.Status != "pass" || c.CheckSlug != "manifest-signature" {
		t.Errorf("Check[0] mismatch: %+v", c)
	}
	if c.Errors == nil || c.Warnings == nil {
		t.Errorf("Errors/Warnings should be empty arrays not null: %+v", c)
	}
	if parsed.Summary.Passed != 1 {
		t.Errorf("Summary.Passed = %d, want 1", parsed.Summary.Passed)
	}
}

func TestJSONFormatterWithErrorsAndWarnings(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	r := checks.CheckResult{
		CheckID:   2,
		CheckName: "artifact integrity",
		CheckSlug: "artifact-integrity",
		Status:    checks.StatusFail,
		Errors:    []error{errors.New("events.jsonl SHA mismatch")},
		Warnings:  []error{errors.New("scenario_index.json artifact path normalized")},
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output not parseable JSON: %v\n%s", err, out)
	}
	if parsed.Verdict != "fail" {
		t.Errorf("Verdict = %q, want %q", parsed.Verdict, "fail")
	}
	if len(parsed.Checks) != 1 {
		t.Fatalf("Checks len = %d, want 1", len(parsed.Checks))
	}
	c := parsed.Checks[0]
	if len(c.Errors) != 1 || c.Errors[0] != "events.jsonl SHA mismatch" {
		t.Errorf("Errors mismatch: %+v", c.Errors)
	}
	if len(c.Warnings) != 1 || c.Warnings[0] != "scenario_index.json artifact path normalized" {
		t.Errorf("Warnings mismatch: %+v", c.Warnings)
	}
}

func TestJSONFormatterPartialVerificationLabel(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	r := checks.CheckResult{
		CheckID:  5,
		Status:   checks.StatusWarn,
		Warnings: []error{errors.New("OTS pending Bitcoin confirmation")},
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not parseable JSON: %v", err)
	}
	if parsed.Verdict != "partial_verification" {
		t.Errorf("Verdict = %q, want %q", parsed.Verdict, "partial_verification")
	}
	if parsed.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", parsed.ExitCode)
	}
}

func TestJSONFormatterSkipReason(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	r := checks.CheckResult{
		CheckID:    5,
		Status:     checks.StatusSkipped,
		SkipReason: "anchor verification skipped — --offline mode",
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{Offline: true})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not parseable JSON: %v", err)
	}
	if len(parsed.Checks) != 1 || parsed.Checks[0].SkipReason == "" {
		t.Errorf("SkipReason should be populated: %+v", parsed.Checks)
	}
}

// =============================================================================
// Indented vs non-indented modes
// =============================================================================

func TestJSONFormatterIndentedVsCompact(t *testing.T) {
	t.Parallel()
	results := []checks.CheckResult{
		{CheckID: 1, Status: checks.StatusPass},
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})

	indented := NewJSONFormatter(true).FormatResults(results, verdict)
	compact := NewJSONFormatter(false).FormatResults(results, verdict)

	// Both must parse to the same content.
	var i, c JSONOutput
	if err := json.Unmarshal([]byte(indented), &i); err != nil {
		t.Fatalf("indented not parseable: %v", err)
	}
	if err := json.Unmarshal([]byte(compact), &c); err != nil {
		t.Fatalf("compact not parseable: %v", err)
	}
	if i.Verdict != c.Verdict || i.ExitCode != c.ExitCode {
		t.Errorf("indented + compact disagree on verdict/exit: %+v vs %+v", i, c)
	}
	// Indented should be longer (whitespace).
	if len(indented) <= len(compact) {
		t.Errorf("indented (%d) should be longer than compact (%d)", len(indented), len(compact))
	}
}

// =============================================================================
// Determinism (Tenant 2)
// =============================================================================

func TestJSONFormatterDeterministic(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	results := []checks.CheckResult{
		{CheckID: 1, Status: checks.StatusPass, DurationMS: 12},
		{CheckID: 2, Status: checks.StatusFail, Errors: []error{errors.New("e")}},
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out1 := f.FormatResults(results, verdict)
	out2 := f.FormatResults(results, verdict)
	if out1 != out2 {
		t.Errorf("non-deterministic output:\n--- out1 ---\n%s\n--- out2 ---\n%s", out1, out2)
	}
}

// =============================================================================
// Empty results
// =============================================================================

func TestJSONFormatterEmptyResults(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	verdict := checks.AggregateVerdict(nil, checks.CheckOptions{})
	out := f.FormatResults(nil, verdict)

	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("empty-results output not parseable: %v\n%s", err, out)
	}
	if parsed.Verdict != "fail" {
		t.Errorf("empty-results Verdict = %q, want fail", parsed.Verdict)
	}
	if parsed.Checks == nil {
		t.Errorf("Checks should be empty array not null")
	}
	if !strings.Contains(parsed.Reason, "no checks executed") {
		t.Errorf("Reason missing 'no checks executed': %q", parsed.Reason)
	}
}

// =============================================================================
// Output format version is the contract version, not a build identifier
// =============================================================================

func TestJSONFormatterOutputFormatVersionConstant(t *testing.T) {
	t.Parallel()
	if OutputFormatVersion != "1" {
		t.Errorf("OutputFormatVersion = %q, want %q (Tenant 1: schema contract is durable; bumping requires intentional change)",
			OutputFormatVersion, "1")
	}
}

// =============================================================================
// v1 contract field stability (D5 c1+c2 reviewer pass clarifications)
// =============================================================================

// TestJSONFormatterSkipReasonAlwaysEmitted pins crypto-integrity-
// reviewer M2 fix: skip_reason is always present (empty string when
// not skipped), not omitted via omitempty. Schema-stability with
// errors/warnings always-emit discipline.
func TestJSONFormatterSkipReasonAlwaysEmitted(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(false)
	results := []checks.CheckResult{
		{CheckID: 1, Status: checks.StatusPass}, // not skipped
	}
	verdict := checks.AggregateVerdict(results, checks.CheckOptions{})
	out := f.FormatResults(results, verdict)
	if !strings.Contains(out, `"skip_reason"`) {
		t.Errorf("skip_reason should always be emitted (empty when not skipped); not found in:\n%s", out)
	}
}

// TestJSONFormatterWarnsOptedIntoPassFieldSurfaced pins that the
// warns_opted_into_pass count appears in the JSON summary. CI
// integrations parse this to understand when a Pass verdict
// includes warnings folded via --allow-* flags.
func TestJSONFormatterWarnsOptedIntoPassFieldSurfaced(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(true)
	r := checks.CheckResult{
		CheckID:  5,
		Status:   checks.StatusWarn,
		Warnings: []error{errors.New("OTS receipt for 2026-04-22 is pending Bitcoin confirmation")},
	}
	verdict := checks.AggregateVerdict([]checks.CheckResult{r}, checks.CheckOptions{AllowPendingOTS: true})
	out := f.FormatResults([]checks.CheckResult{r}, verdict)

	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not parseable: %v\n%s", err, out)
	}
	if parsed.Summary.WarnsOptedIntoPass != 1 {
		t.Errorf("Summary.WarnsOptedIntoPass = %d, want 1\nfull JSON:\n%s",
			parsed.Summary.WarnsOptedIntoPass, out)
	}
	if !strings.Contains(out, `"warns_opted_into_pass"`) {
		t.Errorf("JSON output missing warns_opted_into_pass field:\n%s", out)
	}
}

// TestJSONFormatterReasonFieldPresent pins that the Reason field
// is in v1 contract: present in both happy + sad path. Crypto-
// integrity-reviewer M3 (D5 c1+c2 review).
func TestJSONFormatterReasonFieldPresent(t *testing.T) {
	t.Parallel()
	f := NewJSONFormatter(false)
	cases := []struct {
		name    string
		results []checks.CheckResult
	}{
		{"empty", nil},
		{"all-pass", []checks.CheckResult{{CheckID: 1, Status: checks.StatusPass}}},
		{"fail", []checks.CheckResult{{CheckID: 1, Status: checks.StatusFail, Errors: []error{errors.New("e")}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verdict := checks.AggregateVerdict(c.results, checks.CheckOptions{})
			out := f.FormatResults(c.results, verdict)
			if !strings.Contains(out, `"reason"`) {
				t.Errorf("reason field missing in %s case:\n%s", c.name, out)
			}
		})
	}
}

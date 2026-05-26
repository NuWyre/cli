package output

import (
	"fmt"
	"strings"

	"github.com/nuwyre/cli/internal/checks"
)

// Formatter is the common interface both HumanFormatter and
// JSONFormatter satisfy. Callers (cmd/nuwyre/verify.go) hold a
// Formatter interface value and dispatch to the concrete type per
// the --json flag.
type Formatter interface {
	// FormatResults renders the verification report. The verdict
	// already encodes overall pass/fail/partial + exit code +
	// reason; the formatter surfaces both the per-check breakdown
	// and the overall verdict.
	FormatResults(results []checks.CheckResult, verdict checks.ExitVerdict) string
}

// HumanFormatter renders the verification report for terminal
// consumption. ANSI color is enabled when both:
//
//  1. The caller passed color=true (which the CLI sets based on
//     TTY detection — non-TTY stdout disables color regardless).
//  2. The NO_COLOR env var is unset (per the de-facto NO_COLOR
//     convention at https://no-color.org/).
//
// Color choices are minimal: pass=green, fail=red, warn=yellow,
// skipped=cyan. Reset after each colored token so terminal state
// doesn't leak into surrounding shell prompts.
type HumanFormatter struct {
	color bool
}

// NewHumanFormatter constructs a formatter. Pass color=true when
// stdout is a TTY AND NO_COLOR is unset; the CLI handles that
// detection.
func NewHumanFormatter(color bool) *HumanFormatter {
	return &HumanFormatter{color: color}
}

// ANSI escape codes (only emitted when f.color is true).
const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiBold   = "\x1b[1m"
)

// FormatResults implements Formatter. Output shape:
//
//	Check 1 (manifest signature):       PASS [12ms]
//	Check 2 (artifact integrity):       PASS [45ms]
//	Check 3 (hash chain):               PASS [8ms]
//	Check 4 (Merkle proof):             PASS [3ms]
//	Check 5 (OpenTimestamps):           WARN [102ms]
//	  [warn] OTS receipt for date 2026-04-22 is pending Bitcoin confirmation
//	Check 6 (RFC 3161 timestamp):       PASS [156ms]
//	Check 7 (GitHub anchor):            FAIL [4ms]
//	  [fail] mirror_status="anchor-pending" for daily root date "2026-04-22" — V1 ...
//
//	Summary: 5 passed, 1 failed, 1 warned, 0 skipped
//	Verdict: FAIL — verification FAILED: 1 check(s) failed (check 7)
//	Exit code: 1
//
// Tenant 4 (simplicity): one consistent format across checks; per-
// check warnings/errors indent at two spaces with `[warn]` / `[fail]`
// markers so operators parse the output uniformly.
func (f *HumanFormatter) FormatResults(results []checks.CheckResult, verdict checks.ExitVerdict) string {
	var b strings.Builder

	// Per-check lines + per-check warnings/errors.
	for _, r := range results {
		f.writeCheckLine(&b, r)
		f.writeCheckDetails(&b, r)
	}

	if len(results) > 0 {
		b.WriteString("\n")
	}

	// Summary line.
	fmt.Fprintf(&b, "Summary: %d passed, %d failed, %d warned, %d skipped\n",
		verdict.Summary.Passed, verdict.Summary.Failed,
		verdict.Summary.Warned, verdict.Summary.Skipped)

	// Verdict line + exit code.
	verdictLabel := verdictDisplayLabel(verdict.Verdict)
	verdictColor := verdictDisplayColor(verdict.Verdict)
	fmt.Fprintf(&b, "Verdict: %s — %s\n",
		f.colored(verdictColor, verdictLabel), verdict.Reason)
	fmt.Fprintf(&b, "Exit code: %d\n", verdict.ExitCode)

	return b.String()
}

// writeCheckLine emits the single-line per-check verdict header.
//
// Padding ceiling per code-reviewer S1 (D5 c1+c2 review): production
// header lengths are
//   - "Check 1 (manifest signature):"        — 30 chars
//   - "Check 2 (artifact integrity):"        — 30 chars
//   - "Check 3 (hash chain):"                — 21 chars
//   - "Check 4 (Merkle proof):"              — 23 chars
//   - "Check 5 (OpenTimestamps Bitcoin anchor):" — 40 chars (LONGEST)
//   - "Check 6 (RFC 3161 timestamp anchor):" — 36 chars
//   - "Check 7 (GitHub anchor cross-check):" — 36 chars
//
// Pad to 44 chars: gives check 5 (longest) four padding chars +
// headroom for any future check name <14 chars beyond "Check N (".
// Future checks with longer names MUST honor this 44-char ceiling
// or the column alignment breaks for that one row.
func (f *HumanFormatter) writeCheckLine(b *strings.Builder, r checks.CheckResult) {
	statusLabel := strings.ToUpper(r.Status.String())
	statusColor := statusDisplayColor(r.Status)
	header := fmt.Sprintf("Check %d (%s):", r.CheckID, r.CheckName)
	fmt.Fprintf(b, "%-44s %s [%dms]\n",
		header, f.colored(statusColor, statusLabel), r.DurationMS)
}

// writeCheckDetails emits the indented warnings + errors + skip
// reason under the check header. Errors first (most-actionable),
// then warnings, then skip reason.
func (f *HumanFormatter) writeCheckDetails(b *strings.Builder, r checks.CheckResult) {
	for _, e := range r.Errors {
		fmt.Fprintf(b, "  %s %s\n", f.colored(ansiRed, "[fail]"), e.Error())
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(b, "  %s %s\n", f.colored(ansiYellow, "[warn]"), w.Error())
	}
	if r.Status == checks.StatusSkipped && r.SkipReason != "" {
		fmt.Fprintf(b, "  %s %s\n", f.colored(ansiCyan, "[skip]"), r.SkipReason)
	}
}

// colored wraps s in the given ANSI color when color output is
// enabled; returns s unchanged otherwise. Reset escape always
// follows so terminal state doesn't leak.
func (f *HumanFormatter) colored(color, s string) string {
	if !f.color {
		return s
	}
	return color + s + ansiReset
}

// statusDisplayColor maps CheckStatus → ANSI color code. Stable
// across the formatter's lifetime; color choices match the
// summary-line verdict color.
func statusDisplayColor(s checks.CheckStatus) string {
	switch s {
	case checks.StatusPass:
		return ansiGreen
	case checks.StatusFail:
		return ansiRed
	case checks.StatusWarn:
		return ansiYellow
	case checks.StatusSkipped:
		return ansiCyan
	default:
		return ansiReset
	}
}

// verdictDisplayLabel maps VerdictCode → operator-readable label.
// The label appears in the bold "Verdict:" line of the human output.
//
// Defense-in-depth: unknown VerdictCode defaults to FAIL (matches
// JSON formatter's defensive fallback in jsonVerdictFail). Tenant 3
// fail-secure: should never happen with the typed enum, but if a
// future enum value is added without updating this switch, the
// verifier surfaces FAIL rather than the misleading "UNKNOWN".
func verdictDisplayLabel(v checks.VerdictCode) string {
	switch v {
	case checks.VerdictPass:
		return "PASS"
	case checks.VerdictFail:
		return "FAIL"
	case checks.VerdictPartialVerification:
		return "PARTIAL VERIFICATION"
	default:
		return "FAIL"
	}
}

// verdictDisplayColor maps VerdictCode → ANSI color. Pass=green,
// Fail=red, PartialVerification=yellow (a partial verify isn't a
// definitive failure but isn't full PASS either). Unknown defaults
// to red, matching verdictDisplayLabel's fail-secure fallback.
func verdictDisplayColor(v checks.VerdictCode) string {
	switch v {
	case checks.VerdictPass:
		return ansiGreen
	case checks.VerdictFail:
		return ansiRed
	case checks.VerdictPartialVerification:
		return ansiYellow
	default:
		return ansiRed
	}
}

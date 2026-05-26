package checks

import (
	"errors"
	"strings"
	"testing"
)

// =============================================================================
// AggregateVerdict — verdict aggregation tests (Phase 4 Session 3 D5 commit 1)
//
// Single decision point for verdict logic. Tests cover:
//   - Empty results → Fail (defense against silent zero-check pass)
//   - All Pass → Pass
//   - Any Fail → Fail (terminal; not downgradeable)
//   - Skipped + --offline → Pass
//   - Skipped without --offline → PartialVerification
//   - Warn without opt-in → PartialVerification
//   - Warn with corresponding opt-in → Pass
//   - Warn with WRONG opt-in → PartialVerification
//   - Mixed Fail + Warn: Fail wins
//   - Multi-warning safety: any non-allowed warning blocks the opt-in
//   - Flag interaction matrix: every combination tested
// =============================================================================

func makeResult(id int, name string, status CheckStatus) CheckResult {
	return CheckResult{
		CheckID:   id,
		CheckName: name,
		CheckSlug: name,
		Status:    status,
	}
}

func makeWarn(id int, name string, warningText string) CheckResult {
	return CheckResult{
		CheckID:   id,
		CheckName: name,
		CheckSlug: name,
		Status:    StatusWarn,
		Warnings:  []error{errors.New(warningText)},
	}
}

// =============================================================================
// Empty results — fail-secure (Tenant 3)
// =============================================================================

func TestAggregateVerdictEmptyResultsIsFail(t *testing.T) {
	t.Parallel()
	v := AggregateVerdict(nil, CheckOptions{})
	if v.Verdict != VerdictFail {
		t.Errorf("Verdict = %v, want VerdictFail", v.Verdict)
	}
	if v.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", v.ExitCode)
	}
	if !strings.Contains(v.Reason, "no checks executed") {
		t.Errorf("Reason missing 'no checks executed': %q", v.Reason)
	}
}

func TestAggregateVerdictEmptyResultsSliceIsFail(t *testing.T) {
	t.Parallel()
	v := AggregateVerdict([]CheckResult{}, CheckOptions{})
	if v.Verdict != VerdictFail {
		t.Errorf("Verdict = %v, want VerdictFail", v.Verdict)
	}
}

// =============================================================================
// Happy path — all Pass
// =============================================================================

func TestAggregateVerdictAllPass(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeResult(2, "artifact integrity", StatusPass),
		makeResult(3, "hash chain", StatusPass),
		makeResult(4, "Merkle proof", StatusPass),
	}
	v := AggregateVerdict(results, CheckOptions{})
	if v.Verdict != VerdictPass {
		t.Errorf("Verdict = %v, want VerdictPass", v.Verdict)
	}
	if v.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", v.ExitCode)
	}
	if v.Summary.Passed != 4 || v.Summary.Failed != 0 || v.Summary.Warned != 0 || v.Summary.Skipped != 0 {
		t.Errorf("Summary = %+v, want 4/0/0/0", v.Summary)
	}
}

// =============================================================================
// Fail terminal
// =============================================================================

func TestAggregateVerdictAnyFailIsFail(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeResult(2, "artifact integrity", StatusFail),
		makeResult(3, "hash chain", StatusPass),
	}
	v := AggregateVerdict(results, CheckOptions{})
	if v.Verdict != VerdictFail {
		t.Errorf("Verdict = %v, want VerdictFail", v.Verdict)
	}
	if v.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", v.ExitCode)
	}
	if !strings.Contains(v.Reason, "check 2") {
		t.Errorf("Reason missing failed check ID: %q", v.Reason)
	}
}

// TestAggregateVerdictFailWinsOverWarn pins the precedence rule:
// Fail terminal even when Warn is also present.
func TestAggregateVerdictFailWinsOverWarn(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeWarn(5, "OpenTimestamps", "pending Bitcoin confirmation"),
		makeResult(6, "RFC 3161", StatusFail),
		makeWarn(7, "GitHub anchor", "--allow-anchor-pending opt-in"),
	}
	v := AggregateVerdict(results, CheckOptions{
		AllowPendingOTS:    true,
		AllowAnchorPending: true,
	})
	if v.Verdict != VerdictFail {
		t.Errorf("Verdict = %v, want VerdictFail (Fail wins precedence)", v.Verdict)
	}
}

func TestAggregateVerdictAllFail(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusFail),
		makeResult(2, "artifact integrity", StatusFail),
	}
	v := AggregateVerdict(results, CheckOptions{})
	if v.Verdict != VerdictFail {
		t.Errorf("Verdict = %v, want VerdictFail", v.Verdict)
	}
	if v.Summary.Failed != 2 {
		t.Errorf("Summary.Failed = %d, want 2", v.Summary.Failed)
	}
	if !strings.Contains(v.Reason, "check 1") || !strings.Contains(v.Reason, "check 2") {
		t.Errorf("Reason missing failed check IDs: %q", v.Reason)
	}
}

// =============================================================================
// Skipped + --offline resolution
// =============================================================================

func TestAggregateVerdictSkippedWithOfflineIsPass(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeResult(5, "OpenTimestamps", StatusSkipped),
		makeResult(6, "RFC 3161", StatusSkipped),
		makeResult(7, "GitHub anchor", StatusSkipped),
	}
	v := AggregateVerdict(results, CheckOptions{Offline: true})
	if v.Verdict != VerdictPass {
		t.Errorf("Verdict = %v, want VerdictPass (Skipped + --offline)", v.Verdict)
	}
	if v.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", v.ExitCode)
	}
	if v.Summary.Skipped != 3 {
		t.Errorf("Summary.Skipped = %d, want 3", v.Summary.Skipped)
	}
}

func TestAggregateVerdictSkippedWithoutOfflineIsPartial(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeResult(5, "OpenTimestamps", StatusSkipped),
	}
	v := AggregateVerdict(results, CheckOptions{}) // Offline NOT set
	if v.Verdict != VerdictPartialVerification {
		t.Errorf("Verdict = %v, want VerdictPartialVerification", v.Verdict)
	}
	if v.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", v.ExitCode)
	}
	if !strings.Contains(v.Reason, "skipped without --offline") {
		t.Errorf("Reason missing 'skipped without --offline': %q", v.Reason)
	}
}

// =============================================================================
// Warn opt-in resolution (Tenant 3 fail-secure: per-category match)
// =============================================================================

func TestAggregateVerdictPendingOTSWarnWithoutFlagIsPartial(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeWarn(5, "OpenTimestamps", "OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
	}
	v := AggregateVerdict(results, CheckOptions{}) // AllowPendingOTS NOT set
	if v.Verdict != VerdictPartialVerification {
		t.Errorf("Verdict = %v, want VerdictPartialVerification", v.Verdict)
	}
}

func TestAggregateVerdictPendingOTSWarnWithFlagIsPass(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeWarn(5, "OpenTimestamps", "OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
	}
	v := AggregateVerdict(results, CheckOptions{AllowPendingOTS: true})
	if v.Verdict != VerdictPass {
		t.Errorf("Verdict = %v, want VerdictPass (--allow-pending-ots opts in)", v.Verdict)
	}
	if v.Summary.Passed != 2 {
		t.Errorf("Summary.Passed = %d, want 2 (warn folded into pass)", v.Summary.Passed)
	}
	if v.Summary.Warned != 0 {
		t.Errorf("Summary.Warned = %d, want 0 (warn folded into pass)", v.Summary.Warned)
	}
}

func TestAggregateVerdictAnchorPendingWarnWithFlagIsPass(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeWarn(7, "GitHub anchor", "mirror_status=anchor-pending — V1 deploy-bootstrap state (--allow-anchor-pending opt-in: anchor commit deferred to Phase 5)"),
	}
	v := AggregateVerdict(results, CheckOptions{AllowAnchorPending: true})
	if v.Verdict != VerdictPass {
		t.Errorf("Verdict = %v, want VerdictPass", v.Verdict)
	}
}

// TestAggregateVerdictWarnWithWrongFlagIsPartial — load-bearing
// Tenant 3 regression. --allow-pending-ots MUST NOT opt INTO Pass
// for an anchor-pending warning. Per-category matching.
func TestAggregateVerdictWarnWithWrongFlagIsPartial(t *testing.T) {
	t.Parallel()
	// Scenario 1: anchor-pending warn on check 7 + --allow-pending-ots
	// (wrong flag for the category)
	results1 := []CheckResult{
		makeWarn(7, "GitHub anchor", "mirror_status=anchor-pending — V1 deploy-bootstrap state (--allow-anchor-pending opt-in)"),
	}
	v1 := AggregateVerdict(results1, CheckOptions{AllowPendingOTS: true})
	if v1.Verdict != VerdictPartialVerification {
		t.Errorf("Scenario 1: Verdict = %v, want VerdictPartialVerification (wrong flag)", v1.Verdict)
	}

	// Scenario 2: pending-OTS warn on check 5 + --allow-anchor-pending
	// (wrong flag for the category)
	results2 := []CheckResult{
		makeWarn(5, "OpenTimestamps", "OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
	}
	v2 := AggregateVerdict(results2, CheckOptions{AllowAnchorPending: true})
	if v2.Verdict != VerdictPartialVerification {
		t.Errorf("Scenario 2: Verdict = %v, want VerdictPartialVerification (wrong flag)", v2.Verdict)
	}
}

// TestAggregateVerdictMultiWarnSafety — load-bearing Tenant 3
// regression. A check that emits multiple warnings, only SOME of
// which are in the opt-in category, MUST NOT fold into Pass via the
// opt-in flag. Conservative: only when EVERY warning is allowed-
// category does the opt-in apply.
func TestAggregateVerdictMultiWarnSafety(t *testing.T) {
	t.Parallel()
	// Check 5 with one allowed warning + one unrelated warning.
	// Even with --allow-pending-ots, the unrelated warning blocks
	// the opt-in.
	results := []CheckResult{
		{
			CheckID:   5,
			CheckName: "OpenTimestamps",
			CheckSlug: "opentimestamps",
			Status:    StatusWarn,
			Warnings: []error{
				errors.New("OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
				errors.New("Bitcoin block timestamp is suspiciously close to OTS submission (potential plausibility issue)"),
			},
		},
	}
	v := AggregateVerdict(results, CheckOptions{AllowPendingOTS: true})
	if v.Verdict != VerdictPartialVerification {
		t.Errorf("Verdict = %v, want VerdictPartialVerification (unrelated warning blocks opt-in)", v.Verdict)
		t.Logf("Reason: %s", v.Reason)
	}
}

// TestAggregateVerdictWarnWithoutWarningsIsNotAllowed pins that an
// "empty warnings" Warn check (which shouldn't happen but is
// possible to construct) does NOT auto-opt into Pass via any flag.
func TestAggregateVerdictWarnWithoutWarningsIsNotAllowed(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		{CheckID: 5, Status: StatusWarn, Warnings: nil},
	}
	v := AggregateVerdict(results, CheckOptions{AllowPendingOTS: true})
	if v.Verdict != VerdictPartialVerification {
		t.Errorf("Verdict = %v, want VerdictPartialVerification", v.Verdict)
	}
}

// =============================================================================
// Determinism (Tenant 2 reproducibility)
// =============================================================================

func TestAggregateVerdictIsDeterministic(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeWarn(5, "OpenTimestamps", "OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
		makeResult(7, "GitHub anchor", StatusFail),
	}
	v1 := AggregateVerdict(results, CheckOptions{})
	v2 := AggregateVerdict(results, CheckOptions{})
	if v1.Reason != v2.Reason {
		t.Errorf("non-deterministic Reason:\n  v1: %s\n  v2: %s", v1.Reason, v2.Reason)
	}
	if v1.ExitCode != v2.ExitCode {
		t.Errorf("non-deterministic ExitCode: v1=%d v2=%d", v1.ExitCode, v2.ExitCode)
	}
}

// =============================================================================
// Spec §14 pass-with-skipped reason wording (Tenant 5 transparency)
// =============================================================================

func TestAggregateVerdictPassWithSkippedReason(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeResult(5, "OpenTimestamps", StatusSkipped),
	}
	v := AggregateVerdict(results, CheckOptions{Offline: true})
	if v.Verdict != VerdictPass {
		t.Fatalf("Verdict = %v, want VerdictPass", v.Verdict)
	}
	if !strings.Contains(v.Reason, "skipped per --offline") {
		t.Errorf("Reason should explicitly mention --offline: %q", v.Reason)
	}
}

// =============================================================================
// Warn-folded-into-pass disclosure (Tenant 5 transparency)
// =============================================================================

// TestAggregateVerdictWarnsOptedIntoPassCountSurfaced pins that
// when a WARN folds into PASS via opt-in, the count is surfaced in
// VerdictSummary AND the Reason text so operators can correlate
// the per-check WARN line with the summary's elevated Passed count.
// Code-reviewer S3 (D5 c1+c2 review): without disclosure, the
// per-check WARN + summary 1-passed + verdict "all checks verified"
// presents three inconsistent surfaces.
func TestAggregateVerdictWarnsOptedIntoPassCountSurfaced(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeWarn(5, "OpenTimestamps", "OTS receipt for date 2026-04-22 is pending Bitcoin confirmation"),
	}
	v := AggregateVerdict(results, CheckOptions{AllowPendingOTS: true})
	if v.Verdict != VerdictPass {
		t.Fatalf("Verdict = %v, want VerdictPass", v.Verdict)
	}
	if v.Summary.WarnsOptedIntoPass != 1 {
		t.Errorf("Summary.WarnsOptedIntoPass = %d, want 1", v.Summary.WarnsOptedIntoPass)
	}
	if !strings.Contains(v.Reason, "warn(s) opted INTO pass") {
		t.Errorf("Reason should disclose warn-folded-into-pass: %q", v.Reason)
	}
}

func TestAggregateVerdictWarnsOptedIntoPassZeroWhenNoFold(t *testing.T) {
	t.Parallel()
	// All clean Pass checks — WarnsOptedIntoPass MUST be 0 and
	// the Reason MUST NOT mention the warn-fold disclosure.
	results := []CheckResult{
		makeResult(1, "manifest signature", StatusPass),
		makeResult(2, "artifact integrity", StatusPass),
	}
	v := AggregateVerdict(results, CheckOptions{})
	if v.Summary.WarnsOptedIntoPass != 0 {
		t.Errorf("Summary.WarnsOptedIntoPass = %d, want 0", v.Summary.WarnsOptedIntoPass)
	}
	if strings.Contains(v.Reason, "warn(s) opted INTO pass") {
		t.Errorf("Reason should NOT mention warn-fold for clean-pass case: %q", v.Reason)
	}
}

// TestAggregateVerdictReasonDoesNotPrefixVerdictLabel pins the
// formatter contract per code-reviewer S2: the Reason text MUST NOT
// begin with the verdict label (the formatters render the label
// separately). Pre-fix: Reason started with "verification FAILED:"
// or "PARTIAL VERIFICATION:" which produced stuttering output.
func TestAggregateVerdictReasonDoesNotPrefixVerdictLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		results      []CheckResult
		opts         CheckOptions
		forbidPrefix string
	}{
		{
			"FAIL Reason doesn't start with 'verification FAILED'",
			[]CheckResult{makeResult(1, "x", StatusFail)},
			CheckOptions{},
			"verification FAILED",
		},
		{
			"PARTIAL Reason doesn't start with 'PARTIAL VERIFICATION'",
			[]CheckResult{makeWarn(1, "x", "some warning")},
			CheckOptions{},
			"PARTIAL VERIFICATION",
		},
		{
			"PASS Reason doesn't start with 'verification PASSED'",
			[]CheckResult{makeResult(1, "x", StatusPass)},
			CheckOptions{},
			"verification PASSED",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := AggregateVerdict(c.results, c.opts)
			if strings.HasPrefix(v.Reason, c.forbidPrefix) {
				t.Errorf("Reason starts with forbidden verdict-label prefix %q: %q", c.forbidPrefix, v.Reason)
			}
		})
	}
}

// =============================================================================
// Producer-aggregator integration: catches substring-as-contract drift
//
// Crypto-integrity-reviewer M1 (D5 c1+c2 review): the substring
// match in isPendingOTSWarning / isAnchorPendingWarning is a tight
// coupling between (a) the literal text emitted by the check and
// (b) the substring matched by the aggregator. If a future refactor
// reworded the check's warning text, the substring match would
// silently fail. These integration-style tests exercise the full
// produce→aggregate path so a wording drift surfaces as a test
// failure.
// =============================================================================

// TestProducerAggregatorContract_PendingOTS asserts that the literal
// strings check 5 emits in its pending-state warning are recognized
// by isPendingOTSWarning. If check 5's wording drifts, this test
// fails immediately rather than the silent-allow regression.
func TestProducerAggregatorContract_PendingOTS(t *testing.T) {
	t.Parallel()
	// The producer-side wording from check5_ots.go's pending branch.
	// If check 5's wording changes, update this string AND verify
	// the matcher still recognizes it.
	const producerEmitted = "OTS receipt for date 2026-04-22 is pending Bitcoin confirmation (calendar attestations present, no Bitcoin block yet)"
	if !isPendingOTSWarning(producerEmitted) {
		t.Errorf("isPendingOTSWarning failed to match check 5's literal pending-state message: %q\n"+
			"Producer-aggregator substring contract is broken — either check 5's warning text changed, or isPendingOTSWarning's marker drifted",
			producerEmitted)
	}
}

// TestProducerAggregatorContract_DevKey asserts that check 1's
// spec §5 line 308 mandated dev-key warning text is recognized by
// isDevKeyWarning. If check 1's wording drifts from the spec-
// mandated phrase, this test fails immediately.
func TestProducerAggregatorContract_DevKey(t *testing.T) {
	t.Parallel()
	const producerEmitted = "DEVELOPMENT BUNDLE — verified with dev key, not for production trust"
	if !isDevKeyWarning(producerEmitted) {
		t.Errorf("isDevKeyWarning failed to match check 1's spec-mandated dev-key warning: %q", producerEmitted)
	}
}

// TestAggregateVerdictDevKeyWarnFoldsWithFlag pins that --allow-dev-key
// folds check 1's dev-key informational warning into Pass at the
// verdict layer (the operator opted INTO the dev-signed bundle).
func TestAggregateVerdictDevKeyWarnFoldsWithFlag(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeWarn(1, "manifest signature", "DEVELOPMENT BUNDLE — verified with dev key, not for production trust"),
	}
	v := AggregateVerdict(results, CheckOptions{AllowDevKey: true})
	if v.Verdict != VerdictPass {
		t.Errorf("Verdict = %v, want VerdictPass (--allow-dev-key folds dev-key warn)", v.Verdict)
	}
	if v.Summary.WarnsOptedIntoPass != 1 {
		t.Errorf("Summary.WarnsOptedIntoPass = %d, want 1", v.Summary.WarnsOptedIntoPass)
	}
}

func TestAggregateVerdictDevKeyWarnPartialWithoutFlag(t *testing.T) {
	t.Parallel()
	results := []CheckResult{
		makeWarn(1, "manifest signature", "DEVELOPMENT BUNDLE — verified with dev key, not for production trust"),
	}
	v := AggregateVerdict(results, CheckOptions{}) // no --allow-dev-key
	if v.Verdict != VerdictPartialVerification {
		t.Errorf("Verdict = %v, want VerdictPartialVerification", v.Verdict)
	}
}

// TestProducerAggregatorContract_AnchorPending asserts the same for
// check 7's anchor-pending warning + isAnchorPendingWarning matcher.
func TestProducerAggregatorContract_AnchorPending(t *testing.T) {
	t.Parallel()
	const producerEmitted = `mirror_status="anchor-pending" for daily root date "2026-04-22" — V1 deploy-bootstrap state (--allow-anchor-pending opt-in: anchor commit deferred to Phase 5; operator MUST verify check 5 (OTS Bitcoin) + check 6 (RFC 3161) verdicts to confirm independent witnesses are present)`
	if !isAnchorPendingWarning(producerEmitted) {
		t.Errorf("isAnchorPendingWarning failed to match check 7's literal anchor-pending message: %q\n"+
			"Producer-aggregator substring contract is broken — either check 7's warning text changed, or isAnchorPendingWarning's marker drifted",
			producerEmitted)
	}
}

// =============================================================================
// VerdictCode.String coverage
// =============================================================================

func TestVerdictCodeString(t *testing.T) {
	t.Parallel()
	cases := map[VerdictCode]string{
		VerdictPass:                "pass",
		VerdictFail:                "fail",
		VerdictPartialVerification: "partial_verification",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("VerdictCode(%d).String() = %q, want %q", v, got, want)
		}
	}
	// Defense-in-depth on unknown enum value
	if got := VerdictCode(99).String(); got != "unknown" {
		t.Errorf("VerdictCode(99).String() = %q, want unknown", got)
	}
}

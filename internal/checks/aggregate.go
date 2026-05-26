package checks

import (
	"fmt"
	"strings"
)

// Verdict aggregation. Phase 4 Session 3 D5 commit 1.
//
// **Single decision point** for the overall verification verdict.
// Per Tenant 4 (simplicity): one source of truth for the verdict
// logic, not scattered across check implementations or main
// command. AggregateVerdict is the only function that maps
// per-check results + caller's flag-state to an exit code.
//
// **Spec §14 aggregate semantics** restated for D5:
//
//   - All Pass               → VerdictPass        (exit 0)
//   - At least one Fail      → VerdictFail        (exit 1, terminal)
//   - At least one Skipped
//     under --offline        → VerdictPass        (exit 0)
//     (operator explicitly opted into skipping external-anchor checks)
//   - At least one Warn that
//     IS allowed by an opt-in flag (--allow-pending-ots,
//     --allow-anchor-pending) → folded into Pass count
//     (warn surfaces in the per-check output but doesn't gate
//      overall verdict — the operator opted INTO accepting it)
//   - At least one Warn that is NOT allowed by an opt-in flag,
//     OR at least one Skipped without --offline →
//                              VerdictPartialVerification (exit 1)
//
// **Exit codes are operationally meaningful** (Tenant 5):
//   - 0 = the bundle is fully verified per the operator's flag set
//         (either everything passed, or skips are explicit operator
//          choice via --offline)
//   - 1 = something failed OR something is incomplete that the
//         operator hasn't explicitly opted INTO
//   - 2 = invocation error (handled by main command, not here —
//         AggregateVerdict only emits 0/1)
//
// **Empty results = Fail** (defense against silent zero-check pass
// that would claim verification with no checks run; Tenant 3
// fail-secure).

// VerdictCode is the enum surfaced in ExitVerdict.Verdict.
type VerdictCode int

const (
	// VerdictPass — bundle is fully verified per the caller's
	// flag set. Exit code 0.
	VerdictPass VerdictCode = iota
	// VerdictFail — at least one check definitively failed. Exit
	// code 1. Terminal: cannot be downgraded to Pass by any flag.
	VerdictFail
	// VerdictPartialVerification — no definitive failure, but at
	// least one check is incomplete (Warn without opt-in flag, or
	// Skipped without --offline). Exit code 1. Distinct from Fail
	// because the operator can opt INTO Pass via flags.
	VerdictPartialVerification
)

// String returns the canonical lowercase form. Used by tests +
// debugging. The customer-facing label rendering lives in
// internal/output (humanFormat label = "PASS" / "FAIL" /
// "PARTIAL VERIFICATION"; jsonFormat label = "pass" / "fail" /
// "partial_verification").
func (v VerdictCode) String() string {
	switch v {
	case VerdictPass:
		return "pass"
	case VerdictFail:
		return "fail"
	case VerdictPartialVerification:
		return "partial_verification"
	default:
		return "unknown"
	}
}

// VerdictSummary is the per-bucket count of check verdicts. The
// human + JSON formatters both render this in the summary line.
//
// **WarnsOptedIntoPass** is the count of WARN-status checks that
// were folded into the Passed bucket via --allow-pending-ots /
// --allow-anchor-pending. The per-check WARN status still surfaces
// in the per-check output (so the operator sees which warnings
// were emitted), but the count surfaces in the verdict Reason
// when > 0 so the operator understands WHY summary.Passed exceeds
// the count of clean Pass checks. Tenant 5 (transparency about
// the verdict's rationale).
type VerdictSummary struct {
	Passed             int
	Failed             int
	Warned             int
	Skipped            int
	WarnsOptedIntoPass int
}

// ExitVerdict is the structured output of AggregateVerdict. Carries
// enough information for both formatters (human + JSON) AND the
// main command's exit-code logic without re-running aggregation.
type ExitVerdict struct {
	// Verdict is the enum used by formatters for color/label
	// dispatch.
	Verdict VerdictCode
	// ExitCode is the process exit code the main command emits.
	// Always 0 or 1 here; main command emits 2 for invocation
	// errors (out of scope for AggregateVerdict).
	ExitCode int
	// Reason is the operator-readable explanation of WHY the
	// verdict is what it is. Surfaced in both human and JSON
	// output. Tenant 5: transparency about the verdict's
	// rationale.
	Reason string
	// Summary is the per-bucket count, used by the formatters'
	// summary line.
	Summary VerdictSummary
}

// AggregateVerdict computes the overall verdict from per-check
// results + caller's flag state. See package doc for the spec §14
// aggregate semantics restated.
//
// **Determinism** (Tenant 2): the same results array + same
// CheckOptions produces the same ExitVerdict bytes across runs.
// No map iteration; no goroutine timing; no time.Now() dependency.
//
// **Empty results** are a programmer error — the main command
// always populates results from the registered checks. If the
// caller passes an empty slice, AggregateVerdict returns
// VerdictFail with an explicit "no checks executed" reason rather
// than silently claiming Pass with zero work done.
func AggregateVerdict(results []CheckResult, opts CheckOptions) ExitVerdict {
	if len(results) == 0 {
		return ExitVerdict{
			Verdict:  VerdictFail,
			ExitCode: 1,
			Reason:   "verification FAILED: no checks executed (empty registry — refusing to claim verification with no work done)",
			Summary:  VerdictSummary{},
		}
	}

	var summary VerdictSummary
	var failCheckRefs []string
	var warnCheckRefs []string
	var skipCheckRefs []string

	for _, r := range results {
		switch r.Status {

		case StatusPass:
			summary.Passed++

		case StatusFail:
			summary.Failed++
			failCheckRefs = append(failCheckRefs, fmt.Sprintf("check %d", r.CheckID))

		case StatusWarn:
			// Resolve against opt-in flags. A WARN that the operator
			// has explicitly opted INTO accepting (via --allow-pending-ots
			// or --allow-anchor-pending) folds into Passed; the
			// per-check warning text still surfaces in the output for
			// visibility, but it doesn't gate the overall verdict.
			// WarnsOptedIntoPass tracks the count for transparent
			// disclosure in the verdict Reason text.
			if isWarnAllowed(r, opts) {
				summary.Passed++
				summary.WarnsOptedIntoPass++
			} else {
				summary.Warned++
				warnCheckRefs = append(warnCheckRefs, fmt.Sprintf("check %d", r.CheckID))
			}

		case StatusSkipped:
			// Resolve against --offline. A check skipped because the
			// operator passed --offline counts as Skipped (legitimate
			// operator choice). A check skipped for any other reason
			// (network unavailable mid-run, infrastructure issue)
			// counts as Warned in the verdict aggregation because the
			// bundle's verification is incomplete relative to the
			// operator's expectation.
			if opts.Offline {
				summary.Skipped++
			} else {
				summary.Warned++
				skipCheckRefs = append(skipCheckRefs, fmt.Sprintf("check %d", r.CheckID))
			}
		}
	}

	// Verdict precedence: Fail terminal, then PartialVerification, then Pass.
	//
	// Reason text format: per code-reviewer S2 (D5 c1+c2 review),
	// the Reason MUST NOT begin with the verdict label (the
	// formatters render the label separately via VerdictCode →
	// "PASS" / "FAIL" / "PARTIAL VERIFICATION"). The Reason is the
	// rationale that follows the label, not a duplicate of it.
	if summary.Failed > 0 {
		return ExitVerdict{
			Verdict:  VerdictFail,
			ExitCode: 1,
			Reason: fmt.Sprintf("%d check(s) failed (%s)",
				summary.Failed, strings.Join(failCheckRefs, ", ")),
			Summary: summary,
		}
	}

	if summary.Warned > 0 {
		var refs []string
		if len(warnCheckRefs) > 0 {
			refs = append(refs, "warned: "+strings.Join(warnCheckRefs, ", "))
		}
		if len(skipCheckRefs) > 0 {
			refs = append(refs, "skipped without --offline: "+strings.Join(skipCheckRefs, ", "))
		}
		return ExitVerdict{
			Verdict:  VerdictPartialVerification,
			ExitCode: 1,
			Reason: fmt.Sprintf("%d check(s) incomplete (%s); pass corresponding --allow-* flag or --offline to opt into Pass",
				summary.Warned, strings.Join(refs, "; ")),
			Summary: summary,
		}
	}

	// All Pass (possibly including Skipped-with-Offline +
	// Warns-opted-into-Pass).
	//
	// Per code-reviewer S3 (D5 c1+c2 review): when the operator
	// opted INTO accepting a WARN via --allow-pending-ots /
	// --allow-anchor-pending, the per-check WARN line still
	// surfaces in the output (operator sees the warning) but the
	// summary shows "1 passed" instead of "1 warned". Without
	// disclosure in the Reason, the operator must reverse-engineer
	// what happened. Disclose the fold explicitly. Tenant 5
	// transparency.
	var parts []string
	if summary.Passed > 0 {
		parts = append(parts, fmt.Sprintf("%d check(s) verified", summary.Passed))
	}
	if summary.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped per --offline", summary.Skipped))
	}
	if summary.WarnsOptedIntoPass > 0 {
		parts = append(parts, fmt.Sprintf("%d warn(s) opted INTO pass via --allow-* flag",
			summary.WarnsOptedIntoPass))
	}
	reason := "all checks verified"
	if len(parts) > 0 {
		reason = strings.Join(parts, "; ")
	}
	return ExitVerdict{
		Verdict:  VerdictPass,
		ExitCode: 0,
		Reason:   reason,
		Summary:  summary,
	}
}

// isWarnAllowed reports whether a WARN result has been opted INTO
// Pass-equivalent via the corresponding allow-flag. The match is
// per-check-ID + per-warning-category to avoid an attacker (or a
// confused operator) opting INTO a wrong category by enabling the
// wrong flag.
//
// **Category matching via warning text substring** (per crypto-
// integrity discipline from D4 commit 2 reviewer pass): each check
// generates warnings with a stable substring marker for its
// known opt-in categories. A check 5 OTS warning carrying
// "pending Bitcoin confirmation" is the pending-OTS category;
// a check 7 warning carrying "--allow-anchor-pending opt-in" or
// "V1 deploy-bootstrap state" is the anchor-pending category.
//
// **Multi-warning-category safety**: if a check emits MULTIPLE
// warnings and only SOME are in the opt-in category, isWarnAllowed
// returns false (any non-allowed warning blocks the opt-in). This
// prevents the failure mode where --allow-pending-ots silently
// accepts a "tamper detected" warning that happens to coexist with
// a pending-OTS warning. Conservative: only opt INTO Pass when
// EVERY warning is in the allowed category.
func isWarnAllowed(r CheckResult, opts CheckOptions) bool {
	if len(r.Warnings) == 0 {
		return false
	}

	// **Spec §14.4 (v1.0.7): structured warn_category is authoritative.**
	// When the check populated WarnCategory, the fold decision turns on
	// the category enum AND the opt-in flag for that category. This is
	// the standards-track-correct path — a third-party verifier emitting
	// non-NuWyre warning strings still folds correctly because the
	// decision doesn't depend on warning-text substring matching.
	//
	// **Multi-warning safety invariant** (spec §14.4): the producer
	// MUST tag WarnCategory ONLY when EVERY warning in r.Warnings is
	// in that category. As defense-in-depth at the aggregator, we
	// cross-check by verifying that every warning text matches the
	// category's stable substring marker. A mismatch (producer tagged
	// WarnCategoryX but one of the warnings doesn't match the
	// category's text marker) is treated as "do not fold" — fail-
	// secure per Tenant 3 + the TRIPLE-corroborated fold-safety
	// finding closed at Phase 5.5 Session 5.5.1C reviewer fix-up
	// (code-rev #3 + crypto-int #2 + spec-rev F2-cluster).
	if r.WarnCategory != "" {
		var flag bool
		var textMatcher func(string) bool
		switch r.WarnCategory {
		case WarnCategoryDevKey:
			flag = opts.AllowDevKey
			textMatcher = isDevKeyWarning
		case WarnCategoryPendingOTS:
			flag = opts.AllowPendingOTS
			textMatcher = isPendingOTSWarning
		case WarnCategoryAnchorPending:
			flag = opts.AllowAnchorPending
			textMatcher = isAnchorPendingWarning
		case WarnCategoryTSASurplus:
			// V1: no opt-in flag exists for the surplus-TSA case
			// (future v1.x may introduce --allow-tsa-surplus per
			// spec §14.4). Always returns false; the warn never
			// folds into pass in V1.
			return false
		default:
			// Unknown category — fail-secure: do NOT fold.
			return false
		}
		if !flag {
			return false
		}
		// Defense-in-depth: verify every warning matches the category's
		// stable text marker. If any warning doesn't match, the producer
		// either mis-tagged OR emitted a mixed-category result; either
		// way, fail-secure and do NOT fold.
		for _, w := range r.Warnings {
			if !textMatcher(w.Error()) {
				return false
			}
		}
		return true
	}

	// **Backward-compatibility fallback: pre-v1.0.7 substring matching.**
	// Verifiers that have NOT yet been updated to populate WarnCategory
	// (older code paths, third-party Go forks consuming this package
	// at v1.0.6 or earlier) emit warnings without category metadata.
	// We preserve the substring-marker matching to keep them working.
	// New code paths MUST populate WarnCategory directly.
	switch r.CheckID {
	case 1:
		if !opts.AllowDevKey {
			return false
		}
		for _, w := range r.Warnings {
			if !isDevKeyWarning(w.Error()) {
				return false
			}
		}
		return true
	case 5:
		if !opts.AllowPendingOTS {
			return false
		}
		for _, w := range r.Warnings {
			if !isPendingOTSWarning(w.Error()) {
				return false
			}
		}
		return true
	case 7:
		if !opts.AllowAnchorPending {
			return false
		}
		for _, w := range r.Warnings {
			if !isAnchorPendingWarning(w.Error()) {
				return false
			}
		}
		return true
	}
	return false
}

// isDevKeyWarning reports whether a warning text is the spec §5
// dev-key informational marker. Substring is the spec-mandated
// exact phrase emitted by check 1's dev-signed-bundle branch
// (check1_signature.go). Stable across the v1 spec — diverging
// would break the spec §5 line 308 contract that external tooling
// greps for.
func isDevKeyWarning(text string) bool {
	return strings.Contains(text, "DEVELOPMENT BUNDLE — verified with dev key")
}

// isPendingOTSWarning reports whether a warning text is in the
// pending-OTS category. Substring marker is "pending Bitcoin
// confirmation" — emitted by check 5's pending-state branch
// (check5_ots.go) and stable across the v1 spec.
func isPendingOTSWarning(text string) bool {
	return strings.Contains(text, "pending Bitcoin confirmation")
}

// isAnchorPendingWarning reports whether a warning text is in the
// anchor-pending category. Substring marker is
// "--allow-anchor-pending opt-in" — emitted by check 7's
// handleAnchorPending opt-in branch (check7_github.go) and stable
// across the v1 spec.
func isAnchorPendingWarning(text string) bool {
	return strings.Contains(text, "--allow-anchor-pending opt-in")
}

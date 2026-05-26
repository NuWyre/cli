// Package checks implements the seven verification checks documented
// in /docs/spec/bundle-format-v1.md §14 (v1.0.1). Phase 4 Sessions
// 2-3 populate this package; Session 1 left it empty.
//
// Phase 4 Session 2 lands checks 1-4 (manifest signature, artifact
// integrity, hash chain reconstruction, Merkle proof verification) —
// the local-only cryptographic foundation. Session 3 layers external-
// anchor verification (5: OpenTimestamps Bitcoin, 6: RFC 3161, 7:
// GitHub anchor) on top of the foundation.
//
// Architectural posture (per Phase 4 Session 1 + spec-amendment
// session pinned decisions):
//
//   - **Bytes-as-loaded.** Verification operates on raw bytes the
//     loader read from the zip, NOT on re-serialized struct
//     contents. EventsRaw, EvaluationsRaw, ManifestRaw, SignatureRaw
//     are the signing/hashing inputs. Re-serializing a parsed struct
//     would normalize JSON formatting (whitespace, key order, number
//     representation) and produce different bytes than the writer
//     signed.
//
//   - **Closed-set + warn-not-fail for forensic-data enums whose
//     unknown values do NOT drive verifier behavior.** Severity,
//     verdict, evaluation_source values that the spec doesn't
//     enumerate are surfaced as warnings rather than silent
//     acceptance OR outright rejection. Strict enough to detect spec
//     drift; lenient enough to verify bundles produced under future
//     spec versions until the verifier itself is updated.
//
//     Some enums ARE strict at load time (mirror_status,
//     commit_sha_format) because their values drive code-path
//     dispatch downstream — e.g., commit_sha_format selects the git
//     protocol in check 7. The loader's strict rejection of those is
//     intentional and orthogonal to this package's warn-not-fail
//     posture for the rest. Documented in
//     apps/cli/internal/bundle/load_dirs.go.
//
//   - **No verification weakening for ergonomics.** Defaults are
//     fail-secure: AllowDevKey defaults to false (caller must
//     explicitly opt in to verify example-demo bundles); StrictOTS
//     defaults to false (warn on pending OTS) but the inversion is
//     a documented choice not a bypass.
//
//   - **Skipped is non-Pass.** Per spec §14 "Aggregate semantics":
//     "All seven checks MUST pass for the verifier to report
//     'verified.'" A run with 4 Pass and 3 Skipped is NOT verified;
//     it's partially verified. The aggregator surfaces this with a
//     dedicated overall=Skipped state distinct from Pass and Warn.
//     The CLI's exit-code mapper (Session 4) maps overall=Skipped to
//     exit-code-1 unless --offline was explicitly passed.
package checks

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/nuwyre/cli/internal/bundle"
)

// CheckStatus is the outcome of one verification check OR the
// aggregate status across all checks.
type CheckStatus int

const (
	// StatusPass — every assertion in the check held.
	StatusPass CheckStatus = iota
	// StatusFail — at least one assertion failed; the bundle does
	// not verify under this check's contract.
	StatusFail
	// StatusWarn — the check held its required assertions but
	// surfaced something the operator should know about (placeholder
	// production key, unknown enum value tolerated under warn-not-fail
	// posture, pending OTS receipt under default --allow-pending-ots,
	// etc.). The bundle still verifies overall iff every check is
	// Pass or Warn.
	StatusWarn
	// StatusSkipped — the check did not run because preconditions
	// were not met (e.g., --offline disables checks 5/6/7). The
	// aggregate is Skipped iff at least one check was Skipped and
	// none failed; the CLI exit-code mapper rejects overall=Skipped
	// runs (exit 1) unless --offline was explicitly passed.
	StatusSkipped
)

// String returns the canonical lowercase form: "pass", "fail",
// "warn", "skipped". Used by the reporting layer (Session 4).
func (s CheckStatus) String() string {
	switch s {
	case StatusPass:
		return "pass"
	case StatusFail:
		return "fail"
	case StatusWarn:
		return "warn"
	case StatusSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// CheckResult is what a Check returns after Run. Carries enough
// information for Session 4's reporting layer to render machine-
// readable JSON output AND human-readable terminal output without
// re-running any verification logic.
//
// JSON marshaling note: Errors and Warnings are []error; Go's
// default encoding/json marshals an error interface as {} (no
// exported fields). Session 4's reporting layer MUST use a custom
// marshaler that calls .Error() on each entry to produce a useful
// JSON shape (array of strings or array of {message, ...}). The
// shared infrastructure deliberately keeps Errors/Warnings as
// []error for ergonomic check-implementation code; the marshaling
// concern is a reporting-layer responsibility, not a per-check one.
type CheckResult struct {
	// CheckID is the spec §14 check number (1-7).
	CheckID int
	// CheckName is a short human-readable label used in reports
	// ("manifest signature", "artifact integrity", "hash chain",
	// "Merkle proof", etc.).
	CheckName string
	// CheckSlug is the CLI matcher form for `--check <slug>`
	// selectivity (e.g., "manifest-signature", "artifact-integrity",
	// "hash-chain", "merkle-proof"). Stable across releases; the
	// human-readable Name MAY evolve.
	CheckSlug string
	// Status is the outcome.
	Status CheckStatus
	// SkipReason is populated when Status == Skipped; explains why
	// the check did not run (e.g., "network disabled by --offline").
	// Distinct from Warnings: skipping means the check did NOT
	// verify, while a warning means it DID verify but surfaced
	// operationally meaningful information.
	SkipReason string
	// WarnCategory is the structured warn-fold category per spec §14.4
	// (added at v1.0.7). When Status == StatusWarn and the warn
	// corresponds to an opt-in category, this field MUST be one of
	// the WarnCategory* constants (dev_key, pending_ots, anchor_pending,
	// tsa_surplus). Empty string when not applicable (Status != Warn,
	// or the warn doesn't match an opt-in category).
	//
	// Aggregator (AggregateVerdict + isWarnAllowed) uses WarnCategory
	// as the authoritative fold-decision input. Pre-v1.0.7 substring
	// matching against warning text is preserved as a fallback for
	// backward-compat but new code MUST populate WarnCategory directly.
	WarnCategory string
	// Errors is the populated-on-Fail list of specific errors. Each
	// error message follows the spec §14 convention: "check N (name):
	// <artifact-relative-path>: <expected>/<actual>; spec §X.Y
	// requires <rule>". Errors are deterministically ordered (first-
	// found within the iterated artifact, then by artifact path) so
	// reporting reproduces across runs.
	Errors []error
	// Warnings is the populated-on-Warn list (closed-set unknown
	// values, placeholder prod key, pending OTS, etc.). Warnings
	// MAY be present alongside Fail status — they're surfaced for
	// diagnostic context regardless of overall verdict.
	//
	// Per Result() factoring, len(Warnings)>0 with len(Errors)==0
	// produces Status=Warn. Checks that want Pass-with-information
	// should populate the (forthcoming Session 3) Details map
	// instead of Warnings.
	Warnings []error
	// DurationMS is wall-clock time the check took. Set by
	// RunChecks; checks SHOULD NOT populate this field directly.
	// Tests that bypass RunChecks may see DurationMS == 0.
	DurationMS int64

	// AlgorithmVerdicts is the v2 dual-signature per-algorithm verdict
	// array per spec §18.10 (Phase 7.F.3 v2.0.0-rc1 addition). For v2
	// bundle Check 1: exactly 2 entries [{algorithm:"ed25519",
	// status:"pass"|"fail"}, {algorithm:"ml-dsa-65",
	// status:"pass"|"fail"}]. CI tooling, dispute-investigation tools,
	// and operator dashboards consuming `--json` output SHOULD parse
	// AlgorithmVerdicts as the canonical-source per-algorithm verdict
	// surface. Empty for v1 bundles + non-Check-1 checks.
	AlgorithmVerdicts []AlgorithmVerdict
}

// AlgorithmVerdict is a single algorithm row in the AlgorithmVerdicts
// array per spec §18.10. Phase 7.F.3 v2.0.0-rc1 addition.
type AlgorithmVerdict struct {
	// Algorithm is "ed25519" or "ml-dsa-65" per spec §18.4 closed vocab.
	Algorithm string
	// Status is "pass" or "fail" per spec §18.10 closed vocabulary.
	// Both signatures MUST be "pass" for Check 1 overall to pass per
	// spec §18.7 step 5 (no short-circuit on first failure — emit both
	// verdicts regardless of which fails first).
	Status string
}

// Warn-fold category constants per spec §14.4 (v1.0.7). Closed
// vocabulary used by both the aggregator (isWarnAllowed) and the
// JSON output formatter (CheckJSON.warn_category). The empty string
// "" represents a warn that does NOT match any opt-in category.
const (
	WarnCategoryDevKey         = "dev_key"
	WarnCategoryPendingOTS     = "pending_ots"
	WarnCategoryAnchorPending  = "anchor_pending"
	WarnCategoryTSASurplus     = "tsa_surplus"
)

// CheckOptions is the verifier-wide options the orchestrator passes
// to each check's Run method. Session 4 wires these to CLI flags.
type CheckOptions struct {
	// Offline causes checks 5/6/7 to return StatusSkipped without
	// network access. Has no effect on checks 1-4 (which are
	// local-only by definition). When Offline is true, the CLI
	// exit-code mapper accepts overall=Skipped as a non-failing
	// outcome (caveat: the bundle is "verified offline", a weaker
	// guarantee than "verified" per spec §14).
	Offline bool

	// StrictOTS treats pending-state OTS receipts (commit awaiting
	// Bitcoin block confirmation) as Fail. Default false: pending
	// state is treated as Warn (verification still passes the
	// per-check verdict but contributes to PARTIAL VERIFICATION at
	// the aggregate layer unless --allow-pending-ots is also set).
	// Inversion direction: --strict-ots opts INTO stricter behavior
	// (Warn → Fail). Mutually exclusive with --allow-pending-ots
	// at the aggregate layer; the CLI rejects --offline + --strict-ots
	// as a usage error since offline skips check 5 entirely.
	StrictOTS bool

	// AllowPendingOTS opts the verifier INTO accepting check 5
	// pending-state warnings as Pass-equivalent at the verdict
	// aggregation layer. Default false: pending-state warnings
	// surface as PARTIAL VERIFICATION (exit 1) so the operator
	// notices the V1 OTS bootstrap state. Mirrors the
	// --allow-anchor-pending pattern for check 7.
	//
	// Per Tenant 5 (customer trust): default behavior surfaces the
	// asynchronous-Bitcoin-confirmation state explicitly. The flag
	// exists for V1 example-demo + transitional production cases
	// where the operator knows the OTS receipt is fresh and Bitcoin
	// confirmation is genuinely in flight (typical: ~24h post-
	// submission).
	//
	// Aggregation semantics (see aggregate.go's AggregateVerdict):
	// when --allow-pending-ots is set AND every check 5 warning is
	// in the pending-OTS category, the warning folds into the
	// passed bucket. A non-pending-OTS warning on check 5 (e.g.,
	// a plausibility-check failure) blocks the opt-in to prevent
	// silent acceptance of unrelated warnings.
	AllowPendingOTS bool

	// BitcoinRPCURL overrides the default Esplora endpoint for
	// check 5. Empty string uses the default. Session 3 scope.
	//
	// **Security contract (Session 3 implementation MUST honor):**
	// the URL MUST be HTTPS with cert validation enforced; cleartext
	// HTTP would let an MITM forge "Bitcoin says yes" responses for
	// arbitrary OTS receipts and defeat the entire external-anchor
	// leg. Session 3's check 5 implementation validates the scheme
	// before issuing requests; an HTTP-scheme URL is rejected at
	// option-parsing time, not at fetch time.
	BitcoinRPCURL string

	// AllowAnchorPending opts the verifier INTO accepting GitHub
	// anchor entries whose mirror_status is "anchor-pending" (the V1
	// staging state per build plan §"V1 GitHub anchor staging
	// architecture"). Default false: out-of-the-box behavior FAILS
	// check 7 on anchor-pending, surfacing the V1 deploy-bootstrap
	// state explicitly to the operator. --allow-anchor-pending
	// downgrades the failure to a Warn so verification proceeds
	// while the state remains operator-visible in the verdict.
	//
	// Inversion direction matches --strict-ots: default behavior is
	// the more-honest verdict (Fail surfaces the deploy-bootstrap
	// state explicitly), the flag opts INTO Warn-not-Fail.
	//
	// Per Tenant 5 (customer trust): the default-FAIL behavior
	// honors the principle that verifier output should be
	// operator-actionable. Silent or Warn-by-default acceptance of
	// anchor-pending state would let operators run scripted
	// verification against V1 bundles without realizing the GitHub
	// anchor leg is in deploy-bootstrap. Operators who explicitly
	// understand the V1 state opt-in via this flag; everyone else
	// gets a clear FAIL with operator-actionable diagnostic
	// pointing at the opt-in flag and the OTS + RFC 3161
	// independent-witness checks.
	//
	// Phase 5 deploy-bootstrap landing means anchor-pending becomes
	// rare-to-impossible in production bundles; the flag exists for
	// the V1 example-demo + transitional production cases.
	//
	// (D4 commit 2 reviewer-pass H1 reconciled this doc with
	// check7_github.go's implementation. The earlier doc claimed
	// default-Warn / opt-in-PASS; the implementation chose
	// default-FAIL / opt-in-Warn for stronger operator visibility.
	// This doc now matches the implementation.)
	AllowAnchorPending bool

	// AllowDevKey opts the verifier into accepting issuer-dev-v1
	// signatures for example-demo bundles. Defaults to false:
	// out-of-the-box behavior fails example-demo bundle verification
	// because the production verifier shouldn't trust dev-signed
	// bundles.
	//
	// Defense-in-depth note: spec §5 dispatch is fail-secure
	// (a customer-export bundle's bundle_type swapped to "example-
	// demo" would NOT verify against the dev key without a re-sign,
	// and re-signing requires the dev key). AllowDevKey=false is the
	// second layer: even if an attacker could re-sign, the verifier
	// rejects dev-signed bundles by default. Operators legitimately
	// verifying example bundles (validation suite, reviewer-fixture
	// testing) pass --allow-dev-key explicitly, with out-of-band
	// knowledge that the bundle is theirs.
	AllowDevKey bool

	// Now is the wall-clock time the verification started. Mostly
	// used by Session 3's external-anchor checks (pinned cert
	// validity periods are time-bounded). Defaults to time.Now()
	// in UTC when zero. Caller may override for testing time-
	// sensitive branches.
	Now time.Time
}

// Check is the verification-check interface every check implements.
// Session 2 registers checks 1-4; Session 3 registers checks 5-7.
type Check interface {
	// ID returns the spec §14 check number.
	ID() int

	// Name returns the short human-readable label.
	Name() string

	// Slug returns the CLI matcher form ("manifest-signature",
	// "artifact-integrity", etc.). Stable across releases.
	Slug() string

	// Run executes the check against the loaded bundle and returns
	// the result. Run MUST NOT mutate bundle. Run MUST be safe to
	// call concurrently with other checks (they share no mutable
	// state on bundle). Run MUST return Pass/Fail/Warn/Skipped per
	// the documented semantics.
	//
	// Run SHOULD NOT panic on malformed bundles — the loader
	// rejected those, but defensive runtime must surface as Fail
	// with a clear error rather than crash. RunChecks recovers
	// panics defensively (M1 from commit-1 reviewer pass) so a
	// buggy check's panic doesn't suppress subsequent checks; this
	// is defense-in-depth, not a license to panic.
	//
	// b MUST be non-nil; RunChecks guarantees this in production
	// paths.
	Run(b *bundle.Bundle, opts CheckOptions) CheckResult
}

// RunChecks runs every registered check against the bundle and
// returns the per-check results in spec §14 order (1, 2, 3, 4, ...).
// Returns the results slice plus an OverallStatus summarizing the
// run.
//
// Aggregation rule (spec §14 "Aggregate semantics"):
//   - All Pass                      → overall Pass
//   - At least one Warn, no Fail,
//     no Skipped                    → overall Warn
//   - At least one Skipped, no Fail → overall Skipped (partial)
//   - At least one Fail             → overall Fail (regardless of
//     other statuses)
//
// Skipped contributing to overall=Skipped (NOT overall=Pass) reflects
// the spec §14 mandate that "All seven checks MUST pass for the
// verifier to report 'verified.'" A run with checks 5/6/7 Skipped
// under --offline is partial verification; the CLI's exit-code mapper
// (Session 4) accepts overall=Skipped under --offline but rejects it
// otherwise.
//
// RunChecks recovers panics from individual checks (M1 from commit-1
// reviewer pass): a buggy check's panic is converted to a Fail
// result with an "internal verifier error" message, and subsequent
// checks still run. A panic in one external-anchor parser must not
// suppress every other check's verdict.
//
// RunChecks rejects an empty registry — calling RunChecks with no
// checks is a programmer error; returning Pass would silently claim
// verification with no work done. The aggregator returns a single
// synthetic Fail result in this case.
func RunChecks(b *bundle.Bundle, opts CheckOptions, regs ...Check) ([]CheckResult, CheckStatus) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if len(regs) == 0 {
		err := errors.New("checks: RunChecks called with empty registry; refusing to claim verification with no checks run")
		return []CheckResult{
			{
				CheckID:   0,
				CheckName: "registry",
				CheckSlug: "registry",
				Status:    StatusFail,
				Errors:    []error{err},
			},
		}, StatusFail
	}
	if b == nil {
		err := errors.New("checks: RunChecks called with nil bundle; refusing to verify a non-bundle")
		return []CheckResult{
			{
				CheckID:   0,
				CheckName: "bundle",
				CheckSlug: "bundle",
				Status:    StatusFail,
				Errors:    []error{err},
			},
		}, StatusFail
	}

	results := make([]CheckResult, 0, len(regs))
	overall := StatusPass
	for _, c := range regs {
		r := runWithRecover(c, b, opts)
		results = append(results, r)
		// Aggregate: any Fail demotes overall to Fail (terminal);
		// Skipped demotes Pass/Warn to Skipped but doesn't override
		// Fail; Warn demotes Pass to Warn but doesn't override
		// Skipped or Fail.
		switch r.Status {
		case StatusFail:
			overall = StatusFail
		case StatusSkipped:
			if overall != StatusFail {
				overall = StatusSkipped
			}
		case StatusWarn:
			if overall == StatusPass {
				overall = StatusWarn
			}
		}
	}
	return results, overall
}

// SortByCheckID returns a copy of `results` sorted ascending by CheckID.
// Pre-Phase 6 Item 2 closure 2026-05-15: Check 8 (ephemeral-session)
// runs BEFORE Check 3 in registry order under ephemeral-sessions
// topology (Check 3 reads the bundle.EphemeralPubkeyByID map Check 8
// populates). The cmd-layer report path calls SortByCheckID so the
// JSONOutput emits checks[] in canonical spec §14.1 order (1, 2, 3, 4,
// 5, 6, 7, [8]) regardless of registry-execution order. RunChecks
// itself preserves registry order so direct in-process consumers (tests
// + stub-check harnesses) see the order they registered checks in.
func SortByCheckID(results []CheckResult) []CheckResult {
	out := make([]CheckResult, len(results))
	copy(out, results)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CheckID < out[j].CheckID
	})
	return out
}

// runWithRecover invokes c.Run inside a deferred recover so a panic
// in any one check converts to a Fail result + continues to the next
// check. Without this, an attacker who finds a panic-trigger in any
// external-anchor parser could suppress every other anchor leg's
// verdict — a denial-of-verification primitive even without forgery.
func runWithRecover(c Check, b *bundle.Bundle, opts CheckOptions) (r CheckResult) {
	start := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			// security-auditor H2 closure 2026-05-22: debug.Stack()
			// embedded in the error string leaks build paths to
			// operator-visible JSON output (CLI binary distributed
			// publicly; WASM module loaded by marketing /verify).
			// Stack trace goes to stderr for debugging; the operator-
			// surface message carries only the panic value. The
			// Makefile separately applies -trimpath to both native
			// and WASM builds as defense-in-depth.
			fmt.Fprintf(os.Stderr, "panic in check %d (%s): %v\n%s\n",
				c.ID(), c.Name(), rec, debug.Stack())
			r = CheckResult{
				CheckID:   c.ID(),
				CheckName: c.Name(),
				CheckSlug: c.Slug(),
				Status:    StatusFail,
				Errors: []error{
					fmt.Errorf("check %d (%s): internal verifier error (stack trace written to stderr)",
						c.ID(), c.Name()),
				},
				DurationMS: time.Since(start).Milliseconds(),
			}
		}
	}()
	r = c.Run(b, opts)
	r.DurationMS = time.Since(start).Milliseconds()
	return r
}

// ResultWithCategory builds a CheckResult with errors/warnings/
// warn-category populated. Per spec §14.4 (v1.0.7), checks that emit
// a warn matching an opt-in category (dev_key / pending_ots /
// anchor_pending / tsa_surplus) SHOULD use this factory and supply
// the matching WarnCategory* constant.
//
// `warnCategory` is honored only when the computed Status == Warn.
// Pass "" for warns that do NOT match an opt-in category (the verdict
// aggregator treats empty WarnCategory as "not foldable").
func ResultWithCategory(id int, name, slug string, errs []error, warnings []error, warnCategory string) CheckResult {
	r := Result(id, name, slug, errs, warnings)
	if r.Status == StatusWarn {
		r.WarnCategory = warnCategory
	}
	return r
}

// Result builds a CheckResult with errors/warnings populated. The
// per-check implementations call this with their accumulated lists;
// the function chooses Status from the lists' contents:
//
//   - errors empty + warnings empty             → Pass
//   - errors empty + warnings non-empty         → Warn
//   - errors non-empty                          → Fail (warnings still
//     surfaced for diagnostic context)
//
// This factoring means every check's Run method has the same final
// statement: `return Result(checkID, checkName, checkSlug, errors, warnings)`.
//
// Callers emitting an opt-in-category warn (dev_key / pending_ots /
// anchor_pending / tsa_surplus per spec §14.4) SHOULD prefer
// ResultWithCategory to populate the WarnCategory field for the
// aggregator's warn-fold decision.
func Result(id int, name, slug string, errs []error, warnings []error) CheckResult {
	r := CheckResult{
		CheckID:   id,
		CheckName: name,
		CheckSlug: slug,
		Errors:    errs,
		Warnings:  warnings,
	}
	switch {
	case len(errs) > 0:
		r.Status = StatusFail
	case len(warnings) > 0:
		r.Status = StatusWarn
	default:
		r.Status = StatusPass
	}
	return r
}

// Skipped builds a CheckResult with StatusSkipped. SkipReason is the
// human-readable explanation; it lives in its own field, NOT in
// Warnings, so reporting layers can distinguish "skipped" from
// "warning" without parsing message strings.
func Skipped(id int, name, slug, reason string) CheckResult {
	return CheckResult{
		CheckID:    id,
		CheckName:  name,
		CheckSlug:  slug,
		Status:     StatusSkipped,
		SkipReason: reason,
	}
}

// =============================================================================
// Error message conventions
// =============================================================================
//
// Every check's errors and warnings follow a consistent format so
// Session 4's reporting layer (and external tooling parsing CLI
// output) doesn't have to reverse-engineer per-check vocabulary:
//
//   check N (<short-name>): <bundle-relative-path>: <specific issue>;
//   spec §X.Y requires <one-sentence rule>
//
// Examples:
//
//   check 1 (manifest signature): signature.sig: Ed25519 verification
//   failed against pinned issuer-dev-v1 key; spec §5 requires the
//   signature verifies over manifest.json bytes
//
//   check 2 (artifact integrity): events.jsonl: declared SHA-256
//   abc123… but computed def456…; spec §3 requires manifest hash
//   matches artifact bytes
//
//   check 3 (hash chain): events.jsonl line 14: prev_event_hash
//   declared 3f034d… but expected 88f09d…; spec §6.2 requires every
//   event chains from the prior event's event_hash
//
//   check 4 (Merkle proof): merkle_proofs.json proofs[7]: walked
//   root computed 220c62… but proof.root declared 7a8c9b…; spec
//   §8.2 requires proof.root equals the daily root
//
// **Spec-section references in error messages are intentionally
// strings, not enum constants.** Session 2 commit 2 introduces a
// specrefs.go constants table to address the mechanical-edit-drift
// risk that the spec-amendment session reviewer flagged (H2 from
// commit-1 reviewer pass): if a future spec amendment renumbers
// sections again, every error message hardcoding "spec §6.2" would
// silently desync. The constants table centralizes the references
// so a spec amendment touches one Go file.

// Errorf builds an error in the canonical check-error format.
//
// Args:
//   - checkID: spec §14 check number
//   - checkName: short human-readable label
//   - artifactPath: bundle-relative path (e.g., "events.jsonl",
//     "rfc3161_receipts/2026-04-22__digicert.tsr"), or empty when
//     the error doesn't apply to a specific artifact
//   - issue: short specific description of what failed
//   - specSection: e.g., "§5", "§6.2", "§7.3"
//   - rule: one-sentence spec rule the issue violates
//
// If exactly one of (specSection, rule) is empty (a caller bug), the
// "spec ... requires ..." clause is omitted entirely rather than
// emitting a malformed string. The H4 commit-1 reviewer finding.
func Errorf(checkID int, checkName, artifactPath, issue, specSection, rule string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "check %d (%s)", checkID, checkName)
	if artifactPath != "" {
		fmt.Fprintf(&b, ": %s", artifactPath)
	}
	fmt.Fprintf(&b, ": %s", issue)
	// Both required for the spec-rule clause; if either missing,
	// emit just the issue.
	if specSection != "" && rule != "" {
		fmt.Fprintf(&b, "; spec %s requires %s", specSection, rule)
	}
	return errors.New(b.String())
}

// Warnf builds a warning in the canonical check-warning format. Same
// shape as Errorf; intended for closed-set + warn-not-fail surfaces
// (unknown enum values, placeholder prod key, pending OTS, etc.).
//
// The runtime-emitted string is identical to Errorf — the distinction
// between error and warning lives in which CheckResult slice the
// value lands in (Errors vs Warnings), not in the message text.
// Session 4's reporting layer renders the slice prefix.
func Warnf(checkID int, checkName, artifactPath, issue, specSection, rule string) error {
	return Errorf(checkID, checkName, artifactPath, issue, specSection, rule)
}

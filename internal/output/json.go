package output

import (
	"encoding/json"
	"fmt"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/checks"
)

// OutputFormatVersion is the stable version identifier of the JSON
// output schema. Adding, removing, or renaming a field in JSONOutput
// / CheckJSON / SummaryJSON requires bumping this version. CI
// integrations parse on this version; a v1 parser MUST safely
// handle a v1.x message AND MUST fail loudly on a v2 message
// rather than silently dropping fields it doesn't understand.
//
// **v1 contract field set** (do not change without bumping version):
//
//	JSONOutput:
//	  output_format_version  string
//	  verdict                string  ("pass" | "fail" | "partial_verification")
//	  exit_code              int     (0 | 1)
//	  reason                 string  (operator-readable rationale, ALWAYS present)
//	  checks                 []CheckJSON
//	  summary                SummaryJSON
//
//	CheckJSON:
//	  check_id            int
//	  check_name          string
//	  check_slug          string
//	  status              string  ("pass" | "fail" | "warn" | "skipped")
//	  warn_category       string  (always emitted; v1.0.7 addition)
//	  errors              []string  (always emitted; empty array, never null)
//	  warnings            []string  (always emitted; empty array, never null)
//	  skip_reason         string    (always emitted; empty string when not skipped)
//	  duration_ms         int64
//	  algorithm_verdicts  []{algorithm, status}  (OPTIONAL OMITEMPTY; v1.x
//	                      additive field per spec §18.10 Phase 7.F.3 — omitted
//	                      on v1 bundles + non-Check-1 checks; v1 fixture bytes
//	                      unchanged)
//
//	SummaryJSON:
//	  passed                int
//	  failed                int
//	  warned                int
//	  skipped               int
//	  warns_opted_into_pass int  (count of warns folded into passed via --allow-* flags)
//
// Tenant 1 (long-term value): the schema contract outlasts the
// implementation. CI pipelines built today should keep working in
// 2042; bumping the version is a conscious break, not a silent
// drift.
//
// **Bundle-format-dependent emission (Phase 7.F.3 v2.0.0-rc1 + spec-
// conformance C1 closure 2026-05-22)**: spec §18.10 + §14.1 line 1632
// mandate `output_format_version: "2"` for v2 bundles + `"1"` for v1
// bundles. v1 consumers MUST fail loudly on `output_format_version !=
// "1"` per §14.1 prose. Verifier threads the bundle's BundleFormat
// into FormatResults via FormatResultsForBundle; legacy FormatResults
// (no bundle context) emits v1 for back-compat with v1-only callers.
//
// algorithm_verdicts under omitempty is correct for v1 bundles (the
// v1 single-Ed25519 Check 1 never populates the field, so v1 output
// bytes are byte-identical with pre-Phase-7.F.3 output).
const (
	OutputFormatVersionV1 = "1"
	OutputFormatVersionV2 = "2"
)

// OutputFormatVersion preserves the v1 constant for downstream callers
// that read the package-level identifier. Equals OutputFormatVersionV1.
const OutputFormatVersion = OutputFormatVersionV1

// VerdictPass / VerdictFail / VerdictPartialVerification are the
// canonical lowercase string forms surfaced in the JSON output's
// `verdict` field. CI pipelines pattern-match against these
// strings; do not change them without bumping OutputFormatVersion.
const (
	jsonVerdictPass    = "pass"
	jsonVerdictFail    = "fail"
	jsonVerdictPartial = "partial_verification"
)

// JSONFormatter renders the verification report as JSON. Indented
// mode pretty-prints for human inspection; non-indented mode
// produces a single line for log-shippers that prefer one event
// per line.
type JSONFormatter struct {
	indent bool
}

// NewJSONFormatter constructs a formatter. Pass indent=true for
// pretty-printed output (the CLI default when --json is passed
// without explicit indent control).
func NewJSONFormatter(indent bool) *JSONFormatter {
	return &JSONFormatter{indent: indent}
}

// JSONOutput is the top-level shape of the JSON output. Field order
// in marshaling follows struct declaration order; do not reorder
// without bumping OutputFormatVersion.
type JSONOutput struct {
	OutputFormatVersion string      `json:"output_format_version"`
	Verdict             string      `json:"verdict"`
	ExitCode            int         `json:"exit_code"`
	Reason              string      `json:"reason"`
	Checks              []CheckJSON `json:"checks"`
	Summary             SummaryJSON `json:"summary"`
}

// CheckJSON is one check's verdict in the JSON output. errors and
// warnings are arrays of strings (the .Error() representation of
// each error); CI integrations match on substring or use the
// per-check status field. skip_reason is always emitted (empty
// string when the check wasn't skipped) for schema-stability
// consistency with errors/warnings — crypto-integrity-reviewer M2
// (D5 c1+c2 review).
type CheckJSON struct {
	CheckID    int      `json:"check_id"`
	CheckName  string   `json:"check_name"`
	CheckSlug  string   `json:"check_slug"`
	Status     string   `json:"status"`
	// WarnCategory is the spec §14.4 (v1.0.7) structured warn-fold
	// category. Populated when Status="warn" and the warn corresponds
	// to an opt-in category (dev_key / pending_ots / anchor_pending /
	// tsa_surplus). Empty string when not applicable. Always emitted
	// for shape stability; conformance contract ignores empty values.
	WarnCategory string   `json:"warn_category"`
	Errors       []string `json:"errors"`
	Warnings     []string `json:"warnings"`
	SkipReason   string   `json:"skip_reason"`
	DurationMs   int64    `json:"duration_ms"`
	// AlgorithmVerdicts is the v2 dual-signature per-algorithm verdict
	// surface per spec §18.10 (Phase 7.F.3 v2.0.0-rc1 addition). For
	// v2 bundles' Check 1: exactly 2 entries — {algorithm:"ed25519",
	// status:"pass"|"fail"} + {algorithm:"ml-dsa-65", status:
	// "pass"|"fail"}. Omitted (omitempty) on v1 bundles + non-Check-1
	// checks. CI tooling, dispute-investigation tools, and marketing
	// /verify route consume this as the canonical per-algorithm
	// verdict surface (no short-circuit: both verdicts populate even
	// when one algorithm fails).
	AlgorithmVerdicts []AlgorithmVerdictJSON `json:"algorithm_verdicts,omitempty"`
}

// AlgorithmVerdictJSON is one entry in CheckJSON.AlgorithmVerdicts per
// spec §18.10. Phase 7.F.3 v2.0.0-rc1 addition.
type AlgorithmVerdictJSON struct {
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
}

// SummaryJSON is the per-bucket count of check verdicts. Counts add
// to the total number of checks run (passed + failed + warned +
// skipped == len(checks)). warns_opted_into_pass is the subset of
// passed that was originally WARN status but folded into pass via
// --allow-pending-ots / --allow-anchor-pending; surfaced for
// transparent operator disclosure (Tenant 5).
type SummaryJSON struct {
	Passed             int `json:"passed"`
	Failed             int `json:"failed"`
	Warned             int `json:"warned"`
	Skipped            int `json:"skipped"`
	WarnsOptedIntoPass int `json:"warns_opted_into_pass"`
}

// FormatResults implements Formatter for v1 bundles (back-compat
// caller path that doesn't carry bundle_format context). Emits
// OutputFormatVersionV1. v2 callers MUST use FormatResultsForBundle
// to satisfy spec §18.10 + §14.1 line 1632 ("v2 verifier emits '2'").
func (f *JSONFormatter) FormatResults(results []checks.CheckResult, verdict checks.ExitVerdict) string {
	return f.formatInternal(results, verdict, OutputFormatVersionV1)
}

// FormatResultsForBundle implements Formatter with bundle_format
// awareness per spec-conformance C1 closure 2026-05-22. v2 bundles
// emit OutputFormatVersionV2; v1 bundles emit OutputFormatVersionV1.
// bundleFormat is the manifest.bundle_format string ("nuwyre-bundle/v1"
// or "nuwyre-bundle/v2"); unknown values fall back to v1 for back-compat.
func (f *JSONFormatter) FormatResultsForBundle(results []checks.CheckResult, verdict checks.ExitVerdict, bundleFormat string) string {
	version := OutputFormatVersionV1
	// Phase 7.F.4 promotion gate session 102 2026-05-22 code-rev H1
	// closure: use bundle.BundleFormatV2 constant rather than bare
	// string literal (single source of truth; n=22+ recurring-defect-
	// class first instance — closed-vocabulary spec-pinned field).
	if bundleFormat == bundle.BundleFormatV2 {
		version = OutputFormatVersionV2
	}
	return f.formatInternal(results, verdict, version)
}

// formatInternal is the shared marshaling implementation. Errors
// during marshaling fall back to a minimal error JSON (this should
// never happen with the well-defined struct shape but defensive
// handling avoids producing invalid bytes that would break CI parsers).
func (f *JSONFormatter) formatInternal(results []checks.CheckResult, verdict checks.ExitVerdict, formatVersion string) string {
	out := JSONOutput{
		OutputFormatVersion: formatVersion,
		Verdict:             verdictJSONLabel(verdict.Verdict),
		ExitCode:            verdict.ExitCode,
		Reason:              verdict.Reason,
		Checks:              make([]CheckJSON, 0, len(results)),
		Summary: SummaryJSON{
			Passed:             verdict.Summary.Passed,
			Failed:             verdict.Summary.Failed,
			Warned:             verdict.Summary.Warned,
			Skipped:            verdict.Summary.Skipped,
			WarnsOptedIntoPass: verdict.Summary.WarnsOptedIntoPass,
		},
	}

	for _, r := range results {
		var algoVerdicts []AlgorithmVerdictJSON
		if len(r.AlgorithmVerdicts) > 0 {
			algoVerdicts = make([]AlgorithmVerdictJSON, len(r.AlgorithmVerdicts))
			for i, av := range r.AlgorithmVerdicts {
				algoVerdicts[i] = AlgorithmVerdictJSON{
					Algorithm: av.Algorithm,
					Status:    av.Status,
				}
			}
		}
		out.Checks = append(out.Checks, CheckJSON{
			CheckID:           r.CheckID,
			CheckName:         r.CheckName,
			CheckSlug:         r.CheckSlug,
			Status:            r.Status.String(),
			WarnCategory:      r.WarnCategory,
			Errors:            errorsToStrings(r.Errors),
			Warnings:          errorsToStrings(r.Warnings),
			SkipReason:        r.SkipReason,
			DurationMs:        r.DurationMS,
			AlgorithmVerdicts: algoVerdicts,
		})
	}

	var (
		data []byte
		err  error
	)
	if f.indent {
		data, err = json.MarshalIndent(out, "", "  ")
	} else {
		data, err = json.Marshal(out)
	}
	if err != nil {
		// Defensive: should never happen with the typed struct, but
		// produce parseable error JSON rather than empty output if
		// it does. CI integrations expect parseable JSON regardless
		// of internal verifier state.
		//
		// Code-reviewer M1 (D5 c1+c2 review, raised to High):
		// previous implementation used %s for err.Error() which
		// would emit invalid JSON if the error contained quotes,
		// backslashes, or newlines. Build the fallback via a typed
		// struct + json.Marshal so escaping is handled correctly.
		fallback, marshalErr := json.Marshal(struct {
			OutputFormatVersion string `json:"output_format_version"`
			Verdict             string `json:"verdict"`
			ExitCode            int    `json:"exit_code"`
			Reason              string `json:"reason"`
		}{
			OutputFormatVersion: OutputFormatVersion,
			Verdict:             jsonVerdictFail,
			ExitCode:            1,
			Reason:              "internal: JSON marshal failed: " + err.Error(),
		})
		if marshalErr != nil {
			// Belt-and-suspenders: even the fallback shouldn't fail,
			// but if it does, emit a hardcoded minimal-valid JSON.
			return fmt.Sprintf(`{"output_format_version":%q,"verdict":%q,"exit_code":1,"reason":"internal: fallback marshal also failed"}`,
				OutputFormatVersion, jsonVerdictFail) + "\n"
		}
		return string(fallback) + "\n"
	}
	return string(data) + "\n"
}

// verdictJSONLabel maps VerdictCode → canonical lowercase JSON
// string. Stable across OutputFormatVersion="1"; do not change
// without bumping the version.
func verdictJSONLabel(v checks.VerdictCode) string {
	switch v {
	case checks.VerdictPass:
		return jsonVerdictPass
	case checks.VerdictFail:
		return jsonVerdictFail
	case checks.VerdictPartialVerification:
		return jsonVerdictPartial
	default:
		// Defensive: unknown verdict surfaces as fail to stay fail-
		// secure (Tenant 3). Should never happen with the typed
		// VerdictCode enum.
		return jsonVerdictFail
	}
}

// errorsToStrings converts an []error to a []string for JSON
// marshaling. nil-safe (returns empty slice, not nil — the JSON
// schema specifies empty arrays not null for the errors/warnings
// fields).
func errorsToStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		if e != nil {
			out = append(out, e.Error())
		}
	}
	return out
}

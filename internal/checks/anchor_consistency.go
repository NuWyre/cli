package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nuwyre/cli/internal/bundle"
)

// Cross-anchor consistency: manifest.anchor_status.{ots,rfc3161,github}
// summarizes the same state that manifest.anchors.{opentimestamps,
// rfc3161,github} encodes in detail. Both fields are written by the
// same generator (packages/evidence) at the same time; if they
// disagree, the bundle's narrative integrity is broken — the summary
// claims one state and the detail claims another, and a forensic
// reviewer has no way to know which is authoritative.
//
// Per Phase 4 Prereq Session B Item 5 (canonical 4-state
// mirror_status enum) + spec §4.2 + §11.1, both fields share the
// canonical enum. This consistency check fires before per-check
// verification (5/6/7) — an inconsistency is a structural defect
// the operator should hear about loudly, not a soft warning buried
// inside one of the anchor checks' output.
//
// The check is invoked by checks 5/6/7 at start-of-Run; each check
// is responsible for surfacing its leg's consistency error in its
// own CheckResult. A bundle with manifest/anchors disagreement on
// OTS but agreement on RFC 3161 + github would have check 5 Fail
// + checks 6 + 7 proceeding normally — the failure attribution stays
// granular.

// Per-leg canonical enums per spec §4.2 + §11.1 (post-Session-B
// reconciliation). C1 from D1 reviewer pass: a single shared map
// would let validateGitHubConsistency accept "verified" (RFC 3161
// vocabulary) or validateOTSConsistency accept "anchored" (GitHub
// vocabulary), silently passing cross-leg-confused tampering. Per-leg
// allowlists close that hole.
var (
	otsSummaryStatusValues = map[string]bool{
		"pending":   true, // OTS submitted; awaiting Bitcoin confirmation
		"confirmed": true, // OTS attested in a Bitcoin block
		"failed":    true,
	}
	rfc3161StatusValues = map[string]bool{
		"not_attempted": true,
		"partial":       true, // 1 of 3 TSAs returned valid receipt (below threshold)
		"verified":      true, // ≥2 of 3 TSAs returned valid receipts
		"failed":        true,
	}
	githubStatusValues = map[string]bool{
		"not_attempted":  true,
		"anchor-pending": true,
		"anchored":       true,
		"failed":         true,
	}
)

// validateOTSConsistency checks that manifest.anchor_status.ots_status
// agrees with manifest.anchors.opentimestamps.status. Returns nil on
// agreement; an error describing the disagreement on mismatch.
//
// Used by Check5OTS at start-of-Run. The check then proceeds to
// verify the receipt; the consistency check is a separate Fail
// surface that doesn't gate the rest of the check (so a
// content-tampering finding still gets surfaced even on an
// inconsistent bundle).
func validateOTSConsistency(b *bundle.Bundle) error {
	summary := b.Manifest.AnchorStatus.OTSStatus
	detail := b.Manifest.Anchors.OpenTimestamps.Status
	if summary == "" && detail == "" {
		return fmt.Errorf("both manifest.anchor_status.ots_status and manifest.anchors.opentimestamps.status are empty")
	}
	if !otsSummaryStatusValues[summary] {
		return fmt.Errorf("manifest.anchor_status.ots_status = %q is not a recognized OTS status (expected one of: pending, confirmed, failed)", summary)
	}
	if detail == "" {
		return fmt.Errorf("manifest.anchor_status.ots_status = %q but manifest.anchors.opentimestamps.status is empty",
			summary)
	}
	// H5 from D1 reviewer pass: implement the documented cross-check
	// matrix instead of accepting any non-empty detail. summary
	// "pending" → detail must contain "pending" or "submitted" (the
	// OTS pipeline's pending-state vocabulary). "confirmed" → detail
	// must contain "confirmed" or "attested". "failed" → detail
	// must contain "failed". Substring matching tolerates the OTS
	// pipeline's vocabulary evolution within each state without
	// silently accepting cross-state confusion (a "confirmed"
	// summary paired with "submission-failed" detail is the canonical
	// inconsistency this check exists to catch).
	detailLower := strings.ToLower(detail)
	switch summary {
	case "pending":
		if !strings.Contains(detailLower, "pending") && !strings.Contains(detailLower, "submitted") {
			return fmt.Errorf("manifest.anchor_status.ots_status = %q but manifest.anchors.opentimestamps.status = %q (detail must contain 'pending' or 'submitted' for pending state)",
				summary, detail)
		}
	case "confirmed":
		if !strings.Contains(detailLower, "confirmed") && !strings.Contains(detailLower, "attested") {
			return fmt.Errorf("manifest.anchor_status.ots_status = %q but manifest.anchors.opentimestamps.status = %q (detail must contain 'confirmed' or 'attested' for confirmed state)",
				summary, detail)
		}
	case "failed":
		if !strings.Contains(detailLower, "failed") {
			return fmt.Errorf("manifest.anchor_status.ots_status = %q but manifest.anchors.opentimestamps.status = %q (detail must contain 'failed' for failed state)",
				summary, detail)
		}
	}
	return nil
}

// validateRFC3161Consistency checks that manifest.anchor_status.rfc3161_status
// agrees with the per-TSA detail in manifest.anchors.rfc3161[].
// Returns nil on agreement; an error describing the disagreement
// on mismatch.
//
// Per spec §11.1, the canonical states are "verified" (≥2 of 3
// TSAs verified), "partial" (1 of 3), "failed" (0 of 3),
// "not_attempted".
func validateRFC3161Consistency(b *bundle.Bundle) error {
	summary := b.Manifest.AnchorStatus.RFC3161Status
	detail := b.Manifest.Anchors.RFC3161
	if !rfc3161StatusValues[summary] {
		return fmt.Errorf("manifest.anchor_status.rfc3161_status = %q is not a recognized RFC 3161 status (expected one of: not_attempted, partial, verified, failed)", summary)
	}
	tsaCount := len(detail)
	switch summary {
	case "not_attempted":
		if tsaCount > 0 {
			return fmt.Errorf("manifest.anchor_status.rfc3161_status = %q but manifest.anchors.rfc3161 has %d entries",
				summary, tsaCount)
		}
	case "verified":
		if tsaCount < 2 {
			return fmt.Errorf("manifest.anchor_status.rfc3161_status = %q (≥2 TSAs required) but manifest.anchors.rfc3161 has %d entries",
				summary, tsaCount)
		}
	case "partial":
		if tsaCount != 1 {
			return fmt.Errorf("manifest.anchor_status.rfc3161_status = %q (1 TSA returned valid receipt) but manifest.anchors.rfc3161 has %d entries",
				summary, tsaCount)
		}
	case "failed":
		if tsaCount > 0 {
			return fmt.Errorf("manifest.anchor_status.rfc3161_status = %q but manifest.anchors.rfc3161 has %d entries (failed = no valid receipts)",
				summary, tsaCount)
		}
	}
	// Per-TSA inspection: each entry's tsa_name is non-empty +
	// canonical-form (lowercase, no surrounding whitespace per spec
	// §3 "tsa_name MUST be a lowercase identifier"); receipt_path
	// and chain_path are non-empty.
	tsaNames := make([]string, 0, tsaCount)
	for i, t := range detail {
		// Sec H4 + L5 from D1 reviewer pass: reject non-canonical
		// tsa_name BEFORE normalizing for dup-detection. The
		// canonical-form rejection catches malformed manifests at
		// the format layer; the normalized dup check catches
		// equivalent-but-differently-spelled duplicates that would
		// otherwise falsely satisfy the 2-of-3 threshold.
		trimmed := strings.TrimSpace(t.TSAName)
		if trimmed == "" {
			return fmt.Errorf("manifest.anchors.rfc3161[%d].tsa_name is empty or whitespace", i)
		}
		if trimmed != t.TSAName {
			return fmt.Errorf("manifest.anchors.rfc3161[%d].tsa_name = %q has surrounding whitespace; spec §3 requires lowercase identifier with no whitespace",
				i, t.TSAName)
		}
		if strings.ToLower(trimmed) != trimmed {
			return fmt.Errorf("manifest.anchors.rfc3161[%d].tsa_name = %q is not lowercase; spec §3 requires lowercase identifier",
				i, t.TSAName)
		}
		if t.ReceiptPath == "" || t.ChainPath == "" {
			return fmt.Errorf("manifest.anchors.rfc3161[%d] (tsa_name=%q) missing receipt_path or chain_path",
				i, t.TSAName)
		}
		tsaNames = append(tsaNames, trimmed)
	}
	// Sec H4 from D1 reviewer pass: detect duplicate tsa_name AFTER
	// normalization (lowercase + trim above). This is the load-bearing
	// structural-tampering defense — a manifest that lists "freetsa"
	// + "freetsa " + "FreeTSA" must NOT pass as 3 distinct TSAs and
	// falsely satisfy the 2-of-3 threshold.
	sort.Strings(tsaNames)
	for i := 1; i < len(tsaNames); i++ {
		if tsaNames[i] == tsaNames[i-1] {
			return fmt.Errorf("manifest.anchors.rfc3161 has duplicate tsa_name=%q (after lowercase + whitespace normalization)", tsaNames[i])
		}
	}
	return nil
}

// validateGitHubConsistency checks that manifest.anchor_status.github_status
// agrees with the per-day github_anchors/<date>.json mirror_status
// values. Returns nil on agreement; an error describing the
// disagreement on mismatch.
//
// Per spec §11.1, the canonical 4-state enum applies here:
// "not_attempted" | "anchor-pending" | "anchored" | "failed".
func validateGitHubConsistency(b *bundle.Bundle) error {
	summary := b.Manifest.AnchorStatus.GithubStatus
	if !githubStatusValues[summary] {
		return fmt.Errorf("manifest.anchor_status.github_status = %q is not a recognized GitHub status (expected one of: not_attempted, anchor-pending, anchored, failed)", summary)
	}
	// M1 from D1 reviewer pass: a non-not_attempted summary with
	// zero github_anchors entries is structurally inconsistent —
	// the manifest claims an anchor state but no per-day file
	// substantiates it. Only "not_attempted" legitimately implies
	// zero entries.
	if summary != "not_attempted" && len(b.GithubAnchors) == 0 {
		return fmt.Errorf("manifest.anchor_status.github_status = %q but no github_anchors/<date>.json entries present", summary)
	}
	// M3 from D4 commit 2 security review: symmetric check —
	// not_attempted summary with non-empty github_anchors entries
	// is also structurally inconsistent. The bundle's degraded-mode
	// declaration ("we didn't attempt GitHub anchoring") is
	// contradicted by the presence of per-day entries; even if
	// those entries also declare not_attempted, the existence of
	// the entries is itself the inconsistency. Spec §12.1's
	// expected shape is zero entries when the summary is
	// not_attempted.
	if summary == "not_attempted" && len(b.GithubAnchors) > 0 {
		return fmt.Errorf("manifest.anchor_status.github_status = %q but %d github_anchors/<date>.json entries present (not_attempted MUST mean zero per-day entries)", summary, len(b.GithubAnchors))
	}
	// L9 from D1 reviewer pass: sort utc_day keys before iteration
	// so the surfaced error on a multi-day-disagreement bundle is
	// deterministic across runs.
	utcDays := make([]string, 0, len(b.GithubAnchors))
	for d := range b.GithubAnchors {
		utcDays = append(utcDays, d)
	}
	sort.Strings(utcDays)
	for _, utcDay := range utcDays {
		anchor := b.GithubAnchors[utcDay]
		if !githubStatusValues[anchor.MirrorStatus] {
			return fmt.Errorf("github_anchors/%s.json mirror_status = %q is not a recognized GitHub status (expected one of: not_attempted, anchor-pending, anchored, failed)",
				utcDay, anchor.MirrorStatus)
		}
		if anchor.MirrorStatus != summary {
			return fmt.Errorf("github_anchors/%s.json mirror_status = %q disagrees with manifest.anchor_status.github_status = %q",
				utcDay, anchor.MirrorStatus, summary)
		}
	}
	return nil
}

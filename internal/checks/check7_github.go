package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/keys"
)

// Check7Github verifies the spec §12 GitHub anchor cross-check
// contract: each daily root in `daily_roots.json` has a corresponding
// entry in `github_anchors/<date>.json` declaring an anchor commit
// in NuWyre/anchors that records the daily root in a public, append-
// only, third-party-hosted location.
//
// **Implements all four mirror_status branches:**
//   - Cross-anchor consistency check (per D1's
//     validateGitHubConsistency) runs before per-day dispatch.
//   - V1 anchor-pending state handling: FAIL by default (Tenant 5
//     operator visibility into deploy-bootstrap state);
//     PASS-equivalent at the verdict-aggregator layer under
//     --allow-anchor-pending opt-in (folds the per-check WARN
//     into PASS via aggregate.go's isWarnAllowed dispatch).
//   - failed mirror state: FAIL with operator-actionable framing
//     (writer-declared degradation, not tampering signal).
//   - Unknown mirror_status: FAIL with spec §12.1 reference
//     (fail-secure on unrecognized values per Tenant 3).
//   - --offline short-circuit: SKIPPED.
//
// **Anchored path** (Phase 4 dedicated SSH session, commit 3):
// previously stubbed in D4 commit 2 with explicit "deferred"
// diagnostic; now fully implemented per spec §12.4 verification
// procedure:
//  1. Validate commit_sha format per commit_sha_format dispatch.
//  2. Fetch root.json from anchor repo at the declared commit_sha.
//  3. Parse + cross-check root.json against bundle:
//     - organization_id matches bundle's manifest.organization_id
//     - root_hash matches bundle's daily_roots[date].root
//     - anchors.opentimestamps.receipt_sha256 matches bundle's
//     OTS receipt SHA-256
//     - anchors.rfc3161[].receipt_sha256 + chain_sha256 match
//     bundle's per-TSA SHAs
//  4. Fetch commit metadata (verification.signature + payload).
//  5. Verify SSH signature via SSHSignatureVerifier against pinned
//     issuer SSH key (dispatched by bundle_type + AllowDevKey
//     gate per security-auditor SSH-c1 H1 fix).
//  6. PASS iff all sub-verifications pass; per-anchored-bundle
//     warning surfaces signer fingerprint for forensic transparency.
//
// **Cross-implementation oracle.** The TS verify-bundle.ts at
// packages/example-bundle/scripts/verify-bundle.ts performs basic
// github_anchors structural checks but defers full cross-check to
// "Phase 4 Go CLI". This Go check 7 IS the canonical implementation;
// the post-Phase-5 anchored path will close the cross-check gap
// once the anchor repo bootstrap completes.
type Check7Github struct {
	fetcher GithubFetcher
}

// NewCheck7Github constructs a check 7 instance. Production callers
// pass a GithubHTTPSFetcher; tests inject a MockGithubFetcher.
//
// fetcher MAY be nil — check 7's V1 anchor-pending, failed, and
// unknown mirror_status paths don't require network access. The
// anchored path DOES require a non-nil fetcher; handleAnchored
// validates this and returns an internal-error FAIL with operator-
// readable diagnostic if invoked with nil fetcher.
func NewCheck7Github(fetcher GithubFetcher) *Check7Github {
	return &Check7Github{fetcher: fetcher}
}

func (Check7Github) ID() int      { return 7 }
func (Check7Github) Name() string { return "GitHub anchor cross-check" }
func (Check7Github) Slug() string { return "github" }

func (c *Check7Github) Run(b *bundle.Bundle, opts CheckOptions) CheckResult {
	const id = 7
	const checkName = "GitHub anchor cross-check"
	const slug = "github"

	if opts.Offline {
		return SkippedDueToOffline(id, checkName, slug)
	}

	var errs []error
	var warnings []error
	// Spec §14.4 (v1.0.7) WarnCategory tracking. Two warning sources
	// in check 7:
	//   - handleAnchorPending → anchor_pending category warns (single
	//     warn per day; folds INTO pass under --allow-anchor-pending)
	//   - handleAnchored → transient-network warns (NOT in any opt-in
	//     category; MUST NOT fold under --allow-anchor-pending — that
	//     would silently accept "couldn't fetch the anchor" as
	//     "verified-against-the-anchor")
	//
	// We tag the final result with WarnCategoryAnchorPending ONLY when
	// ALL warnings emitted across all days came from the anchor-pending
	// path. A single transient warn from handleAnchored disqualifies
	// the tag (spec §14.4 multi-warning safety invariant). Aggregator
	// then folds correctly: anchor_pending warns fold under the flag;
	// mixed-with-transient does NOT.
	//
	// (Phase 5.5 Session 5.5.1C reviewer fix-up batch: closes
	// TRIPLE-corroborated fold-safety regression at code-rev #2 +
	// crypto-int #1 + spec-rev F2-cluster.)
	allWarnsFromAnchorPending := true

	// 1. Cross-anchor consistency (per D1's anchor_consistency.go).
	// Run BEFORE per-day verification so a manifest-vs-detail
	// inconsistency is reported at its native level rather than
	// masked by per-day errors.
	if err := validateGitHubConsistency(b); err != nil {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("anchor consistency failure: %v", err),
			SpecRefGitHubAnchorSchema,
			"manifest.anchor_status.github_status agrees with github_anchors/<date>.json mirror_status per the canonical 4-state enum"))
		return Result(id, checkName, slug, errs, warnings)
	}

	githubStatus := b.Manifest.AnchorStatus.GithubStatus

	// 2. Short-circuit on declared "not_attempted" — degraded-mode
	// bundle, operator opted out of GitHub anchoring. The
	// consistency check above already enforced that this implies
	// zero entries in github_anchors/. Pass with no warnings; the
	// degraded state is visible in the manifest disclosure itself.
	if githubStatus == "not_attempted" {
		return Result(id, checkName, slug, errs, warnings)
	}

	// 3. Iterate daily roots in deterministic (sorted by date) order.
	dailyRoots := make([]bundle.DailyRootEntry, len(b.DailyRoots.Roots))
	copy(dailyRoots, b.DailyRoots.Roots)
	sort.SliceStable(dailyRoots, func(i, j int) bool {
		return dailyRoots[i].Date < dailyRoots[j].Date
	})

	for _, dr := range dailyRoots {
		dayErrs, dayWarnings, daySource := c.verifyDailyRoot(b, dr, githubStatus, opts)
		errs = append(errs, dayErrs...)
		warnings = append(warnings, dayWarnings...)
		// Multi-warning safety: a day whose mirror_status routed
		// through handleAnchored AND produced warnings emitted
		// transient-network warns (NOT anchor_pending). Disqualify
		// the anchor_pending tag for the whole result.
		if len(dayWarnings) > 0 && daySource != warnSourceAnchorPending {
			allWarnsFromAnchorPending = false
		}
	}

	var warnCategory string
	if allWarnsFromAnchorPending && len(warnings) > 0 {
		warnCategory = WarnCategoryAnchorPending
	}
	return ResultWithCategory(id, checkName, slug, errs, warnings, warnCategory)
}

// warnSource tags the source of warnings produced by verifyDailyRoot,
// so check 7's Run can decide whether to tag the aggregated result
// with WarnCategoryAnchorPending. Spec §14.4 (v1.0.7).
type warnSource int

const (
	// warnSourceNone — no warnings produced.
	warnSourceNone warnSource = iota
	// warnSourceAnchorPending — produced by handleAnchorPending under
	// mirror_status="anchor-pending". Foldable under --allow-anchor-pending.
	warnSourceAnchorPending
	// warnSourceTransient — produced by handleAnchored under transient
	// network failure. NOT in any opt-in category; MUST NOT fold.
	warnSourceTransient
)

// verifyDailyRoot performs per-day GitHub anchor verification.
// Returns (errors, warnings, warnSource) for that day; the caller
// accumulates across days. The third return tags the WarnCategory
// source per spec §14.4 (v1.0.7) — Run uses it to decide whether to
// emit WarnCategoryAnchorPending on the aggregated result.
func (c *Check7Github) verifyDailyRoot(
	b *bundle.Bundle,
	dr bundle.DailyRootEntry,
	githubStatus string,
	opts CheckOptions,
) (errs, warnings []error, src warnSource) {
	const id = 7
	const checkName = "GitHub anchor cross-check"

	// 3a. Locate per-day github_anchors entry.
	anchor, ok := b.GithubAnchors[dr.Date]
	if !ok {
		// Bundle declares non-"not_attempted" status but has no
		// per-day entry. Operator-actionable framing per D3 commit 2's
		// pattern: distinguish writer-declared degradation from
		// tampering signal.
		// Defense-in-depth on dr.Date interpolation: daily_roots.json
		// roots[].date isn't loader-validated as YYYY-MM-DD (the
		// loader only enforces shape on filename-derived dates, not
		// on JSON content). %q neutralizes any control characters /
		// ANSI escapes that a tampered daily_roots.json could smuggle
		// into operator terminal output. (Security-auditor M1, D4
		// commit 2 review.)
		var msg string
		switch githubStatus {
		case "anchored", "anchor-pending":
			msg = fmt.Sprintf(
				"manifest declares github_status=%q but no github_anchors/%q.json entry present",
				githubStatus, dr.Date,
			)
		case "failed":
			msg = fmt.Sprintf(
				"writer-declared github_status=%q for daily root date %q; bundle does not satisfy spec §12 GitHub anchor",
				githubStatus, dr.Date,
			)
		default:
			msg = fmt.Sprintf(
				"no github_anchors/%q.json entry present under manifest.anchor_status.github_status=%q",
				dr.Date, githubStatus,
			)
		}
		return []error{Errorf(id, checkName,
			fmt.Sprintf("github_anchors/%s.json", dr.Date),
			msg,
			SpecRefGitHubAnchor,
			"every daily root has a corresponding github_anchors/<date>.json entry unless github_status='not_attempted'")}, nil, warnSourceNone
	}

	// 3b. Dispatch on per-day mirror_status. The canonical 4-state
	// enum is enforced by the loader (load_dirs.go) + validateGitHub
	// Consistency above; the dispatch here uses the canonical names
	// directly. Defense-in-depth: an unknown value reaching this
	// switch indicates the loader OR the consistency check missed
	// something — fail-secure with explicit spec reference.
	switch anchor.MirrorStatus {

	case "anchor-pending":
		e, w := c.handleAnchorPending(dr, anchor, opts)
		s := warnSourceNone
		if len(w) > 0 {
			s = warnSourceAnchorPending
		}
		return e, w, s

	case "failed":
		// Writer-declared degradation — operator-actionable framing.
		return []error{Errorf(id, checkName,
			fmt.Sprintf("github_anchors/%s.json", dr.Date),
			fmt.Sprintf(
				"writer-declared mirror_status=%q for daily root date %q; the anchor commit attempt did not succeed (this is bundle-side honest disclosure of a known failure, not a tampering signal — but the bundle does not satisfy spec §12 GitHub anchor)",
				anchor.MirrorStatus, dr.Date,
			),
			SpecRefGitHubAnchor,
			"every anchored daily root has a successful anchor commit (mirror_status='anchored') in NuWyre/anchors")}, nil, warnSourceNone

	case "anchored":
		e, w := c.handleAnchored(b, dr, anchor, opts)
		s := warnSourceNone
		if len(w) > 0 {
			// handleAnchored emits only transient-network warns (not in
			// any opt-in category). Tag as transient so Run does NOT
			// fold under --allow-anchor-pending.
			s = warnSourceTransient
		}
		return e, w, s

	default:
		// Fail-secure on unknown mirror_status — should never reach
		// here if validateGitHubConsistency + the loader did their
		// job. Defense-in-depth.
		return []error{Errorf(id, checkName,
			fmt.Sprintf("github_anchors/%s.json", dr.Date),
			fmt.Sprintf(
				"unknown mirror_status %q for daily root date %q (spec §12.1 + §4.2 define canonical 4-state enum: not_attempted | anchor-pending | anchored | failed)",
				anchor.MirrorStatus, dr.Date,
			),
			SpecRefGitHubAnchorSchema,
			"mirror_status MUST be one of the canonical 4 enum values")}, nil, warnSourceNone
	}
}

// handleAnchorPending implements the V1 deploy-bootstrap path:
// WARN by default (operator visibility); PASS-equivalent under
// --allow-anchor-pending (opt-in suppression). Mirrors the
// --allow-pending-ots pattern from check 5.
//
// Per Tenant 5 (customer trust): default behavior surfaces the
// deploy-bootstrap state explicitly so operators understand what
// they're verifying. The flag exists for the V1 example-demo
// + transitional production cases; as Phase 5 production cron
// lands, the flag becomes increasingly rare and the verifier's
// default behavior naturally tightens over time.
func (c *Check7Github) handleAnchorPending(
	dr bundle.DailyRootEntry,
	anchor bundle.GithubAnchorJSON,
	opts CheckOptions,
) (errs, warnings []error) {
	const id = 7
	const checkName = "GitHub anchor cross-check"

	if opts.AllowAnchorPending {
		// Operator opted INTO accepting V1 deploy-bootstrap state.
		// Surface as WARN so the state is still operator-visible in
		// the verdict, just doesn't gate the overall PASS.
		//
		// M2 from D4 commit 2 crypto review: do NOT make unconditional
		// cross-leg claims about OTS / RFC 3161 providing "independent
		// witnesses today" — check 7 doesn't verify those legs, and a
		// bundle with degraded OTS+RFC3161 legs would surface a
		// misleading warning. Direct the operator to the other checks'
		// verdicts instead. Tenant 5: warnings stay honest about what
		// this check actually verified.
		return nil, []error{Warnf(id, checkName,
			fmt.Sprintf("github_anchors/%s.json", dr.Date),
			fmt.Sprintf(
				"mirror_status=%q for daily root date %q — V1 deploy-bootstrap state (--allow-anchor-pending opt-in: anchor commit deferred to Phase 5; operator MUST verify check 5 (OTS Bitcoin) + check 6 (RFC 3161) verdicts to confirm independent witnesses are present)",
				anchor.MirrorStatus, dr.Date,
			),
			SpecRefGitHubAnchor,
			"V1 anchor-pending state is operator-acknowledged degradation; full anchor verification awaits post-Phase-5 anchored commits")}
	}

	// Default: FAIL with explicit V1 deploy-bootstrap framing AND
	// the --allow-anchor-pending opt-in pointer. Tenant 5: the
	// operator reading this knows (a) what state the bundle is in,
	// (b) why verification fails, (c) how to opt-in to PASS if
	// they accept the V1 trade-off.
	return []error{Errorf(id, checkName,
		fmt.Sprintf("github_anchors/%s.json", dr.Date),
		fmt.Sprintf(
			"mirror_status=%q for daily root date %q — V1 deploy-bootstrap state (the GitHub anchor commit + push that lifts mirror_status to 'anchored' is deferred to Phase 5; pass --allow-anchor-pending to accept this V1 state and verify with the other anchor legs — see check 5 (OTS) + check 6 (RFC 3161) verdicts)",
			anchor.MirrorStatus, dr.Date,
		),
		SpecRefGitHubAnchor,
		"GitHub anchor MUST be in 'anchored' state for full verification; --allow-anchor-pending opts INTO PASS for V1 example-demo + transitional production bundles")}, nil
}

// handleAnchored implements the full spec §12.4 anchored-bundle
// verification path. Replaces D4 commit 2's deferred stub. See
// Check7Github type doc for the 6-step procedure.
func (c *Check7Github) handleAnchored(
	b *bundle.Bundle,
	dr bundle.DailyRootEntry,
	anchor bundle.GithubAnchorJSON,
	opts CheckOptions,
) (errs, warnings []error) {
	const id = 7
	const checkName = "GitHub anchor cross-check"

	artifactPath := fmt.Sprintf("github_anchors/%s.json", dr.Date)

	if c.fetcher == nil {
		return []error{Errorf(id, checkName, artifactPath,
			"internal: anchored verification requires a fetcher; nil fetcher passed to NewCheck7Github",
			SpecRefGitHubAnchorVerify,
			"the anchored path needs network access to fetch root.json + commit metadata from the anchor repo")}, nil
	}

	// 1. commit_sha format validation per commit_sha_format dispatch
	// (per Phase 4 prereq Session B Item 4).
	if anchor.CommitSha == nil || *anchor.CommitSha == "" {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("anchored mirror_status declared for date %q but commit_sha is null/empty", dr.Date),
			SpecRefGitHubAnchorSchema,
			"anchored github_anchors entries MUST carry a non-null commit_sha")}, nil
	}
	commitSha := *anchor.CommitSha
	switch anchor.CommitShaFormat {
	case "sha1":
		if err := validateLowercaseHexLen(commitSha, 40); err != nil {
			return []error{Errorf(id, checkName, artifactPath,
				fmt.Sprintf("commit_sha for date %q has format=sha1 but value is invalid: %v", dr.Date, err),
				SpecRefGitHubAnchorSchema,
				"sha1 commit_sha is 40-char lowercase hex")}, nil
		}
	case "sha256":
		if err := validateLowercaseHexLen(commitSha, 64); err != nil {
			return []error{Errorf(id, checkName, artifactPath,
				fmt.Sprintf("commit_sha for date %q has format=sha256 but value is invalid: %v", dr.Date, err),
				SpecRefGitHubAnchorSchema,
				"sha256 commit_sha is 64-char lowercase hex")}, nil
		}
	default:
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("unknown commit_sha_format %q for date %q (spec §12.1 defines: sha1 | sha256)", anchor.CommitShaFormat, dr.Date),
			SpecRefGitHubAnchorSchema,
			"commit_sha_format MUST be one of: sha1, sha256")}, nil
	}

	// AllowDevKey gate (per security-auditor SSH-c1 H1): fast-fail
	// BEFORE any network call. An example-demo bundle without
	// --allow-dev-key shouldn't waste an HTTPS round-trip to surface
	// the gate. Tenant 5 (operator gets actionable error fast).
	if b.Manifest.BundleType == "example-demo" && !opts.AllowDevKey {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("anchored example-demo bundle for date %q requires --allow-dev-key to verify SSH signature against issuer-ssh-dev-v1", dr.Date),
			SpecRefGitHubAnchorVerify,
			"example-demo bundles' anchor commits are SSH-signed by the dev key; pass --allow-dev-key to opt INTO dev-key verification")}, nil
	}

	// Construct ctx with timeout for the network calls. 60s matches
	// check 5's pattern.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 2. Fetch root.json from anchor repo. Phase 6.2.C session 70
	// BACKLOG 1.33 closure: bundle_type subdirectory layer per session
	// 69 staging path extension at apps/api/src/lib/daily-root/act.ts.
	// b.Manifest.BundleType drives the resolution; customer-export +
	// audit-log-export + example-demo + sandbox-preview each resolve
	// to their own per-bundle-type subdirectory under daily-roots/
	// <orgID>/<date>/.
	rootJsonBytes, err := c.fetcher.FetchRootJson(ctx, b.Manifest.OrganizationID, dr.Date, b.Manifest.BundleType, commitSha)
	if err != nil {
		if IsTransient(err) {
			return nil, []error{Warnf(id, checkName, artifactPath,
				fmt.Sprintf("network unavailable fetching root.json for date %q at commit %s: %v", dr.Date, commitSha, err),
				SpecRefGitHubAnchorVerify,
				"transient network failure; retry verification when network is restored")}
		}
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("failed to fetch root.json for date %q at commit %s: %v", dr.Date, commitSha, err),
			SpecRefGitHubAnchorVerify,
			"the anchor repo's root.json MUST be retrievable at the declared commit_sha")}, nil
	}

	// 3. Parse root.json.
	rootJson, err := ParseRootJsonV2(rootJsonBytes)
	if err != nil {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("malformed root.json at commit %s for date %q: %v", commitSha, dr.Date, err),
			SpecRefGitHubAnchorSchema,
			"anchor repo root.json conforms to spec §12.2 schema")}, nil
	}

	// 4. Cross-check root.json against bundle.
	if crossCheckErrs := crossCheckRootJsonAgainstBundle(b, dr, rootJson); len(crossCheckErrs) > 0 {
		// Surface all cross-check mismatches in a single error
		// message so the operator sees the full divergence picture.
		var combined string
		for i, e := range crossCheckErrs {
			if i > 0 {
				combined += "\n  "
			}
			combined += e.Error()
		}
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("root.json cross-check failed for date %q at commit %s:\n  %s", dr.Date, commitSha, combined),
			SpecRefGitHubAnchorVerify,
			"anchor repo root.json's anchored fields MUST match the bundle's per-spec-§12.4 cross-check")}, nil
	}

	// 5. Fetch commit metadata for SSH signature verification.
	commitMeta, err := c.fetcher.FetchCommitMetadata(ctx, commitSha)
	if err != nil {
		if IsTransient(err) {
			return nil, []error{Warnf(id, checkName, artifactPath,
				fmt.Sprintf("network unavailable fetching commit metadata for %s: %v", commitSha, err),
				SpecRefGitHubAnchorVerify,
				"transient network failure; retry verification when network is restored")}
		}
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("failed to fetch commit metadata for %s: %v", commitSha, err),
			SpecRefGitHubAnchorVerify,
			"the anchor commit MUST be SSH-signed and retrievable via the GitHub commits API")}, nil
	}

	// 6. SSH signature verification. AllowDevKey gate already fired
	// above (before any network call) per Tenant 5 fast-fail.
	pinnedSSHKey, err := keys.SSHKeyForBundle(b.Manifest.BundleType, time.Now().UTC())
	if err != nil {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("internal: failed to dispatch SSH issuer key for bundle_type=%q: %v", b.Manifest.BundleType, err),
			SpecRefGitHubAnchorVerify,
			"the verifier ships pinned SSH issuer keys; this dispatch should never fail")}, nil
	}
	// M3 fix (crypto reviewer): customer-export anchored bundles
	// hit the prod placeholder pinned key in V1; without an
	// explicit fail-fast here, ssh.ParseAuthorizedKey rejects the
	// placeholder string downstream and surfaces as the generic
	// "tampering signal OR rotation timing" error. Operator should
	// see the precise V1-pending diagnostic instead.
	if pinnedSSHKey.AuthorizedKeyFormat == keys.PlaceholderProdSSHAuthorizedKey {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("anchored customer-export bundle for date %q cannot be verified by this V1 CLI: the production SSH issuer key is a placeholder pending Phase 5 deploy-bootstrap", dr.Date),
			SpecRefGitHubAnchorVerify,
			"customer-export anchored bundles require a CLI version with the post-Phase-5 production SSH issuer key pinned")}, nil
	}

	verifier := NewSSHSignatureVerifier(pinnedSSHKey)
	sshResult := verifier.VerifyCommit(commitMeta.SignatureArmored, commitMeta.SignedPayload)
	if sshResult.Verdict == SSHInvalid {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("SSH signature verification failed for commit %s on date %q: %s\n  spec §12.4 requires anchor commits to be SSH-signed by a pinned NuWyre issuer key\n  this is a tampering signal (unauthorized signer) OR an issuer-key-rotation timing issue (commit signed by old key not yet pinned in this CLI version)",
				commitSha, dr.Date, sshResult.ErrorReason),
			SpecRefGitHubAnchorVerify,
			"anchor commits MUST verify under the pinned issuer SSH key dispatched by bundle_type")}, nil
	}

	// H2 (security reviewer, dedicated SSH session commit 3 review):
	// cross-check bundle's declared signed_by_ssh_key_fingerprint
	// against the actual signer fingerprint extracted from the
	// SSHSIG. Catches tampering with bundle's metadata claim about
	// who signed the anchor commit (a defense layer distinct from
	// the cryptographic pinned-key match in SSH verifier).
	if anchor.SignedBySSHFingerprint != "" &&
		anchor.SignedBySSHFingerprint != sshResult.SignerKeyFingerprint {
		return []error{Errorf(id, checkName, artifactPath,
			fmt.Sprintf("bundle declares signed_by_ssh_key_fingerprint=%q for date %q at commit %s but actual SSH signature was made by key %q",
				anchor.SignedBySSHFingerprint, dr.Date, commitSha, sshResult.SignerKeyFingerprint),
			SpecRefGitHubAnchorVerify,
			"bundle's claimed SSH signer fingerprint MUST match the fingerprint extracted from the anchor commit's SSHSIG signature")}, nil
	}

	// All anchored sub-verifications passed. Return nil warnings →
	// StatusPass at the per-check Result helper → VerdictPass at
	// AggregateVerdict.
	//
	// **Critical fix** (crypto + security reviewers, dedicated SSH
	// session commit 3 review): the previous implementation appended
	// a Warn surfacing the signer fingerprint, which produced
	// StatusWarn → VerdictPartialVerification (exit 1) for every
	// successfully-anchored bundle — violating the spec §14 contract
	// "all seven checks MUST pass for verifier to report 'verified'".
	// The aggregator's per-category WARN-fold doesn't recognize the
	// success disclosure substring (it's not an anchor-pending opt-in
	// warning), so a fully-verified anchored bundle could not return
	// exit 0 regardless of flag combination.
	//
	// Forensic transparency for the signer fingerprint is preserved
	// via the operator running --json (where the per-check status
	// + signer metadata could be exposed via a Details field in a
	// future Session 4 reporting-layer commit). For V1 default
	// human output, the loss is "Check 7: PASS [Xms]" without the
	// signer fingerprint visible — acceptable trade-off for
	// returning correct PASS verdicts on anchored bundles.
	//
	// (Same defect class exists in check 6's "≥3 distinct TSAs
	// extra confirmation" warning — out of scope for this commit;
	// tracked as separate cleanup.)
	_ = sshResult.SignerKeyFingerprint // forensic info available; surface via Details in Session 4
	_ = pinnedSSHKey.KeyID
	return nil, nil
}

// crossCheckRootJsonAgainstBundle compares the anchor repo's
// root.json fields against the bundle's per-spec-§12.4 expectations.
// Returns a list of mismatch errors (empty on full agreement).
//
// Cross-checked fields (per spec §12.4 + dedicated SSH session
// commit 3 reviewer-pass H1 + H3 + M2 fixes for symmetric coverage):
//   - root.json:organization_id == bundle.manifest.organization_id
//   - root.json:root_hash == bundle.daily_roots[date].root
//   - root.json:date == dr.Date
//   - root.json:issuer.key_fingerprint_spki_b64 ==
//     bundle.manifest.signing.key_fingerprint_spki_b64 (H3 fix:
//     binds the anchor-repo issuer claim to the bundle's manifest
//     signing claim; defense against tampering either side
//     independently)
//   - bidirectional OTS check: presence + SHA-256 (H1 fix: missing
//     bundle OTS with declared root.json OTS is a tampering signal)
//   - bidirectional per-TSA check (M2 fix): every TSA in either
//     direction MUST appear + match in the other direction
func crossCheckRootJsonAgainstBundle(b *bundle.Bundle, dr bundle.DailyRootEntry, rj *RootJsonV2) []error {
	var errs []error

	if rj.Date != dr.Date {
		errs = append(errs, fmt.Errorf("date mismatch: bundle daily_roots[].date=%q, root.json date=%q", dr.Date, rj.Date))
	}
	if rj.OrganizationID != b.Manifest.OrganizationID {
		errs = append(errs, fmt.Errorf("organization_id mismatch: bundle manifest.organization_id=%q, root.json organization_id=%q",
			b.Manifest.OrganizationID, rj.OrganizationID))
	}
	if rj.RootHash != dr.Root {
		errs = append(errs, fmt.Errorf("root_hash mismatch: bundle daily_roots[].root=%q, root.json root_hash=%q",
			dr.Root, rj.RootHash))
	}

	// H3 fix (security reviewer): cross-check the issuer key
	// fingerprint between root.json and bundle's manifest.
	if rj.Issuer.KeyFingerprintSPKIB64 != b.Manifest.Signing.KeyFingerprintB64 {
		errs = append(errs, fmt.Errorf("issuer.key_fingerprint_spki_b64 mismatch: bundle manifest.signing=%q, root.json issuer=%q",
			b.Manifest.Signing.KeyFingerprintB64, rj.Issuer.KeyFingerprintSPKIB64))
	}

	// H1 fix (security reviewer): bidirectional OTS receipt
	// presence + SHA-256 check. Both bundle-missing-OTS and
	// root.json-missing-OTS surface as inconsistencies (defense-in-
	// depth against bundle/anchor divergence even if check 5 / OTS
	// status declares the other side legitimately absent).
	otsBytes, otsOK := b.OTSReceipts[dr.Date]
	otsRootDeclared := rj.Anchors.OpenTimestamps.ReceiptSHA256 != ""
	switch {
	case otsOK && otsRootDeclared:
		bundleOTSSha := sha256.Sum256(otsBytes)
		bundleOTSShaHex := hex.EncodeToString(bundleOTSSha[:])
		if bundleOTSShaHex != rj.Anchors.OpenTimestamps.ReceiptSHA256 {
			errs = append(errs, fmt.Errorf("OTS receipt SHA-256 mismatch: bundle %s, root.json %s",
				bundleOTSShaHex, rj.Anchors.OpenTimestamps.ReceiptSHA256))
		}
	case !otsOK && otsRootDeclared:
		errs = append(errs, fmt.Errorf("anchor repo root.json declares OTS receipt sha=%s for date %q but bundle has no ots_receipts/%s.ots",
			rj.Anchors.OpenTimestamps.ReceiptSHA256, dr.Date, dr.Date))
	case otsOK && !otsRootDeclared:
		errs = append(errs, fmt.Errorf("bundle has ots_receipts/%s.ots but anchor repo root.json declares no OTS receipt for date %q",
			dr.Date, dr.Date))
	}

	// Per-TSA cross-check (forward direction: every root.json TSA
	// must appear + match in bundle).
	tsaMap, tsaMapOK := b.RFC3161Receipts[dr.Date]
	for _, anchorTSA := range rj.Anchors.RFC3161 {
		if !tsaMapOK {
			errs = append(errs, fmt.Errorf("anchor repo declares TSA %q but bundle has no rfc3161_receipts for date %q",
				anchorTSA.TSAName, dr.Date))
			continue
		}
		bundlePair, ok := tsaMap[anchorTSA.TSAName]
		if !ok {
			errs = append(errs, fmt.Errorf("anchor repo declares TSA %q but bundle has no matching receipt",
				anchorTSA.TSAName))
			continue
		}
		bundleTSRSha := sha256.Sum256(bundlePair.TSR)
		bundleTSRShaHex := hex.EncodeToString(bundleTSRSha[:])
		if bundleTSRShaHex != anchorTSA.ReceiptSHA256 {
			errs = append(errs, fmt.Errorf("TSA %q TSR SHA-256 mismatch: bundle %s, root.json %s",
				anchorTSA.TSAName, bundleTSRShaHex, anchorTSA.ReceiptSHA256))
		}
		bundleChainSha := sha256.Sum256(bundlePair.ChainPEM)
		bundleChainShaHex := hex.EncodeToString(bundleChainSha[:])
		if bundleChainShaHex != anchorTSA.ChainSHA256 {
			errs = append(errs, fmt.Errorf("TSA %q chain.pem SHA-256 mismatch: bundle %s, root.json %s",
				anchorTSA.TSAName, bundleChainShaHex, anchorTSA.ChainSHA256))
		}
	}

	// M2 fix (security reviewer): reverse direction — every bundle
	// TSA must appear in root.json. Catches bundle-side-extra-TSA
	// (degraded operational state OR post-anchor tampering).
	if tsaMapOK {
		rootTSAs := make(map[string]bool, len(rj.Anchors.RFC3161))
		for _, anchorTSA := range rj.Anchors.RFC3161 {
			rootTSAs[anchorTSA.TSAName] = true
		}
		for tsaName := range tsaMap {
			if !rootTSAs[tsaName] {
				errs = append(errs, fmt.Errorf("bundle has rfc3161_receipts for TSA %q on date %q but anchor repo root.json doesn't declare it (degraded operational state OR post-anchor tampering)",
					tsaName, dr.Date))
			}
		}
	}
	return errs
}

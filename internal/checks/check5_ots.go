package checks

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nbd-wtf/opentimestamps"
	"github.com/nuwyre/cli/internal/bundle"
)

// Check5OTS verifies the spec §10 OpenTimestamps Bitcoin anchor
// contract: each daily root in `daily_roots.json` has a corresponding
// `.ots` receipt that anchors that root to a specific Bitcoin block
// via the OpenTimestamps protocol. The check:
//
//  1. Cross-anchor consistency (manifest.anchor_status.opentimestamps
//     vs anchors.opentimestamps detail) per D1's
//     validateOTSConsistency.
//  2. For each daily root entry, locate the matching `.ots` receipt
//     in bundle.OTSReceipts (keyed by date). Missing receipts are
//     expected when manifest.anchor_status.ots_status="not_attempted";
//     otherwise FAIL.
//  3. Parse receipt via nbd-wtf/opentimestamps. ReadFromFile
//     returns the receipt's File.Digest (the SHA-256 the receipt
//     was created against) and Sequences (proof chains terminating
//     in pending or Bitcoin attestations).
//  4. Verify the receipt's Digest equals the daily root's RootHash.
//     If the receipt is for a different digest, the receipt does
//     NOT anchor our claim and the bundle is structurally broken.
//  5. Distinguish pending (calendar-only) from upgraded (Bitcoin-
//     attested) sequences. Pending state under `--strict-ots` →
//     FAIL; default → WARN. Upgraded → proceed to Bitcoin
//     verification.
//  6. For each upgraded sequence, call Sequence.Verify(adapter,
//     digest) — the library walks the sequence's operations,
//     computes the expected merkle root, fetches the claimed
//     Bitcoin block via our adapter, compares the block's actual
//     merkle root. Any mismatch produces a definitive error;
//     network failure produces a transient error → SKIPPED.
//  7. After Verify succeeds, check the Bitcoin block's timestamp
//     is plausible: the block MUST be confirmed AT or AFTER the
//     OTS submission time (minus a clock-skew tolerance). A block
//     timestamp before the OTS submission is impossible — the
//     receipt couldn't reference a block that didn't exist yet.
//
// **Pending vs Upgraded** (Pinned Decision: enforced strictly).
// A pending receipt has only calendar attestations
// (Attestation.CalendarServerURL set, BitcoinBlockHeight == 0); the
// daily root has been submitted to OpenTimestamps calendars but no
// Bitcoin block has folded the calendar's commitment in yet. Default
// posture treats pending as WARN (verification incomplete but no
// tampering signal); --strict-ots treats it as FAIL (the bundle
// claims OTS-anchored but isn't yet, fail loudly).
//
// **Network unavailable** (Pinned Decision: SKIPPED, not silent
// failure). Per D1's TransientError vs DefiniteError split: if the
// adapter's Bitcoin lookups exhaust retries with network errors,
// return StatusSkipped with "anchor verification skipped — network
// unavailable" reason. The CLI exit-code mapper treats overall-
// Skipped as exit 1 unless --offline was explicitly passed.
//
// **No silent fall-through.** A receipt with no sequences at all,
// or only "unknown/broken" attestations (neither calendar nor
// Bitcoin), surfaces as FAIL — not silently passed.
//
// **Cross-implementation oracle.** The TS verify-bundle.ts at
// packages/example-bundle/scripts/verify-bundle.ts:625-684 explicitly
// defers full Bitcoin verification to "the Phase 4 Go CLI" (TS does
// only structural checks: magic header + manifest status disclosure).
// This Go check 5 IS the canonical Bitcoin-anchored verification.
type Check5OTS struct {
	httpClient *HTTPClient

	// testEndpoints overrides the production failover pair when
	// non-empty. Test-only seam used by check5_ots_test.go to
	// redirect adapter requests at httptest mock servers. Production
	// callers leave this nil; the adapter uses the default pair
	// (blockstream.info + mempool.space).
	testEndpoints []string
}

// NewCheck5OTS constructs a check 5 instance. httpClient is the
// D1-configured HTTPClient (with retries, scrubbed errors, body
// size cap) shared across external-anchor checks.
//
// **Phase 5+ verifier tightening bookmark** (Phase 5.5 Session 5.5.1B
// reviewer-batch finding: spec-rev #7 + crypto-int M3 + code-rev #16):
// The current V1 verifier does NOT cryptographically verify pending-
// state OTS receipts — byte-level mutations to the receipt past its
// magic header are caught by check 2 (artifact-integrity SHA-256
// mismatch) but NOT by check 5 (which short-circuits on pending state
// and emits a warn rather than running the calendar-attestation cross-
// check). The `forged-ots` conformance fixture pins this V1 baseline
// as-is. Phase 5+ tightening: run the OTS protocol's calendar-
// attestation cross-check on pending receipts (parse the receipt; verify
// each attestation's calendar signature against the calendar's known
// pubkey; ensure attestations are well-formed even before Bitcoin
// confirmation lands). When tightening lands: regenerate the forged-ots
// fixture's results.json with check 5 = fail. Preservation surface 1
// of 3 (code FIXME); surface 2 = ops log entry at Session 5.5.1B
// closure; surface 3 = README PROVISIONAL banner's "V1 verifier-
// baseline observations encoded as contract" section.
func NewCheck5OTS(httpClient *HTTPClient) *Check5OTS {
	return &Check5OTS{httpClient: httpClient}
}

func (Check5OTS) ID() int      { return 5 }
func (Check5OTS) Name() string { return "OpenTimestamps Bitcoin anchor" }
func (Check5OTS) Slug() string { return "opentimestamps" }

func (c *Check5OTS) Run(b *bundle.Bundle, opts CheckOptions) CheckResult {
	const id = 5
	const checkName = "OpenTimestamps Bitcoin anchor"
	const slug = "opentimestamps"

	if opts.Offline {
		return SkippedDueToOffline(id, checkName, slug)
	}

	var errs []error
	var warnings []error
	// Spec §14.4 (v1.0.7) WarnCategory tagging: V1 check 5's only
	// warn-emission site is the pending-OTS branch below. The final
	// result tags WarnCategoryPendingOTS when warnings are present.
	//
	// **Multi-warning safety** (spec §14.4 invariant): if a future
	// contributor adds a non-pending-OTS warn-emission branch to this
	// function, they MUST either (a) reach a separate exit point that
	// tags an empty WarnCategory, OR (b) accept that the aggregator's
	// defense-in-depth text-matcher cross-check (aggregate.go's
	// isWarnAllowed) will refuse to fold the mixed-category result
	// under --allow-pending-ots — which is fail-secure but produces
	// `partial_verification` rather than `pass`. The simpler-and-
	// correct path is (a): tag empty WarnCategory at the new branch.
	//
	// (Phase 5.5 Session 5.5.1C reviewer fix-up batch: closed
	// TRIPLE-corroborated dead-variable finding at code-rev #4 +
	// sec-aud H3 + crypto-int #4. The previous tracking-flag pattern
	// was vacuously true; aggregator-side defense-in-depth is the
	// load-bearing safety net.)

	// 1. Cross-anchor consistency (per D1's anchor_consistency.go).
	// Run BEFORE per-receipt verification so a manifest-vs-detail
	// inconsistency is reported at its native level rather than
	// masked by per-receipt errors.
	if err := validateOTSConsistency(b); err != nil {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("anchor consistency failure: %v", err),
			SpecRefOTS, "manifest.anchor_status.ots_status agrees with manifest.anchors.opentimestamps.status"))
		return Result(id, checkName, slug, errs, warnings)
	}

	// 2. Iterate daily roots in deterministic (sorted by date) order.
	// Each daily root MUST have a corresponding .ots receipt unless
	// manifest.anchor_status.ots_status="not_attempted" (but the
	// consistency check above already rejected non-attempted state
	// for non-empty receipt sets).
	dailyRoots := make([]bundle.DailyRootEntry, len(b.DailyRoots.Roots))
	copy(dailyRoots, b.DailyRoots.Roots)
	sort.SliceStable(dailyRoots, func(i, j int) bool {
		return dailyRoots[i].Date < dailyRoots[j].Date
	})

	otsStatus := b.Manifest.AnchorStatus.OTSStatus
	// H3 from D2 reviewer pass: when ots_status indicates the anchor
	// was attempted, manifest.anchors.opentimestamps.submitted_at is
	// REQUIRED per spec §10. A malformed/empty value would silently
	// skip the block-timestamp plausibility defense; surface as Fail.
	otsAnchorSubmittedAt, submittedAtOK := parseAnchorTimestamp(b.Manifest.Anchors.OpenTimestamps.SubmittedAt)
	if otsStatus != "not_attempted" && !submittedAtOK {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("manifest.anchors.opentimestamps.submitted_at = %q is empty or not RFC 3339",
				b.Manifest.Anchors.OpenTimestamps.SubmittedAt),
			SpecRefOTS, "every attempted OTS anchor declares submitted_at as a valid RFC 3339 UTC timestamp"))
		return Result(id, checkName, slug, errs, warnings)
	}

	// A.1.7 — Phase 7.D session 88: audit-log-export bundles + V1
	// deploy-bootstrap state may declare ots_status="pending" with
	// receipt_path="" (null in JSON). This represents the pre-receipt
	// submission-deferred lifecycle state — submission has been
	// scheduled but no calendar receipt has been written to disk yet.
	// Without this short-circuit the per-daily-root iteration below
	// would Fail unconditionally on missing receipt files; emitting
	// Warn(pending) instead lets --allow-pending-ots opt-in fold to
	// pass, parallel to how a written-but-Bitcoin-pending receipt
	// folds at the per-daily-root pending branch.
	//
	// Structural-prevention closure (A.1.7): closes 4th instance of
	// the recurring-defect-class-at-parallel-substrate pattern in
	// Phase 7.D session 88 — Go verifier paths that derive bundle
	// paths from convention without honoring manifest's explicit
	// null/empty fields. A.1.1 (keys dispatch) + A.1.2 (Check 3
	// empty events.jsonl) + A.1.3 (Check 4 dual-subtree root) +
	// A.1.7 (this) all share the same defect class.
	if otsStatus == "pending" && b.Manifest.Anchors.OpenTimestamps.ReceiptPath == "" {
		warnings = append(warnings, Warnf(id, checkName,
			"manifest.anchors.opentimestamps",
			"OTS submission declared pending Bitcoin confirmation with receipt_path=null (no on-disk receipt yet); --allow-pending-ots opt-in folds to pass — anchor pipeline run deferred to post-submission window",
			SpecRefOTS, "pending OTS state with null receipt_path is the pre-receipt submission-deferred lifecycle state; receipt is written when the calendar response is captured"))
		return ResultWithCategory(id, checkName, slug, errs, warnings, WarnCategoryPendingOTS)
	}

	for _, dr := range dailyRoots {
		receiptBytes, ok := b.OTSReceipts[dr.Date]
		if !ok {
			// Per spec §4.2, ots_status ∈ {pending, confirmed,
			// failed} — no "not_attempted" enum value (unlike
			// rfc3161_status / github_status which CAN be
			// "not_attempted" and legitimately have no per-day
			// data). For OTS, every daily root MUST have a
			// receipt regardless of pending/confirmed/failed
			// state. Missing receipt is structural.
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
				fmt.Sprintf("missing OTS receipt for daily root date %s (manifest.anchor_status.ots_status=%q)",
					dr.Date, otsStatus),
				SpecRefOTS, "every daily root has a corresponding ots_receipts/<date>.ots file"))
			continue
		}

		// 3. Parse receipt. The nbd-wtf/opentimestamps library
		// panics on truncated / structurally-malformed input
		// (e.g., short buffer in the magic-header check) instead
		// of returning a clean error. parseOTSReceiptSafe wraps
		// the call with defer-recover so panic becomes Fail with
		// a specific error rather than crashing the verifier.
		// This is the local equivalent of checks.go runWithRecover
		// applied at the library boundary.
		otsFile, err := parseOTSReceiptSafe(receiptBytes)
		if err != nil {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
				fmt.Sprintf("OTS receipt parse failed: %v", err),
				SpecRefOTS, "OTS receipts are valid OpenTimestamps protocol bytes (header magic + sha256 op + sequences)"))
			continue
		}

		// 4. Verify the receipt's Digest equals our daily root's
		// RootHash. If the receipt is for a different digest, the
		// receipt does NOT anchor OUR claim — even if the receipt
		// itself is valid, it doesn't prove anything about our
		// bundle's daily_root.
		//
		// M1 from D2 reviewer pass: enforce lowercase-hex format
		// before hex.DecodeString. Go's hex.DecodeString accepts
		// uppercase silently; check 4 enforces the spec §6.1
		// lowercase invariant. Check 5 mirrors the discipline so
		// bundles with uppercase-hex daily roots are rejected here
		// even when run with --check opentimestamps in isolation
		// (skipping check 4).
		if !isLowercaseHex64(dr.Root) {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("daily_roots.json roots[%s]", dr.Date),
				fmt.Sprintf("daily root %q is not 64-char lowercase hex", truncate(dr.Root, 16)),
				SpecRefDailyRoots, "daily_roots.json roots[].root is 64-char lowercase hex SHA-256"))
			continue
		}
		rootHashBytes, err := hex.DecodeString(dr.Root)
		if err != nil {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("daily_roots.json roots[%s]", dr.Date),
				fmt.Sprintf("daily root hex decode failed: %v", err),
				SpecRefDailyRoots, "daily_roots.json roots[].root is 64-char lowercase hex SHA-256"))
			continue
		}
		if !bytes.Equal(otsFile.Digest, rootHashBytes) {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
				fmt.Sprintf("OTS receipt digest %s does not match daily_roots.json roots[%s].root %s; receipt anchors a different digest",
					truncate(hex.EncodeToString(otsFile.Digest), 16),
					dr.Date,
					truncate(dr.Root, 16)),
				SpecRefOTS, "OTS receipt's digest equals the daily root the receipt was submitted for"))
			continue
		}

		// 5. Distinguish pending from upgraded.
		attestedSeqs := otsFile.GetBitcoinAttestedSequences()
		pendingSeqs := otsFile.GetPendingSequences()
		if len(attestedSeqs) == 0 && len(pendingSeqs) == 0 {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
				"OTS receipt has no calendar or Bitcoin attestations (unknown/broken state)",
				SpecRefOTS, "OTS receipt contains at least one valid attestation (pending calendar or Bitcoin block)"))
			continue
		}
		if len(attestedSeqs) == 0 {
			// Pending state — calendar-only, no Bitcoin yet.
			pendingMsg := fmt.Sprintf("OTS receipt for date %s is pending Bitcoin confirmation (calendar attestations present, no Bitcoin block yet)",
				dr.Date)
			if opts.StrictOTS {
				errs = append(errs, Errorf(id, checkName,
					fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
					pendingMsg+" — --strict-ots requires Bitcoin attestation",
					SpecRefOTS, "under --strict-ots, OTS receipts MUST have a Bitcoin block attestation"))
			} else {
				warnings = append(warnings, Warnf(id, checkName,
					fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
					pendingMsg+" (default --allow-pending-ots posture: verification proceeds with Warn)",
					SpecRefOTS, "OTS Bitcoin confirmation is asynchronous; pending state is normal within ~24h of submission"))
				// This warning IS a pending-OTS opt-in category warn;
				// allPendingOTS stays true (no flip needed). Spec §14.4.
			}
			continue
		}

		// 6. Verify each Bitcoin-attested sequence against the public
		// Bitcoin chain. The library's Sequence.Verify call internally
		// fetches the block via our adapter, computes the sequence's
		// merkle root, compares to the block's actual merkle root.
		//
		// We use the FIRST successful attestation as the verification
		// witness; if the first attestation fails verification, the
		// bundle is broken (the writer included a Bitcoin attestation
		// that doesn't reconstruct).
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		adapter := newOTSBitcoinAdapter(c.httpClient, ctx)
		if len(c.testEndpoints) > 0 {
			adapter.endpoints = c.testEndpoints
		}
		verified := false
		// M2 from D2 reviewer pass: accumulate per-sequence failures
		// instead of overwriting. Multiple Bitcoin attestations of
		// varying validity (an attacker confusion attempt) preserves
		// per-sequence forensics for the operator.
		var seqErrs []error
		for i, seq := range attestedSeqs {
			err := verifySequenceSafe(seq, adapter, otsFile.Digest)
			if err == nil {
				verified = true
				break
			}
			seqErrs = append(seqErrs, fmt.Errorf("sequence[%d]: %w", i, err))
			// If the error is transient (network unavailable), short-
			// circuit to SKIPPED rather than continuing through other
			// sequences (which would compound the network failure).
			if isWrappedTransient(err) {
				cancel()
				return SkippedDueToNetworkUnavailable(id, checkName, slug, err)
			}
		}
		cancel()

		if !verified {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
				fmt.Sprintf("OTS Bitcoin verification failed for all %d attested sequence(s): %v",
					len(attestedSeqs), errors.Join(seqErrs...)),
				SpecRefOTS, "OTS receipt's Bitcoin attestation reconstructs to the actual block's merkle root"))
			continue
		}

		// 7. Plausibility: block timestamp >= OTS submission time
		// minus skew tolerance. A block confirmed BEFORE the OTS
		// submission is impossible — the receipt couldn't reference
		// a block that didn't exist yet. Defense-in-depth against
		// blocks specifically crafted to contain a target merkle root
		// with an impossibly early timestamp (cryptographically
		// infeasible today, but cheap to check).
		if adapter.LastHeader != nil && !otsAnchorSubmittedAt.IsZero() {
			blockTime := time.Unix(int64(adapter.LastHeader.Timestamp.Unix()), 0).UTC()
			skewTolerance := 1 * time.Hour
			minBlockTime := otsAnchorSubmittedAt.Add(-skewTolerance)
			if blockTime.Before(minBlockTime) {
				errs = append(errs, Errorf(id, checkName,
					fmt.Sprintf("ots_receipts/%s.ots", dr.Date),
					fmt.Sprintf("Bitcoin block timestamp %s is before OTS submission %s (minus %s skew tolerance); receipt references a block that predates the submission",
						blockTime.Format(time.RFC3339),
						otsAnchorSubmittedAt.Format(time.RFC3339),
						skewTolerance),
					SpecRefOTS, "OTS receipt's Bitcoin attestation references a block confirmed at or after the OTS submission time"))
				continue
			}
		}
	}

	// Spec §14.4 (v1.0.7): tag WarnCategoryPendingOTS when warnings
	// were emitted. The aggregator's defense-in-depth (isWarnAllowed
	// at aggregate.go) cross-checks every warning text against the
	// pending-OTS substring marker before folding under
	// --allow-pending-ots; a mis-tagged result is rejected automatically.
	var warnCategory string
	if len(warnings) > 0 {
		warnCategory = WarnCategoryPendingOTS
	}
	return ResultWithCategory(id, checkName, slug, errs, warnings, warnCategory)
}

// parseAnchorTimestamp parses an RFC 3339 anchor submission timestamp.
// Returns zero time + ok=false on parse failure (caller decides
// whether to treat missing-or-malformed as fatal or skip the
// timestamp plausibility check).
func parseAnchorTimestamp(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// isWrappedTransient reports whether err wraps a TransientError (per
// D1's network.go). The library's Sequence.Verify wraps adapter
// errors with `fmt.Errorf("failed to get block N hash: %w", err)`,
// so we use errors.As to unwrap.
func isWrappedTransient(err error) bool {
	if err == nil {
		return false
	}
	var t *TransientError
	return errors.As(err, &t)
}

// parseOTSReceiptSafe wraps opentimestamps.ReadFromFile with a
// defer-recover so library panics on malformed input become clean
// errors. The nbd-wtf/opentimestamps library v0.4.0 panics on
// truncated buffers (e.g., a 23-byte input fails the 31-byte magic-
// header read with a slice-bounds panic). Without this wrapper,
// a tampered bundle with a malformed .ots file would crash the
// verifier instead of producing a clean Fail verdict.
//
// This is the load-bearing third-party-library boundary defense
// referenced in the type doc-comment. Same pattern as checks.go
// runWithRecover, applied at the library call site.
func parseOTSReceiptSafe(receiptBytes []byte) (file *opentimestamps.File, err error) {
	defer func() {
		if r := recover(); r != nil {
			file = nil
			err = fmt.Errorf("OTS library panic during parse (likely malformed receipt): %v", r)
		}
	}()
	return opentimestamps.ReadFromFile(receiptBytes)
}

// verifySequenceSafe wraps opentimestamps Sequence.Verify with the
// same defer-recover discipline as parseOTSReceiptSafe. C1 from
// D2 reviewer pass: the library has four "not implemented" op-tag
// panics (reverse 0xf2, hexlify 0xf3, sha1 0x02, keccak256 0x67).
// The PARSER accepts these tags without filtering, so a malicious
// .ots file can list them in a sequence and crash the verifier
// inside Compute() during Verify. Without this wrapper, a single
// tampered receipt becomes a denial-of-verification primitive
// against check 5's per-receipt error reporting (the outer
// runWithRecover catches the panic but loses date / receipt-path
// / spec-section context). Wrapping per-call preserves clean
// per-receipt forensics.
func verifySequenceSafe(seq opentimestamps.Sequence, adapter opentimestamps.Bitcoin, digest []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("OTS library panic during Sequence.Verify (likely poisoned op tag in sequence): %v", r)
		}
	}()
	_, err = seq.Verify(adapter, digest)
	return err
}

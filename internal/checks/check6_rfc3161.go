package checks

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/tsa"
)

// Check6RFC3161 verifies the spec §11 RFC 3161 timestamp anchor
// contract: each daily root in `daily_roots.json` is timestamped by
// ≥2 of 3 distinct Time Stamp Authorities (FreeTSA + Sectigo +
// DigiCert in production), each producing a {.tsr, .chain.pem} pair
// stored under rfc3161_receipts/<utc_day>__<tsa_name>.{tsr,chain.pem}.
// The check:
//
//  1. Cross-anchor consistency (manifest.anchor_status.rfc3161_status
//     vs manifest.anchors.rfc3161[]) per D1's
//     validateRFC3161Consistency. Caught at this layer rather than
//     masked by per-pair errors.
//  2. Short-circuit when manifest.anchor_status.rfc3161_status =
//     "not_attempted" (the bundle's degraded-mode declaration —
//     operator chose not to attempt RFC 3161 anchoring; verifier
//     does not interpret absence as failure here, because the
//     operator's choice IS the contract). The consistency check
//     above already enforced that "not_attempted" implies zero
//     anchor entries.
//  3. For each daily root, locate the per-TSA pair set in
//     bundle.RFC3161Receipts[date]. Missing data when the bundle's
//     declared status is non-"not_attempted" is a structural defect
//     surfaced as Fail.
//  4. Verify each pair via D3 commit 1's tsa.VerifyPair (passes the
//     daily root's hex-decoded SHA-256 root as expectedHashedMessage).
//     Each pair returns PairValid (with SignerCert + GenTime + trust
//     source) or PairInvalid (with forensic ErrorReason).
//  5. Apply the spec §11.1 threshold WITH SignerCert distinctness
//     defense: count distinct SignerCert subjects among PairValid
//     results, NOT raw valid-pair count. Three pairs that all share
//     the same signing cert subject count as 1, not 3 — closing the
//     H2 attack vector from D3 commit 1's reviewer pass (an attacker
//     who relabels copies of one TSR with three different tsa_name
//     values would otherwise inflate verifiedCount past 2-of-3).
//  6. ≥2 distinct signers → daily root passes; <2 → daily root fails
//     with full per-TSA breakdown (SignerCert subject for valid
//     pairs, ErrorReason for invalid). 3-of-3 distinct → "extra
//     confirmation" warning per build plan §"Cryptographic integrity
//     is foundational" (the third receipt isn't required but its
//     presence is operationally meaningful). A 3-valid-pairs-with-
//     fewer-distinct-signers configuration meets threshold but
//     warns operationally about the duplicate-signer state.
//
// **Time semantics** (per D3 commit 1's H1 fix): chain validation
// inside tsa.VerifyPair uses CurrentTime = ts.Time (TSA-asserted
// timestamp), NOT time.Now(). Spec §11.2 + methodology §09
// indefinite-verifiability: the captured chain.pem MUST keep
// validating against the cert windows live when the TSA stamped,
// not against today's wall clock.
//
// **No network calls.** Unlike check 5 (OTS Bitcoin verification),
// check 6 is fully local — the .tsr + .chain.pem pairs carry every
// byte the verifier needs. The Offline option still SHORT-CIRCUITS
// to Skipped to honor the documented per-check behavior (every
// external-anchor check skips under --offline) and to avoid
// surprising operators who expect uniform behavior across checks
// 5/6/7.
//
// **Cross-implementation oracle.** The TS verify-bundle.ts at
// packages/example-bundle/scripts/verify-bundle.ts performs RFC 3161
// structural checks (PKI status + messageImprint + signed-attribute
// hash + signer signature + chain linkage) but explicitly DEFERS
// system-trust-store + chain-validity-time validation to "Phase 4
// verification CLI" — i.e., this check. Together they form the
// canonical RFC 3161 verification surface.
type Check6RFC3161 struct {
	pool *tsa.TSAPool
}

// NewCheck6RFC3161 constructs a check 6 instance with a single
// shared TSAPool (system trust + pinned roots loaded once at
// construction). Returns an error if the pinned-root pool fails
// to load — fail-secure: a partial trust pool would silently
// reject TSA chains whose roots production stamping uses,
// producing false negatives that look like tampering.
func NewCheck6RFC3161() (*Check6RFC3161, error) {
	pool, err := tsa.NewTSAPool()
	if err != nil {
		return nil, fmt.Errorf("check 6 (RFC 3161 timestamp anchor): failed to construct TSA pool: %w", err)
	}
	return &Check6RFC3161{pool: pool}, nil
}

func (Check6RFC3161) ID() int      { return 6 }
func (Check6RFC3161) Name() string { return "RFC 3161 timestamp anchor" }
func (Check6RFC3161) Slug() string { return "rfc3161" }

func (c *Check6RFC3161) Run(b *bundle.Bundle, opts CheckOptions) CheckResult {
	const id = 6
	const checkName = "RFC 3161 timestamp anchor"
	const slug = "rfc3161"

	if opts.Offline {
		return SkippedDueToOffline(id, checkName, slug)
	}

	var errs []error
	var warnings []error

	// 1. Cross-anchor consistency (per D1's anchor_consistency.go).
	// Run BEFORE per-pair verification so a manifest-vs-detail
	// inconsistency is reported at its native level rather than
	// masked by per-pair errors.
	if err := validateRFC3161Consistency(b); err != nil {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("anchor consistency failure: %v", err),
			SpecRefRFC3161Threshold,
			"manifest.anchor_status.rfc3161_status agrees with manifest.anchors.rfc3161[] per the canonical 4-state enum"))
		return Result(id, checkName, slug, errs, warnings)
	}

	rfc3161Status := b.Manifest.AnchorStatus.RFC3161Status

	// 2. Short-circuit on declared "not_attempted" — degraded-mode
	// bundle, operator opted out of RFC 3161 anchoring. The
	// consistency check above already enforced that this implies
	// zero entries in manifest.anchors.rfc3161[] AND would have
	// flagged any RFC3161Receipts data as inconsistent. Pass with
	// no warnings; the degraded state is visible in the manifest
	// disclosure itself, not surfaced as a verifier warning.
	if rfc3161Status == "not_attempted" {
		return Result(id, checkName, slug, errs, warnings)
	}

	// 3. Iterate daily roots in deterministic (sorted by date) order.
	dailyRoots := make([]bundle.DailyRootEntry, len(b.DailyRoots.Roots))
	copy(dailyRoots, b.DailyRoots.Roots)
	sort.SliceStable(dailyRoots, func(i, j int) bool {
		return dailyRoots[i].Date < dailyRoots[j].Date
	})

	for _, dr := range dailyRoots {
		dayErrs, dayWarnings := c.verifyDailyRoot(b, dr, rfc3161Status)
		errs = append(errs, dayErrs...)
		warnings = append(warnings, dayWarnings...)
	}

	// Spec §14.4 (v1.0.7) WarnCategory tagging: tag with
	// WarnCategoryTSASurplus when warnings are present. V1 has no
	// --allow-tsa-surplus opt-in flag, so the aggregator's
	// isWarnAllowed returns false for this category regardless —
	// tagging it serves the v1.0.7 conformance contract (the JSON
	// output's warn_category field reflects the structured category)
	// without changing fold behavior. Future v1.x adding the opt-in
	// flag will pair with an isTSASurplusWarning text-matcher in
	// aggregate.go for defense-in-depth.
	//
	// (Phase 5.5 Session 5.5.1C reviewer fix-up batch: closes
	// spec-rev F1 NOT-IMPL + code-rev #6 + crypto-int finding 10.)
	var warnCategory string
	if len(warnings) > 0 {
		warnCategory = WarnCategoryTSASurplus
	}
	return ResultWithCategory(id, checkName, slug, errs, warnings, warnCategory)
}

// verifyDailyRoot performs per-pair verification + threshold +
// distinctness for one daily root. Returns (errors, warnings) for
// that day; the caller accumulates across days.
func (c *Check6RFC3161) verifyDailyRoot(
	b *bundle.Bundle,
	dr bundle.DailyRootEntry,
	rfc3161Status string,
) (errs, warnings []error) {
	const id = 6
	const checkName = "RFC 3161 timestamp anchor"

	// 3a. Validate root_hash hex format (mirror check 5's M1
	// discipline: hex.DecodeString accepts uppercase silently;
	// spec §6.1 requires lowercase).
	if !isLowercaseHex64(dr.Root) {
		return []error{Errorf(id, checkName,
			fmt.Sprintf("daily_roots.json roots[%s]", dr.Date),
			fmt.Sprintf("daily root %q is not 64-char lowercase hex", truncate(dr.Root, 16)),
			SpecRefDailyRoots,
			"daily_roots.json roots[].root is 64-char lowercase hex SHA-256")}, nil
	}
	expectedHashedMessage, err := hex.DecodeString(dr.Root)
	if err != nil {
		return []error{Errorf(id, checkName,
			fmt.Sprintf("daily_roots.json roots[%s]", dr.Date),
			fmt.Sprintf("daily root hex decode failed: %v", err),
			SpecRefDailyRoots,
			"daily_roots.json roots[].root is 64-char lowercase hex SHA-256")}, nil
	}

	// 3b. Locate per-TSA receipts for this date.
	tsaMap, ok := b.RFC3161Receipts[dr.Date]
	if !ok || len(tsaMap) == 0 {
		// Branch the operator-facing diagnostic on the bundle's
		// declared state. "verified" with no receipts is a
		// tampering-class signal (the manifest claims success
		// but the data isn't there); "partial"/"failed" is the
		// writer honestly admitting to a degraded state — same
		// Fail verdict either way (spec §11.1 ≥2-of-3 isn't
		// satisfied), but different framing helps the operator
		// understand why.
		var msg string
		switch rfc3161Status {
		case "verified":
			msg = fmt.Sprintf(
				"manifest declares rfc3161_status=%q but no RFC 3161 receipts present for daily root date %s",
				rfc3161Status, dr.Date,
			)
		case "partial", "failed":
			msg = fmt.Sprintf(
				"writer-declared rfc3161_status=%q for daily root date %s; bundle does not satisfy the spec §11.1 ≥2-of-3 distinct-TSA threshold",
				rfc3161Status, dr.Date,
			)
		default:
			msg = fmt.Sprintf(
				"no RFC 3161 receipts present for daily root date %s under manifest.anchor_status.rfc3161_status=%q",
				dr.Date, rfc3161Status,
			)
		}
		return []error{Errorf(id, checkName,
			fmt.Sprintf("rfc3161_receipts/%s__*.{tsr,chain.pem}", dr.Date),
			msg,
			SpecRefRFC3161,
			"every daily root has corresponding rfc3161_receipts/<date>__<tsa_name>.{tsr,chain.pem} pairs unless rfc3161_status='not_attempted'")}, nil
	}

	// 4. Verify each pair via D3 commit 1's tsa.VerifyPair, sorted
	// alphabetically by tsa_name for deterministic output.
	tsaNames := make([]string, 0, len(tsaMap))
	for n := range tsaMap {
		tsaNames = append(tsaNames, n)
	}
	sort.Strings(tsaNames)

	perTSA := make([]tsa.PairResult, 0, len(tsaNames))
	for _, tsaName := range tsaNames {
		pair := tsaMap[tsaName]
		result := tsa.VerifyPair(pair.TSR, pair.ChainPEM, expectedHashedMessage, tsaName, c.pool)
		perTSA = append(perTSA, result)
	}

	// 4b. Spec §11.3 step 4: PRIMARY defense against cert-identity
	// substitution. The signer cert's subject CN MUST include the
	// expected tsa_name (case-insensitive substring). A pair whose
	// chain validates but whose signer cert doesn't bind to the
	// claimed TSA identity is downgraded from PairValid to
	// PairInvalid for threshold purposes (with a forensic
	// ErrorReason).
	//
	// Without this enforcement, an attacker with a valid Sectigo TSR
	// could label it "digicert" — chain validates (Sectigo IS a
	// trusted TSA), distinctness collapses correctly within the
	// label-set, but the bundle's verified-witnesses claim is a
	// LIE: DigiCert never actually stamped this root, only Sectigo
	// did. Step 4 ties the cert IDENTITY to the claimed TSA, closing
	// the gap. The §11.3 step 4 example "a FreeTSA chain's signer
	// is FreeTSA's signing cert" formalizes this binding requirement.
	//
	// Substring (not exact-equality) is the right grain: production
	// signer CNs include version/key-type qualifiers (DigiCert →
	// "DigiCert SHA256 RSA4096 Timestamp Responder 2025 1"; Sectigo
	// → "Sectigo Public Time Stamping Signer R36"; FreeTSA →
	// "www.freetsa.org") that prefix the canonical TSA name. Token-
	// equality would over-reject legitimate certs.
	for i := range perTSA {
		r := &perTSA[i]
		if r.Verdict != tsa.PairValid {
			continue
		}
		if r.SignerCert == nil {
			// Defense-in-depth: PairValid implies SignerCert non-nil
			// per D3 commit 1's contract. Treat any divergence as
			// invalid rather than as silent under-counting.
			r.Verdict = tsa.PairInvalid
			r.ErrorReason = "internal verifier error: PairValid with nil SignerCert"
			r.SignerCert = nil
			continue
		}
		cnLower := strings.ToLower(r.SignerCert.Subject.CommonName)
		nameLower := strings.ToLower(r.TSAName)
		if !strings.Contains(cnLower, nameLower) {
			r.ErrorReason = fmt.Sprintf(
				"spec §11.3 step 4: signer cert subject CN %q does not include claimed tsa_name %q",
				r.SignerCert.Subject.CommonName, r.TSAName,
			)
			r.Verdict = tsa.PairInvalid
			r.SignerCert = nil
		}
	}

	// 5. Distinctness defense (BACKSTOP for §11.3 step 4): count
	// distinct SignerCert subjects among the still-valid pairs. With
	// step 4 enforced above, this catches the residual case where
	// two pairs both pass step 4 (e.g., two CN substrings of the
	// same DigiCert cert: "digicert" + "timestamp") but cryptographically
	// share one signer. SignerCert distinctness is enforced cert-side
	// (Subject.String() canonical form), not via the caller-supplied
	// tsa_name parameter.
	distinctSigners := make(map[string]bool)
	validCount := 0
	for _, r := range perTSA {
		if r.Verdict == tsa.PairValid && r.SignerCert != nil {
			distinctSigners[canonicalSignerKey(r.SignerCert)] = true
			validCount++
		}
	}
	distinctValidCount := len(distinctSigners)

	// 6. Apply spec §11.1 ≥2-of-3 distinct-TSA threshold.
	if distinctValidCount < 2 {
		// Threshold breached → FAIL with full per-TSA breakdown.
		breakdown := buildPerTSABreakdown(perTSA)
		return []error{Errorf(id, checkName,
			fmt.Sprintf("rfc3161_receipts/%s__*.{tsr,chain.pem}", dr.Date),
			fmt.Sprintf("≥2-of-3 distinct TSA threshold breached for daily root %s (%d distinct valid signer(s) of %d pair(s) attempted)\n%s",
				dr.Date, distinctValidCount, len(perTSA), breakdown),
			SpecRefRFC3161Threshold,
			"≥2 of 3 distinct TSAs MUST produce verifying {token, chain} pairs per daily root (distinctness measured by signer cert subject after spec §11.3 step 4 CN binding)")}, nil
	}

	// Threshold met. Emit operationally-meaningful warnings:
	//
	// (a) ≥3 distinct signers verified → "extra confirmation"
	//     surfaces the surplus to the operator. Production today is
	//     3-TSA configurations; future spec amendments may expand
	//     to 4+ TSAs, in which case "≥3 distinct" remains the right
	//     "extra confirmation" threshold.
	if distinctValidCount >= 3 {
		warnings = append(warnings, Warnf(id, checkName,
			fmt.Sprintf("rfc3161_receipts/%s__*.{tsr,chain.pem}", dr.Date),
			fmt.Sprintf("%d distinct TSAs verified for daily root %s — extra confirmation beyond the spec §11.1 ≥2-of-3 requirement",
				distinctValidCount, dr.Date),
			SpecRefRFC3161Threshold,
			"≥2 of 3 distinct TSAs is the requirement; ≥3 is operationally desirable surplus"))
	}

	// (b) Distinctness reduction: more valid pairs than distinct
	//     signers. Threshold met BUT the configuration has
	//     duplicate signers, which warrants operator attention
	//     (potential misconfiguration or partial substitution
	//     attempt where the attacker only achieved a subset).
	if validCount > distinctValidCount {
		warnings = append(warnings, Warnf(id, checkName,
			fmt.Sprintf("rfc3161_receipts/%s__*.{tsr,chain.pem}", dr.Date),
			fmt.Sprintf("daily root %s: %d valid pair(s) verified but only %d distinct SignerCert subject(s) — possible duplicate-signer configuration; threshold met based on distinct count",
				dr.Date, validCount, distinctValidCount),
			SpecRefRFC3161Threshold,
			"distinct TSAs (measured by signer cert subject) drive the threshold; duplicate signers count once"))
	}

	// (c) Surface invalid pairs as warnings even when threshold met,
	//     so operators see the full per-TSA state and can correlate
	//     a partial failure (e.g., one TSA's chain validation broke
	//     because their cert rotated) with operational metrics. Use
	//     %q to neutralize control characters in tsa_name (the
	//     loader's filename parser tolerates them; quoting prevents
	//     terminal-output mangling / log injection).
	for _, r := range perTSA {
		if r.Verdict != tsa.PairValid {
			warnings = append(warnings, Warnf(id, checkName,
				fmt.Sprintf("rfc3161_receipts/%s__%s.{tsr,chain.pem}", dr.Date, r.TSAName),
				fmt.Sprintf("TSA %q failed for daily root %s but threshold met (%d distinct valid signer(s)): %s",
					r.TSAName, dr.Date, distinctValidCount, r.ErrorReason),
				SpecRefRFC3161Verify,
				"per-TSA verification status surfaces forensic context even when overall threshold passes"))
		}
	}

	return nil, warnings
}

// canonicalSignerKey returns the distinctness-comparison key for a
// signing certificate. Spec §11.1 distinctness is enforced cert-side;
// the canonical form is the cert's Subject DN string (Go's
// pkix.Name.String() which RFC 4514-encodes attributes deterministically).
//
// **Why Subject.String() and not other fields:**
//   - Issuer is shared across TSA generations from the same CA family
//     (e.g., DigiCert reissues signing certs annually under the same
//     intermediate); a 2024 + 2026 DigiCert signing pair would have
//     identical Issuer but distinct Subjects + SerialNumbers.
//   - SerialNumber is unique per cert but shared across the same cert
//     reissued unchanged — cryptographically distinct from the perspective
//     of "did we get an independent witness."
//   - SubjectKeyID/AuthorityKeyID are present on most production certs
//     but not universally; depending on them would silently pass through
//     pre-2010 legacy chains.
//
// Subject DN is the right grain because two signing certs with the same
// Subject DN are issued for the same TSA identity (per CA naming
// conventions); two distinct Subject DNs are unambiguously distinct
// TSA identities.
func canonicalSignerKey(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	// Defense-in-depth: trim the subject string so a canonicalization
	// difference between digitorus/pkcs7 and Go's stdlib pkix encoders
	// doesn't silently produce false distinctness. Production TSAs all
	// emit consistent DN forms; this is insurance.
	return strings.TrimSpace(cert.Subject.String())
}

// buildPerTSABreakdown formats per-TSA verdicts as a multi-line
// human-readable diagnostic appended to threshold-breach errors.
// Sort order is alphabetical by TSA name (matches the perTSA slice's
// pre-sort) for reproducible output. Uses %q for TSAName to neutralize
// control characters / ANSI escapes in attacker-supplied filenames
// (the loader tolerates them in tsa_name; quoting prevents terminal-
// output mangling / log-injection in forensic output).
func buildPerTSABreakdown(perTSA []tsa.PairResult) string {
	var b strings.Builder
	for _, r := range perTSA {
		if r.Verdict == tsa.PairValid {
			signerCN := ""
			if r.SignerCert != nil {
				signerCN = r.SignerCert.Subject.CommonName
			}
			fmt.Fprintf(&b, "  %q: valid (signer=%q, trust=%s, genTime=%s)\n",
				r.TSAName, signerCN, r.TrustSource, r.GenTime.Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Fprintf(&b, "  %q: invalid — %s\n", r.TSAName, r.ErrorReason)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

package bundle

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Path-parsing logic for the directory-based zip entries:
//
//   - ots_receipts/<UTC_DAY>.ots
//   - rfc3161_receipts/<UTC_DAY>__<TSA_NAME>.{tsr,chain.pem}
//   - github_anchors/<UTC_DAY>.json
//
// All filenames use a strict YYYY-MM-DD UTC day prefix; the loader
// rejects malformed paths to prevent attacker-supplied filenames from
// quietly bypassing keying. tsa_name is the lowercased writer-side
// label (currently "freetsa" | "digicert" | "sectigo"; spec §11 does
// not constrain the alphabet beyond [a-z0-9-] per the reference
// implementation).

// validUTCDay validates that s is a strict YYYY-MM-DD UTC day string:
// 10 chars, hyphens at positions 4 and 7, digits elsewhere, AND month
// in 01..12, day in 01..31. The calendar-shape check goes beyond
// regex-style validation to reject impossible dates like "0000-00-00"
// or "9999-99-99" that an attacker might smuggle to confuse downstream
// keying without tripping format-only validation.
//
// We deliberately do NOT validate "day-in-month" (e.g., reject
// 2026-02-30) because the loader's job is shape-rejection, not
// calendar-correctness; spec §11/§12 don't impose that constraint.
// Any genuine date-correctness bug surfaces at Session 2 cross-checks
// against daily_roots.json.
func validUTCDay(s string) bool {
	if len(s) != 10 {
		return false
	}
	for i, ch := range s {
		switch i {
		case 4, 7:
			if ch != '-' {
				return false
			}
		default:
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	month := (int(s[5]-'0') * 10) + int(s[6]-'0')
	if month < 1 || month > 12 {
		return false
	}
	day := (int(s[8]-'0') * 10) + int(s[9]-'0')
	if day < 1 || day > 31 {
		return false
	}
	return true
}

// loadOTSReceipt parses one ots_receipts/<utc_day>.ots entry.
// Spec §10: one .ots per UTC day; bytes are an opaque
// OpenTimestamps receipt the verifier hands off to the OTS library.
func loadOTSReceipt(bundle *Bundle, f *zip.File) error {
	rest := strings.TrimPrefix(f.Name, "ots_receipts/")
	// Reject directory entries + nested paths. The dispatcher already
	// skips IsDir() entries but a malformed bundle could embed a
	// nested path like "ots_receipts/sub/x.ots" — reject explicitly.
	if rest == "" || strings.Contains(rest, "/") {
		return fmt.Errorf("bundle: malformed ots_receipts path %q (expected ots_receipts/<utc_day>.ots)", f.Name)
	}
	if !strings.HasSuffix(rest, ".ots") {
		return fmt.Errorf("bundle: ots_receipts entry %q must end in .ots", f.Name)
	}
	utcDay := strings.TrimSuffix(rest, ".ots")
	if !validUTCDay(utcDay) {
		return fmt.Errorf("bundle: ots_receipts entry %q has malformed utc_day prefix (expected YYYY-MM-DD)", f.Name)
	}
	if _, dup := bundle.OTSReceipts[utcDay]; dup {
		return fmt.Errorf("bundle: duplicate ots receipt for %s", utcDay)
	}
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", f.Name, err)
	}
	bundle.OTSReceipts[utcDay] = raw
	return nil
}

// loadRFC3161Entry parses one rfc3161_receipts/<utc_day>__<tsa>.{tsr,chain.pem}
// entry. Spec §11 mandates that every TSR has a paired chain.pem; the
// pair-completeness check runs in finalizeBundleAfterDispatch() once
// all entries are seen.
func loadRFC3161Entry(bundle *Bundle, f *zip.File) error {
	rest := strings.TrimPrefix(f.Name, "rfc3161_receipts/")
	if rest == "" || strings.Contains(rest, "/") {
		return fmt.Errorf("bundle: malformed rfc3161_receipts path %q", f.Name)
	}

	var utcDay, tsaName string
	var isChain bool
	switch {
	case strings.HasSuffix(rest, ".chain.pem"):
		isChain = true
		stem := strings.TrimSuffix(rest, ".chain.pem")
		utcDay, tsaName = splitDayTSA(stem)
	case strings.HasSuffix(rest, ".tsr"):
		isChain = false
		stem := strings.TrimSuffix(rest, ".tsr")
		utcDay, tsaName = splitDayTSA(stem)
	default:
		return fmt.Errorf("bundle: rfc3161_receipts entry %q must end in .tsr or .chain.pem", f.Name)
	}

	if !validUTCDay(utcDay) {
		return fmt.Errorf("bundle: rfc3161_receipts entry %q has malformed utc_day prefix", f.Name)
	}
	if tsaName == "" {
		return fmt.Errorf("bundle: rfc3161_receipts entry %q missing tsa_name (expected <utc_day>__<tsa_name>.tsr|chain.pem)", f.Name)
	}

	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", f.Name, err)
	}

	dayMap, ok := bundle.RFC3161Receipts[utcDay]
	if !ok {
		dayMap = make(map[string]RFC3161Pair)
		bundle.RFC3161Receipts[utcDay] = dayMap
	}
	pair := dayMap[tsaName]
	if isChain {
		if pair.ChainPEM != nil {
			return fmt.Errorf("bundle: duplicate chain.pem for %s/%s", utcDay, tsaName)
		}
		pair.ChainPEM = raw
	} else {
		if pair.TSR != nil {
			return fmt.Errorf("bundle: duplicate .tsr for %s/%s", utcDay, tsaName)
		}
		pair.TSR = raw
	}
	dayMap[tsaName] = pair
	return nil
}

// splitDayTSA splits "<utc_day>__<tsa_name>" on the literal "__"
// separator. Returns ("", "") if the separator is absent.
func splitDayTSA(stem string) (utcDay, tsaName string) {
	idx := strings.Index(stem, "__")
	if idx < 0 {
		return "", ""
	}
	return stem[:idx], stem[idx+2:]
}

// loadAudioFile parses one audio/<sha256>.<ext> entry. Spec §13.1
// mandates the path discipline `audio/<sha256>.<ext>` exactly:
// 64-char lowercase-hex SHA-256 stem + non-empty extension. The
// content-addressed binding (file's SHA-256 == path stem) is verified
// at Session 2 Check 2 (manifest artifacts) — not here, because
// verification of cryptographic content is not the loader's
// responsibility. The loader only enforces that the FILENAME meets
// the spec's content-addressing shape so nothing exotic gets keyed.
func loadAudioFile(bundle *Bundle, f *zip.File) error {
	rest := strings.TrimPrefix(f.Name, "audio/")
	if rest == "" || strings.Contains(rest, "/") {
		return fmt.Errorf("bundle: malformed audio path %q (expected audio/<sha256>.<ext>)", f.Name)
	}
	// Stem must be 64 hex chars lowercase; extension must be present.
	dotIdx := strings.Index(rest, ".")
	if dotIdx < 0 {
		return fmt.Errorf("bundle: audio entry %q missing extension (spec §13.1)", f.Name)
	}
	stem := rest[:dotIdx]
	ext := rest[dotIdx+1:]
	if len(stem) != 64 || !isLowercaseHex(stem) {
		return fmt.Errorf("bundle: audio entry %q stem must be 64-char lowercase hex SHA-256 (spec §13.1)", f.Name)
	}
	if ext == "" {
		return fmt.Errorf("bundle: audio entry %q has empty extension after dot", f.Name)
	}
	if _, dup := bundle.AudioFiles[rest]; dup {
		return fmt.Errorf("bundle: duplicate audio file %s", rest)
	}
	// AUDIT-1-FIXUP-3 HIGH-5: use the audio-class cap (1 GiB) instead of
	// the strict metadata cap (64 MiB). Legitimate audio fixtures routinely
	// exceed 64 MiB (a 30-min 44.1kHz stereo PCM recording is ~317 MiB).
	raw, err := readAudioZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", f.Name, err)
	}
	bundle.AudioFiles[rest] = raw
	return nil
}

// isLowercaseHex reports whether s is non-empty and contains only
// lowercase hex digits 0-9 and a-f. Used to validate audio filename
// stems (spec §13: "64-char lowercase hex SHA-256").
func isLowercaseHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}

// loadGithubAnchor parses one github_anchors/<utc_day>.json entry.
// Spec §12.1: per-day anchor metadata; commit_sha may be null when
// mirror_status is "anchor-pending" (the mirror commit hasn't landed
// yet). schema_version=1 is pinned via the same forward-compat
// posture as merkle_proofs.json.
func loadGithubAnchor(bundle *Bundle, f *zip.File) error {
	rest := strings.TrimPrefix(f.Name, "github_anchors/")
	if rest == "" || strings.Contains(rest, "/") {
		return fmt.Errorf("bundle: malformed github_anchors path %q", f.Name)
	}
	if !strings.HasSuffix(rest, ".json") {
		return fmt.Errorf("bundle: github_anchors entry %q must end in .json", f.Name)
	}
	utcDay := strings.TrimSuffix(rest, ".json")
	if !validUTCDay(utcDay) {
		return fmt.Errorf("bundle: github_anchors entry %q has malformed utc_day prefix", f.Name)
	}
	if _, dup := bundle.GithubAnchors[utcDay]; dup {
		return fmt.Errorf("bundle: duplicate github_anchors entry for %s", utcDay)
	}
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", f.Name, err)
	}
	var anchor GithubAnchorJSON
	if err := json.Unmarshal(raw, &anchor); err != nil {
		return fmt.Errorf("bundle: parse %s: %w", f.Name, err)
	}
	// P2 closure (session 113): schema_version pin enforcement.
	if err := validateSchemaVersion(f.Name, anchor.SchemaVersion, 1); err != nil {
		return err
	}
	// Independent calendar-shape check on the JSON date field — the
	// path-vs-JSON mismatch check below would silently match if BOTH
	// the path and the JSON carried the same malformed string (e.g.,
	// "" == "" or "9999-99-99" == "9999-99-99"). Validating the JSON
	// date independently closes that smuggle vector.
	if !validUTCDay(anchor.Date) {
		return fmt.Errorf("bundle: %s json.date %q is not valid YYYY-MM-DD", f.Name, anchor.Date)
	}
	// Cross-check: the file's path-derived utc_day MUST match the
	// JSON's date field. Mismatch is a tampering signal — an attacker
	// might swap the JSON content for a different date while keeping
	// the path stable.
	if anchor.Date != utcDay {
		return fmt.Errorf("bundle: github_anchors path date %q != json.date %q", utcDay, anchor.Date)
	}
	// Phase 4 prereq Session B Item 4: commit_sha_format is a hard
	// discriminator. Enforce at the loader so Session 2 check 7 can
	// trust the value without re-validating.
	switch anchor.CommitShaFormat {
	case "sha1", "sha256":
	default:
		return fmt.Errorf("bundle: %s commit_sha_format = %q (must be sha1 or sha256)", f.Name, anchor.CommitShaFormat)
	}
	// Phase 4 prereq Session B Item 5: mirror_status canonical 4-state.
	switch anchor.MirrorStatus {
	case "not_attempted", "anchor-pending", "anchored", "failed":
	default:
		return fmt.Errorf("bundle: %s mirror_status = %q (must be one of: not_attempted, anchor-pending, anchored, failed)", f.Name, anchor.MirrorStatus)
	}
	bundle.GithubAnchors[utcDay] = anchor
	return nil
}

// finalizeBundleAfterDispatch runs after the second pass completes,
// asserting cross-entry invariants that single-entry parsers can't
// enforce. Spec §11: every (utc_day, tsa_name) MUST have both a
// .tsr AND a .chain.pem; half-pairs are a writer bug.
//
// Errors are collected, sorted by (utc_day, tsa_name, kind) so the
// returned message is deterministic across runs (Go's map iteration
// order is randomized; a forensic tool whose output a third-party
// verifier captures into a written report needs reproducible
// diagnostics). All half-pair findings are returned via errors.Join
// so a multi-half-pair bundle surfaces every divergence in a single
// Load() call rather than one-error-per-call.
func finalizeBundleAfterDispatch(bundle *Bundle) error {
	type finding struct{ utcDay, tsaName, msg string }
	var findings []finding
	for utcDay, dayMap := range bundle.RFC3161Receipts {
		for tsaName, pair := range dayMap {
			if pair.TSR == nil {
				findings = append(findings, finding{
					utcDay: utcDay, tsaName: tsaName,
					msg: fmt.Sprintf("bundle: rfc3161_receipts/%s__%s.chain.pem present but matching .tsr missing (spec §11 mandates pairs)", utcDay, tsaName),
				})
			}
			if pair.ChainPEM == nil {
				findings = append(findings, finding{
					utcDay: utcDay, tsaName: tsaName,
					msg: fmt.Sprintf("bundle: rfc3161_receipts/%s__%s.tsr present but matching .chain.pem missing (spec §11 mandates pairs)", utcDay, tsaName),
				})
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].utcDay != findings[j].utcDay {
			return findings[i].utcDay < findings[j].utcDay
		}
		if findings[i].tsaName != findings[j].tsaName {
			return findings[i].tsaName < findings[j].tsaName
		}
		return findings[i].msg < findings[j].msg
	})
	errs := make([]error, 0, len(findings))
	for _, f := range findings {
		errs = append(errs, errors.New(f.msg))
	}
	return errors.Join(errs...)
}

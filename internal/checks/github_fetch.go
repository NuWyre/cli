package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GitHub fetch primitive for check 7 (GitHub anchor cross-check).
// Phase 4 Session 3 D4 commit 1.
//
// **Architectural posture** (per the five tenants):
//
//   - Tenant 1 (long-term value). The fetcher uses raw.githubusercontent.com
//     instead of the GitHub Contents API. Raw is hosted on a CDN with
//     no rate limiting, no authentication required, and returns bytes
//     identically across clients — preserving the v3.1.9 byte-stability
//     dependency (see spec §12.3 + .gitattributes binary rule). The
//     Contents API base64-encodes responses and may inject metadata
//     wrapping that breaks byte-exact SHA-256 cross-checks; raw avoids
//     that surface entirely.
//
//   - Tenant 3 (security/privacy). HTTPS-only via D1's HTTPClient
//     (which enforces requireHTTPS on every URL + redirect hop). No
//     authentication headers — the anchor repo is public and the
//     verifier MUST NOT leak operator identity by authenticating.
//     User-Agent identifies the CLI version per D1's pattern
//     (forensic transparency for server-side telemetry) but no system
//     info beyond that.
//
//   - Tenant 4 (simplicity). Single-purpose interface (fetch
//     root.json + commit metadata); production implementation wraps
//     D1's HTTPClient; test implementation is a mock that returns
//     canned bytes. No multi-implementation matrix to maintain.
//
//   - Tenant 5 (customer trust). Inputs validated before URL
//     construction (org_id, date, commit_sha format-checked) — an
//     attacker can't smuggle path traversal through a tampered
//     bundle's organization_id field. Errors scrub URLs (D1's
//     scrubURL pattern) so operator output doesn't leak internals.

// AnchorRepoDefault is the production NuWyre/anchors GitHub repo.
// Test code overrides via NewGithubHTTPSFetcher's repo argument.
const AnchorRepoDefault = "NuWyre/anchors"

// GithubFetcher abstracts the anchor-repo HTTPS fetch. Production:
// GithubHTTPSFetcher (talks to raw.githubusercontent.com +
// api.github.com). Tests: MockGithubFetcher (canned responses;
// see github_fetch_test.go).
//
// **Why an interface and not a concrete type:** check 7 (D4 commit
// 2) consumes GithubFetcher; tests inject a mock to exercise every
// cross-check path without live-network dependency. The mock-vs-
// production split is the canonical seam for this style of
// external-dependency check.
type GithubFetcher interface {
	// FetchRootJson retrieves daily-roots/<orgID>/<date>/<bundleType>/
	// root.json from the anchor repo at the given commit SHA. Returns
	// the raw bytes; the caller parses against spec §12.2 (RootJsonV2).
	//
	// Phase 6.2.C session 70 BACKLOG 1.33 closure: bundleType
	// subdirectory layer added per session 69 anchor pipeline staging
	// extension at apps/api/src/lib/daily-root/act.ts:792-793. Each
	// bundle_type now gets its own per-day subdirectory so
	// customer-export and audit-log-export rows for the same
	// (org, date) get isolated trees. bundleType is the canonical
	// closed-vocabulary value from manifest.bundle_type
	// ({"customer-export", "audit-log-export", "example-demo",
	// "sandbox-preview"}); empty string defaults to "customer-export"
	// for backward-compat with pre-session-69 anchor commits (none
	// exist yet — V1 anchor pipeline is in deploy-bootstrap state —
	// but the default preserves the option to verify legacy commits
	// without forcing every caller to pass the value).
	//
	// orgID MUST be a canonical lowercase UUID (validated upstream
	// via ParseRootJsonV2's helpers). date MUST be strict YYYY-MM-DD
	// (validated via validateUTCDayStrict). commitSHA's format is
	// caller-validated based on the bundle's commit_sha_format
	// (40-char lowercase hex for sha1, 64-char for sha256).
	//
	// Returns *DefiniteError for 4xx (file/commit not found, URL
	// malformed) and *TransientError for 5xx / network. Caller
	// uses IsTransient (network.go) to map to StatusSkipped vs
	// StatusFail.
	FetchRootJson(ctx context.Context, orgID, date, bundleType, commitSHA string) ([]byte, error)

	// FetchCommitMetadata retrieves the commit's metadata from
	// api.github.com (NOT raw — the metadata isn't a file).
	// Returns the parsed CommitMetadata including the SSH
	// signature bytes when present.
	//
	// **D4 status (post-Phase-5 work).** SSH signature verification
	// itself is deferred to a follow-up commit per the Phase 4
	// Session 3 D4 directive's stop condition on Go SSH-signature
	// library landscape. This method is currently unused by check
	// 7 (the anchored cross-check that consumes it is stubbed in
	// D4 commit 2); included in the interface so the future commit
	// landing the anchored path doesn't need to reshape this API.
	FetchCommitMetadata(ctx context.Context, commitSHA string) (*CommitMetadata, error)
}

// CommitMetadata is the commit-object information needed for SSH
// signature verification. The shape mirrors the GitHub API's
// /repos/{owner}/{repo}/git/commits/{sha} response, restricted to
// fields check 7 actually consumes.
type CommitMetadata struct {
	// SHA is the commit SHA (echoed back from the request).
	SHA string
	// AuthorName + AuthorEmail + AuthorTimestamp from the commit
	// object's `author` field. Forensic-debugging output only;
	// not consumed by signature verification.
	AuthorName      string
	AuthorEmail     string
	AuthorTimestamp time.Time
	// SignatureArmored is the PEM-armored SSH signature block
	// (between "-----BEGIN SSH SIGNATURE-----" and "-----END SSH
	// SIGNATURE-----") extracted from the commit's `verification`
	// field. Empty when the commit isn't SSH-signed.
	SignatureArmored string
	// SignedPayload is the canonical commit-object bytes that the
	// signature was computed over (the commit object minus the
	// signature header). Future SSH signature verifier will hash
	// this + verify against the pinned issuer SSH key.
	SignedPayload []byte
}

// GithubHTTPSFetcher is the production GithubFetcher. Wraps D1's
// HTTPClient.
type GithubHTTPSFetcher struct {
	client *HTTPClient
	// repo is the "owner/name" form, e.g., "NuWyre/anchors". Test
	// code overrides via NewGithubHTTPSFetcher; production callers
	// pass AnchorRepoDefault.
	repo string
}

// NewGithubHTTPSFetcher constructs a fetcher pointing at the given
// repo. Production: NewGithubHTTPSFetcher(AnchorRepoDefault, ...).
// Tests: pass a fixture repo name + a custom HTTPClient with mock
// transport.
func NewGithubHTTPSFetcher(repo string, client *HTTPClient) (*GithubHTTPSFetcher, error) {
	if err := validateRepoSlug(repo); err != nil {
		return nil, fmt.Errorf("invalid GitHub repo %q: %w", repo, err)
	}
	if client == nil {
		return nil, errors.New("nil HTTPClient")
	}
	return &GithubHTTPSFetcher{client: client, repo: repo}, nil
}

// FetchRootJson implements GithubFetcher.
//
// URL pattern (Phase 6.2.C session 70 BACKLOG 1.33 closure):
//
//	https://raw.githubusercontent.com/<repo>/<commitSHA>/daily-roots/<orgID>/<date>/<bundleType>/root.json
//
// Pre-session-69 anchor commits (none exist; V1 anchor pipeline is in
// deploy-bootstrap state) used `daily-roots/<orgID>/<date>/root.json`
// without the bundleType subdirectory layer. Session 69's apps/api
// staging-path extension adds the per-bundle-type subdir to disambiguate
// customer-export from audit-log-export anchor artifacts at the same
// (org, date) tuple. bundleType empty string defaults to "customer-
// export" to preserve verifier-side resolution if a legacy commit ever
// surfaces.
//
// raw.githubusercontent.com serves files at any commit SHA (resolves
// the tree + emits raw bytes). No authentication, no rate-limiting
// at the raw CDN tier (vs the api.github.com 60req/hr unauth limit).
//
// **Byte-stability** (spec §12.3, v3.1.9). raw.githubusercontent.com
// returns bytes-as-stored, bypassing git's smudge filter that would
// re-normalize line endings on Windows. The anchor repo's
// .gitattributes declares `daily-roots/** binary` to lock byte
// content even for direct git clones; raw fetch makes this
// belt-and-suspenders.
func (f *GithubHTTPSFetcher) FetchRootJson(ctx context.Context, orgID, date, bundleType, commitSHA string) ([]byte, error) {
	// Pre-fetch input validation (Tenant 3: defense-in-depth at
	// every URL-construction site, not just at the schema parser).
	if err := validateOrgIDCanonical(orgID); err != nil {
		return nil, fmt.Errorf("FetchRootJson: invalid orgID: %w", err)
	}
	if err := validateUTCDayStrict(date); err != nil {
		return nil, fmt.Errorf("FetchRootJson: invalid date: %w", err)
	}
	if err := validateCommitSHAShape(commitSHA); err != nil {
		return nil, fmt.Errorf("FetchRootJson: invalid commitSHA: %w", err)
	}
	// bundleType is closed-vocabulary; empty string defaults to customer-
	// export per backward-compat (no pre-session-69 commits exist).
	// Defense-in-depth: reject unknown vocabulary values to prevent path
	// traversal via attacker-controlled bundleType (e.g., "../forged").
	resolvedBundleType := bundleType
	if resolvedBundleType == "" {
		resolvedBundleType = "customer-export"
	}
	switch resolvedBundleType {
	case "customer-export", "audit-log-export", "example-demo", "sandbox-preview":
		// OK — closed-vocabulary spec §4.1 + §16.5 + §17 values.
	default:
		return nil, fmt.Errorf("FetchRootJson: invalid bundleType %q (closed vocabulary: customer-export, audit-log-export, example-demo, sandbox-preview)", bundleType)
	}

	rawURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/%s/%s/daily-roots/%s/%s/%s/root.json",
		f.repo, commitSHA, orgID, date, resolvedBundleType,
	)
	return f.client.Fetch(ctx, rawURL)
}

// FetchCommitMetadata implements GithubFetcher.
//
// URL pattern:
//
//	https://api.github.com/repos/<repo>/commits/<commitSHA>
//
// Returns the commit's metadata + SSH signature for verification by
// SSHSignatureVerifier (internal/checks/ssh_signature.go).
//
// **GitHub API response shape** (relevant fields):
//
//	{
//	  "sha": "ade149b25785eab3...",
//	  "commit": {
//	    "author":    { "name": "...", "email": "...", "date": "..." },
//	    "verification": {
//	      "verified": true,
//	      "reason":   "valid",
//	      "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----",
//	      "payload":   "tree <SHA>\nparent <SHA>\nauthor ...\n..."
//	    }
//	  }
//	}
//
// `verification.payload` is the canonical commit-object bytes (the
// commit object minus the gpgsig header) — exactly the bytes that
// were SSH-signed. The verifier consumes payload + signature
// directly without reconstructing canonical commit form (Tenant 4).
//
// **Verification posture** (Tenant 5):
//   - GitHub's verification.verified flag is INFORMATIONAL only.
//     The verifier verifies the signature against PINNED issuer
//     keys (internal/keys/PinnedSSHIssuerKeys); GitHub verifies
//     against keys IT knows about. The two checks have different
//     trust roots and we don't conflate them.
//   - Unsigned commits (verification.signature == "") are rejected
//     here as DefiniteError — anchor commits MUST be SSH-signed
//     per spec §12.4 step 6. This is fail-secure (operator gets a
//     clear error rather than a downstream signature-verify failure
//     with empty input).
func (f *GithubHTTPSFetcher) FetchCommitMetadata(ctx context.Context, commitSHA string) (*CommitMetadata, error) {
	if err := validateCommitSHAShape(commitSHA); err != nil {
		return nil, fmt.Errorf("FetchCommitMetadata: invalid commitSHA: %w", err)
	}

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", f.repo, commitSHA)
	body, err := f.client.Fetch(ctx, apiURL)
	if err != nil {
		return nil, err
	}

	// Defense-in-depth size cap on the response body. D1's
	// HTTPClient already caps at 4 MiB; this is tighter local
	// enforcement at the parser layer. Production commit metadata
	// responses are <8 KB; 256 KiB covers any plausible
	// commit-message-heavy response.
	const MaxCommitMetadataBytes = 256 * 1024
	if len(body) > MaxCommitMetadataBytes {
		return nil, &DefiniteError{
			URL: scrubURL(apiURL),
			Err: fmt.Errorf("commit metadata response too large (%d bytes; cap %d)", len(body), MaxCommitMetadataBytes),
		}
	}

	parsed, err := parseGithubCommitResponseSafe(body)
	if err != nil {
		return nil, &DefiniteError{
			URL: scrubURL(apiURL),
			Err: fmt.Errorf("commit metadata JSON parse failed: %w", err),
		}
	}

	// Strict validation on response shape (Tenant 3 fail-secure).
	if parsed.SHA == "" {
		return nil, &DefiniteError{
			URL: scrubURL(apiURL),
			Err: errors.New("commit metadata response missing 'sha' field"),
		}
	}
	if parsed.Commit.Verification.Signature == "" {
		return nil, &DefiniteError{
			URL: scrubURL(apiURL),
			Err: fmt.Errorf("commit %s has no SSH signature (anchor commits MUST be SSH-signed per spec §12.4)", commitSHA),
		}
	}
	if parsed.Commit.Verification.Payload == "" {
		return nil, &DefiniteError{
			URL: scrubURL(apiURL),
			Err: fmt.Errorf("commit %s has signature but no payload (GitHub API response shape unexpected)", commitSHA),
		}
	}

	// Author timestamp is forensic-only; tolerate parse failures.
	authorTime, _ := time.Parse(time.RFC3339, parsed.Commit.Author.Date)

	return &CommitMetadata{
		SHA:              parsed.SHA,
		AuthorName:       parsed.Commit.Author.Name,
		AuthorEmail:      parsed.Commit.Author.Email,
		AuthorTimestamp:  authorTime,
		SignatureArmored: parsed.Commit.Verification.Signature,
		SignedPayload:    []byte(parsed.Commit.Verification.Payload),
	}, nil
}

// githubCommitResponse mirrors the subset of the GitHub API's
// /repos/{owner}/{repo}/commits/{sha} response we consume. Strict
// (no DisallowUnknownFields per crypto-integrity D4-c1 review's M2
// finding rationale: GitHub may evolve the response with additional
// fields; we tolerate them per JSON's standard forward-compat
// posture and only reject when REQUIRED fields are missing).
type githubCommitResponse struct {
	SHA    string `json:"sha"`
	Commit struct {
		Author struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Date  string `json:"date"`
		} `json:"author"`
		Verification struct {
			Verified  bool   `json:"verified"`
			Reason    string `json:"reason"`
			Signature string `json:"signature"`
			Payload   string `json:"payload"`
		} `json:"verification"`
	} `json:"commit"`
}

// parseGithubCommitResponseSafe wraps json.Unmarshal with parseSafe
// per D2's library-boundary discipline. encoding/json is panic-free
// in production but the wrapper is cheap insurance against
// undocumented edge cases + future library changes.
func parseGithubCommitResponseSafe(body []byte) (resp *githubCommitResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp = nil
			err = fmt.Errorf("encoding/json Unmarshal panic (likely malformed GitHub API response): %v", r)
		}
	}()
	if len(body) == 0 {
		return nil, errors.New("empty response body")
	}
	var parsed githubCommitResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}
	return &parsed, nil
}

// =============================================================================
// Input validation (defense-in-depth per Tenant 3)
// =============================================================================
//
// Each validator rejects malformed inputs BEFORE they reach URL
// construction. An attacker who tampers a bundle's organization_id
// to "../../etc/passwd" must not be able to smuggle that path
// through to the GitHub URL — the validator rejects it at the
// schema-parser AND at the fetcher. Both layers exist deliberately.

// validateRepoSlug enforces "owner/name" form with conservative
// character classes (alphanumeric + hyphen + underscore + dot).
// GitHub's actual rules are slightly looser but this conservative
// allowlist is sufficient for "NuWyre/anchors" + test fixtures and
// rejects any input that could be confused for a path traversal or
// URL-injection.
func validateRepoSlug(s string) error {
	if s == "" {
		return errors.New("empty repo")
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return fmt.Errorf("repo must have exactly one '/' separator (got %d parts)", len(parts))
	}
	for _, p := range parts {
		if p == "" {
			return errors.New("empty owner or name segment")
		}
		if len(p) > 100 {
			return fmt.Errorf("segment too long (>100 chars): %q", p)
		}
		for _, r := range p {
			ok := (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				r == '-' || r == '_' || r == '.'
			if !ok {
				return fmt.Errorf("segment %q contains disallowed character %q", p, r)
			}
		}
		if p == "." || p == ".." {
			return fmt.Errorf("segment %q rejected (path-traversal token)", p)
		}
		// L1 from D4 commit 1 security review: reject any segment
		// composed entirely of dots ("...", "....", etc.). Not a
		// path-traversal vector per RFC 3986 (Go's net/url doesn't
		// normalize them) but also not a valid GitHub repo segment;
		// fail-closed at the validator boundary.
		if strings.Trim(p, ".") == "" {
			return fmt.Errorf("segment %q rejected (all-dots)", p)
		}
	}
	return nil
}

// validateOrgIDCanonical enforces canonical lowercase UUID form
// (8-4-4-4-12 hex with hyphens, ALL lowercase). Matches the
// anchor-schema.ts assertUuid() canonicalization from Phase 4
// prereq Session A.
//
// Path-traversal defense (Tenant 3): any non-hex character outside
// hyphens at the right positions is rejected, including '.', '/',
// '\\', null bytes, and non-ASCII.
func validateOrgIDCanonical(s string) error {
	if len(s) != 36 {
		return fmt.Errorf("UUID must be 36 chars (got %d)", len(s))
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return fmt.Errorf("UUID position %d must be '-' (got %q)", i, r)
			}
		default:
			ok := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
			if !ok {
				return fmt.Errorf("UUID position %d must be lowercase hex (got %q)", i, r)
			}
		}
	}
	return nil
}

// validateUTCDayStrict enforces YYYY-MM-DD shape AND calendar
// correctness (e.g., rejects "2026-02-30", "2026-04-31", "2026-02-29"
// in non-leap years). Stricter than bundle.validUTCDay (which does
// shape + month/day range only); matches the TS composer's Date.parse
// rejection per packages/evidence/src/anchor-schema.ts.
//
// Per crypto-integrity-reviewer M1 (D4 commit 1 review):
// cross-language strictness parity — the Go reader MUST be at least
// as strict as the TS writer to close the writer-reader contract.
// Tenant 4 (single source of truth across implementations).
func validateUTCDayStrict(s string) error {
	if len(s) != 10 {
		return fmt.Errorf("date must be YYYY-MM-DD (10 chars; got %d)", len(s))
	}
	for i, ch := range s {
		switch i {
		case 4, 7:
			if ch != '-' {
				return fmt.Errorf("date position %d must be '-' (got %q)", i, ch)
			}
		default:
			if ch < '0' || ch > '9' {
				return fmt.Errorf("date position %d must be digit (got %q)", i, ch)
			}
		}
	}
	month := (int(s[5]-'0') * 10) + int(s[6]-'0')
	if month < 1 || month > 12 {
		return fmt.Errorf("date month %02d out of range (01..12)", month)
	}
	day := (int(s[8]-'0') * 10) + int(s[9]-'0')
	if day < 1 || day > 31 {
		return fmt.Errorf("date day %02d out of range (01..31)", day)
	}
	// Calendar correctness: time.Parse with "2006-01-02" rejects
	// non-existent dates like Feb 30 or Apr 31. Use strict-mode
	// parse + round-trip check to catch Go's lenient overflow
	// behavior (e.g., Feb 30 → Mar 2). The round-trip ensures the
	// reformatted date matches the input exactly.
	parsed, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("date %q is not a valid calendar date: %w", s, err)
	}
	if parsed.Format("2006-01-02") != s {
		return fmt.Errorf("date %q overflowed in calendar (e.g., Feb 30 → Mar 2)", s)
	}
	return nil
}

// validateCommitSHAShape enforces "lowercase hex, length 40 (sha1)
// OR length 64 (sha256)". The check 7 caller MUST ensure
// length-vs-format alignment via commit_sha_format dispatch BEFORE
// calling FetchRootJson; this helper is a defense-in-depth backstop
// at the URL-construction site.
func validateCommitSHAShape(s string) error {
	if len(s) != 40 && len(s) != 64 {
		return fmt.Errorf("commit SHA must be 40 (sha1) or 64 (sha256) chars (got %d)", len(s))
	}
	for i, r := range s {
		ok := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !ok {
			return fmt.Errorf("commit SHA position %d must be lowercase hex (got %q)", i, r)
		}
	}
	return nil
}

// (Compile-time interface assertion — surfaces drift between
// GithubFetcher and GithubHTTPSFetcher at build time rather than
// at runtime in check 7.)
var _ GithubFetcher = (*GithubHTTPSFetcher)(nil)

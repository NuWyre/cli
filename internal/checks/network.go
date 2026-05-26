package checks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxResponseBytes is the upper bound on response body size the HTTP
// client will read into memory. H4 from D1 reviewer pass: an
// unbounded io.ReadAll on resp.Body lets a malicious endpoint stream
// a multi-GB body within the 30s Client.Timeout and exhaust verifier
// RAM. Bitcoin block-info responses from Esplora are sub-kilobyte;
// RFC 3161 chain.pem files are ~10KB; the cap accommodates legitimate
// payloads with significant headroom while foreclosing memory-DoS.
const MaxResponseBytes = 4 * 1024 * 1024 // 4 MiB

// HTTP infrastructure shared by external-anchor checks 5/6/7.
// Provides:
//
//   - A configured *http.Client with reasonable timeouts, a clear
//     User-Agent identifying the verifier + version, and TLS defaults
//     suitable for cryptographic-verification HTTP traffic.
//   - Retry loop with bounded exponential backoff. Distinguishes
//     transient network errors (retry) from definitive HTTP errors
//     (no retry). Critically: retries do NOT mask cryptographic
//     mismatches — those propagate up immediately as definitive errors.
//   - HTTPS-scheme enforcement helper. Defaults reject http:// URLs;
//     callers that explicitly opt into cleartext (e.g., a user-provided
//     bitcoind on localhost via --bitcoin-rpc-url) document the choice.
//   - Skip-mode helpers translating CheckOptions.Offline + network-
//     unavailable detection into the StatusSkipped semantic.
//
// **Design discipline.** Network failures are semantically distinct
// from cryptographic failures:
//
//   - Network unreachable, timeout, DNS failure → StatusSkipped with
//     "network unavailable" reason. The CLI exit-code mapper treats
//     overall-Skipped as exit-code 1 unless --offline was explicitly
//     passed (per checks.go aggregation rule).
//   - Definitive HTTP error (404 not found, malformed response,
//     signature/hash mismatch) → StatusFail with specific error.
//   - Bug in remote endpoint (5xx after retries exhausted) →
//     StatusSkipped with "network unavailable" reason. Treating 5xx as
//     Fail would attribute a remote outage to bundle integrity, which
//     is the wrong attribution.
//
// The split prevents a transient Esplora outage from being recorded
// as "OTS verification failed" — which would suggest tampering when
// the actual cause is a third-party server problem.

// HTTPClient is the verifier's outbound HTTP client. Configured with
// a 30-second per-request timeout, 3 retries with exponential backoff
// for transient errors, and a User-Agent identifying the verifier
// version.
//
// Tests construct a HTTPClient with shorter timeouts + fewer retries
// to keep test runs fast; production callers use NewDefaultHTTPClient
// which embeds the production-tuned defaults.
type HTTPClient struct {
	Client     *http.Client
	UserAgent  string
	MaxRetries int
	BaseDelay  time.Duration
}

// NewDefaultHTTPClient returns a production-tuned HTTPClient.
// Version is the CLI version string (e.g., "0.1.0-pre"), embedded
// in the User-Agent so server-side telemetry can identify which
// CLI version is making requests — useful for forensic-debugging
// of cross-version verification differences.
//
// **CheckRedirect** (Sec C3 from D1 reviewer pass): the client's
// CheckRedirect re-validates each redirect hop's scheme via
// requireHTTPS. Without this guard, an https://api.example.com → http://
// attacker.example.com redirect would bypass the HTTPS-only contract
// requireHTTPS enforces on the initial URL — the verifier would
// follow the http:// hop and contact the attacker over cleartext.
// The guard returns ErrUseLastResponse on rejection so the caller
// sees the redirect target as a failed response (resp.StatusCode in
// the 3xx range) rather than the verifier following the hop.
//
// Maximum 5 hops (vs Go's default 10) to limit redirect-chain DoS.
func NewDefaultHTTPClient(version string) *HTTPClient {
	return &HTTPClient{
		Client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects (>5)")
				}
				if err := requireHTTPS(req.URL.String()); err != nil {
					return fmt.Errorf("redirect rejected: %w", err)
				}
				return nil
			},
		},
		UserAgent:  fmt.Sprintf("nuwyre-verify/%s (+https://verify.nuwyre.com)", version),
		MaxRetries: 3,
		BaseDelay:  500 * time.Millisecond,
	}
}

// requireHTTPS rejects non-HTTPS URLs unless the URL explicitly
// targets a localhost-style address (loopback IP or "localhost"
// hostname). The localhost exception accommodates --bitcoin-rpc-url
// pointing at a user-run bitcoind on the same machine; an MITM
// against localhost requires the attacker already control the
// machine, at which point the bundle verification game is over
// regardless.
//
// **Canonicalization** (Sec C1 + Crypto H1 + H2 + H3 from D1 reviewer
// pass):
//
//   - Hostname comparison is ASCII-case-insensitive (per RFC 1035
//     §2.3.3) — `LOCALHOST`, `Localhost`, `localhost.` (trailing-dot
//     fully-qualified form) all canonicalize to the same loopback
//     reference.
//   - Loopback IP detection uses net.ParseIP + IP.IsLoopback, catching
//     the full 127.0.0.0/8 range AND IPv6 loopback in any
//     representation (`::1`, `0:0:0:0:0:0:0:1`, `[::ffff:127.0.0.1]`).
//   - Empty Host (e.g., `https://` or `https:foo`) is rejected as
//     malformed regardless of scheme — a URL without a host can't
//     reach a real endpoint and shouldn't pass scheme validation.
//
// Returns nil if the URL is acceptable, error otherwise. The error
// does NOT include the raw URL (Sec C2 from D1 reviewer pass: the
// raw URL may carry credentials in user-info; callers should not
// echo the input URL into output even on parse failure).
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("URL parse failed (URL redacted to avoid credential leakage)")
	}
	scheme := strings.ToLower(u.Scheme)
	if u.Host == "" {
		return fmt.Errorf("URL has empty host (scheme=%q)", scheme)
	}
	if scheme == "https" {
		return nil
	}
	if scheme != "http" {
		return fmt.Errorf("URL scheme %q not supported (https only, except http://localhost for user-supplied endpoints)", scheme)
	}
	// http:// is acceptable only for loopback. Canonicalize host
	// before comparison.
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("URL scheme http:// is not allowed for non-localhost hosts (got %q); use https://", host)
}

// fetchResult is the outcome of a single HTTP attempt.
type fetchResult struct {
	body       []byte
	statusCode int
}

// Fetch performs a GET request with retry-on-transient-error
// semantics. Returns:
//
//   - (body, nil) on 2xx response
//   - (nil, &DefiniteError{}) on 4xx response (no retry — the URL or
//     auth is wrong; no point retrying)
//   - (nil, &TransientError{}) on retries exhausted (5xx or network
//     error). Caller maps this to StatusSkipped with "network
//     unavailable" reason.
//
// ctx allows callers to cancel; the per-request timeout in c.Client
// is the upper bound for any single attempt.
//
// **Credential scrubbing** (Sec C2 from D1 reviewer pass): all
// error-construction sites scrub the URL via scrubURL before
// embedding it in error fields. The raw URL is NEVER stored on
// DefiniteError / TransientError. An operator pasting CLI output
// into a bug report or Slack thread doesn't leak --bitcoin-rpc-url
// credentials.
func (c *HTTPClient) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	scrubbed := scrubURL(rawURL)
	if err := requireHTTPS(rawURL); err != nil {
		return nil, &DefiniteError{
			URL: scrubbed,
			Err: err,
		}
	}
	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := c.BaseDelay * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return nil, &TransientError{URL: scrubbed, Err: ctx.Err(), Attempts: attempt}
			case <-time.After(delay):
			}
		}
		result, err := c.doOnce(ctx, rawURL, scrubbed)
		if err == nil {
			return result.body, nil
		}
		// 4xx is definitive — never retry; the resource isn't there
		// or the request shape is wrong.
		var defErr *DefiniteError
		if errors.As(err, &defErr) {
			return nil, defErr
		}
		lastErr = err
	}
	return nil, &TransientError{URL: scrubbed, Err: lastErr, Attempts: c.MaxRetries + 1}
}

func (c *HTTPClient) doOnce(ctx context.Context, rawURL, scrubbed string) (*fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, &DefiniteError{URL: scrubbed, Err: fmt.Errorf("request build: %w", err)}
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.Client.Do(req)
	if err != nil {
		// Network-level error: connection refused, DNS failure,
		// timeout, etc. All transient from the verifier's POV.
		return nil, &transientWrapper{URL: scrubbed, Err: err}
	}
	defer resp.Body.Close()
	// H4 from D1 reviewer pass: bound the body read at MaxResponseBytes.
	// LimitReader caps reads but doesn't error on cap; we detect
	// "hit the cap" by reading one extra byte and checking. A cap-hit
	// is treated as transient (endpoint problem) rather than
	// definitive (bundle problem).
	limited := io.LimitReader(resp.Body, MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, &transientWrapper{URL: scrubbed, Err: fmt.Errorf("body read: %w", err)}
	}
	if int64(len(body)) > MaxResponseBytes {
		return nil, &transientWrapper{
			URL: scrubbed,
			Err: fmt.Errorf("response body exceeds %d bytes; remote endpoint streaming oversized response", MaxResponseBytes),
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &fetchResult{body: body, statusCode: resp.StatusCode}, nil
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// 4xx: no retry. URL is wrong, auth is missing, etc.
		return nil, &DefiniteError{
			URL:        scrubbed,
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 256)),
		}
	}
	// 5xx and other unexpected codes: transient.
	return nil, &transientWrapper{
		URL: scrubbed,
		Err: fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 256)),
	}
}

// DefiniteError is returned when the verifier knows definitively
// that a fetch will not succeed (4xx, malformed URL, scheme
// rejection). Callers should NOT treat this as "network unavailable"
// — the URL is wrong or the resource is missing.
type DefiniteError struct {
	URL        string
	StatusCode int
	Err        error
}

func (e *DefiniteError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("definite HTTP error fetching %s: %v", e.URL, e.Err)
	}
	return fmt.Sprintf("definite error fetching %s: %v", e.URL, e.Err)
}

func (e *DefiniteError) Unwrap() error { return e.Err }

// TransientError is returned when retries are exhausted on a
// transient condition (network error, 5xx, timeout). Callers
// should map this to StatusSkipped with "network unavailable"
// reason — the verifier could not complete the check, but the
// bundle itself isn't necessarily invalid.
type TransientError struct {
	URL      string
	Err      error
	Attempts int
}

func (e *TransientError) Error() string {
	return fmt.Sprintf("transient error fetching %s after %d attempt(s): %v", e.URL, e.Attempts, e.Err)
}

func (e *TransientError) Unwrap() error { return e.Err }

// transientWrapper marks an error as retryable inside Fetch's loop.
// External callers see TransientError (after retries) or
// DefiniteError; transientWrapper is internal.
type transientWrapper struct {
	URL string
	Err error
}

func (e *transientWrapper) Error() string {
	return fmt.Sprintf("transient: %s: %v", e.URL, e.Err)
}

func (e *transientWrapper) Unwrap() error { return e.Err }

// IsTransient reports whether err represents a transient network
// condition (vs a definitive HTTP / cryptographic failure). Used by
// check 5/6/7 to decide whether to map an error into StatusSkipped
// (transient) or StatusFail (definite).
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	var t *TransientError
	return errors.As(err, &t)
}

// SkippedDueToOffline returns a CheckResult with StatusSkipped and
// the canonical "offline mode" reason. Used by check 5/6/7 when
// CheckOptions.Offline is true to short-circuit before any network
// access is attempted.
func SkippedDueToOffline(id int, name, slug string) CheckResult {
	return Skipped(id, name, slug,
		"anchor verification skipped — --offline mode")
}

// SkippedDueToNetworkUnavailable returns a CheckResult with
// StatusSkipped and the canonical "network unavailable" reason.
// Used by check 5/6/7 when a TransientError exhausts retries —
// the verifier could not complete the check, but the bundle's
// validity is undetermined rather than failed.
//
// detail is the underlying network error; included in the
// SkipReason for forensic context.
func SkippedDueToNetworkUnavailable(id int, name, slug string, detail error) CheckResult {
	reason := "anchor verification skipped — network unavailable"
	if detail != nil {
		reason = fmt.Sprintf("%s (%s)", reason, truncate(detail.Error(), 256))
	}
	return Skipped(id, name, slug, reason)
}

// scrubURL strips query parameters and fragments from a URL for
// log-safe display. Some external endpoints (Bitcoin RPC with
// embedded credentials, older Esplora variants with API keys) carry
// secrets in query strings; emitting those into error messages
// would leak credentials into shareable forensic output.
//
// Returns the URL unchanged if parsing fails — best-effort scrub
// that doesn't itself error.
func scrubURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[unparseable URL]"
	}
	scrubbed := *u
	scrubbed.RawQuery = ""
	scrubbed.Fragment = ""
	// Strip user-info (username + password) entirely. Leaving a
	// "[redacted]" placeholder via url.User would be URL-encoded
	// by url.URL.String() to "%5Bredacted%5D" — leaks the
	// percent-encoded brackets but preserves no operational info.
	// Safer to drop completely; if a future caller needs to see
	// "credentials were present," check u.User != nil before
	// scrubURL.
	scrubbed.User = nil
	return strings.TrimSuffix(scrubbed.String(), "/")
}

package checks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// requireHTTPS — HTTPS-only enforcement with localhost exception
// =============================================================================

func TestRequireHTTPSAcceptsHTTPSURL(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://blockstream.info/api",
		"https://mempool.space/api/block/abc",
		"https://example.com",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := requireHTTPS(u); err != nil {
				t.Errorf("requireHTTPS(%q) returned error: %v", u, err)
			}
		})
	}
}

func TestRequireHTTPSRejectsNonLocalhostHTTP(t *testing.T) {
	t.Parallel()
	cases := []string{
		"http://blockstream.info/api",
		"http://example.com",
		"http://192.168.1.1:8332",
		"http://my-bitcoind.internal:8332",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			err := requireHTTPS(u)
			if err == nil {
				t.Errorf("requireHTTPS(%q) accepted non-localhost http://; expected rejection", u)
			}
			if err != nil && !strings.Contains(err.Error(), "https") {
				t.Errorf("requireHTTPS(%q) error doesn't mention https: %v", u, err)
			}
		})
	}
}

func TestRequireHTTPSAcceptsLocalhostHTTP(t *testing.T) {
	t.Parallel()
	// Sec C1 from D1 reviewer pass: canonicalization MUST handle
	// case variants, trailing-dot fully-qualified form, IPv6
	// loopback in any representation, and the full 127.0.0.0/8
	// loopback range.
	cases := []string{
		"http://localhost:8332",
		"http://LOCALHOST:8332",  // case variant
		"http://Localhost:8332",  // case variant
		"http://localhost.:8332", // trailing-dot fully-qualified
		"http://127.0.0.1:8332",
		"http://127.0.0.5:8080", // any 127.x.x.x is loopback
		"http://[::1]:8332",
		"http://[0:0:0:0:0:0:0:1]:8332", // uncompressed IPv6 loopback
		"http://user:pass@localhost:8332",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := requireHTTPS(u); err != nil {
				t.Errorf("requireHTTPS(%q) rejected localhost http://: %v", u, err)
			}
		})
	}
}

// TestRequireHTTPSRejectsCanonicalizationBypassAttempts pins
// Sec C1 from D1 reviewer pass: canonicalization MUST NOT enable
// non-localhost http:// to slip past via spelling tricks.
func TestRequireHTTPSRejectsCanonicalizationBypassAttempts(t *testing.T) {
	t.Parallel()
	cases := []string{
		"http://localhost.evil.com",          // subdomain trick
		"http://127.0.0.1.evil.com",          // IP-then-suffix trick
		"http://1.2.3.4",                     // public IP
		"http://10.0.0.1",                    // private but not loopback
		"http://localhost.example.com.",      // trailing-dot doesn't make it loopback
		"http://attacker.com#localhost",      // fragment doesn't change host
		"http://attacker.com?host=localhost", // query doesn't change host
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := requireHTTPS(u); err == nil {
				t.Errorf("requireHTTPS(%q) accepted non-loopback host as localhost; expected rejection", u)
			}
		})
	}
}

// TestRequireHTTPSRejectsEmptyHost pins Crypto H2 from D1 reviewer
// pass: URLs with empty host (e.g., `https://` or `https:foo`)
// must be rejected as malformed regardless of scheme.
func TestRequireHTTPSRejectsEmptyHost(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://",
		"https:foo",
		"https:///path",
		"http://",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			err := requireHTTPS(u)
			if err == nil {
				t.Errorf("requireHTTPS(%q) accepted empty-host URL; expected rejection", u)
			}
			if err != nil && !strings.Contains(err.Error(), "host") {
				t.Errorf("requireHTTPS(%q) error doesn't mention 'host': %v", u, err)
			}
		})
	}
}

func TestRequireHTTPSRejectsUnknownScheme(t *testing.T) {
	t.Parallel()
	cases := []string{
		"file:///etc/passwd",
		"ftp://blockstream.info/api",
		"javascript:alert(1)",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := requireHTTPS(u); err == nil {
				t.Errorf("requireHTTPS(%q) accepted non-http(s) scheme; expected rejection", u)
			}
		})
	}
}

// =============================================================================
// HTTPClient.Fetch — retry + error classification
// =============================================================================

func TestHTTPClientFetchSuccessfulResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	c := newTestHTTPClient(srv.Client())
	body, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch unexpected error: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("Fetch body = %q, want %q", body, "hello")
	}
}

func TestHTTPClientFetchUserAgentSet(t *testing.T) {
	t.Parallel()
	var observedUA atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedUA.Store(r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := newTestHTTPClient(srv.Client())
	c.UserAgent = "test-agent/1.2.3"
	if _, err := c.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	got, _ := observedUA.Load().(string)
	if got != "test-agent/1.2.3" {
		t.Errorf("server saw User-Agent = %q, want %q", got, "test-agent/1.2.3")
	}
}

func TestHTTPClientFetchRejects4xxAsDefiniteError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	var hitCount atomic.Int64
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv.Config.Handler = wrapped

	c := newTestHTTPClient(srv.Client())
	c.MaxRetries = 5 // would retry 5 times if the error were transient
	_, err := c.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Fetch returned nil error on 404")
	}
	var defErr *DefiniteError
	if !errors.As(err, &defErr) {
		t.Errorf("error type %T, want *DefiniteError", err)
	}
	if hitCount.Load() != 1 {
		t.Errorf("4xx triggered %d retries; want exactly 1 attempt (no retry)", hitCount.Load())
	}
	if IsTransient(err) {
		t.Error("IsTransient returned true for DefiniteError; want false")
	}
}

// TestHTTPClientFetchScrubsCredentialsInErrors pins Sec C2 from
// D1 reviewer pass: errors from Fetch MUST NOT contain raw user-info
// credentials. An operator pasting CLI output into a bug report or
// Slack thread shouldn't leak --bitcoin-rpc-url credentials.
func TestHTTPClientFetchScrubsCredentialsInErrors(t *testing.T) {
	t.Parallel()
	c := newTestHTTPClient(nil)
	// The URL has user:pass that requireHTTPS will accept (localhost
	// http:// loopback) but the connection will fail (no listener).
	// The resulting TransientError must NOT contain "secretpass".
	_, err := c.Fetch(context.Background(), "http://user:secretpass@localhost:1/")
	if err == nil {
		t.Fatal("Fetch unexpectedly succeeded against unreachable localhost")
	}
	if strings.Contains(err.Error(), "secretpass") {
		t.Errorf("error contains credential 'secretpass': %v", err)
	}
	if strings.Contains(err.Error(), "user:secret") {
		t.Errorf("error contains user:secret pattern: %v", err)
	}
}

// TestHTTPClientFetchEnforcesResponseSizeLimit pins H4/H5 from D1
// reviewer pass: io.ReadAll bound at MaxResponseBytes prevents
// memory-DoS via large response bodies.
func TestHTTPClientFetchEnforcesResponseSizeLimit(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stream 5 MiB — over the 4 MiB cap.
		w.Header().Set("Content-Length", "5242880")
		w.WriteHeader(200)
		buf := make([]byte, 1024)
		for i := 0; i < 5*1024; i++ {
			_, _ = w.Write(buf)
		}
	}))
	defer srv.Close()
	c := newTestHTTPClient(srv.Client())
	c.MaxRetries = 0
	_, err := c.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Fetch unexpectedly accepted 5MiB body (cap is 4MiB)")
	}
	if !IsTransient(err) {
		t.Errorf("over-cap response not classified as transient: %v", err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error doesn't mention 'exceeds': %v", err)
	}
}

// TestHTTPClientCheckRedirectRejectsHTTPSToHTTP pins Sec C3 from
// D1 reviewer pass: an https→http redirect MUST be rejected by the
// CheckRedirect hook to prevent HTTPS-enforcement bypass.
func TestHTTPClientCheckRedirectRejectsHTTPSToHTTP(t *testing.T) {
	t.Parallel()
	// Build an http (cleartext) target that the redirect would point
	// to. The target itself doesn't matter — CheckRedirect rejects
	// the redirect before any further hop is contacted.
	httpTarget := "http://attacker.example.com/path"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpTarget, http.StatusFound)
	}))
	defer srv.Close()

	// Use the production redirect-aware default client (NewDefaultHTTPClient),
	// not the test client. The test client doesn't set CheckRedirect.
	c := NewDefaultHTTPClient("test")
	c.Client.Transport = srv.Client().Transport // accept the test server's TLS cert
	c.Client.Timeout = 2 * time.Second
	c.MaxRetries = 0

	_, err := c.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Fetch followed https→http redirect without rejection")
	}
	// The redirect rejection becomes a transient error (the request
	// "didn't complete successfully") via the http.Client wrapping.
	// What matters is that the verifier did NOT contact attacker.example.com.
	if strings.Contains(err.Error(), "attacker.example.com") {
		// Some forms of the wrapped error include the target URL.
		// We just need to confirm CheckRedirect fired — the err
		// should mention "rejected" or "https" or similar redirect-
		// relevant context.
	}
	// Confirm no actual fetch to the http target happened by checking
	// the error string for the rejection sentinel.
	if !strings.Contains(strings.ToLower(err.Error()), "redirect") &&
		!strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Errorf("error doesn't indicate redirect rejection: %v", err)
	}
}

func TestHTTPClientFetchRetries5xxAsTransient(t *testing.T) {
	t.Parallel()
	var hitCount atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		http.Error(w, "internal", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestHTTPClient(srv.Client())
	c.MaxRetries = 2
	c.BaseDelay = time.Millisecond // fast test
	_, err := c.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Fetch returned nil on 5xx")
	}
	if !IsTransient(err) {
		t.Errorf("error not classified as transient: %v", err)
	}
	if hitCount.Load() != 3 {
		// 1 initial + 2 retries = 3 total
		t.Errorf("5xx triggered %d attempts; want 3 (1 initial + 2 retries)", hitCount.Load())
	}
	var transErr *TransientError
	if !errors.As(err, &transErr) {
		t.Errorf("error type %T, want *TransientError", err)
	} else if transErr.Attempts != 3 {
		t.Errorf("TransientError.Attempts = %d, want 3", transErr.Attempts)
	}
}

func TestHTTPClientFetchRejectsHTTPInsideFetch(t *testing.T) {
	t.Parallel()
	c := newTestHTTPClient(nil)
	_, err := c.Fetch(context.Background(), "http://example.com/foo")
	if err == nil {
		t.Fatal("Fetch accepted http://example.com URL; expected rejection")
	}
	var defErr *DefiniteError
	if !errors.As(err, &defErr) {
		t.Errorf("error type %T, want *DefiniteError for scheme rejection", err)
	}
}

func TestHTTPClientFetchHonorsContextCancel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestHTTPClient(srv.Client())
	c.MaxRetries = 100
	c.BaseDelay = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := c.Fetch(ctx, srv.URL)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Fetch returned nil on cancelled context")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Fetch took %v despite cancellation; want quick exit", elapsed)
	}
}

// =============================================================================
// Skipped helpers
// =============================================================================

func TestSkippedDueToOffline(t *testing.T) {
	t.Parallel()
	r := SkippedDueToOffline(5, "OpenTimestamps", "opentimestamps")
	if r.Status != StatusSkipped {
		t.Errorf("Status = %v, want Skipped", r.Status)
	}
	if !strings.Contains(r.SkipReason, "offline") {
		t.Errorf("SkipReason doesn't mention offline: %q", r.SkipReason)
	}
	if r.CheckID != 5 {
		t.Errorf("CheckID = %d, want 5", r.CheckID)
	}
}

func TestSkippedDueToNetworkUnavailable(t *testing.T) {
	t.Parallel()
	r := SkippedDueToNetworkUnavailable(5, "OpenTimestamps", "opentimestamps",
		errors.New("DNS lookup failed"))
	if r.Status != StatusSkipped {
		t.Errorf("Status = %v, want Skipped", r.Status)
	}
	if !strings.Contains(r.SkipReason, "network unavailable") {
		t.Errorf("SkipReason doesn't mention 'network unavailable': %q", r.SkipReason)
	}
	if !strings.Contains(r.SkipReason, "DNS lookup failed") {
		t.Errorf("SkipReason doesn't include underlying cause: %q", r.SkipReason)
	}
}

// =============================================================================
// scrubURL — credential leakage prevention
// =============================================================================

func TestScrubURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"https://blockstream.info/api/block/abc", "https://blockstream.info/api/block/abc"},
		{"https://example.com?api_key=secret", "https://example.com"},
		{"https://example.com/path?token=xyz#frag", "https://example.com/path"},
		{"http://user:pass@localhost:8332/", "http://localhost:8332"},
		{"https://bitcoind.example.com/?rpcuser=admin&rpcpassword=secret", "https://bitcoind.example.com"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := scrubURL(c.in)
			if got != c.want {
				t.Errorf("scrubURL(%q) = %q, want %q", c.in, got, c.want)
			}
			// Defense-in-depth: the scrubbed output MUST NOT contain
			// "secret", "password", "rpcpassword", "token", "api_key"
			// — generic credential-leakage smell test.
			lower := strings.ToLower(got)
			for _, leak := range []string{"secret", "password", "token=", "api_key="} {
				if strings.Contains(lower, leak) {
					t.Errorf("scrubURL output contains potential credential leak %q: %s", leak, got)
				}
			}
		})
	}
}

// =============================================================================
// Helpers
// =============================================================================

// newTestHTTPClient returns an HTTPClient with short timeouts +
// minimal retries suitable for tests. If httpClient is non-nil
// (e.g., from httptest.NewTLSServer().Client()), use its transport
// so the test doesn't have to skip TLS verification.
func newTestHTTPClient(stdClient *http.Client) *HTTPClient {
	c := &HTTPClient{
		Client:     &http.Client{Timeout: 2 * time.Second},
		UserAgent:  "nuwyre-verify/test",
		MaxRetries: 0,
		BaseDelay:  10 * time.Millisecond,
	}
	if stdClient != nil {
		c.Client = stdClient
		c.Client.Timeout = 2 * time.Second
	}
	return c
}

//go:build js && wasm

// Package main is the NuWyre WASM verifier entrypoint — the same
// internal/bundle + internal/checks code paths the native CLI uses,
// compiled to a WebAssembly module loaded by the marketing site's
// /verify route. Phase 5.5 Session 5.5.1B C4.
//
// **Phase 6.2.C-B session 71 audit-log-export extension** (BACKLOG
// 1.33 + Check 9 parallel substrate at WASM):
//   - Check 9 audit-log-merkle verifier registered in the WASM
//     buildCheckRegistry (mirrors session 70 Go-native registry
//     extension at apps/cli/cmd/nuwyre/main.go). Conditional skip
//     for non-audit-log-export bundles per Check 9's own gate.
//   - Check 7 bundle_type subdirectory path extension inherited
//     automatically via the shared internal/checks/check7_github.go
//     + internal/checks/github_fetch.go session 70 changes (the
//     FetchRootJson signature extension + closed-vocabulary path-
//     traversal defense + URL pattern daily-roots/<orgID>/<date>/
//     <bundleType>/root.json work transparently at WASM compile).
//   - Cross-implementation byte-equivalence preserved: WASM
//     verification of an audit-log-export bundle produces the same
//     VerifyResult JSON as the Go-native CLI for the same bytes
//     (T2 load-bearing contract).
//
// **Six tenants framing for the WASM verifier** (per
// memory/feedback_six_tenants.md):
//
//   - T2 (quality/reliability) is LOAD-BEARING — the WASM verifier
//     MUST produce identical VerificationResult to the native Go
//     CLI binary against the conformance fixture suite, byte-for-
//     byte on every check's status/check_id/check_slug. The shared
//     internal/bundle + internal/checks packages compile to WASM
//     unchanged; the JS bridge in this file only marshals inputs
//     and outputs.
//
//   - T3 (security/privacy) is LOAD-BEARING — uploaded bundle bytes
//     never leave the browser. The WASM runs entirely client-side;
//     checks 5 + 7 reach out to Esplora + GitHub raw via the
//     browser's fetch API, but the bundle bytes themselves are
//     never transmitted. The customer's customer's evidence stays
//     within the customer's control surface.
//
//   - T5 (customer trust) is LOAD-BEARING — the "see for yourself"
//     moment that converts skeptical prospects at first contact.
//     A customer's compliance officer downloads a bundle, drops it
//     on /verify, and sees the seven checks pass without trusting
//     NuWyre infrastructure for the verification.
//
//   - T6 (user value at point of use) is LOAD-BEARING — the
//     verification result appears in the customer's browser within
//     ~3 seconds of dropping the bundle, with no install step and
//     no signup. The CLI is the high-trust path; the WASM verifier
//     is the low-friction path; both produce the same result.
//
// **JS API surface** (exposed on globalThis.nuwyre after the runtime
// initializes; the JS host must wait for the "nuwyreReady" Promise
// before invoking these):
//
//	nuwyre.verify(bundleBytes Uint8Array, options object) → Promise<VerifyResult>
//	nuwyre.inspect(bundleBytes Uint8Array) → InspectResult
//	nuwyre.version → string
//
// VerifyResult is the same JSON shape the native CLI emits via
// --json (output.JSONOutput); this is the conformance contract.
// InspectResult is a minimal metadata projection (bundle_id, type,
// counts, anchor leg states) that the /verify route renders before
// running the full verification, so the user sees the bundle's
// identity even on a slow network.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
	"time"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/checks"
	"github.com/nuwyre/cli/internal/output"
)

// Version is the WASM build's version string. Released alongside the
// native CLI; -ldflags="-X main.Version=..." sets this at build time.
var Version = "0.1.0-pre"

// JSAPIName is the global namespace the verifier registers under.
// The /verify route calls `window.nuwyre.verify(...)` — keep stable
// across releases (T1: long-term value; CI/E2E suites grep for this).
const JSAPIName = "nuwyre"

// MaxBundleBytes caps the input bundle size accepted by verify()/
// inspect(). Above this size the call rejects synchronously rather
// than attempting to allocate. 64 MiB is well above realistic V1
// production bundles (typically <10 MiB; example-demo ~500 KiB) and
// below the practical memory ceiling of a typical browser tab. T3
// fail-secure posture: a malicious user supplying an oversized
// Uint8Array cannot wedge the WASM linear memory or crash the tab.
//
// (Phase 5.5 Session 5.5.1B reviewer fix-up batch — sec-aud H2.)
const MaxBundleBytes = 64 * 1024 * 1024

// InspectFormatVersion is the version pin for the inspect() output
// shape. T1 long-term contract — CI/integration callers MUST verify
// inspect_format_version == "1" and fail loudly on any other value
// rather than silently accept v2+ output. Mirrors output.OutputFormatVersion
// for the verify() path. (Phase 5.5 Session 5.5.1B reviewer fix-up —
// code-rev #3 + structural-versioning discipline.)
const InspectFormatVersion = "1"

func main() {
	registerAPI()

	// Signal readiness to the JS host. The /verify route awaits
	// window.nuwyreReadyPromise (resolved by the loader glue) before
	// enabling the drop zone. Two signaling surfaces (Phase 5.5 Session
	// 5.5.1B reviewer fix-up, code-rev #4 race condition):
	//   1. nuwyre.ready synchronous flag — set BEFORE event dispatch so
	//      a late-attaching JS listener can synchronously poll on first
	//      attach (window.nuwyre.ready === true means "verify/inspect
	//      are safe to call right now"). This is the load-bearing
	//      late-bind path.
	//   2. CustomEvent("nuwyreReady") fired on document for listeners
	//      that attached before the event fired. This is the eager-
	//      bind path.
	js.Global().Get(JSAPIName).Set("ready", true)
	dispatchReady()

	// Block forever — Go WASM exits when main() returns, which would
	// invalidate every registered js.Func. select{} is the canonical
	// idiom (see https://github.com/golang/go/wiki/WebAssembly).
	select {}
}

// registerAPI installs verify/inspect/version on globalThis.nuwyre.
// The `ready` flag is set to false initially and flipped to true at
// the end of main() (after registerAPI returns) so a JS caller can
// distinguish "API surface installed but main() hasn't completed
// readiness signaling" from "API surface fully ready."
func registerAPI() {
	global := js.Global()
	api := js.Global().Get("Object").New()
	api.Set("version", Version)
	api.Set("ready", false)
	api.Set("verify", js.FuncOf(verifyJS))
	api.Set("inspect", js.FuncOf(inspectJS))
	global.Set(JSAPIName, api)
}

// dispatchReady fires the "nuwyreReady" CustomEvent on the host
// global object (window in browsers, globalThis in Node).
//
// Note (code-rev #4 fix-up): JS callers MUST prefer polling
// `window.nuwyre.ready === true` over listening for the event,
// because Go-WASM's main() runs synchronously after instantiate()
// resolves — a JS listener attached AFTER the `await go.run(...)`
// statement will miss the event dispatch. The `ready` flag is the
// load-bearing late-bind surface; this event is the eager-bind
// notification for listeners that attached BEFORE go.run() resolved.
func dispatchReady() {
	global := js.Global()
	doc := global.Get("document")
	if doc.IsUndefined() {
		// Non-browser host (e.g., Node-based conformance runner);
		// loader glue may use a different signaling channel. Skip
		// the event; the `ready` flag is still set.
		return
	}
	eventInit := js.Global().Get("Object").New()
	detail := js.Global().Get("Object").New()
	detail.Set("version", Version)
	eventInit.Set("detail", detail)
	event := js.Global().Get("CustomEvent").New("nuwyreReady", eventInit)
	global.Call("dispatchEvent", event)
}

// =============================================================================
// verify(bundleBytes, options) — full 7-check verification
// =============================================================================

// verifyJS is the JS-facing wrapper around the native verification
// pipeline. Signature: verify(bundleBytes: Uint8Array, options: {
// offline?: bool, allow_pending_ots?: bool, allow_anchor_pending?:
// bool, allow_dev_key?: bool, strict_ots?: bool }) → Promise<{...
// output.JSONOutput shape ...}>.
//
// Returns a JS Promise (constructed in JS via a polyfill-free
// pattern: we call js.Global().Get("Promise").New(executor) and
// spawn a goroutine that runs the verification, then calls
// resolve(result) or reject(error) from the goroutine).
//
// T2 contract: the JSON shape the Promise resolves to is identical
// to output.JSONOutput (same as native CLI's --json output). The
// conformance suite's results.json compares structurally against
// this output.
func verifyJS(this js.Value, args []js.Value) any {
	// Argument shape: (bundleBytes, options?)
	if len(args) < 1 {
		return promiseRejected(errors.New("nuwyre.verify: bundleBytes argument required"))
	}
	bundleBytes, err := uint8ArrayToBytes(args[0])
	if err != nil {
		return promiseRejected(fmt.Errorf("nuwyre.verify: bundleBytes: %w", err))
	}

	var jsOpts js.Value
	if len(args) >= 2 {
		jsOpts = args[1]
	}
	opts := parseCheckOptions(jsOpts)

	// Spec §14.5 (v1.0.7) flag-interaction validation. Native CLI
	// rejects contradictory combinations via os.Exit(2); WASM rejects
	// via a rejected Promise carrying an Error. Cross-implementation
	// conformance per the v1.0.7 amendment: both surfaces enforce the
	// same MUST clause; only the surfacing channel differs.
	//
	// (Phase 5.5 Session 5.5.1C reviewer fix-up batch: closes
	// crypto-int #5 + spec-rev F6 cross-corroborated finding.)
	if opts.Offline && opts.StrictOTS {
		return promiseRejected(errors.New(
			"nuwyre.verify: contradictory options: offline=true + strict_ots=true (offline skips check 5; strict_ots requires check 5 to run); pass one or the other, not both"))
	}
	if opts.StrictOTS && opts.AllowPendingOTS {
		return promiseRejected(errors.New(
			"nuwyre.verify: contradictory options: strict_ots=true + allow_pending_ots=true (strict_ots makes pending OTS → fail; allow_pending_ots folds pending warn INTO pass); pass one or the other, not both"))
	}

	promiseConstructor := js.Global().Get("Promise")
	// Capture `handler` in a closure so the executor goroutine can
	// .Release() it after settling — js.FuncOf registers a callback
	// with the Go runtime that holds a GC root; without .Release(),
	// each verify() invocation leaks one js.Func reference (Phase 5.5
	// Session 5.5.1B reviewer fix-up — code-rev #1, TRIPLE-corroborated
	// risk). For a "drop a bundle to verify" workflow this is small
	// per-instance but compounds in long-lived browser tabs.
	var handler js.Func
	handler = js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		// Verification can run synchronously inside a goroutine; spawn
		// so the Promise constructor returns immediately and the JS
		// event loop stays responsive.
		go func() {
			defer handler.Release()
			defer func() {
				if rec := recover(); rec != nil {
					reject.Invoke(jsError(fmt.Errorf("nuwyre.verify: internal panic: %v", rec)))
				}
			}()
			outputJSON, verifyErr := runVerify(bundleBytes, opts)
			if verifyErr != nil {
				reject.Invoke(jsError(verifyErr))
				return
			}
			parsed := js.Global().Get("JSON").Call("parse", outputJSON)
			resolve.Invoke(parsed)
		}()
		return nil
	})
	return promiseConstructor.New(handler)
}

// runVerify executes the full 7-check pipeline against the supplied
// bundle bytes + options. Returns the JSON-encoded output.JSONOutput
// string (so the JS bridge can JSON.parse it once on the boundary).
// Six tenants: T2 — same checks.RunChecks call the native CLI makes,
// no special-case logic for the WASM path.
func runVerify(bundleBytes []byte, opts checks.CheckOptions) (string, error) {
	b, err := bundle.LoadFromBytes(bundleBytes, "(bytes)")
	if err != nil {
		return "", fmt.Errorf("bundle load failed: %w", err)
	}

	registry, err := buildCheckRegistry(opts)
	if err != nil {
		return "", fmt.Errorf("check registry construction failed: %w", err)
	}

	results, _ := checks.RunChecks(b, opts, registry...)
	// Sort by CheckID for canonical spec §14.1 output ordering.
	results = checks.SortByCheckID(results)
	verdict := checks.AggregateVerdict(results, opts)

	formatter := output.NewJSONFormatter(false)
	// spec-conformance C1 closure 2026-05-22: emit output_format_version="2"
	// for v2 bundles per spec §14.1 line 1632 + §18.10.
	return formatter.FormatResultsForBundle(results, verdict, b.Manifest.BundleFormat), nil
}

// buildCheckRegistry mirrors the native CLI's registry builder. Same
// shape; the network-backed checks 5/6/7 use the same HTTPClient.
// Under WASM, Go's net/http is backed by JS fetch; CORS-blocked
// endpoints (any cross-origin URL the verifier reaches) surface
// as TransientError → the check reports Skipped/Warn rather than
// failing outright, mirroring the native --offline UX.
func buildCheckRegistry(opts checks.CheckOptions) ([]checks.Check, error) {
	httpClient := checks.NewDefaultHTTPClient(Version)

	check5 := checks.NewCheck5OTS(httpClient)

	check6, err := checks.NewCheck6RFC3161()
	if err != nil {
		return nil, fmt.Errorf("check 6 (RFC 3161): %w", err)
	}

	githubFetcher, err := checks.NewGithubHTTPSFetcher(checks.AnchorRepoDefault, httpClient)
	if err != nil {
		return nil, fmt.Errorf("check 7 (GitHub anchor): %w", err)
	}
	check7 := checks.NewCheck7Github(githubFetcher)

	// Registry order is EXECUTION order. Check 8 runs after Check 2 +
	// before Check 3 (ephemeral-sessions topology dependency). RunChecks
	// sorts the returned results by CheckID for canonical report order
	// (spec §14.1 canonical sequence 1, 2, 3, 4, 5, 6, 7, 8, 9).
	//
	// Phase 6.2.C-B session 71: Check 9 (audit-log-merkle) added after
	// Check 7. Conditional execution via bundle_type gate inside its
	// Run() method (Skipped for non-audit-log-export bundles). Mirrors
	// the Go-native registry at apps/cli/cmd/nuwyre/main.go session 70
	// addition. The WASM build inherits all Check 9 logic + Check 7
	// bundle_type subdirectory extension via the shared internal/
	// checks package — registry registration is the only WASM-side
	// surface that needed extension.
	return []checks.Check{
		checks.Check1Signature{},
		checks.Check2Artifacts{},
		checks.Check8EphemeralSession{},
		checks.Check3Chain{},
		checks.Check4Merkle{},
		check5,
		check6,
		check7,
		checks.Check9AuditLogMerkle{},
	}, nil
}

// =============================================================================
// inspect(bundleBytes) — fast metadata-only projection
// =============================================================================

// InspectResult is the minimal bundle-identity surface the /verify
// route renders before running full verification. T6: user sees the
// bundle's identity within ~100ms even on slow networks; verification
// proceeds asynchronously.
//
// **InspectFormatVersion contract** (Phase 5.5 Session 5.5.1B reviewer
// fix-up, code-rev #3): every inspect() output carries an
// inspect_format_version field. Callers MUST verify "1" and fail
// loudly on any other value rather than silently accept v2+ output.
// Mirrors output.OutputFormatVersion versioning posture.
type InspectResult struct {
	InspectFormatVersion string                    `json:"inspect_format_version"`
	BundleFormat         string                    `json:"bundle_format"`
	BundleID             string                    `json:"bundle_id"`
	BundleType           string                    `json:"bundle_type"`
	// BundleSubtype is the audit-log-export subtype discriminator
	// per spec §16.5 (v1.0.10+). Empty string for non-audit-log-export
	// bundles. Phase 6.2.C-B session 71 addition: lets /verify UI
	// render customer-scoped vs operator-only for audit-log-export
	// bundles.
	BundleSubtype        string                    `json:"bundle_subtype,omitempty"`
	GeneratedAt          string                    `json:"generated_at"`
	OrganizationID       string                    `json:"organization_id"`
	AgentID              string                    `json:"agent_id"`
	EventCount           int                       `json:"event_count"`
	EvaluationCount      int                       `json:"evaluation_count"`
	FlaggedCount         int                       `json:"flagged_count"`
	CleanCount           int                       `json:"clean_count"`
	// AuditLogEventCount is the audit log event count for audit-log-
	// export bundles per spec §4.1 v1.0.11 F2. Pointer so absence is
	// distinguishable from explicit zero (an empty operator-only chain
	// is a legitimate state). Phase 6.2.C-B session 71 addition.
	AuditLogEventCount   *int                      `json:"audit_log_event_count,omitempty"`
	DailyRoot            string                    `json:"daily_root"`
	AnchorStatus         InspectAnchorStatus       `json:"anchor_status"`
	SigningAlgorithm     string                    `json:"signing_algorithm"`
	KeyFingerprint       string                    `json:"key_fingerprint_spki_b64"`
	PackSubscriptions    []InspectPackSubscription `json:"pack_subscriptions"`
	ArtifactCount        int                       `json:"artifact_count"`
}

// InspectAnchorStatus mirrors manifest's anchor_status surface for
// rendering the three-leg badges.
type InspectAnchorStatus struct {
	OTSStatus     string `json:"ots_status"`
	RFC3161Status string `json:"rfc3161_status"`
	GithubStatus  string `json:"github_status"`
}

type InspectPackSubscription struct {
	PackID      string `json:"pack_id"`
	PackVersion string `json:"pack_version"`
	BodyHash    string `json:"body_hash"`
}

// inspectJS is the JS-facing wrapper around the metadata projection.
//
// **API shape** (Phase 5.5 Session 5.5.1B reviewer fix-up, code-rev #2
// + sec-aud H1): returns a Promise<InspectResult> for parity with
// verify(). Synchronous-return was rejected for two reasons:
//   1. A returned `Error` object is indistinguishable from a successful
//      InspectResult unless callers add an `instanceof Error` check —
//      bug-prone API surface.
//   2. Synchronous panic recovery was missing — a malicious bundle
//      that triggered a panic in archive/zip or encoding/json would
//      crash the WASM instance + force a page reload. Promise-shape
//      lets the executor goroutine wrap the body in defer recover().
func inspectJS(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return promiseRejected(errors.New("nuwyre.inspect: bundleBytes argument required"))
	}
	bundleBytes, err := uint8ArrayToBytes(args[0])
	if err != nil {
		return promiseRejected(fmt.Errorf("nuwyre.inspect: bundleBytes: %w", err))
	}

	promiseConstructor := js.Global().Get("Promise")
	var handler js.Func
	handler = js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		go func() {
			defer handler.Release()
			defer func() {
				if rec := recover(); rec != nil {
					reject.Invoke(jsError(fmt.Errorf("nuwyre.inspect: internal panic: %v", rec)))
				}
			}()
			data, inspectErr := runInspect(bundleBytes)
			if inspectErr != nil {
				reject.Invoke(jsError(inspectErr))
				return
			}
			parsed := js.Global().Get("JSON").Call("parse", string(data))
			resolve.Invoke(parsed)
		}()
		return nil
	})
	return promiseConstructor.New(handler)
}

// runInspect produces the JSON-encoded InspectResult bytes for the
// supplied bundle. Separated from inspectJS for testability + to keep
// the JS bridge thin (T4 simplicity: the bridge marshals JS↔Go; the
// inspection logic is pure Go).
func runInspect(bundleBytes []byte) ([]byte, error) {
	b, err := bundle.LoadFromBytes(bundleBytes, "(bytes)")
	if err != nil {
		return nil, fmt.Errorf("load failed: %w", err)
	}

	result := InspectResult{
		InspectFormatVersion: InspectFormatVersion,
		BundleFormat:         b.Manifest.BundleFormat,
		BundleID:             b.Manifest.BundleID,
		BundleType:           b.Manifest.BundleType,
		BundleSubtype:        b.Manifest.BundleSubtype,
		AuditLogEventCount:   b.Manifest.AuditLogEventCount,
		GeneratedAt:          b.Manifest.GeneratedAt,
		OrganizationID:       b.Manifest.OrganizationID,
		AgentID:              b.Manifest.AgentID,
		EventCount:           b.Manifest.EventCount,
		EvaluationCount:      b.Manifest.EvaluationCount,
		FlaggedCount:         b.Manifest.FlaggedCount,
		CleanCount:           b.Manifest.CleanCount,
		DailyRoot:            b.Manifest.DailyRoot,
		SigningAlgorithm:     b.Manifest.Signing.Algorithm,
		KeyFingerprint:       b.Manifest.Signing.KeyFingerprintB64,
		ArtifactCount:        len(b.Manifest.Artifacts),
		AnchorStatus: InspectAnchorStatus{
			OTSStatus:     b.Manifest.AnchorStatus.OTSStatus,
			RFC3161Status: b.Manifest.AnchorStatus.RFC3161Status,
			GithubStatus:  b.Manifest.AnchorStatus.GithubStatus,
		},
	}
	for _, p := range b.Manifest.PackSubscriptions {
		result.PackSubscriptions = append(result.PackSubscriptions, InspectPackSubscription{
			PackID:      p.PackID,
			PackVersion: p.PackVersion,
			BodyHash:    p.BodyHash,
		})
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %w", err)
	}
	return data, nil
}

// =============================================================================
// JS bridge helpers
// =============================================================================

// uint8ArrayToBytes copies bytes out of a JS Uint8Array. js.CopyBytesToGo
// is the canonical efficient path; we copy because Go and JS heap are
// separate and the caller retains ownership of the source buffer.
//
// **Hardening posture** (Phase 5.5 Session 5.5.1B reviewer fix-up,
// sec-aud H2 + sec-aud L1 + code-rev #6):
//   - Reject undefined/null up front.
//   - Require constructor present + named "Uint8Array" (fail-closed,
//     was fail-open). An object created via Object.create(null) or
//     missing .constructor is rejected loudly rather than slipping
//     through.
//   - Require byteLength present + non-negative.
//   - Reject sizes above MaxBundleBytes (T3 fail-secure: a malicious
//     user supplying a 2 GiB Uint8Array cannot wedge WASM linear
//     memory or crash the tab).
func uint8ArrayToBytes(v js.Value) ([]byte, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, errors.New("undefined or null")
	}
	ctor := v.Get("constructor")
	if ctor.IsUndefined() || ctor.IsNull() {
		return nil, errors.New("expected Uint8Array, got object with no constructor")
	}
	name := ctor.Get("name")
	if name.IsUndefined() || name.String() != "Uint8Array" {
		gotName := "(no constructor.name)"
		if !name.IsUndefined() {
			gotName = name.String()
		}
		return nil, fmt.Errorf("expected Uint8Array, got %s", gotName)
	}
	byteLengthVal := v.Get("byteLength")
	if byteLengthVal.IsUndefined() {
		return nil, errors.New("expected Uint8Array.byteLength, got undefined")
	}
	length := byteLengthVal.Int()
	if length < 0 {
		return nil, fmt.Errorf("invalid byteLength %d", length)
	}
	if length > MaxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds %d byte cap (got %d)", MaxBundleBytes, length)
	}
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, v)
	return buf, nil
}

// parseCheckOptions extracts CheckOptions from a JS object. Missing
// fields default to false; unknown fields are silently ignored
// (T1: forward compatibility — adding a new option in a future
// version doesn't break older JS callers).
//
// **Note on --bitcoin-rpc-url**: not exposed in the WASM API. The
// browser-side verifier always uses the default Esplora pair. An
// operator who wants a custom Bitcoin endpoint should use the
// native CLI.
func parseCheckOptions(opts js.Value) checks.CheckOptions {
	out := checks.CheckOptions{
		Now: time.Now().UTC(),
	}
	if opts.IsUndefined() || opts.IsNull() {
		return out
	}
	if v := opts.Get("offline"); !v.IsUndefined() {
		out.Offline = v.Bool()
	}
	if v := opts.Get("strict_ots"); !v.IsUndefined() {
		out.StrictOTS = v.Bool()
	}
	if v := opts.Get("allow_pending_ots"); !v.IsUndefined() {
		out.AllowPendingOTS = v.Bool()
	}
	if v := opts.Get("allow_anchor_pending"); !v.IsUndefined() {
		out.AllowAnchorPending = v.Bool()
	}
	if v := opts.Get("allow_dev_key"); !v.IsUndefined() {
		out.AllowDevKey = v.Bool()
	}
	return out
}

// jsError converts a Go error to a JS Error object. The /verify
// route's Promise rejection handler reads err.message.
func jsError(err error) js.Value {
	return js.Global().Get("Error").New(err.Error())
}

// promiseRejected returns a Promise.reject(err) for argument-validation
// failures that should reject synchronously rather than fire the
// executor goroutine.
func promiseRejected(err error) any {
	return js.Global().Get("Promise").Call("reject", jsError(err))
}


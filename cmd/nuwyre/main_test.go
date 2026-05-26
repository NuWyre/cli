package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// =============================================================================
// Shared smoke-test infrastructure (Phase 4 Session 3 D5).
//
// D5 wires all 7 checks + adds CLI flags + ships output formatters.
// These end-to-end smoke tests build the binary once and exercise
// the verify command against the regenerated example bundle.
// =============================================================================

var (
	buildBinaryOnce sync.Once
	binaryPath      string
	binaryBuildErr  error
)

func verifierBinary(t *testing.T) string {
	t.Helper()
	buildBinaryOnce.Do(func() {
		// Build under GOTMPDIR if set (Windows AppControl on this
		// dev box whitelists the workspace's .gotmp directory but
		// blocks fresh executables in default %TEMP%; per memory
		// "feedback_go_test_tmpdir.md", GOTMPDIR set to a workspace-
		// local path is the standard fix). Fall back to OS temp
		// otherwise (CI / non-Windows / dev boxes without AppControl).
		baseRoot := os.Getenv("GOTMPDIR")
		if baseRoot == "" {
			baseRoot = os.TempDir()
		}
		base, err := os.MkdirTemp(baseRoot, "nuwyre-verifier-*")
		if err != nil {
			binaryBuildErr = err
			return
		}
		binName := "nuwyre"
		if runtime.GOOS == "windows" {
			binName += ".exe"
		}
		binaryPath = filepath.Join(base, binName)
		build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/nuwyre")
		if out, err := build.CombinedOutput(); err != nil {
			binaryBuildErr = &buildErr{Err: err, Output: string(out)}
		}
	})
	if binaryBuildErr != nil {
		t.Fatalf("build failed: %v", binaryBuildErr)
	}
	return binaryPath
}

type buildErr struct {
	Err    error
	Output string
}

func (e *buildErr) Error() string {
	return e.Err.Error() + "\noutput:\n" + e.Output
}

// runVerifyCmd invokes the verifier with the given args + returns
// (output, exitCode). NO_COLOR is set in env so output assertions
// are stable across TTY environments.
func runVerifyCmd(t *testing.T, args ...string) (string, int) {
	t.Helper()
	bin := verifierBinary(t)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("verify run failed unexpectedly (not an ExitError): %v\noutput:\n%s", err, out)
		}
		return string(out), exitErr.ExitCode()
	}
	return string(out), 0
}

// exampleBundlePath returns the regenerated example bundle path or
// skips the test if the bundle is missing (fresh checkout case).
func exampleBundlePath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "apps", "marketing",
		"public", "examples", "nuwyre_export_cypress-derm_2026-04-22.zip")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("example bundle missing at %s; regenerate via `pnpm --filter @nuwyre/example-bundle generate`", p)
	}
	return p
}

// =============================================================================
// Smoke tests — D5 acceptance signal
//
// The example bundle's expected check states (per Phase 3 + D2-D4
// generation):
//   - Check 1: PASS (or WARN with --allow-dev-key for example-demo)
//   - Check 2: PASS (artifact integrity)
//   - Check 3: PASS (hash chain)
//   - Check 4: PASS (Merkle proof)
//   - Check 5: WARN (OTS receipt is in pending Bitcoin confirmation state)
//   - Check 6: PASS (3 distinct TSAs verify against pinned + system trust)
//   - Check 7: FAIL by default (V1 anchor-pending state); WARN with
//     --allow-anchor-pending; SKIPPED with --offline
//
// Smoke variants:
//   - default: --allow-dev-key only → check 7 FAIL → exit 1
//   - all-allow: --allow-* trio → all PASS or WARN-folded → exit 0
//   - --offline: 5-7 skipped → exit 0
//   - --json + all-allow: parseable JSON with output_format_version="1"
//   - contradictory --offline + --strict-ots → exit 2
// =============================================================================

func TestVerifyVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	out, exitCode := runVerifyCmd(t, "--version")
	if exitCode != 0 {
		t.Errorf("--version: exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(out, "nuwyre ") {
		t.Errorf("--version output missing 'nuwyre ': %s", out)
	}
}

// TestVerifyExampleBundleOfflineFlagsPasses pins the --offline path:
// with --allow-dev-key + --offline, checks 5-7 are SKIPPED → exit 0
// → operator explicitly opted INTO offline mode + accepted dev-key.
// All 7 check lines still appear in the output. (Code-reviewer S2,
// D5 c3+c4 review: previously misnamed as DefaultFlagsFails which
// contradicted the body — V1 default-flags FAIL is covered by
// TestVerifyExampleBundleAnchorPendingDefaultFails which is
// LIVE_NETWORK-gated.)
func TestVerifyExampleBundleOfflineFlagsPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	bundlePath := exampleBundlePath(t)
	output, exitCode := runVerifyCmd(t, "verify", "--allow-dev-key", "--offline", bundlePath)
	t.Logf("verify --offline output:\n%s", output)

	if exitCode != 0 {
		t.Errorf("--offline run: exit code = %d, want 0", exitCode)
	}
	for _, want := range []string{
		"Check 1 (manifest signature):",
		"Check 2 (artifact integrity):",
		"Check 3 (hash chain):",
		"Check 4 (Merkle proof):",
		"Check 5 (OpenTimestamps Bitcoin anchor):",
		"Check 6 (RFC 3161 timestamp anchor):",
		"Check 7 (GitHub anchor cross-check):",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if !strings.Contains(output, "SKIPPED") {
		t.Errorf("--offline output should contain SKIPPED status for checks 5-7:\n%s", output)
	}
	if !strings.Contains(output, "Verdict: PASS") {
		t.Errorf("--offline + clean checks 1-4 should produce Verdict: PASS:\n%s", output)
	}
}

// TestVerifyExampleBundleAllAllowFlagsPasses pins the all-opt-in
// path: --allow-dev-key + --allow-pending-ots + --allow-anchor-pending
// folds checks 5+7 warns into pass → exit 0 with PASS verdict.
func TestVerifyExampleBundleAllAllowFlagsPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	bundlePath := exampleBundlePath(t)
	output, exitCode := runVerifyCmd(t, "verify",
		"--allow-dev-key",
		"--allow-pending-ots",
		"--allow-anchor-pending",
		"--offline", // Skip the actual OTS Bitcoin lookup (would hit live network)
		bundlePath,
	)
	t.Logf("verify all-allow output:\n%s", output)

	// With all opt-ins + --offline, exit 0.
	if exitCode != 0 {
		t.Errorf("all-allow run: exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "Verdict: PASS") {
		t.Errorf("all-allow run should produce Verdict: PASS:\n%s", output)
	}
}

// TestVerifyExampleBundleAnchorPendingDefaultFails pins the
// load-bearing V1 fail-secure: without --allow-anchor-pending +
// without --offline, check 7's V1 anchor-pending surfaces as
// FAIL → exit 1. The operator gets explicit V1 deploy-bootstrap
// state visibility.
//
// This test runs with --offline disabled which means check 5 + 6
// also run; check 5 may produce a network-skipped result if the
// test box has no internet, which is acceptable. The load-bearing
// assertion is exit 1 + check 7's V1 diagnostic in the output.
func TestVerifyExampleBundleAnchorPendingDefaultFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	if os.Getenv("LIVE_NETWORK") != "true" {
		t.Skip("skipping live-network smoke (set LIVE_NETWORK=true to run)")
	}
	bundlePath := exampleBundlePath(t)
	output, exitCode := runVerifyCmd(t, "verify", "--allow-dev-key", bundlePath)
	t.Logf("verify default-flags output:\n%s", output)

	if exitCode != 1 {
		t.Errorf("default-flags run: exit code = %d, want 1 (V1 anchor-pending FAIL)", exitCode)
	}
	if !strings.Contains(output, "Check 7 (GitHub anchor cross-check):") {
		t.Errorf("output missing Check 7 line:\n%s", output)
	}
	if !strings.Contains(output, "V1 deploy-bootstrap state") {
		t.Errorf("output should explain V1 deploy-bootstrap state:\n%s", output)
	}
	if !strings.Contains(output, "--allow-anchor-pending") {
		t.Errorf("output should point operator at --allow-anchor-pending opt-in:\n%s", output)
	}
}

// TestVerifyJSONOutputParseable pins the JSON contract: --json
// produces parseable JSON with output_format_version="1" and the
// expected schema fields.
func TestVerifyJSONOutputParseable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	bundlePath := exampleBundlePath(t)
	output, exitCode := runVerifyCmd(t, "verify",
		"--json",
		"--allow-dev-key",
		"--allow-pending-ots",
		"--allow-anchor-pending",
		"--offline",
		bundlePath,
	)
	if exitCode != 0 {
		t.Errorf("JSON all-allow run: exit code = %d, want 0", exitCode)
		t.Logf("output:\n%s", output)
	}

	// Parse the JSON output. The verifier may print warnings to
	// stderr but in our exec.CombinedOutput we get stdout+stderr
	// combined. JSON should be on stdout; locate the leading {
	// to skip any pre-JSON text.
	jsonStart := strings.Index(output, "{")
	if jsonStart < 0 {
		t.Fatalf("output has no JSON object:\n%s", output)
	}
	jsonText := output[jsonStart:]

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonText), &parsed); err != nil {
		t.Fatalf("output is not parseable JSON: %v\n%s", err, jsonText)
	}

	// Schema field assertions.
	if v, _ := parsed["output_format_version"].(string); v != "1" {
		t.Errorf("output_format_version = %v, want '1'", parsed["output_format_version"])
	}
	if v, _ := parsed["verdict"].(string); v != "pass" {
		t.Errorf("verdict = %v, want 'pass'", parsed["verdict"])
	}
	if v, ok := parsed["exit_code"].(float64); !ok || int(v) != 0 {
		t.Errorf("exit_code = %v, want 0", parsed["exit_code"])
	}
	if _, ok := parsed["checks"].([]interface{}); !ok {
		t.Errorf("checks field missing or wrong type: %T", parsed["checks"])
	}
	if _, ok := parsed["summary"].(map[string]interface{}); !ok {
		t.Errorf("summary field missing or wrong type: %T", parsed["summary"])
	}
	if _, ok := parsed["reason"].(string); !ok {
		t.Errorf("reason field missing or wrong type: %T", parsed["reason"])
	}
}

// =============================================================================
// Flag interaction validation (Tenant 3: explicit > inferred)
// =============================================================================

func TestVerifyContradictoryFlagsFailLoudly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	bundlePath := exampleBundlePath(t)
	out, exitCode := runVerifyCmd(t, "verify", "--offline", "--strict-ots", "--allow-dev-key", bundlePath)
	if exitCode != 2 {
		t.Errorf("--offline + --strict-ots: exit code = %d, want 2 (contradictory flags)", exitCode)
	}
	if !strings.Contains(out, "contradictory") {
		t.Errorf("contradictory-flags output should explain why: %s", out)
	}
}

// TestVerifyStrictOTSPlusAllowPendingFailsLoudly pins code-reviewer
// S1 (D5 c3+c4 review): --strict-ots + --allow-pending-ots is the
// analogous contradiction caught by explicit validation.
func TestVerifyStrictOTSPlusAllowPendingFailsLoudly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	bundlePath := exampleBundlePath(t)
	out, exitCode := runVerifyCmd(t, "verify", "--strict-ots", "--allow-pending-ots", "--allow-dev-key", bundlePath)
	if exitCode != 2 {
		t.Errorf("--strict-ots + --allow-pending-ots: exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(out, "contradictory") {
		t.Errorf("contradictory-flags output should explain why: %s", out)
	}
}

// TestVerifyBitcoinRPCURLRejectedAsReserved pins code-reviewer S3
// (D5 c3+c4 review): --bitcoin-rpc-url is reserved infrastructure
// not honored in this build; reject loudly so operators don't
// silently fall through to the default endpoint.
func TestVerifyBitcoinRPCURLRejectedAsReserved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	bundlePath := exampleBundlePath(t)
	out, exitCode := runVerifyCmd(t, "verify", "--bitcoin-rpc-url", "https://my-mempool.example.com", "--allow-dev-key", bundlePath)
	if exitCode != 2 {
		t.Errorf("--bitcoin-rpc-url: exit code = %d, want 2 (reserved flag)", exitCode)
	}
	if !strings.Contains(out, "reserved") {
		t.Errorf("--bitcoin-rpc-url output should explain RESERVED status: %s", out)
	}
}

// =============================================================================
// Invocation-error smoke tests (carried-forward from Session 2)
// =============================================================================

func TestVerifyMissingBundlePathFailsLoudly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	out, exitCode := runVerifyCmd(t, "verify")
	if exitCode != 2 {
		t.Errorf("missing path: exit code = %d, want 2; output:\n%s", exitCode, out)
	}
	if !strings.Contains(out, "bundle path") {
		t.Errorf("missing path: output doesn't mention 'bundle path': %s", out)
	}
}

func TestVerifyNonexistentBundleFailsLoudly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	tmp := t.TempDir()
	out, exitCode := runVerifyCmd(t, "verify", filepath.Join(tmp, "does-not-exist.zip"))
	if exitCode != 2 {
		t.Errorf("nonexistent bundle: exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(out, "load failed") {
		t.Errorf("nonexistent bundle: output doesn't mention 'load failed': %s", out)
	}
}

func TestVerifyFlagsAfterPathSurfaceClearError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping smoke in -short mode")
	}
	out, exitCode := runVerifyCmd(t, "verify", "bundle.zip", "--allow-dev-key")
	if exitCode != 2 {
		t.Errorf("flags after path: exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(out, "flags must precede the bundle path") {
		t.Errorf("flags after path: output doesn't mention 'flags must precede': %s", out)
	}
}

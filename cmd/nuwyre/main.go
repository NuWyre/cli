// Package main is the nuwyre verification CLI entrypoint.
//
// Phase 4 Session 1: --version flag only.
// Phase 4 Session 2: `nuwyre verify <bundle.zip>` subcommand wiring
// checks 1-4 (manifest signature, artifact integrity, hash chain,
// Merkle proof).
// Phase 4 Session 3 D1-D4: checks 5 (OpenTimestamps Bitcoin), 6
// (RFC 3161 timestamp), 7 (GitHub anchor cross-check) added.
// Phase 4 Session 3 D5 (this file's current shape): full main
// wiring — all 7 checks composed via a single registry, CLI flags
// for every documented operator-controlled behavior, output
// formatters (human + JSON), single-decision-point verdict
// aggregation, exit-code semantics per Tenant 5.
//
// **Five-tenant attribution** for D5 main wiring:
//
//   - Tenant 1 (long-term value): exit-code semantics + JSON
//     output_format_version="1" become operational interface for
//     every NuWyre customer + every third-party verifier.
//     Decisions made here outlast every other Phase 4 decision in
//     operator-visible terms.
//   - Tenant 3 (security/privacy): flag-interaction validation
//     surfaces contradictions as usage errors (e.g., --offline +
//     --strict-ots) rather than silent precedence. Default flag
//     state is fail-secure.
//   - Tenant 4 (simplicity): stdlib `flag` package, not urfave/
//     cli/v2 — D5 directive's stop condition explicitly preferred
//     stdlib for this use case. One subcommand, ~8 flags; cli/v2
//     would be over-engineered.
//   - Tenant 5 (customer trust): exit codes operationally honest
//     (0 = verified per operator's flag set; 1 = something failed
//     OR something is incomplete that operator hasn't explicitly
//     opted INTO; 2 = invocation error). Flag combinations cannot
//     produce silent verification weakening.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/checks"
	"github.com/nuwyre/cli/internal/output"
)

// Version is the CLI version string. Session 4 will inject this via
// -ldflags="-X main.Version=$(git describe --tags)" at release-build
// time; pre-release dev builds carry "0.1.0-pre" verbatim.
var Version = "0.1.0-pre"

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "--version", "-version", "-v":
		fmt.Printf("nuwyre %s\n", Version)
		return
	case "--help", "-help", "-h":
		printUsage(os.Stdout)
		return
	default:
		// Allow legacy `nuwyre --version` (single flag, no subcommand)
		// via the standard flag package.
		versionFlag := flag.Bool("version", false, "print version and exit")
		flag.CommandLine.SetOutput(os.Stderr)
		if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
			printUsage(os.Stderr)
			os.Exit(2)
		}
		if *versionFlag {
			fmt.Printf("nuwyre %s\n", Version)
			return
		}
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "nuwyre %s — NuWyre evidence bundle verifier\n\n", Version)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  nuwyre verify [flags] <bundle.zip>")
	fmt.Fprintln(w, "  nuwyre --version")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Verify flags:")
	fmt.Fprintln(w, "  --offline               Skip checks 5-7 (Bitcoin, RFC 3161, GitHub); exit 0")
	fmt.Fprintln(w, "  --strict-ots            FAIL on pending OTS receipts (default: WARN)")
	fmt.Fprintln(w, "  --allow-pending-ots     Treat pending OTS receipts as PASS (folds WARN into PASS)")
	fmt.Fprintln(w, "  --allow-anchor-pending  Treat V1 anchor-pending GitHub anchors as PASS (folds WARN into PASS)")
	fmt.Fprintln(w, "  --allow-dev-key         Accept issuer-dev-v1 for example-demo bundles")
	fmt.Fprintln(w, "  --bitcoin-rpc-url URL   (RESERVED — not honored in this build; rerun without)")
	fmt.Fprintln(w, "  --json                  Emit machine-readable JSON output")
	fmt.Fprintln(w, "  --no-color              Disable ANSI color in human output")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Exit codes:")
	fmt.Fprintln(w, "  0  All checks PASS (or SKIPPED with --offline)")
	fmt.Fprintln(w, "  1  At least one check FAILED, or PARTIAL VERIFICATION (warns/skips without opt-in)")
	fmt.Fprintln(w, "  2  Invocation error (missing path, unknown flag, bundle won't load, contradictory flags)")
}

// runVerify implements the `nuwyre verify [flags] <bundle.zip>`
// subcommand. Returns the process exit code.
//
// Exit codes (Tenant 5: customers reading CI output trust exit
// codes; ambiguity produces silent acceptance of unverified
// bundles):
//
//	0  All checks PASS or SKIPPED-with---offline.
//	1  At least one FAIL, or at least one WARN-without-corresponding-
//	   allow-flag, or at least one SKIPPED-without-offline. Reported
//	   as VerdictFail (any check failed) OR VerdictPartialVerification
//	   (warns/skips without opt-in).
//	2  Invocation error: missing/extra positional arg, unknown flag,
//	   bundle won't load, contradictory flag combination.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		offline            = fs.Bool("offline", false, "skip checks 5-7 (network)")
		strictOTS          = fs.Bool("strict-ots", false, "FAIL on pending OTS")
		allowPendingOTS    = fs.Bool("allow-pending-ots", false, "treat pending OTS as PASS")
		allowAnchorPending = fs.Bool("allow-anchor-pending", false, "treat V1 anchor-pending as PASS")
		allowDevKey        = fs.Bool("allow-dev-key", false, "accept issuer-dev-v1")
		bitcoinRPCURL      = fs.String("bitcoin-rpc-url", "", "override default Bitcoin endpoint")
		jsonOut            = fs.Bool("json", false, "emit machine-readable JSON")
		noColor            = fs.Bool("no-color", false, "disable ANSI color")
	)

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError already printed usage; just exit.
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		// Carried-forward H1 from Session 2 commit-6: detect flag
		// placed AFTER the bundle path so the operator gets a
		// specific error rather than the generic "exactly one
		// bundle path required."
		hasFlagAfterPath := false
		for i := 1; i < len(rest); i++ {
			if strings.HasPrefix(rest[i], "-") {
				hasFlagAfterPath = true
				break
			}
		}
		if hasFlagAfterPath {
			fmt.Fprintln(os.Stderr, "verify: flags must precede the bundle path")
			fmt.Fprintln(os.Stderr, "usage: nuwyre verify [flags] <bundle.zip>")
			fmt.Fprintf(os.Stderr, "got: %v\n", rest)
		} else {
			fmt.Fprintln(os.Stderr, "verify: exactly one bundle path required")
			fmt.Fprintln(os.Stderr, "usage: nuwyre verify [flags] <bundle.zip>")
		}
		return 2
	}
	bundlePath := rest[0]

	// Flag-interaction validation per the D5 directive's Pinned
	// Decision: explicit > inferred for security-relevant flag
	// combinations. Tenant 3.
	if *offline && *strictOTS {
		fmt.Fprintln(os.Stderr, "verify: --offline + --strict-ots is contradictory:")
		fmt.Fprintln(os.Stderr, "  --offline skips check 5 entirely (network disabled)")
		fmt.Fprintln(os.Stderr, "  --strict-ots requires check 5 to run + treat pending as FAIL")
		fmt.Fprintln(os.Stderr, "Pass one or the other, not both.")
		return 2
	}
	// Code-reviewer S1 (D5 c3+c4 review): --strict-ots produces
	// FAIL on pending OTS; --allow-pending-ots folds pending WARN
	// into PASS. Strict makes pending → FAIL, so the WARN branch
	// the allow-flag would fold never fires — the operator who
	// passes both expecting allow-pending to win gets an
	// unexplained FAIL. Reject explicitly (same Tenant 3 principle
	// as --offline + --strict-ots).
	if *strictOTS && *allowPendingOTS {
		fmt.Fprintln(os.Stderr, "verify: --strict-ots + --allow-pending-ots is contradictory:")
		fmt.Fprintln(os.Stderr, "  --strict-ots requires Bitcoin-attested OTS receipts (pending → FAIL)")
		fmt.Fprintln(os.Stderr, "  --allow-pending-ots opts pending receipts INTO PASS")
		fmt.Fprintln(os.Stderr, "Pass one or the other, not both.")
		return 2
	}
	// Code-reviewer S3 (D5 c3+c4 review): --bitcoin-rpc-url is
	// reserved infrastructure but check 5 doesn't read it yet (the
	// adapter uses the default Esplora pair). Reject loudly rather
	// than silently using the default — an operator who passed a
	// custom endpoint expecting it to be honored MUST get an
	// explicit signal, not silent fall-through to the default.
	// Tenant 5: operator trust. Wire-through to check 5 is deferred
	// to a follow-up commit.
	// Phase 7.E session 114 closure (crypto-int HIGH V1 from comprehensive
	// code review): the reservation gate fires unconditionally when
	// *bitcoinRPCURL != "". An operator passing --offline + --bitcoin-rpc-url
	// is correctly skipping check 5 (so the URL was harmless anyway) but
	// is wrongly rejected. Gate now scoped to !*offline. Symmetric with
	// the existing --strict-ots / --allow-pending-ots interaction
	// (both contradict each other only when network paths are active).
	if *bitcoinRPCURL != "" && !*offline {
		fmt.Fprintln(os.Stderr, "verify: --bitcoin-rpc-url is reserved but not honored in this build")
		fmt.Fprintln(os.Stderr, "  the adapter will be wired to read this option in a follow-up commit")
		fmt.Fprintln(os.Stderr, "  rerun without the flag to use the default Esplora endpoint pair, OR pass --offline to skip check 5 entirely")
		return 2
	}

	// Construct CheckOptions from flag state.
	opts := checks.CheckOptions{
		Offline:            *offline,
		StrictOTS:          *strictOTS,
		AllowPendingOTS:    *allowPendingOTS,
		AllowAnchorPending: *allowAnchorPending,
		AllowDevKey:        *allowDevKey,
		BitcoinRPCURL:      *bitcoinRPCURL,
	}

	// Load bundle. Bundle-load errors are exit 2 (invocation
	// error) — the operator gave us a path that doesn't exist or
	// doesn't parse; they need to fix the input, not the bundle.
	b, err := bundle.Load(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load failed: %v\n", err)
		return 2
	}

	// Build the check registry. The order is the spec §14 order
	// (1, 2, 3, 4, 5, 6, 7) which the formatters render in the
	// same order. Constructing checks 5+ that need network
	// infrastructure happens here so a bundle-load-fail short-
	// circuits before any network setup.
	registry, err := buildCheckRegistry(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: failed to construct check registry: %v\n", err)
		return 2
	}

	// Run checks. RunChecks recovers panics defensively and emits
	// per-check DurationMS. Sort by CheckID for canonical spec §14.1
	// output ordering (Check 8 runs after Check 2 in registry order
	// but reports as check_id=8 after the sort).
	results, _ := checks.RunChecks(b, opts, registry...)
	results = checks.SortByCheckID(results)

	// Single decision point for the overall verdict.
	verdict := checks.AggregateVerdict(results, opts)

	// Format output.
	var formatter output.Formatter
	if *jsonOut {
		formatter = output.NewJSONFormatter(true)
	} else {
		// Color = NOT --no-color AND NOT NO_COLOR env var (per
		// no-color.org convention) AND stdout is a TTY (Session 5
		// detection enhancement; for D5, default to color-on
		// when --no-color isn't passed and NO_COLOR isn't set).
		colorEnabled := !*noColor && os.Getenv("NO_COLOR") == ""
		formatter = output.NewHumanFormatter(colorEnabled)
	}
	// spec-conformance C1 closure 2026-05-22: thread bundle_format into
	// JSON output so v2 bundles emit output_format_version="2" per spec
	// §14.1 line 1632. HumanFormatter is bundle-format-agnostic.
	if jsonF, ok := formatter.(*output.JSONFormatter); ok {
		fmt.Print(jsonF.FormatResultsForBundle(results, verdict, b.Manifest.BundleFormat))
	} else {
		fmt.Print(formatter.FormatResults(results, verdict))
	}

	return verdict.ExitCode
}

// buildCheckRegistry constructs the seven CheckRunner instances in
// spec §14 order. Returns the registry slice + an error if any
// check's construction fails (currently only check 6's TSAPool can
// fail at construction).
//
// Tenant 4 (simplicity): single function builds the full registry;
// no per-check construction scattered across runVerify. A future
// addition (e.g., a Phase 5 check 8) drops in here.
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
	// before Check 3 because Check 3's ephemeral-sessions topology
	// branch reads the session_id → ephemeral_pubkey map Check 8
	// populates on bundle.EphemeralPubkeyByID. RunChecks sorts the
	// returned results by CheckID so the report-layer order is
	// canonical (1, 2, 3, 4, 5, 6, 7, 8, 9) per spec §14.1.
	//
	// Phase 6.2.C session 70: Check 9 (audit-log-merkle) added after
	// Check 7. Check 9 is conditionally executed via bundle_type gate
	// inside its Run() method (Skipped for non-audit-log-export
	// bundles). The unconditional registry registration mirrors the
	// Check 8 pattern: presence in the registry is the spec §14
	// completeness invariant; runtime applicability is the check's
	// own responsibility.
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

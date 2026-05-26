// Package output formats verification reports. Phase 4 Session 3 D5
// populates this package with two stable customer-facing formats:
//
//   - HumanFormatter — terminal output with optional ANSI color
//     (gated by TTY detection + NO_COLOR env-var convention). The
//     output is the operator-readable summary surfaced when the CLI
//     runs interactively or in CI logs.
//
//   - JSONFormatter — machine-readable output for CI integration.
//     Strict-allowlist schema versioned by output_format_version.
//     Adding a field requires bumping the version (Tenant 1: CI
//     integrations are durable; the schema contract outlasts the
//     implementation).
//
// **Five-tenant attribution.** Output is the operator-facing surface;
// Tenant 5 (customer trust) + Tenant 4 (consistent format across
// checks, no per-check drift) drive the design. Tenant 2 (quality)
// requires deterministic output so the same input bytes always
// produce the same output bytes — the smoke test asserts this.
//
// **Information-leakage discipline is owned by the checks**, not
// the formatters. The formatters surface check-emitted error +
// warning text verbatim — they don't redact, truncate, or rewrite.
// Per RunChecks' panic-recovery contract (checks.go runWithRecover),
// a panic surfaces as a Fail check with debug.Stack() in the error
// text; that stack includes file paths and goroutine info. Operators
// see this in both human and JSON output, intentionally — a panic
// is a verifier defect, not a bundle defect, and the stack trace
// is the actionable diagnostic.
package output

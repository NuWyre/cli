# Bundle Format v1 — Conformance Fixture Suite

**Status:** CANONICAL. Standards-track conformance fixtures for `bundle-format-v1`. First green CI run landed at commit `099d476` on 2026-05-14 (workflow: `.github/workflows/spec-conformance.yml`; jobs: `conformance: ts` + `conformance: go-native` + `conformance: go-wasm` + `conformance: divergence check` all PASS). The NEAR-CANONICAL banner previously gating on first green CI is removed at that landing.

**Conformance substrate** (Phase 5.5 Session 5.5.1C; canonical per the v1.0.7 spec amendment at `docs/spec/bundle-format-v1.md`):

- Six normative subsections at `docs/spec/bundle-format-v1.md` §14.1-§14.6 (JSONOutput shape; verdict enum; per-check status enum; warn-fold + `warn_category` field; flag set; check slug enum) reference this fixtures directory as the conformance contract.
- Three reference implementations pass 10/10 fixtures structurally — Go-native (`apps/cli/internal/checks/conformance_test.go`), TS (`packages/example-bundle/scripts/conformance-fixtures/validate-ts.ts` subprocess-pattern validator emitting JSONOutput shape; the historical TS verifier at `packages/example-bundle/scripts/verify-bundle.ts` is preserved as-is for the marketing demo terminal snapshot test), and Go-WASM (`packages/example-bundle/scripts/conformance-fixtures/validate-wasm.ts` Node-host loader).
- Three fixtures (`forged-ots`, `forged-rfc3161`, `forged-rfc3161-chain`) pin the V1 verifier's current limitations as the expected status; the `tsa_surplus` warn_category surfaces on `valid-bundle`. Phase 5+ verifier-tightening tracked as a separate bookmark; per-fixture `tamper.json` `notes` arrays document the path.
- `mismatched-github` declares `offline: false` per §14.5; CI runners have network access. Offline-variant fixtures tracked as a separate bookmark.

This directory contains a fixed suite of **27 evidence bundles** (14 v1 + 13 v2) + their expected verification results. A conformant verifier — written in any language, by any third party — MUST produce the per-check verdicts declared in each fixture's `results.json` when run against that fixture's `bundle.zip` with the declared `verification_options`.

**v2.0.0 final fixtures landed at Phase 7.F.4 promotion gate session 102 (2026-05-22)**: 1 valid-v2-bundle + 5 sig-tamper variants (`tampered-ed25519-sig`, `tampered-ml-dsa-sig`, `tampered-both-sigs`, `wrong-pq-key-id`, `malformed-pq-sig-length`) + 5 structural-tamper variants (`manifest-signing-mismatch`, `swapped-signature-slots`, `mixed-environment-keys`, `dev-keys-claiming-prod`, `extra-file-smuggled`) + 1 `valid-v2-audit-log-export` + 1 `dev-keys-claiming-operator-only-audit-log` = 13 v2 fixtures. All produced byte-deterministically by 5 generator scripts at `packages/example-bundle/scripts/conformance-fixtures/v2-*-generator.ts`. The TS writer (`packages/evidence/src/generate-bundle.ts` v2 dispatch + `generate-audit-log-bundle.ts` v2 dispatch) + Go reference verifier (`apps/cli/internal/checks/check1_v2_dual_sig.go`) + Go-WASM verifier (`apps/cli/web/nuwyre.wasm`) all produce structurally-identical `results.json` output per the 27-fixture conformance contract.

The fixtures are the **conformance contract** between the spec and any implementing verifier. The reference NuWyre implementations (TypeScript verifier at `packages/evidence`, native Go CLI at `apps/cli`, and Go-WASM verifier at `apps/cli/cmd/nuwyre-wasm`) all consume this suite via the cross-implementation divergence check in `.github/workflows/spec-conformance.yml` (Phase 5.5 Session 5.5.1C).

## Why a conformance fixture suite

Per [bundle-format-v1.md §14 Aggregate semantics](../../bundle-format-v1.md), a verifier's overall verdict depends on:

1. The bundle's bytes (every artifact's SHA-256, cryptographic chain reconstruction, merkle proof verification, etc.)
2. The verifier's flag state (`--offline`, `--allow-pending-ots`, `--allow-anchor-pending`, `--allow-dev-key`)
3. The current state of external anchors (Bitcoin chain, RFC 3161 TSA certificate validity, GitHub anchor commits)

A conformance suite needs to pin the bundle bytes (1) and the flag state (2), and either pin or skip the external state (3). This suite does both:

- Per-fixture `bundle.zip` is committed verbatim — byte-stable across reproductions.
- Per-fixture `results.json` declares the expected verdict structure (verdict, exit_code, per-check status + slug + ID, summary counts).
- Per-fixture `verification_options.json` declares the CLI flag set that produces the expected verdict.
- Checks 5 (OpenTimestamps Bitcoin), 6 (RFC 3161 TSA), and 7 (GitHub anchor) require network access. Conformance runs invoke `--offline` to skip them when the fixture's `verification_options.json` declares `offline: true`, OR run them online when the fixture declares `offline: false`. Each fixture's `results.json` declares the expected per-check status under the declared options.

## Fixtures

The table below describes each fixture's tamper + the **actual V1 verifier behavior** (captured against the reference Go-native CLI 2026-05-13). Each fixture's `results.json` declares the structural shape a conformant verifier MUST produce.

| # | Fixture | Tamper | Verdict | Failing check(s) |
|---|---|---|---|---|
| 1 | `valid-bundle/` | (none — verbatim base) | `partial_verification` | (no fails; check 6 emits surplus-TSAs warn that no flag folds) |
| 2 | `tampered-event/` | event_hash hex byte flipped (last char) | `fail` | check 2 + check 3 + check 4 |
| 3 | `tampered-audio/` | audio file byte XOR'd at midpoint | `fail` | check 2 |
| 4 | `swapped-event/` | two adjacent same-session events swapped in file order | `fail` | check 2 only (V1 check 3 walks chains via prev_event_hash, not file-line order) |
| 5 | `forged-merkle/` | merkle_proofs.json proof sibling hex byte flipped | `fail` | check 2 + check 4 |
| 6 | `forged-ots/` | OTS receipt byte XOR'd past magic header | `fail` | check 2 only (V1 doesn't cryptographically verify pending-state OTS) |
| 7 | `forged-rfc3161/` | one .tsr token byte XOR'd | `fail` | check 2 only (3-of-3 TSAs verified; 1 invalidated still leaves ≥2 verifying per spec §11.1) |
| 8 | `forged-rfc3161-chain/` | one .chain.pem character flipped within base64 alphabet | `fail` | check 2 only (same multi-TSA tolerance) |
| 9 | `mismatched-github/` | github_anchors/<date>.json mirror_status mutated to "anchored" with zeroed commit_sha | `fail` | check 2 + check 7 |
| 10 | `pending-ots/` | (none — verbatim base; verification_options omits allow_pending_ots) | `partial_verification` | (no fails; check 5 + check 6 both surface unfolded warns) |
| 11 | `cross-lang-ephemeral.json` | (cross-language primitive fixture; not a bundle) | (n/a — fixture validates HKDF-SHA-256 + Ed25519 keypair derivation byte-equivalence between TS reference impl `apps/api/src/lib/__tests__/session-signing.test.ts` and Go reference impl `apps/cli/internal/checks/check8_ephemeral_session_test.go`) | (Phase 6.1 v1.0.9 §6.5 ephemeral-session protocol fixture) |
| 12 | `valid-audit-log-export/` | (none — verbatim base) | `partial_verification` | (no fails; check 1 dev_key warn + check 5 pending_ots warn + check 7 anchor_pending warn; Check 9 audit-log-merkle PASS) |
| 13 | `tampered-audit-log-event/` | first audit log event's stored forensic.event_hash last hex char flipped | `fail` | check 2 + check 3 + check 4 + check 9 |
| 14 | `audit-log-missing-events/` | last line of audit_log_events.jsonl removed entirely | `fail` | check 2 + check 3 + check 4 + check 9 |
| 15 | `forged-audit-log-merkle-subtree/` | first proof's first sibling_hash last hex char flipped in audit_log_subtree.json | `fail` | check 2 + check 4 + check 9 |

**Fixtures 12-15 status (Phase 6.2.A 2026-05-15)**: results.json + verification_options.json + tamper.json metadata files shipped at v1.0.10 spec-amendment session (Phase 6.2.A); bundle.zip generation deferred to Phase 6.2.B implementation session per operator Decision 5 (minimum viable scope at 6.2.A; full bundle.zip generation requires `packages/evidence/src/audit-log-export.ts` writer pipeline which lands at 6.2.B). Each fixture directory's results.json declares the verifier conformance contract; when bundle.zip ships at 6.2.B, the reference Go-native verifier MUST emit JSONOutput matching the declared shape.

**v1.0.11 amendment header (Phase 6.2.A Tier B first-fix-up batch closure 2026-05-15).** The 4 v1.0.10 fixture directories' metadata files were authored against the v1.0.10 spec text. The v1.0.11 follow-up amendment pins the audit_log_subtree.json proof-step field names to `{"position": "left|right", "sibling": "<hex>"}` (matching §8 + §8.2 walker verbatim per F1 closure); pins `manifest.audit_log_event_count` field per F2 closure; pins the dual-subtree composition byte ordering MUST-language per F3 closure; pins the audit log subtree leaf ordering to `forensic.sequence_number` ascending per F9 closure; pins the operator-only `organization_id` sentinel to the all-zero RFC 4122 UUID per F8 closure; pins the audit-log event canonical content_hash derivation per F4 closure. The fixtures' results.json + tamper.json metadata files remain UNCHANGED at v1.0.11 (no shape modification needed; the fixture-asserted contracts were already aligned to F1/F2/etc. per Standards-Track Posture §3 fixtures-are-the-standard — the spec text caught up). The bundle.zip generation at Phase 6.2.B will encode the v1.0.11-pinned field names + ordering + sentinels per the reconciled spec text; cross-language byte-equivalence asserted at Phase 6.2.B 3-way conformance CI.

**Naming convention update at v1.0.10**: prior fixtures (1-10) use `<verb>-<noun>/` directory naming (e.g., `tampered-event/`, `forged-merkle/`); v1.0.10 fixtures (12-15) use `<verb>-audit-log-<noun>/` to disambiguate audit-log-export tamper variants from primary-event tamper variants. Cross-language fixture (11) is a single JSON file rather than a bundle directory because it validates protocol-level byte-equivalence rather than full bundle verification flow.

### Notable V1 verifier-baseline observations

The conformance suite documents the V1 verifier behavior exactly as-built. Several of the per-check outcomes are surprising at first glance; the fixtures pin them down so future verifier tightening is an intentional, reviewed change rather than silent drift:

1. **valid-bundle's overall verdict is `partial_verification`, not `pass`.** The base bundle has 3 distinct TSAs verified. Check 6 (RFC 3161) treats 3-of-3 as "extra confirmation beyond the spec §11.1 ≥2-of-3 requirement" and emits a warn framed as "operationally desirable surplus." No opt-in flag folds this warn into pass; the overall verdict is therefore `partial_verification` (exit code 1). Phase 5+ verifier may add a `--allow-tsa-surplus` flag OR the bundle generator may emit only 2 TSAs.

2. **swapped-event does NOT fail check 3.** V1 check 3 (hash-chain) walks each session's chain by following `prev_event_hash` links from event to event — it does NOT enforce that events appear in chronological / sequence_number order in the file. A swap of two adjacent same-session events leaves the chain links structurally intact (just discovered in a different file order); check 3 passes. Only check 2 (file SHA-256 mismatch) fails on this fixture. A future verifier tightening could enforce file-line ordering; this fixture would then need an updated `results.json`.

3. **forged-ots does NOT fail check 5.** The base bundle's OTS receipt is in pending-Bitcoin-confirmation state (V1 example-demo norm). V1 check 5 does NOT cryptographically verify pending-state receipts — it surfaces the pending state as a warn and accepts the file structurally. Byte-level mutations to the OTS receipt are caught by check 2 (file SHA mismatch) but not by check 5. A future verifier that runs OTS calendar-attestation cross-checks on pending receipts WOULD catch this tamper.

4. **forged-rfc3161 and forged-rfc3161-chain do NOT fail check 6.** The base bundle has 3 distinct TSAs verified. Spec §11.1 mandates ≥2-of-3; invalidating ONE TSA leaves ≥2 verifying, which satisfies the requirement. Check 6 still passes structurally (with the surplus-warn becoming a 2-of-3-min-met-warn, but still warn-not-fail). A bundle with only 2 TSAs would fail check 6 under these tampers. The fixtures document the multi-TSA tolerance explicitly.

5. **All fixtures emit check 1 as warn (dev-key informational), folded into pass via `--allow-dev-key`.** Spec §5 mandates this warn on every dev-signed bundle even when the operator opts INTO accepting dev-signed bundles. The warn surfaces in the per-check output (for operator visibility) and folds into the passed count via `warns_opted_into_pass`.

These observations are why the conformance contract compares STRUCTURAL fields (verdict, exit_code, per-check check_id + check_slug + status, summary counts) rather than reasoning about "this should fail because the tamper is forensic-equivalent to ...". The verifier is the reference; each fixture's `results.json` is the captured shape; conformance is bytes-for-bytes structural identity.

The `tamper.json` for each tampered fixture carries an `expected_failures` list AND (where the V1 baseline is surprising) a `notes` array documenting what the V1 verifier does NOT detect, with a pointer to the Phase 5+ tightening that could surface the case.

## Per-fixture layout

Each fixture is a directory containing:

```
docs/spec/fixtures/bundle-format-v1/<fixture-name>/
├── bundle.zip                 — the artifact under test
├── results.json               — expected verifier output (matches output.JSONOutput shape)
├── verification_options.json  — the verification flags used
└── tamper.json                — for tampered variants: bytewise description of the tamper
                                  (omitted for valid-bundle + pending-ots which have no tamper)
```

`results.json` follows the same JSON shape as the native CLI's `--json` output (see `apps/cli/internal/output/json.go` — `OutputFormatVersion = "1"`). Each conformant verifier produces this shape directly; the divergence check in CI compares structural fields (verdict, exit_code, per-check status + check_id + check_slug, summary counts) and ignores text-dependent fields (per-check errors[], warnings[], reason — these may differ between implementations).

`results.schema.json` at this directory documents the structural shape that the divergence check compares against.

## Verification options

The `verification_options.json` per fixture is a JSON object with these fields (all default to `false`):

```json
{
  "offline":              boolean  — skip checks 5/6/7 (no network)
  "strict_ots":           boolean  — FAIL on pending OTS receipts (default: WARN)
  "allow_pending_ots":    boolean  — fold pending-OTS WARN into PASS
  "allow_anchor_pending": boolean  — fold V1 anchor-pending WARN into PASS
  "allow_dev_key":        boolean  — accept issuer-dev-v1 for example-demo bundles
}
```

The base bundle (`valid-bundle`) is `bundle_type = "example-demo"` and uses the `issuer-dev-v1` Ed25519 dev key — so `allow_dev_key: true` is required for check 1 to pass. The base bundle's OTS receipt is in pending-Bitcoin-confirmation state (V1 example-demo state) — so `allow_pending_ots: true` is required for check 5 to pass without partial verification. The base bundle's GitHub anchor is `anchor-pending` (no public NuWyre/anchors repo at the demo day) — so `allow_anchor_pending: true` is required for check 7.

## Reproducibility

A third party can reproduce the fixtures from source by running:

```bash
pnpm --filter @nuwyre/example-bundle generate-conformance-fixtures
```

The script reads the committed example bundle at `apps/marketing/public/examples/nuwyre_export_cypress-derm_2026-04-22.zip` and produces all 10 fixture directories deterministically. Source: `packages/example-bundle/scripts/conformance-fixtures/build.ts`.

The committed bundle.zip files in this directory are the canonical conformance artifacts. CI consumes them verbatim — the build script regenerates the same bytes from the same input, but is not invoked in CI.

## Cross-implementation conformance contract

A conformant `bundle-format-v1` verifier MUST:

1. For each fixture, run verification with the fixture's `verification_options.json` flags.
2. Produce an output structurally matching the fixture's `results.json`:
   - Same `verdict` (`pass` | `fail` | `partial_verification`)
   - Same `exit_code` (0 or 1)
   - For each check listed in `results.json.checks[]`, produce a check with the same `check_id`, `check_slug`, and `status` (`pass` | `fail` | `warn` | `skipped`)
   - Same `summary` per-bucket counts (passed / failed / warned / skipped / warns_opted_into_pass)
3. NOT match exact `errors[]`, `warnings[]`, or `reason` text — these are implementation-localized natural-language strings.

A divergence in any structural field (verdict, exit_code, per-check status, summary counts) is a conformance failure.

## See also

- [bundle-format-v1.md](../../bundle-format-v1.md) — the canonical spec
- [event-v1.schema.json](../../event-v1.schema.json) — the event schema
- `apps/cli/internal/output/json.go` — the reference JSON output format
- `.github/workflows/spec-conformance.yml` (Phase 5.5 Session 5.5.1C) — the 3-way conformance CI job

## Provenance

- Suite created: Phase 5.5 Session 5.5.1B (2026-05-13), commit (TBD).
- Base bundle: `apps/marketing/public/examples/nuwyre_export_cypress-derm_2026-04-22.zip` (committed May 12, 2026).
- Spec version: bundle-format-v1.md §14 aggregate semantics + output.JSONOutput v1.

Six tenants framing: T1 long-term value (the conformance contract outlasts every individual verifier implementation), T2 quality/reliability (fixtures pin the conformance contract byte-for-byte), T5 customer trust (any third party can independently produce a conformant verifier from the spec + fixtures + ~200 LOC, per Standards-Track Posture §5).

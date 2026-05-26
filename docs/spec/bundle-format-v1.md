<!-- doclinkcheck:ignore-file -->
<!-- Rationale: this spec doc contains many citations to paths
     relative to specific contexts (e.g., `output/json.go:185`
     relative to apps/cli/internal/checks/; `audit-log-missing-
     events/tamper.json` relative to docs/spec/fixtures/bundle-
     format-v1/; example-bundle internal paths like
     `rfc3161_receipts/2026-04-22__freetsa.tsr`). The doc-link-
     checker V1 only validates repo-rooted paths. Extending the
     checker to support context-relative path resolution is a
     follow-up enhancement (see BACKLOG). Until then this file is
     deliberately exempted; the spec-conformance reviewer +
     external-implementer simulation discipline are the relying
     verification mechanisms for this doc's citations. -->
# NuWyre Bundle Format Specification — v1 + v2.0.1 (multi-version)

**Format identifiers:** `nuwyre-bundle/v1` (legacy; single Ed25519 signature; locked) AND `nuwyre-bundle/v2` (current; ML-DSA-65 + Ed25519 dual signature; **locked at v2.0.0** as of Phase 7.F.4 promotion gate session 102 + **v2.0.1 additive amendment** at Phase 7.F.5 session 103 (informative §18.3.1 library-API-shape registry; no on-wire byte change) — 27/27 conformance fixtures PASS + Tier A 5-reviewer pass closed with 0 CRITICAL / 6 HIGH / 13 MEDIUM all closed inline at promotion + Tier B 3-reviewer pass closed at v2.0.1; cumulative reviewer-protocol track preserved at 0 shipped defects)
**Status:** v1 LOCKED across the v1.0.x amendment series; **v2.0.0 LOCKED + v2.0.1 additive** as of 2026-05-22 (Phase 7.F.4 promotion gate session 102 + Phase 7.F.5 KAT regeneration session 103; build-plan v3.1.55 + v3.1.56) — promotion criteria met: cross-language byte-equivalence verified across TS writer (Phase 7.F.2) + Go-native verifier (Phase 7.F.3) + Go-WASM verifier (Phase 7.F.3); 27-fixture conformance suite (14 v1 + 13 v2) at `docs/spec/fixtures/bundle-format-v1/` produces declared output across all three reference verifiers; Tier A 5-reviewer pass (spec-conformance + crypto-integrity + code-reviewer + security-auditor + performance-auditor) closed with 0 CRITICAL findings + 6 HIGH findings closed inline pre-promotion; recurring-defect-class memory ratcheted n=21+ → n=25+ during this session (4 new named instances across all three procurement-narrative directions). Per Phase 7.F.1 build-plan v3.1.54 §"Phase 7.F" override of `feedback_pre_customer_revenue_priority`: the v2.0.0 amendment exists because operator chose to invest pre-customer engineering time in a sticky cryptographic decision rather than defer it; the 9 reviewer-discipline points (§18 below) are load-bearing for byte-equivalence across implementations and were empirically verified at promotion.
**Last revised:** 2026-05-22 (v2.0.1; build-plan v3.1.56; Phase 7.F.5 KAT regeneration session 103 — §18.3.1 library-API-shape registry additive amendment)
**Reference implementation:** `packages/example-bundle/` (Phase 2 example bundle generator) + 5 v2 fixture generators at `packages/example-bundle/scripts/conformance-fixtures/v2-*-generator.ts`. v1 + v2 reference TS writers at `packages/evidence` (`generate-bundle.ts` v1/v2 dispatch + `generate-audit-log-bundle.ts` v1/v2 dispatch + `ml-dsa-65.ts` primitives). v1 + v2 reference Go verifier at `apps/cli/internal/checks/` (`check1_signature.go` v1/v2 dispatch + `check1_v2_dual_sig.go` v2 implementation) + WASM build at `apps/cli/web/nuwyre.wasm`. **File-naming pragmatism**: this spec doc retains the `bundle-format-v1.md` filename (rather than splitting to a sibling `bundle-format-v2.md` per SPEC_GOVERNANCE.md §3.2 default directive) because v1 + v2 are best read as a single multi-version contract; the SPEC_GOVERNANCE.md §3.2 file-naming directive is reconciled in favor of multi-version-in-single-file at Phase 7.F.7 by operator decision (the file-rename cost outweighs the marginal external-implementer benefit). v1 prose is preserved verbatim throughout; v2 amendment prose is interleaved at §§2, 4, 5, 14, 15 + the new §18 "Bundle format v2.0.0 amendment" section consolidates the full dual-sig contract.

## Revision history

- **2026-05-22 (v2.0.1)** — **Additive amendment** per Phase 7.F.5 session 103 (build-plan v3.1.56). New §18.3.1 "Library API call shapes (informative registry)" closing heavy-bookmark `spec-conformance H5` (library API shape pinning, originally bookmarked at v2.0.0-rc1 amendment session 2026-05-21 for Phase 7.F.5 closure). Registry enumerates cloudflare/circl `mldsa65.SignTo(sk, msg, nil, false, sig)` Go API + `@noble/post-quantum` `ml_dsa65.sign(M, sk, {extraEntropy: false})` TS API as the per-library deterministic-variant invocation patterns; KAT-V2-2 at `apps/cli/internal/checks/testdata/v2_dual_sig_kats_v1.json` is the empirical-proof artifact pinning byte-equivalence. **Pure informative additive amendment** — no on-wire byte change; cross-language byte-equivalence contract unchanged; v2.0.0 verifiers continue to operate unchanged. First v2.0.1 additive after v2.0.0 LOCKED at Phase 7.F.4 session 102; rehearses SPEC_GOVERNANCE.md §3.1 third-dot additive cadence. **Session 103 also lands**: KAT vector regeneration (3 vectors: ML-DSA-65 keygen-from-seed + deterministic sign + Ed25519 deterministic sign) at `apps/cli/internal/checks/testdata/v2_dual_sig_kats_v1.json` + TS source-of-truth test at `packages/evidence/src/v2-dual-sig-kats.test.ts` + Go consumer test at `apps/cli/internal/checks/v2_dual_sig_kats_test.go`. Cross-language byte-equivalence now BYTE-PRECISE EMPIRICALLY VERIFIED at the primitive layer (not just structurally via 27-fixture conformance). Tier B 3-reviewer pass (spec-conformance + crypto-integrity + code-reviewer) closed: 0 CRITICAL + 1 HIGH + 6 MEDIUM (5 inline + 4 heavy-bookmarked) + 7 LOW (3 inline + remaining heavy-bookmarked).

- **2026-05-22 (v2.0.0 final)** — **PROMOTION from v2.0.0-rc1 to v2.0.0 final** per Phase 7.F.4 promotion gate session 102 (build-plan v3.1.55). Promotion criteria met per SPEC_GOVERNANCE.md §3.2: (a) cross-language byte-equivalence empirically verified across TS writer + Go-native verifier + Go-WASM verifier; (b) all PLANNED conformance fixtures shipped — 27/27 (14 v1 + 13 v2: 1 valid-v2-bundle + 5 sig-tampers + 5 structural-tampers + 1 valid-v2-audit-log-export + 1 dev-keys-claiming-operator-only-audit-log) producing declared `results.json` output across all three reference verifiers; (c) Tier A 5-reviewer pass (spec-conformance + crypto-integrity + code-reviewer + security-auditor + performance-auditor; crypto-int LOAD-BEARING per dual-sig promotion gate per Phase 7.C.B + 7.F.3 precedent) closed with 0 CRITICAL / 6 HIGH / 13 MEDIUM / 12 LOW findings; 6 HIGH + 4 MEDIUM closed inline pre-promotion; (d) reference impl TS writer + Go verifier + WASM shipped at sessions 97-101; (e) "PLANNED" markers removed from §14.4. **Substantive session 102 inline closures**: n=20 (placeholder constant drift v1↔v2 path; `check1_v2_dual_sig.go:309-320`) + n=21 (spec §18.6 audit-log clause `dev_key` → fail elevation; `check1_v2_dual_sig.go:444-470`) + n=22 (string-literal dispatch → `bundle.BundleFormatV2` constant in `check1_signature.go:69` + `output/json.go:185`; code-rev H1) + n=23 (fixture mojibake from PowerShell stdout cp1252 re-encoding; 5 v2 sig-tamper `results.json` regenerated via Python subprocess UTF-8 capture; crypto-int H1 + spec-conf M2 + sec-aud M1 TRIPLE-corroborated) + n=24 (defensive-helper bypass: 3 sites inlined `Buffer.from(...).toString("base64")` instead of `encodeSignatureB64()`; crypto-int H2) + n=25 (shared dispatch-table coupling v1+v2 evolution risk; heavy-bookmarked for post-promotion refactor per crypto-int M1). **Recurring-defect-class memory** ratcheted n=21+ → n=25+ during this session; 7 → 11 documented named instances comprising procurement currency for the "0 shipped defects across 108+ sessions" CISO narrative. **Cumulative reviewer-protocol track**: preserved at 0 shipped defects through promotion gate.

- **2026-05-21 (v2.0.0-rc1)** — **Major-version amendment per Phase 7.F.1 (build-plan v3.1.54): ML-DSA-65 dual signing at the manifest level alongside Ed25519, with `bundle_format` identifier `nuwyre-bundle/v1` → `nuwyre-bundle/v2` + `schema_version` 1 → 2**. The amendment triggers SPEC_GOVERNANCE.md §3.2 "Breaking (v2.0 major amendment)" cadence per the "Signing-format change" + "Cryptographic algorithm replacement (post-quantum migration)" conditions explicitly enumerated at §15.2. **Posture**: ships as **release-candidate (v2.0.0-rc1)**, NOT v2.0.0 final. Promotion gate at Phase 7.F.4 cross-language byte-equivalence across TS writer (Phase 7.F.2) + Go-native verifier (Phase 7.F.3) + Go-WASM verifier (Phase 7.F.3) + conformance fixture suite regeneration (Phase 7.F.4). The rc1 posture mitigates "vapor spec" risk while preserving the engineering output of the 9 reviewer-discipline points encoded in spec text (§18 below). SPEC_GOVERNANCE.md itself is documented as v0.1 draft pending Year-3 formalization; the rc1 amendment posture follows the same institutional precedent of intentionally-not-yet-final status.

  **Substantive changes (v1 → v2)**:
  1. **`manifest.signing` becomes a container object** with `schema_version: 1` (the signing-container schema version, not the bundle schema_version) + `signatures: []` array of EXACTLY 2 entries (positional: Ed25519 at index 0, ML-DSA-65 at index 1). Each signatures[i] entry contains `{algorithm, key_id, key_fingerprint_spki_b64, key_purpose}`. See §4.1 + §18.1 for full schema.
  2. **`signature.sig` becomes a JSON multi-signature container** wrapping TWO signature byte strings over identical canonical manifest.json bytes. signature.sig itself MUST be RFC 8785 JCS-canonicalized when written into the bundle ZIP. See §5 + §18.2 for full schema.
  3. **`bundle_format` identifier** `nuwyre-bundle/v1` → `nuwyre-bundle/v2`; `schema_version` integer 1 → 2. See §2 for the dual-version dispatch contract.
  4. **9 reviewer-discipline points** encoded with normative MUST/MUST NOT language at §18: (a) FIPS 204 §5.2 + §6.2 + §3.7 deterministic-variant framing pin (pure mode; `rnd = 32 zero bytes`; `ctx = ""` empty); (b) RFC 5280 SubjectPublicKeyInfo wrapping with OID `2.16.840.1.101.3.4.3.18` (id-ml-dsa-65 per NIST CSOR) + AlgorithmIdentifier parameters ABSENT (not NULL) + raw 1952-byte public key as BIT STRING with zero unused bits; (c) raw 3309-byte ML-DSA-65 signature per FIPS 204 §4 Table 1 final + base64-encoded RFC 4648 §4 standard alphabet (no padding required since 3309 % 3 == 0); (d) signature.sig JCS-canonicalization itself (lexicographic key ordering within signatures[i] sub-objects) prevents Go encoding/json vs TS JSON.stringify divergence on signature.sig SHA-256; (e) `manifest.artifacts[]` MUST NOT list signature.sig + bidirectional set-equality invariant `ZIP_files = {manifest.json, signature.sig} ∪ {artifacts[].path}`; (f) atomic key rotation across both algorithms (writer blocks during rotation transition); (g) cross-environment-slot discipline (both signature slots MUST belong to same env slot); (h) positional ordering pinned (Ed25519@0, ML-DSA-65@1); (i) Check 1 failure taxonomy with three categories (structural / schema-cross-check / cryptographic) + ordered short-circuit progression.

  **Preserved verbatim from v1.0.17**: per-event Ed25519 `ingestion_signature` (§6.3); three-leg anchoring (OTS Bitcoin + RFC 3161 ≥2-of-3 TSA quorum + GitHub anchor commit; §§10-12); audio binding (§13); per-organization JSONL hash chain (§6); daily Merkle tree construction (§8); dual-subtree audit-log composition for `bundle_type = "audit-log-export"` (§§8 + 16); canonicalization rule RFC 8785 JCS (§§4.3 + 7.5); SHA-256 hash algorithm (§4.3). GitHub anchor leg is explicitly preserved per Phase 7.F "explicitly NOT in scope" boundary (Phase 7.F is sticky-pre-customer cryptographic schema decisions only; reversible features like GitHub anchor removal defer until customer signal).

  **Multi-version verifier discipline**: per SPEC_GOVERNANCE.md §3.2 (12-month deprecation window) + §5.4 (no NuWyre-specific verification paths) + §15.3 (CLI multi-version support): v1.x verifiers continue to verify v1.x bundles forever; v2.x verifiers MUST verify both v1.x (via dispatch by `bundle_format` string) AND v2.x bundles. The 12-month deprecation window is **operationally moot pre-customer-#1** since zero v1.0.17 customer bundles exist at the time of this amendment; the multi-version discipline is enforced for forensic-record-preservation invariant integrity (per §5.4) rather than customer-migration management.

  **External-implementer simulation posture**: a competent implementer reading §§18.1-18.9 + the §14.4 PLANNED fixture inventory can produce a conformant v2.0.0-rc1 writer (TS, Go, Python, Rust, Java) without recourse to NuWyre-internal documentation. Cross-language byte-equivalence is empirically verifiable once Phase 7.F.4 ships the regenerated fixture suite. The §18.9 library-selection-criteria section enumerates the FIPS 204 conformance evidence required of any candidate ML-DSA-65 library (deterministic-variant API exposure; npm + Go ecosystem availability; active maintenance ≥1 substantive commit per quarter; license compatibility; SPKI wrapping conformance).

  **Conformance fixture impact**: 10 new tamper variants enumerated at §14.4 + PLANNED implementation at Phase 7.F.4 (`tampered-ed25519-sig`, `tampered-ml-dsa-sig`, `tampered-both-sigs`, `wrong-pq-key-id`, `malformed-pq-sig-length`, `manifest-signing-mismatch`, `swapped-signature-slots`, `mixed-environment-keys`, `dev-keys-claiming-prod`, `extra-file-smuggled`). Existing v1.0.x fixtures preserved at `docs/spec/fixtures/bundle-format-v1/` for v1 verifier conformance; v2.0.0 fixtures land at the same directory structure with `bundle_format = "nuwyre-bundle/v2"` discriminator. The conformance fixture suite split discipline per SPEC_GOVERNANCE §3.2 manifests as side-by-side fixture rows within a single suite directory rather than a separate `bundle-format-v2/` directory (file-naming pragmatism parallel to the spec doc's `bundle-format-v1.md` filename retention).

  **Cross-implementation impact**: TS reference impl extension at Phase 7.F.2; Go-native + Go-WASM verifier extension at Phase 7.F.3; KAT vector regeneration at Phase 7.F.5; methodology §3.4 amendment at Phase 7.F.6; SPEC_GOVERNANCE.md amendment + CI workflow extension at Phase 7.F.7. Estimated 5-8 weeks focused engineering total across 7.F.2-7.F.9; ML-DSA-65 library maturity in Go + TS ecosystems is the gating risk (FIPS 204 finalized August 2024; library maturity is thin enough that manual SPKI wrapping or custom binding to a vetted C library may be required).

  **Six tenants framing** (load-bearing per Phase 7.F.1 sounding-board sequencing): T1 (long-term correctness) LOAD-BEARING — sticky cryptographic schema decision committed pre-customer means customer #1's first bundle is emitted under the v2 contract that will hold under post-quantum threat models from 2026 through Q-Day; T3 (security/privacy) LOAD-BEARING — dual-signature topology hedges against future Ed25519 weakening (whether CRQC-driven or classical-cryptanalysis-driven) without re-emitting historical bundles; T5 (customer trust) — procurement-claim integrity preserved (a compliance-buyer's general counsel reading "NuWyre ships post-quantum dual signing" can verify the signatures byte-by-byte against the conformance fixture suite once 7.F.4 promotes); T6 (user value at point of use) — first paying customer's bundles are emitted under the contract that holds for the bundles' forensic-relevance lifetime (typically 3-7 years for TCPA cases; up to 30+ years for federal records-retention regulations).

  **Reviewer-pass closures pre-commit (Tier B 3-reviewer composition)**: spec-conformance-reviewer + crypto-integrity-reviewer + security-auditor; reviewer findings closed inline OR heavy-bookmarked per the cumulative reviewer-protocol track preservation discipline (0 shipped defects across 97 sessions through this amendment).

- **2026-05-16 (v1.0.17)** — Schema-companion adoption amendment per Phase 7.D session 85 (institutional ratchet-back Sub-arc 1; BACKLOG 1.48 A.2). Fixture-suite completion (A.1) defers to session 86-87 cross-session per the operator-directive scope estimate (2.5-3 sessions for A.1 alone). **One surface closed at this amendment**: **A.2 — `audit-log-event-v1.schema.json` companion adopted** at `docs/spec/audit-log-event-v1.schema.json`. Closes the "if/when adopted" forward-bookmark at SPEC_GOVERNANCE.md §1. Provides machine-readable validation contract for §16.2 audit-log event shape: closed enums for `actor.type` (`{user, admin, system, cron}`) + `subject.type` (`{customer, user, api-key, policy-pack, admin-action, cross-tenant, system, cron}`) + `forensic.*` sub-shape per §16.2 chain-integrity contract + UUID v5 pattern for `event_id` per §16.2 derivation rule + `audit-log:<category>:<verb>` pattern for `event_type` + 64-char-lowercase-hex pattern for `prev_event_hash` / `event_hash` / `content_hash` + base64 pattern + length bounds for `ingestion_signature`. Strict-fields posture (v1.0.12 F-SC-4 closure) enforced via `additionalProperties: false` at every sub-object. **A.1 — audit-log-export conformance fixture suite extension** opens at session 86-87 per BACKLOG 1.48 A.1 (extends `packages/example-bundle/scripts/conformance-fixtures/build.ts` invoking `generateAuditLogExportBundle` at `packages/evidence/src/generate-audit-log-bundle.ts`; tamper-ops documented per fixture README; cross-language byte-equivalence verification per Phase 6.4 KAT pattern). The deferral opened at v1.0.10 (Phase 6.2.C-D Sub-arc 1b) closes when A.1 lands. **Six tenants framing**: T1 (long-term correctness) load-bearing — A.2 establishes the machine-readable validation oracle that A.1 fixture-generation will validate against; without A.2 the fixtures would be generated against prose-only spec text and propagate any ambiguity into the conformance suite. T5 (customer trust) — fixture suite IS the standard per spec-governance §3; A.2 is the load-bearing prerequisite. T6 (user value) — A.2 alone unblocks third-party JSON-schema-validator-based audit-log writers; A.1 unblocks bundle-level conformance testing. **External-implementer simulation pass at A.2**: a Python implementer running JSON Schema draft-07 validator against the new schema can independently validate audit-log event payloads from §16.2 prose without ambiguity (closed enums machine-checked; forensic chain-integrity field shapes machine-checked; UUID v5 pattern + decimal-ASCII timestamp_unix_ns + 64-char-lowercase-hex content_hash all enforced; sequence_number left uncapped at the spec-level schema per F-SC-11 cross-language framing). **Reviewer-pass closures pre-commit**: spec-conf primary reviewer surfaced 3 HIGH + 2 MEDIUM + 3 LOW; all 5 HIGH+MEDIUM closed inline at this amendment: (H1) `sequence_number` `maximum` removed (was 2^53-1 = JS-specific cap; leaked NuWyre TS-implementation constraint into the cross-language writer contract — Standards-Track Posture §1 violation); (H2) `ingestion_signature` pattern tightened from `^[A-Za-z0-9+/]+={0,2}$` (admits 86/87/89/90-char invalid lengths) to `^[A-Za-z0-9+/]{86}==$` matching event-v1.schema.json verbatim (Ed25519 = 64 bytes = always exactly 88 chars + mandatory `==`); (H3) SPEC_GOVERNANCE.md §1 corrected to accurately describe fixture state (10 customer-export with bundle.zip + 4 audit-log-export scaffolds WITHOUT bundle.zip pending A.1; the prior text prematurely declared "14 fixtures with bundle.zip" closure that has not occurred); (M1) §16.2 "structurally a subset of event-v1" corrected to "share `schema_version` + `event_id` + `forensic`; the two schemas are siblings sharing forensic-chain fields, not a subset relationship"; (M2) `timestamp_unix_ns` pattern aligned to `^(0|[1-9][0-9]*)$` matching F-SC-1 prose verbatim (admits literal `"0"` for canonical zero). Plus 2 LOW closures: L1 redundant `minLength: 11` on `event_type` removed; L2 Subject $comment narrowing of null-tolerance to "cross-tenant" subject.type corrected to "any org-agnostic subject" per F-SC-12 prose. L3 (actor.id/subject.id type-conditional UUID format) deferred per F-SC-15 heavy-bookmark + §16.2.3 "verifiers MUST NOT validate PII discipline... writer-side invariant" framing.

- **2026-05-15 (v1.0.16)** — Windowing reconciliation amendment closing BACKLOG 1.30 per Phase 6.2.B-F session 69 (Phase 6.2.B sub-arc closure session). v1.0.13 + v1.0.14 + v1.0.15 amendments composed multiple window-predicate semantics across customer-export + audit-log-export bundle types; v1.0.16 reconciles the windowing prose in normative spec text. **Windowing semantic reconciliation** (BACKLOG 1.30 closure): customer-export bundle generation filters primary events by `ingestion_timestamp` (server-stamped at ingestion time per AUDIT-1 C3/S-C6 closure); audit-log-export bundle generation filters audit log events by `forensic.timestamp_iso` (authored timestamp per v1.0.14 §16.3 leaf-anchor semantic). v1.0.15 §8.2 dual-subtree composition formula `SHA-256(events_subtree_root_bytes || audit_log_subtree_root_bytes)` binds two differently-windowed leaf sets at the daily_root level; the composed root carries the cryptographic commitment to both subtrees at canonical byte order. **v1.0.16 §8.2 prose pin** (extends v1.0.15 §8.2 amendment): "events_subtree_root_bytes IS the customer-export single-tree root_hash from the daily_roots row at the same (organization_id, root_date) tuple with bundle_type='customer-export'. Verifiers MUST query the customer-export daily_roots row for the events_subtree_root value rather than recomputing from bundle events.jsonl leaves under any window predicate — the events_subtree_root anchored at customer-export time is the canonical commitment regardless of bundle.jsonl leaf-set windowing differences." **v1.0.16 §16.3 prose pin** (extends v1.0.15 §16.3 amendment): "audit-log-export bundle's audit_log_subtree.json is built from audit_log_events filtered by `forensic.timestamp_iso ∈ [period_start_iso, period_end_iso + 1 day)`; primary events.jsonl in audit-log-export bundle (when included for cross-validation) is the same content as customer-export events.jsonl for the same period_start UTC day, NOT re-windowed; the daily_root composition binds the customer-export events_subtree_root (server-stamped ingestion_timestamp window) and audit-log-export audit_log_subtree_root (authored timestamp_iso window) without windowing reconciliation at the leaf-set boundary." **v1.0.16 §16.4 anchor binding clarification**: per-(organization_id, root_date, bundle_type) daily_roots row receives independent OTS + RFC 3161 + GitHub anchor receipts; verifier Check 5/6/7 cross-checks anchor receipt against the daily_root row's root_hash at the matching 3-tuple. **Backward compatibility**: v1.0.13 + v1.0.14 + v1.0.15 audit-log-export bundles (zero shipped pre-v1.0.16; pre-implementation pinning posture preserved) and pre-v1.0.10 customer-export bundles continue to verify against single-row daily_roots semantics; v1.0.16+ verifiers query by 3-tuple. The Phase 6.2.B-D session 67 + Phase 6.2.B-F session 69 substrate is the canonical TS implementation. **Conformance fixture extension** (deferred to Phase 6.2.C per established conformance fixture deferral pattern): 3 new fixtures exercising windowing reconciliation (customer-export-events-with-audit-log-overlap, audit-log-export-with-backdated-emit, dual-subtree-composed-root-verification) may ship at Phase 6.2.C verifier extension session. **Six tenants framing** (load-bearing per Phase 6.2.B-F session 69): T1 (long-term correctness) — windowing reconciliation prose closes the cross-implementation conformance gap that v1.0.13 + v1.0.14 + v1.0.15 amendments collectively created; T2 (quality/reliability) — verifier contract clarity prevents Go-CLI Check 9 + WASM verifier from implementing divergent reconstruction semantics; T5 (customer trust) — first paying customer audit-log-export bundle verification under any external verifier converges to the same root_hash byte values.

- **2026-05-15 (v1.0.15)** — Pre-implementation reconciliation amendment closing BACKLOG 1.26 architectural decision (dual-subtree daily-root composition contract pinned at v1.0.15 per Phase 6.2.B-D session 67 substantive engineering). v1.0.15 absorbs the per-bundle-type daily_roots schema contract that the Phase 6.2.B-C session 66 schema substrate (migration 20260525010000 + bundle_type discriminator column + composite unique (organization_id, root_date, bundle_type)) enabled but did not normatively pin. v1.0.15 §8.2 amendment: dual-subtree daily-root composition per v1.0.13 §16.3 events-first MUST-language extends to the daily_roots TABLE LAYER — for `bundle_type = "audit-log-export"`, the `daily_roots.root_hash` value MUST be the composed dual-subtree root `SHA-256(events_subtree_root_bytes || audit_log_subtree_root_bytes)` per v1.0.13 §16.3 byte order; for `bundle_type = "customer-export"` (or implicit single-tree bundles per pre-v1.0.10 baseline), `daily_roots.root_hash` continues to be the single-tree events-root per v1.0.7 + earlier baseline. **§8.2 amendment text**: per-(organization_id, root_date, bundle_type) tuple uniquely identifies a daily_roots row; verifiers MUST query daily_roots by the full 3-tuple when validating audit-log-export bundle daily_root invariant per v1.0.13 §8.2 dual-subtree composition + §16.3 daily_root anchoring + §16.4 cross-bundle-type anchor-binding. **§16.x amendment**: audit-log-export bundles in v1.0.15+ MUST reference the audit-log-export-specific daily_roots row (bundle_type='audit-log-export'); verifier Check 4 + Check 9 (audit-log-merkle) MUST validate against the composed daily_root from that row, NOT the customer-export single-tree row for the same (organization_id, root_date). **Backward compatibility**: v1.0.13 + v1.0.14 audit-log-export bundles (pre-implementation; no bundles shipped) and pre-v1.0.10 customer-export bundles continue to verify against single-row daily_roots semantics; v1.0.15+ verifiers query by 3-tuple. The session 66 schema substrate (migration 20260525010000) is the canonical DB layer for v1.0.15 contracts. **OTS + RFC3161 + GitHub anchor pipeline**: the existing daily-root cron anchoring pipeline (apps/api/src/lib/daily-root/act.ts actStampOts + actStampRfc3161 + actCommitGithub) applies UNCHANGED to the new audit-log-export daily_roots rows — composed root_hash bytes flow through the same OTS calendar submission + RFC 3161 TSA submission + GitHub anchor staging pipeline. Per-org-prefix path patterns: customer-export ots_receipt_path = `<org_id>/<date>.ots`; audit-log-export ots_receipt_path = `<org_id>/<date>__audit-log.ots` (disambiguates same-day customer-export + audit-log-export OTS receipts at storage bucket level). Phase 6.2.B-D implementation at `apps/api/src/lib/daily-root/act.ts:actComputeRoot + computeAuditLogExportDailyRootForOrg + actComputeOperatorOnlyAuditLogRoot` is the reference TS implementation. **Six tenants framing** (load-bearing per Phase 6.2.B-D session 67): T1 (long-term correctness) — operator decision at Phase 6.2.B-C selected architecturally-complete daily-root cron extension over weakened-assertion workaround; v1.0.15 normatively pins that architectural decision at spec layer; T2 (quality/reliability) — composed daily_root preserves snapshot-drift safety property at cron-stored ground truth (no on-the-fly recomputation race); T3 (security/privacy) — per-(org, bundle_type) row isolation preserves cross-tenant Merkle subtree boundary per sec-aud C2 closure at v1.0.12 strict-fields posture; T5 (customer trust) — Phase 6.2.B sub-arc end-state ships full TS-implementation for audit-log-export bundle type; first paying customer audit-log-export bundle ships against v1.0.15 contract.

- **2026-05-15 (v1.0.14)** — Pre-implementation reconciliation amendment closing the Phase 6.2.B-C session 66 Tier A 5-reviewer first-fix-up batch against v1.0.13. The Tier A composition returned ~55 findings; spec-conformance produced 5 NOT_IMPLEMENTABLE pre-implementation gaps (S1-S5) deferred from session-66 fold per operator decision (6 CRITICAL inline closures + 4 BACKLOG additions deferring v1.0.14 + HIGH/MEDIUM to Phase 6.2.B-D). v1.0.14 closes those 5 spec-side gaps before Phase 6.2.B-D session 67 BACKLOG 1.26 deploy-blocker substrate ships. **NOT_IMPLEMENTABLE-from-spec-alone closures** (5 findings; pre-implementation cross-language pinning per established Phase 6.2.A/B/B-B/B-C pattern): **(S1)** §16.4.1 NEW pinning audit-log-event bundle inclusion window to `forensic.timestamp_iso` (on-wire field; cross-implementation-reproducible). Pre-S1 the BundleDataSource.streamAuditLogEvents query used `created_at` (DB column NOT serialized into audit_log_events.jsonl); two implementations could legitimately interpret "audit-log events for day D" differently. v1.0.14 pins `forensic.timestamp_iso` as the canonical bundle-inclusion-window field. (TRIPLE-corroborated session-66 closure: sec-aud HIGH #1 + spec-conf NOT_IMPLEMENTABLE S1 + crypto-int adjacent.) **(S2)** §16.8.1 NEW pinning `bundle_id` format: UUID v4 canonical lowercase per existing customer-export pattern (matches /v1/audit-log-exports POST endpoint export_id semantic + audit_log_exports.export_id column type). Pre-S2 the bundle_id format was implementer-defined; v1.0.14 pins for cross-language conformance. **(S3)** §16.6.2 RLS-context contract amended: spec text now reads "writer pipeline executes its audit_log query under either (a) the requesting principal's RLS context with policies enforcing the scope, OR (b) a service-role context (RLS-bypassing) with explicit equality filters `WHERE organization_id = manifest.organization_id AND bundle_subtype = manifest.bundle_subtype` providing equivalent scoping. Defense-in-depth requires BOTH the cross-tenant invariant verifier check (§16.5) AND writer-side scoping; either RLS-mode satisfies writer-side". The Phase 6.2.B-C session 66 implementation uses service-role + explicit-filter mode at `apps/api/src/app/api/cron/audit-log-export/route.ts` + BundleDataSource queries; v1.0.14 spec pins this as a permissible writer-mode. **(S4)** §16.8 audit-log-export bundle file layout: CONFIRMED cover.pdf + verify.md REMOVED per v1.0.13 F3 closure at Phase 6.2.B Sub-arc 2 session 64. v1.0.14 re-validates the §16.8 file table consistency post-v1.0.13 amendment; no further spec text changes required at v1.0.14. **(S5)** §16.5 amendment: writer-side MUST-language pin — bundle-generation MUST reject (`bundle_subtype = "operator-only" AND organization_id != sentinel UUID`) OR (`bundle_subtype = "customer-scoped" AND organization_id == sentinel UUID`). The Phase 6.2.B-C session 66 cron handler enforces this at `/api/cron/audit-log-export/route.ts` fail-fast assertion (TRIPLE-corroborated closure: sec-aud HIGH #2 + code-rev HIGH #1 + spec-conf S5). v1.0.14 spec text pins this as normative writer-side discipline. **Forward-compat tolerance** per §15.1 unchanged: v1.0.14 is additive-on-additive (v1.0.13 + spec-clarity amendments only; no byte-shape changes to pre-v1.0.10 bundle types; no on-disk file layout changes for audit-log-export). **Cumulative Tier A 5-reviewer composition test outcome at Phase 6.2.B-C Sub-arcs 1+2 substantive engineering work: STRONG ADOPT continued at n=4** (Phase 6.1 Tier A n=1; Phase 6.2.B Sub-arc 2 Tier A n=2; Phase 6.2.B-B Sub-arc 3 Tier A n=3; Phase 6.2.B-C Sub-arcs 1+2 Tier A n=4); ~55 findings density; 6 CRITICAL distinct findings (3 TRIPLE-corroborated + 3 unique inline-closure). **Six tenants framing** (load-bearing per session 66): T1 (long-term correctness) — chose CRITICAL-only inline fold per session-66 fold-scope decision; v1.0.14 + v1.0.15 composed amendments at Phase 6.2.B-D session 67 preserve pre-implementation pinning posture; T2 (quality/reliability) — S1 timestamp_iso pinning prevents cross-language window-predicate divergence; T3 (security/privacy) — S3 RLS-context flexibility documents the established defense-in-depth pattern; T5 (customer trust) — spec amendments compound institutional discipline at standards-track posture.

- **2026-05-15 (v1.0.13)** — Pre-implementation reconciliation amendment closing the Tier A 5-reviewer first-fix-up batch against v1.0.12 surfaced at Phase 6.2.B-B Sub-arc 3 (`packages/evidence/src/generate-audit-log-bundle.ts` + `audit-log-export-emit.ts` + `audit_log_exports.bundle_subtype` migration substrate review). The Tier A composition returned ~60 findings; 8 distinct CRITICAL-level + 5 NOT_IMPLEMENTABLE pre-implementation gaps + 12 IMPLEMENTABLE-WITH-LEAK gaps. v1.0.13 closes the spec-side gaps before any v1.0.12 audit-log-export bundle bytes ship at Phase 6.2.B-C (pre-implementation pinning posture continued from Phase 6.2.A v1.0.10→v1.0.11 + Phase 6.2.B Sub-arc 2 v1.0.11→v1.0.12 fold-ups). **NOT_IMPLEMENTABLE-from-spec-alone closures** (5 findings; cross-language Go-CLI vs TS divergence guaranteed at Phase 6.2.C without these): **(F1)** §9 daily_roots.json `roots[].date` field name re-confirmed (the Go CLI verifier at `apps/cli/internal/bundle/types.go` expects `Date string \`json:"date"\``; v1.0.12-pinned audit-log-export TS implementation initially used `utc_day` which is the v3.1.8 anchor-repo `root.json` key NOT the bundle `daily_roots.json` key — direct field-name regression; spec §9 + §16.8 reaffirms `date` is the canonical field name). **(F2)** §8 `merkle_proofs.json` shape explicitly carries `schema_version: 1` at top of file (additive clarification; the customer-export reference impl already emits this field; audit-log-export TS impl missed it at initial Sub-arc 3c implementation). **(F3)** §16.8 audit-log-export bundle file layout — `cover.pdf` + `verify.md` REMOVED from the §16.8 file table (operator decision at session 65 fold). Rationale: audit-log-export bundles are machine-readable artifacts for compliance officers + regulators (machine-only-artifact posture); cover.pdf is a customer-facing PDF surface that doesn't serve the audit-log use case; verify.md is similarly customer-facing. Operator-only bundles have no customer surface. Tenant 4 (simplicity) — fewer artifacts; smaller bundles; no Puppeteer dependency on audit-log path. **(F4)** §16.3 + §8.2 `daily_roots.json:roots[].root` semantic clarified for audit-log-export bundles — under dual-subtree composition the `root` field is the COMPOSED daily_root (per §16.3 SHA-256 of events_subtree_root_bytes || audit_log_subtree_root_bytes), NOT the events-subtree root. Data-source interface contract documented at `DailyRootEntry.rootSha256`: for `bundleType = "audit-log-export"`, the field carries the composed root (cron writer is responsible for composing + storing the composed value). **(§16.5 writer-side enforcement)** §16.5 amended to MUST-language at writer boundary: operator-only bundles MUST have `manifest.organization_id` = all-zero sentinel UUID; MUST have `agent_id` = NULL (or sentinel); MUST have `agent_attestation_id` = all-zero sentinel UUID. Customer-scoped bundles MUST NOT use the sentinel UUID as `manifest.organization_id`. Writer-side enforcement at the bundle-generation entry boundary (mirror of `buildAuditLogSubtree` + `emitAuditLogEvent` contrapositive guards at the primitive + emit-helper boundaries). **IMPLEMENTABLE-WITH-LEAK closures** (4 findings; load-bearing for byte-stable cross-language conformance): **(L1)** §16.6.1 pins `manifest.signing.key_purpose` literal for audit-log-export bundles as `"audit-log-export bundle signing (v1.0.13 §16.6.1 single-key topology)"` (deferred to operator decision at Phase 6.2.B-C cron implementation; current TS impl pins the v1.0.12 literal). **(L2)** §16.4 / §16.5 `evaluation_source` for audit-log-export bundles by subtype: `"live-evaluator"` for customer-scoped (parallel to customer-export); `"operator-action-log"` for operator-only (new implementation-defined literal per §4.1 forward-compat clause). **(L3)** §16 `binding` field set for audit-log-export bundles pinned to mirror §4 customer-export pattern (`methodology_doc` + `methodology_section` + `validation_scenarios_dir`) for cross-bundle consistency. **(L7)** §4.3 amendment — `artifacts[]` array sort MUST-language: "entries MUST be sorted by `path` lexicographically (ASCII byte order) prior to JCS canonicalization." Closes a cross-implementation manifest byte-parity gap that would surface at Phase 6.2.C Go-CLI byte comparison even for customer-export bundles (JCS canonicalizes object keys lexicographically but does NOT canonicalize array order). Forward-compat note: existing customer-export reference impl already produces a stable (alphabetical-ish) artifact order; backporting to spec text closes the writer-discipline gap. **CRITICAL substrate closures fold inline** at session 65 commit (NOT spec-side): (1) `audit_log_exports.organization_id` FK to `customers(id)` DROPPED + `audit_log_exports_org_subtype_consistency` CHECK constraint ADDED (mirroring audit_log_events precedent at migration 20260523000000) — the FK FK-blocked operator-only INSERT since the all-zero sentinel UUID is NOT a real customer row; rls-policy-reviewer CRITICAL #1 unique catch. (2) GitHub anchor `path` layout corrected from `roots/<date>.json` to `daily-roots/<organization_id>/<date>/root.json` per spec §12.1 + customer-export precedent — code-rev CRITICAL #2 unique catch; Phase 4 Go CLI Check 7 hash cross-check against anchor repo blocker. (3) Chain-integrity invariant `prev_event_hash[i] == event_hash[i-1]` verification at bulk-bundle path (crypto-int HIGH H3 unique catch; emit-helper enforces at emission boundary but bulk-stream-then-bundle re-bypassed the discipline; defense-in-depth re-verification added at bundle generation boundary). **Documentation-vs-implementation drift sub-pattern continued ADOPTED** — n=4 firing this session alone: (a) sec-aud MEDIUM index/cron comment vs index column ordering; (b) code-rev NIT version-refs drift (v1.0.10 vs v1.0.12); (c) crypto-int LOW defaultClock docstring claims `process.hrtime.bigint()` vs actual `Date.getTime() * 1_000_000n`; (d) spec-conf F3 §16.8 prose-vs-impl divergence on cover.pdf/verify.md. Pattern was ADOPTED at n=2 (Pre-Phase 6 Item 2 + Phase 6.2.B Sub-arc 2 + Phase 6.2.B-B Sub-arc 3 collectively firing n=4); reviewer prompts in future sessions reference this discriminant for TRIPLE-corroboration density at affected substrates. **Heavy-bookmarked to BACKLOG with three preservation surfaces**: BACKLOG 1.21 audit_log_exports test-rls.ts coverage extension (4 scenarios per rls-policy HIGH #4); BACKLOG 1.22 BundleDataSource SSH key fingerprint provider method extension (Phase 6.2.B-C wiring); BACKLOG 1.23 strict-shape Zod validation at streamAuditLogEvents boundary (Tier B defense-in-depth); BACKLOG 1.24 §16.5 contrapositive guard extracted to single helper function (Tenant 4 maintainability; sec-aud LOW). **Forward-compat tolerance** per §15.1 unchanged: v1.0.13 is additive-on-additive (spec-clarity amendments only; no byte-shape changes to pre-v1.0.10 bundle types; L7 artifacts[] sort is a writer-discipline addition — verifiers tolerate any order per §4.3 existing prose). **Cumulative Tier A 5-reviewer composition test outcome at Phase 6.2.B-B Sub-arc 3 substantive engineering work: STRONG ADOPT continued at n=3** (Phase 6.1 Tier A n=1; Phase 6.2.B Sub-arc 2 Tier A n=2; Phase 6.2.B-B Sub-arc 3 Tier A n=3). ~60 findings density; 4 TRIPLE-corroborated CRITICAL/HIGH findings; documentation-vs-implementation drift n=4 firing. Phase 6.2.B-C entry preconditions: v1.0.13 + migration FK fix + TS impl fix-ups landed inline at session 65 commit.

- **2026-05-15 (v1.0.12)** — Pre-implementation reconciliation amendment closing the Tier A 5-reviewer first-fix-up batch against v1.0.11 surfaced at Phase 6.2.B Sub-arc 2 (`packages/evidence/src/audit-log-export.ts` substrate review). The Tier A composition (code-reviewer + security-auditor + rls-policy-reviewer + crypto-integrity-reviewer + spec-conformance-reviewer; policy-evaluation-quality-reviewer OMITTED — bundle-format implementation surface has no LLM evaluator code) returned ~59 distinct findings of which spec-conformance contributed 5 NOT_IMPLEMENTABLE pre-implementation gaps + 8 IMPLEMENTABLE-WITH-LEAK gaps. v1.0.12 closes those spec-side gaps before any v1.0.11 audit-log-export bundle bytes ship at Phase 6.2.B-B (no v1.0.11 audit-log-export bundle has been generated yet — same pre-implementation-pinning posture as the v1.0.10 → v1.0.11 fold at Phase 6.2.A). **NOT_IMPLEMENTABLE-from-spec-alone closures** (5 findings; cross-language Go-CLI vs TS divergence would be guaranteed at Phase 6.2.C without these): **(F-SC-1)** §16.2 name-input `<sequence_number>` formatting pinned to **decimal ASCII representation** (no leading zeros for positive values; the literal string `0` for zero; the canonical form Python `str(int)` / Go `strconv.FormatInt(n, 10)` / Rust `n.to_string()` produces). **(F-SC-2)** §16.2 name-input `<organization_id>` MUST be **lowercase canonical RFC 4122 §3 UUID** string at name-string construction; uppercase or mixed-case inputs MUST be normalized to lowercase before name construction (TS reference impl at `packages/evidence/src/audit-log-export.ts:deriveAuditLogEventId` validates with regex `/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/`). **(F-SC-3)** §16.2 UUID v5 derivation now explicitly cites RFC 4122 §4.3: **16-byte network-byte-order namespace UUID** input (NOT the 36-char ASCII string). SHA-1 over (namespace_bytes || UTF-8 encoded name string bytes); truncate to first 128 bits; set octet 6 high nibble to `0x5`; set octet 8 high two bits to `0b10`; format as canonical 8-4-4-4-12 lowercase hex per RFC 4122 §3. **(F-SC-4)** §16.2.1 canonical content payload field set elevated to **MUST-language strict-fields posture**: the `actor` sub-object contains EXACTLY `{type, id}`; `subject` contains EXACTLY `{type, id, organization_id}`; the top-level object contains EXACTLY `{actor, subject, event_type}`. Implementations MUST NOT include additional fields in the canonical payload even when the source audit log row carries extension fields per §1 forward-compat tolerance (Arc #1 H1 defect-class parallel — defaults/extensions FORBIDDEN in the canonical pre-image; the canonical-payload-vs-row-fields distinction is load-bearing). **(F-SC-5)** §16.2.2 audit log `event_hash` derivation pinned to the verbatim §6.2 4-field formula: `event_hash = SHA-256( JCS({prev_event_hash, content_hash, sequence_number, timestamp_unix_ns}) )`. The canonical pre-image field set is the SAME 4 fields as primary events; `event_type`, `actor`, and `subject` are NOT in the event_hash pre-image (they are in the content_hash pre-image per §16.2.1). **IMPLEMENTABLE-WITH-LEAK closures** (load-bearing for cross-language byte-equivalence): **(F-SC-6)** §16.2 `actor.type` closed vocabulary pinned to `{user, admin, system, cron}`; `subject.type` closed vocabulary pinned to `{customer, user, api-key, policy-pack, admin-action, cross-tenant, system, cron}`. Writers MUST reject events with out-of-vocabulary type values; verifiers MAY tolerate unknown values per §1 forward-compat (writer-side strictness; reader-side tolerance). **(F-SC-7)** §16.3.1 empty-subtree composition clarified: when `audit_log_events.jsonl` is empty, `audit_log_subtree.json` is STILL emitted with `{schema_version: 1, subtree_root: "00..00", proofs: []}`; the file is REQUIRED for all `bundle_type = "audit-log-export"` bundles regardless of leaf count. **(F-SC-9)** §8.1 single-leaf padding rule pinned: `padded_leaf_count = max(1, next_power_of_two(leaf_count))`. For a single leaf (`leaf_count == 1`), `padded_leaf_count == 1` AND the `subtree_root == leaf_hash` directly (no internal-node hashing; the tree is depth-0). For zero leaves, the §16.3.1 empty-subtree composition applies. For ≥2 leaves, pad with `GENESIS_SENTINEL_HASH` to the next power of two; internal-node hashing per the §8.1 formula proceeds bottom-up. **(F-SC-10)** §8.1 raw-byte-concat MUST-language: internal-node hashing uses raw byte concatenation WITHOUT RFC 6962 leaf/internal prefixing (`node = SHA-256(decoded_left_32bytes || decoded_right_32bytes)`). The Merkle tree is NOT RFC 6962-compatible; second-preimage resistance derives from leaf `event_hash` values themselves being SHA-256 outputs with chain-internal context binding (per §6.2 + §16.2.2 chain isolation), not from leaf/internal node domain separation. **(F-SC-11)** §16.2 `sequence_number` range pinned to `[0, 2^63 - 1]` (Postgres `bigserial` ceiling); JCS canonicalizes integers per RFC 8785 §3.2.2.3. Implementations using JS `number` MUST validate `sequence_number <= Number.MAX_SAFE_INTEGER` (`2^53 - 1`) and either reject or escalate to a bigint representation when exceeded (TS reference impl rejects with explicit error). **(F-SC-12)** §16.5 cross-tenant invariant amended to permit `null` `subject.organization_id` (org-agnostic subject — e.g., a built-in policy pack or global resource referenced from a customer-scoped chain): "EVERY audit log event's `subject.organization_id` MUST be either NULL (subject is org-agnostic) OR equal to `manifest.organization_id`". Cross-tenant subject linkage (subject.organization_id != null AND != manifest.organization_id) is forbidden under `bundle_subtype = "customer-scoped"`. **NITs**: F-SC-13 (`leaf_index` field schema divergence between §8 primary-event proofs + §16.8 audit-log proofs) heavy-bookmarked to BACKLOG (additive forward-compat backport to §8 deferred); F-SC-14 (TS `nextPowerOfTwo` Math.log2 vs bit-twiddle) closed in code (substrate uses bit-twiddle); F-SC-15 (system identifier format `^cron:[a-z0-9-]+$` vs `^system:[a-z0-9-]+$`) heavy-bookmarked. **Sentinel UUID contrapositive guard** at TS impl: customer-scoped bundles MUST NOT use the all-zero sentinel UUID as `manifestOrganizationId`; operator-only bundles MUST use the sentinel. Enforced at `buildAuditLogSubtree` (TS reference) + `audit_log_events_org_subtype_consistency` CHECK (DB) per the §16.5 contrapositive of the bundle-subtype/sentinel-UUID consistency discipline. **Forward-compat tolerance** per §15.1 unchanged: v1.0.12 is additive-on-additive (v1.0.11 + spec-clarity amendments only; no byte-shape changes to pre-v1.0.10 bundle types). **Tier A 5-reviewer composition test outcome at Phase 6.2.B Sub-arc 2: STRONG ADOPT continued at substantive engineering work**. TRIPLE-corroborated CRITICAL findings folded inline (DELETE trigger service-role bypass replaced with canonical `auth.uid() IS NULL` pattern per `profiles_block_role_updates_fn` precedent — closes code-rev CRITICAL + sec-aud HIGH + rls-policy CRITICAL); TRIPLE-corroborated admin policy collapse (4b + 4c → single `audit_log_events_admin_select`); sentinel-UUID defensive check added to customer-scoped SELECT policy (rls-policy CRITICAL unique). Documentation-vs-implementation drift sub-pattern fires AGAIN at the migration's `:296` comment-vs-`:299` code (n=2 since Pre-Phase 6 Item 2; calibration CANDIDATE → ADOPTED at n=2 per established discipline). **Heavy-bookmarked to BACKLOG with three preservation surfaces**: duplicate Merkle implementation refactor (extract to `@nuwyre/schema` with `preserveOrder` option; architectural change deferred to dedicated session); test-rls.ts 13-scenario coverage extension (Tier A rls-policy HIGH); event_id UNIQUE constraint + ingestion_signature CHECK already added inline (Tier A MEDIUM batch); F-SC-13 `leaf_index` schema divergence backport to §8 primary-event proofs (additive forward-compat amendment). **Six tenants framing**: T1 (long-term correctness) load-bearing — chose inline v1.0.12 fold over heavy-bookmark per revised Tenant 1 framing ("long-term correctness over short-term convenience"; shape clear from 5 spec-conformance NOT_IMPLEMENTABLE proposed amendments + TRIPLE-corroborated CRITICAL DELETE trigger fix); T2 (quality/reliability) load-bearing — pre-implementation pinning prevents Phase 6.2.C cross-language divergence (Go-CLI verifier extension consumes v1.0.12 contracts); T3 (security/privacy) load-bearing — sentinel-UUID defensive SELECT + canonical service-role bypass close two critical security boundaries; T5 (customer trust) load-bearing — chain integrity at audit-log-export bundles ships against v1.0.12 contract.

- **2026-05-15 (v1.0.11)** — Reconciliation amendment closing the Tier B 3-reviewer first-fix-up batch against v1.0.10. The Tier B 3-reviewer composition test at Phase 6.2.A (spec-conformance-reviewer + crypto-integrity-reviewer + security-auditor; code-reviewer + policy-evaluation-quality-reviewer explicitly OMITTED) returned 43 distinct findings of which the load-bearing pre-implementation pinning closures land here. **NOT_IMPLEMENTABLE-from-spec-alone closures** (8 findings; cross-language divergence would be guaranteed at Phase 6.2.B implementation without these): **(F1)** §16.8 `audit_log_subtree.json` proof-step field name reconciled to `"position": "left|right"` (matches §8 + §8.2 verification walker verbatim; the v1.0.10 draft used `"side"` which conflicts with the §8.2 walker's `step.position` dispatch — an external implementer reading both sections cannot determine which name a conformant subtree carries). **(F2)** §4.1 + §16.8 + §17.3 add **`audit_log_event_count`** required field (integer; REQUIRED when `bundle_type = "audit-log-export"`; MUST equal line count in `audit_log_events.jsonl`); fixture-asserted at `audit-log-missing-events/tamper.json` but spec-silent at v1.0.10 — fixture wins per Standards-Track Posture §3 fixtures-are-the-standard; spec text catches up. **(F3)** §16.3 ordering promoted to MUST-language (events_subtree_root_bytes MUST precede audit_log_subtree_root_bytes; swapping is a generation defect) + new §16.3.1 documents **empty-subtree composition** (32-byte all-zero genesis sentinel substituted for empty subtree root; rule applies to BOTH events + audit_log subtrees; covers operator-only subtype where `events.jsonl` MAY be empty). **(F4)** §16.2.1 added documenting audit-log event content_hash canonical derivation (`canonicalize({actor, subject, event_type})` per RFC 8785 JCS; SHA-256 of canonicalized bytes encoded lowercase hex); §5 KeyForBundle dispatch table extended with `audit-log-export → issuer-prod-v1` (prod) / `issuer-dev-v1` (dev); §16.2.2 added documenting audit-log chain isolation per `(organization_id, bundle_subtype)` (DISJOINT sequence space from primary event chain per §6.2; sequence_number is per-chain). **(F6)** §14.6 Check slug enum table extended with row 9 (`audit-log-merkle`); §14.1 check_slug enum string + check_id range extended (`1..9`); §14.1 checks[] cardinality bullet list unified across single-key × ephemeral-sessions × non-audit-log-export × audit-log-export 2×2 grid. **(F9)** §16.3.2 added documenting **audit log subtree leaf ordering** (`forensic.sequence_number` ascending — explicitly NOT `event_id` ascending per §8.1 primary-event rule; rationale: audit log event UUIDs are v5 deterministic which is implementation-namespace-dependent). **(F11)** §14 Check 3 + Check 4 prose extended with v1.0.10/v1.0.11 amendment paragraphs (Check 3 walks BOTH primary + audit log chains independently; Check 4 verifies BOTH primary `merkle_proofs.json` + `audit_log_subtree.json` independently); §16.9 prose updated to "Check 9 OMITTED otherwise" matching §14.1 omit-inapplicable v1.0.9 pattern. **(crypto-int H1)** §8.2 invariant amendment: per-event proof's `root` MUST equal `manifest.json:daily_root` only under single-tree composition (pre-v1.0.10 bundle types); under v1.0.10 dual-subtree composition the per-event proof's `root` equals the SUBTREE root (events_root for primary; audit_log_root for audit log), and `manifest.daily_root` is the SHA-256 composition of both subtree roots per §16.3. **IMPLEMENTABLE-WITH-LEAK closures** (load-bearing security-substrate closures): **(F5)** §14.1 checks[] cardinality unified to OMIT-inapplicable pattern (Check 8 + Check 9 are both omitted when inapplicable; not emitted as `skipped`); §16.9 "skipped otherwise" prose corrected. **(F7)** §14 fixture suite table extended with 5 rows (cross-lang-ephemeral note + 4 v1.0.10 fixtures); lead-in fixture count updated 10 → 15. **(F8)** §16.5 operator-only `organization_id` sentinel pinned in spec text to `"00000000-0000-0000-0000-000000000000"` (all-zero RFC 4122 UUID; TRIPLE-corroborated finding crypto-int C1 + sec-aud H1 + spec-conf F8 — deferred-to-operator-manual was a Standards-Track Posture §1 "moat" leak); §16.5 also adds the cross-tenant invariant: under `bundle_subtype = "customer-scoped"`, EVERY audit log event's `subject.organization_id` (when non-null) MUST equal `manifest.organization_id` — cross-tenant subject linkage is a bundle-byte-level invariant violation (sec-aud C2 closure). **(F12)** §16.4 anchor-binding rewrite: customer-export + audit-log-export bundles for the same UTC day are SEPARATE BUNDLES with SEPARATE `daily_root` values (customer-export uses single-tree events_root; audit-log-export uses dual-subtree composition); each anchored independently. The v1.0.10 prose ("MUST anchor against the same `daily_root`") was incoherent — corrected. **(F14)** §15.1 v1.0.10 backward-compat paragraph added parallel to v1.0.9 paragraph (pre-v1.0.10 verifiers fail at §4.1 closed-enum bundle_type validation; fail-loudly outcome with specific "unknown bundle_type" diagnostic). **(crypto-int H2)** §16.3 byte-encoding ambiguity closure: `events_subtree_root_bytes` and `audit_log_subtree_root_bytes` are 32 raw bytes EACH (NOT hex-decoded-from-double-hex; NOT base64); the SHA-256 input is exactly 64 bytes (32 || 32 raw byte concatenation). **(sec-aud H3)** §16.2.3 added: audit log event content payload **MUST NOT** include free-text PII (email addresses, names, phone numbers) at `actor.id` or `subject.id` positions when those fields are otherwise opaque identifiers — when an `actor.id` is a UUID, MUST NOT additionally embed an email address in the event_type or content payload. The audit log content_hash is bundle-byte-level — PII leakage into an audit-log-export bundle's bytes is permanent post-anchoring. **(sec-aud H4 + crypto-int H3 DUAL-corroborated)** §16.3 + §8.1 Merkle byte-order discipline elevated to MUST-language (raw byte concatenation; left-sibling-first per §8.2 walker; left-vs-right encoded in the `path[i].position` field per §16.8 reconciled-name). **(sec-aud C1)** §16.6 corrected: the v1.0.10 §16.1 prose referenced "(RLS enforced per §16.6)" but §16.6 carried signing topology content with zero RLS material — that cross-reference is a spec-text-absent defect. v1.0.11 §16.6 is now split: §16.6.1 (signing topology, unchanged from v1.0.10) + §16.6.2 (RLS at audit log event access, NEW; documents the customer-scoped query gate at the `audit_log` table reads + the operator-only access pattern + the `bundle_subtype` filter at bundle-generation time). **DUAL-corroborated CHECK 9 conditional ambiguity closure** (crypto-int M1 + sec-aud M3): §16.9 Check 9 dispatch text clarified — Check 9 runs WHEN-AND-ONLY-WHEN `bundle_type = "audit-log-export"`; under any other bundle_type, Check 9 is OMITTED from `checks[]` (NOT emitted as `skipped`). **DUAL-corroborated event_id derivation closure** (crypto-int M3 + sec-aud M4): §16.2 audit log event `event_id` derivation pinned to UUID v5 with namespace `urn:nuwyre:audit-log-event` (deterministic across implementations via fixed namespace UUID) + name input `<organization_id>:<sequence_number>:<timestamp_unix_ns>` (canonical string). **SPEC_GOVERNANCE.md §6 version-naming rule** rewritten to match de facto v1.0.x amendment cadence (third-dot = additive amendment per the v1.0.7 + v1.0.9 + v1.0.10 + v1.0.11 history; second-dot reserved for future delineation; first-dot for breaking amendments) — closes F10. **DEFERRED to BACKLOG** (heavy-bookmarked with three preservation surfaces): F13 SPEC_GOVERNANCE Year-3 bookmarks (named public archive mirrors + spec-repo split timing); F15 revision-history style refactor (applies retroactively to v1.0.7 + v1.0.9 + v1.0.10 + v1.0.11; pure cosmetic). **Forward-compat tolerance** per §15.1 unchanged: v1.0.11 is additive-on-additive (v1.0.10 + spec-clarity amendments only; no byte-shape changes to pre-v1.0.10 bundle types). The v1.0.10 audit-log-export bundle bytes are PRE-IMPLEMENTATION at Phase 6.2.A — no v1.0.10 bundle has been generated yet; v1.0.11 reconciles the spec text BEFORE Phase 6.2.B implementation pins byte-shape. **Tier B 3-reviewer composition test outcome at Phase 6.2.A: STRONG ADOPT** (43/43 distinct findings from omitted Tier A reviewers' composed coverage; 100% from crypto-int + 86% from sec-aud + 100% from spec-conf with 5 NOT_IMPLEMENTABLE pre-implementation-only catches that ONLY spec-conformance surfaces at pre-impl timing). Recorded at `docs/reviewer-protocol-calibration.md`. **Six tenants framing** (per revised Tenant 1 "long-term correctness over short-term convenience"): T1 (long-term correctness) load-bearing — v1.0.11 is the architecturally complete answer when shape clear (spec-conformance authored fully-drafted reconciliation text covering F1-F12; default-to-architecturally-complete chooses inline fold over heavy-bookmark per Tenant 1); T2 (quality/reliability) load-bearing — pre-implementation pinning prevents Phase 6.2.B cross-language divergence; T3 (security/privacy) load-bearing — cross-tenant invariant (sec-aud C2) + PII handling (sec-aud H3) + RLS spec-text-presence (sec-aud C1) all preserve customer data isolation; T5 (customer trust) load-bearing — first paying customer's audit-log-export bundle ships against v1.0.11 contract.

- **2026-05-15 (v1.0.10)** — Amendment adding **`audit-log-export` bundle type** for operator + customer self-service audit-log evidence surfaces. Closes Phase 6.2.A authoring per build plan v3.1.18 §"Sub-arc 6.2 — `audit_log_export.generate_artifact`" + operator manual §9 Decisions Made archive ("audit_log_export.generate_artifact deferred to Phase 6+. Option B: extend packages/evidence with audit-log-export bundle type via bundle-format-v1 spec amendment + cross-implementation conformance fixtures. Locked."). The amendment is **additive-and-discriminated** following the v1.0.9 pattern: extends the `bundle_type` enum at §4.1 from `{"customer-export", "example-demo", "sandbox-preview"}` to `{"customer-export", "example-demo", "sandbox-preview", "audit-log-export"}`; introduces optional `bundle_subtype` field at §4.1 (closed vocabulary `"customer-scoped" | "operator-only"`; REQUIRED when `bundle_type = "audit-log-export"`, FORBIDDEN otherwise); preserves single-key signing topology per Pre-Phase 6 Item 1 closure; introduces dual-subtree Merkle composition under shared daily root per §8 amendment (audit-log subtree + primary-event subtree share `daily_root = H(events_subtree_root || audit_log_subtree_root)`); preserves existing OTS + RFC 3161 + GitHub anchor semantics per §§10-12 (single anchor per day, dual-subtree daily root anchored as the §9 daily_roots `root` field). **Operator decisions locked at recon-pass 2026-05-15** (5 class (a) decisions surfaced; all resolved on default-recommendation track under revised Tenant 1 framing "long-term correctness over short-term convenience"): (D1) Merkle composition = single daily root + dual Merkle subtrees [extensible composition shape; supports future bundle types as additional subtrees rather than anchor proliferation]; (D2) signing topology = single-key [preserves Pre-Phase 6 Item 1 closure; two-key topology stays evidence-gated]; (D3) retention = 7-year default + customer-configurable upward [aligns with SOC 2 retention pattern + Type 1 readiness]; (D4) scope inheritance = both subtypes [customer-scoped (customer self-service evidence for their data access events) + operator-only (operator-side SOC 2 + regulatory inquiry response); two distinct `bundle_subtype` values]; (D5) fixture scope = minimum viable [1 valid + 3 tamper variants ship at 6.2.A; full coverage extends across 6.2.B + 6.2.C sub-arcs]. **Six new spec subsections + cross-section amendments land together**: (1) **§4.1 amendment** — `bundle_type` enum extended; new optional `bundle_subtype` field (REQUIRED iff `bundle_type = "audit-log-export"`); validates closed vocabulary `{customer-scoped, operator-only}` at parse time; (2) **§8 amendment** — Merkle tree construction extended to support dual-subtree composition: when `bundle_type = "audit-log-export"`, manifest carries `merkle_subtrees` object with `events_root` + `audit_log_root` fields; verifier MUST compute `daily_root = SHA-256(events_root_bytes || audit_log_root_bytes)` and confirm equals `manifest.daily_root`; pre-v1.0.10 bundles (single-subtree) emit `merkle_subtrees` field as ABSENT (forward-compat); (3) **NEW §16** — full audit-log-export protocol: bundle purpose + scope; audit-log event schema (extending event-v1.schema.json subset); Merkle composition; daily root anchoring (inherits OTS + RFC 3161 + GitHub semantics); bundle subtypes; signing topology; retention semantics (7-year default; customer-configurable upward); bundle file layout (`audit_log_events.jsonl` + `audit_log_subtree.json` augmenting the existing manifest + signature + events.jsonl + merkle_proofs.json + daily_roots.json artifacts); verification semantics extension (Checks 1-7 applicability + new optional Check 9 audit-log-merkle); cross-version compatibility (v1.0.7 + v1.0.9 + v1.0.10 coexistence; pre-v1.0.10 verifiers reject `bundle_type = "audit-log-export"` per §15.1 unknown-bundle-type discipline); (4) **NEW §17** — v1.0.10 compatibility surface: `bundle_format` field accepts `"nuwyre-bundle/v1"` unchanged (the major-version-stable contract per §15.1 holds); `bundle_type` accepts the 4-value extended set; `bundle_subtype` accepts the 2-value closed vocabulary when applicable; implementations declare SUPPORTED_BUNDLE_FORMATS metadata accepting the v1.0.0 / v1.0.7 / v1.0.9 / v1.0.10 amendment markers; deprecation timeline = NONE (purely additive amendment per §15.1 forward-compat tolerance); (5) **§14 amendment** — adds **Check 9 (`audit-log-merkle`)** that runs conditionally when `bundle_type = "audit-log-export"` AND `merkle_subtrees` field present: verifies the dual-subtree composition (events_root + audit_log_root) hashes to manifest.daily_root + each subtree's leaves verify against their declared root; preserves existing Check 4 (`merkle-proof`) semantics for the primary-event subtree; new `check_slug` enum entry `"audit-log-merkle"` (slot 9); §14.1 JSONOutput shape allows 9 entries in `checks[]` when audit-log-merkle check is active + retains exactly 7 for `topology = "single-key"` customer-export bundles + retains exactly 8 for `topology = "ephemeral-sessions"` sandbox-preview bundles (per v1.0.9 + this amendment); (6) **§15.1 amendment** — clarifies that audit-log-export is a v1.x-eligible additive amendment per the established forward-compat tolerance pattern; pre-v1.0.10 verifiers MUST reject `bundle_type = "audit-log-export"` (the closed-enum gate at §4.1 catches this naturally — pre-v1.0.10 verifiers fail at bundle_type validation before any later check runs); v1.0.10 verifiers accept all prior versions per backward-compat. **Forward-compat tolerance.** Pre-v1.0.10 verifiers processing pre-v1.0.10 customer-export + example-demo + sandbox-preview bundles continue to verify identically. Pre-v1.0.10 verifiers encountering a v1.0.10 `audit-log-export` bundle: fail at the §4.1 closed-enum bundle_type validation gate (existing v1.0.7 verifier behavior; the new enum value is rejected as unknown). The outcome is fail-loudly (the bundle does NOT verify under a pre-v1.0.10 verifier); the diagnostic is a specific "unknown bundle_type" error per the existing enum-validation surface. **§15.2 versioning posture.** Audit-log-export bundle type as scoped here is a backward-compatible additive amendment per §15.1; it does NOT trigger §15.2's "signing-format change" v2 condition because the customer-export + sandbox-preview signing topologies are unchanged (both continue at their v1.0.7 + v1.0.9 contracts respectively). The Merkle composition change is dual-subtree-when-bundle-type-equals-audit-log-export (gated by bundle_type); pre-v1.0.10 bundle types continue with single-tree composition. A future application of dual-subtree composition to customer-export bundles WOULD potentially trigger §15.2 v2 if it changed customer-export bundle bytes; that is explicitly out of scope for this v1.0.10 amendment. **Conformance fixtures.** Minimum viable fixture set ships with this amendment per operator Decision 5: 1 valid (`valid-audit-log-export`) + 3 tamper variants (`tampered-audit-log-event` + `audit-log-missing-events` + `forged-audit-log-merkle-subtree`) at `docs/spec/fixtures/bundle-format-v1/`. Full conformance coverage extends across Phase 6.2.B + 6.2.C sub-arcs per documented timeline. **Reference implementations** for v1.0.10 land at: `packages/evidence/src/audit-log-export.ts` (NEW; Phase 6.2.B) for the writer-side bundle generation; `apps/cli/internal/checks/check9_audit_log_merkle.go` (NEW; Phase 6.2.C) for the Go-native verifier; WASM verifier inherits Go-native source per existing build pattern. **Six tenants framing** (per revised Tenant 1 "long-term correctness over short-term convenience"): T1 (long-term correctness) load-bearing — audit-log-export is structurally correct long-term architecture per Standards-Track Posture §4 spec governance + §5 multiple-implementations-as-goal; defaulting to dual-subtree composition (D1 = Option A) chooses the extensible long-term shape over per-bundle-type root proliferation; T2 (quality/reliability) load-bearing — spec amendment correctness is foundational because every future audit-log-export bundle depends on the v1.0.10 contract; T3 (security/privacy) load-bearing — audit log bundle scope handling preserves customer data isolation via bundle_subtype gate + RLS at audit-log event access patterns; T5 (customer trust) load-bearing — audit-log-export IS the customer self-service evidence surface that compliance officers need for internal audit + regulatory inquiry response. **Phase 6.2.A operates as TIER B 3-reviewer composition test** per the calibration framework introduced at session-open: spec-conformance-reviewer + crypto-integrity-reviewer + security-auditor (code-reviewer + policy-evaluation-quality-reviewer explicitly OMITTED from Tier B — documentation + spec-amendment + cross-implementation work doesn't compose multiple cross-cutting concerns at substantive engineering density). Test outcome recorded at `docs/reviewer-protocol-calibration.md` per calibration-artifact discipline; if Tier B passes (coverage equivalent at lower session-time cost), pattern adopts at future documentation + spec-amendment work; if Tier B fails (missed findings), revert to full 5-reviewer composition at all future Phase 6+ sessions.

- **2026-05-15 (v1.0.9)** — Amendment adding **sandbox-only session-scoped ephemeral signing keys** for `bundle_type = "sandbox-preview"` bundles. Closes Pre-Phase 6 Item 2 KMS-latency mitigation for the sandbox wizard 30-second target without amending the production customer-export signing topology (which retains the v1.0.7 single-pinned-key path verbatim). The amendment is **additive-and-discriminated**: a new optional `manifest.signing.topology` field (closed vocabulary `"single-key" | "ephemeral-sessions"`; absence defaults to `"single-key"`) selects the verifier dispatch path; a new optional `manifest.signing.ephemeral_sessions[]` array (REQUIRED when `topology = "ephemeral-sessions"`, FORBIDDEN otherwise) carries per-session KMS attestation + HKDF-derived ephemeral SPKI metadata. **Scope limited to sandbox-preview**: customer-export + example-demo bundles MUST continue to emit `topology = "single-key"` (or omit the field) and sign every event with the bundle-type-dispatched pinned issuer key per §5 + §6.3. Verifiers encountering `topology = "ephemeral-sessions"` on a non-sandbox-preview bundle MUST reject with a specific topology/bundle-type mismatch error (spec §5 v1.0.9 paragraph). Six new spec subsections land together: (1) **§5 amendment** — adds `signing.topology` enum + `signing.ephemeral_sessions[]` shape to the manifest schema; (2) **§6.3 amendment** — verifier discipline routes per-event `ingestion_signature` verification by `topology` (single-key → pinned-issuer-key path unchanged; ephemeral-sessions → per-bundle ephemeral SPKI from `signing.ephemeral_sessions[0]`); (3) **NEW §6.5** — full ephemeral-session protocol: session seed construction + KMS attestation primitive + HKDF-SHA-256 derivation (`ikm = seed_bytes ‖ kms_attestation`, `salt = ""`, `info = "nuwyre/v1.0.9-ephemeral-session-key"`, `length = 32`) + Ed25519 keypair from 32-byte seed per RFC 8032 §5.1.5 + per-event signing primitive (unchanged from §6.3, signs decoded-hex `event_hash` bytes with the ephemeral private key) + verifier discipline + forward-secrecy claim scoping; (4) **§14 amendment** — adds **Check 8 (`ephemeral-session`)** that runs BEFORE Check 3 when `topology = "ephemeral-sessions"`: verifies each `ephemeral_sessions[i].kms_attestation_b64` against the pinned KMS issuer SPKI over `ephemeral_sessions[i].session_seed_bytes_b64` (decoded to raw bytes), recomputes the ephemeral Ed25519 public key via HKDF-then-RFC-8032 from `(seed_bytes ‖ attestation)`, cross-checks the recomputed SPKI matches `ephemeral_sessions[i].ephemeral_spki_b64`. Check 3's per-event signature step then routes to the ephemeral SPKI rather than the pinned-issuer SPKI when topology is ephemeral; (5) **§14.6 amendment** — `check_slug` enum gains `"ephemeral-session"` (slot 8); §14.1 JSONOutput shape allows 8 entries in `checks[]` for `topology = "ephemeral-sessions"` bundles + retains exactly 7 for `topology = "single-key"`. The `summary.passed + failed + warned + skipped` invariant becomes `== 8` for ephemeral-sessions bundles; (6) **§15.1 amendment** — clarifies that the sandbox-only-discrimination path is a backward-compatible v1.x amendment (legacy v1.0.7 verifiers processing a v1.0.9 sandbox-preview bundle SHOULD reject via the unknown-topology branch rather than misverify under single-key dispatch). **Forward-compat tolerance.** Customer-export + example-demo bundles unchanged under v1.0.9; pre-v1.0.9 verifiers processing such bundles continue to verify identically. Pre-v1.0.9 verifiers encountering a v1.0.9 sandbox-preview ephemeral bundle: per spec §1 forward-compat tolerance, they will silently tolerate the unknown `topology` + `ephemeral_sessions[]` fields (drop them on parse) and dispatch per-event signature verification through the single-key path (the legacy v1.0.7-or-earlier behavior). Check 3 then FAILS with a per-event signature mismatch — the ephemeral signing key (not the dev key) signed those events. The outcome is fail-loudly (the bundle does NOT verify under a pre-v1.0.9 verifier), but the diagnostic is a generic signature-mismatch error rather than a specific topology-rejection message. The v1.0.9 reference Go verifier emits the specific topology-rejection error (Check 3 + Check 8 both refuse unknown topology values) for cleaner operator messaging; pre-v1.0.9 verifiers emit the by-accident-of-design signature-mismatch path. Both are fail-loudly outcomes; neither admits the bundle as verified. (Spec-conformance-reviewer M5 closure 2026-05-15.) **§15.2 versioning posture.** Strategy A as scoped here (sandbox-only) is a backward-compatible additive amendment per §15.1; it does NOT trigger §15.2's "signing-format change" v2 condition because the customer-export production signing format is unchanged. A future application of ephemeral-session signing to customer-export bundles WOULD trigger §15.2 v2 (the production signing format would change) and is explicitly out of scope for this v1.0.9 amendment. **Conformance fixtures.** Two layers land at different timings:

1. **Cross-language primitive fixture (this v1.0.9 amendment)**: `docs/spec/fixtures/bundle-format-v1/cross-lang-ephemeral.json` carries `{hkdf_info, session_seed_bytes_b64, kms_attestation_b64, pinned_kms_public_key_b64, pinned_kms_spki_b64, expected_ephemeral_spki_b64, sample_event_hash_b64, sample_event_signature_b64}` — sufficient for an external implementer to validate their HKDF-SHA-256 + Ed25519 keypair derivation byte-for-byte against the canonical reference. The TS reference impl (`apps/api/src/lib/__tests__/session-signing.test.ts`) emits this fixture; the Go reference impl (`apps/cli/internal/checks/check8_ephemeral_session_test.go`) consumes it. Mismatch on either side fails CI. This fixture validates §6.5.3–§6.5.5 byte-equivalence.

2. **Bundle-level conformance fixtures (deferred to follow-up arc)**: Three full-bundle fixtures (`valid-bundle-ephemeral-sandbox/`, `forged-ephemeral-attestation/`, `mismatched-ephemeral-spki/`) at `docs/spec/fixtures/bundle-format-v1/` are TRACKED for a follow-up arc post-v1.0.9. The deferral rationale: bundle-level fixtures require a byte-stable, deterministic sandbox-preview bundle from end-to-end pipeline execution against a test database harness — substantial harness work orthogonal to the v1.0.9 protocol amendment. The cross-language primitive fixture above is sufficient for an external implementer to validate their Check 8 implementation byte-for-byte; bundle-level fixtures add coverage for the Check 3 routing surface + tamper-variant behavior, which the Go-side Check 8 unit tests (`apps/cli/internal/checks/check8_ephemeral_session_test.go`) already exercise in-process. The BACKLOG entry pins the follow-up. **Reference implementations.** TypeScript: `apps/api/src/lib/session-signing.ts` (new) implements the writer-side primitive (KMS Sign → HKDF → ephemeral keypair → per-event sign). Go: `apps/cli/internal/checks/check8_ephemeral_session.go` (new) implements the verifier-side primitive. `@noble/ed25519` is added to `packages/integrations` for the Node-side seed→keypair derivation (Node's built-in `crypto` module does not provide a direct seed→Ed25519-keypair API; `@noble/ed25519` is the well-vetted, audited, pure-JS, zero-dep alternative). Cross-language byte-for-byte equivalence of the HKDF + Ed25519 derivation is asserted by a Vitest cross-language test that emits a fixture JSON containing `{seed_b64, attestation_b64, expected_ephemeral_spki_b64}` and a Go test reads the fixture and recomputes — same byte-equivalence contract as the existing TS/Go cross-implementation oracle for content_hash + event_hash. **Six tenants framing**: T3 (security/privacy) load-bearing — forward-secrecy on session close + ephemeral private keys never persisted to disk or DB; T1 (long-term value) — sandbox wizard 30-second target met under canonical KMS path; T2 (quality/reliability) — cross-language verifier equivalence + conformance fixtures; T4 (simplicity in reason) — additive amendment; legacy verifiers untouched.
- **2026-05-13 (v1.0.7)** — Amendment formalizing the JSON output schema + aggregate verdict semantics + conformance fixture suite as part of the canonical spec, closing the **orphan-conformance-contract gap** surfaced at Phase 5.5 Session 5.5.1B via the spec-conformance-reviewer batch (6 NOT-IMPLEMENTABLE findings). Pre-v1.0.7, this spec was silent on the surfaces a conformant verifier MUST produce; the fixtures' README + `results.schema.json` defined the contract in isolation. v1.0.7 adds six new subsections to §14: (1) §14.1 **JSONOutput shape** — the canonical top-level schema (`output_format_version`, `verdict`, `exit_code`, `reason`, `checks[]`, `summary`) with `output_format_version: "1"` versioning; (2) §14.2 **Verdict enum** — closed vocabulary `pass`/`fail`/`partial_verification` with exit-code mapping (0 for pass; 1 for fail or partial; 2 reserved for invocation error); (3) §14.3 **Per-check status enum** — closed vocabulary `pass`/`fail`/`warn`/`skipped`; (4) §14.4 **Warn-fold mechanic + warn_category field** — `warns_opted_into_pass` semantics + the structured `warn_category` per-check field (NEW additive field replacing aggregate.go's warning-text substring matching) with closed vocabulary `dev_key`/`pending_ots`/`anchor_pending`/`tsa_surplus`/`""` (empty string for warns NOT in an opt-in category; spec text + schema + Go reference impl all agree on empty-string sentinel rather than JSON `null`); (5) §14.5 **Flag set** — closed vocabulary `offline`/`strict_ots`/`allow_pending_ots`/`allow_anchor_pending`/`allow_dev_key` with each flag's fold-semantics + default state; (6) §14.6 **Check slug enum** — closed vocabulary `manifest-signature`/`artifact-integrity`/`hash-chain`/`merkle-proof`/`opentimestamps`/`rfc3161`/`github` as the stable conformance-identifier per check (matches `apps/cli/internal/checks/check*_*.go` Slug() returns). §14 "Tampering fixture suite" subsection (formerly lines 1221-1236) is rewritten to match the as-built 10-fixture suite + each fixture's actual V1-verifier baseline. The Aggregate semantics subsection is expanded to reference the new §14.1-§14.6 normatively, plus a new "External implementer guidance" paragraph. **Forward-compat: pre-v1.0.7 bundles remain conformant unchanged.** No on-disk bundle-file shape changes. The verifier's JSON output gains a new `checks[].warn_category` field (additive; emitted as empty string `""` when the warn is not in an opt-in category; pre-v1.0.7 verifiers consuming v1.0.7+ output should ignore the field gracefully). Six NOT-IMPLEMENTABLE findings from Session 5.5.1B spec-conformance-reviewer batch close against this amendment: (sc-1) verdict enum + partial_verification → §14.1-§14.2; (sc-2) warn-fold substring-matching contradicts ignored-warnings contract → §14.4 warn_category structured field; (sc-3) valid-bundle 3-of-3 surplus warn → documented in §14.4 as the `tsa_surplus` warn_category (still warn-not-fail under V1; future v1.x may introduce `--allow-tsa-surplus` opt-in flag, tracked as Phase 5+ bookmark); (sc-4) `mismatched-github` network dependency → §14.5 documents offline behavior; the offline-variant fixture is now non-blocking for conformance (the network-required fixture documents the canonical contract; offline runners skip the network-dependent assertion); (sc-5) TS reference verifier conformance → new TS-driven conformance harness at `packages/example-bundle/scripts/conformance-fixtures/validate-ts.ts` (subprocess pattern: invokes the compiled Go binary and parses its JSONOutput; NOT a TS-native verifier — the historical TS verifier at `scripts/verify-bundle.ts` is preserved as-is for the marketing demo terminal; its CheckStatus enum is internal to that reference impl, not part of the conformance contract; a TS-native verifier emitting JSONOutput from independent TS source is a future arc, heavy-bookmarked); (sc-6) canonical spec orphan → this amendment adds the normative inbound reference at §3 and §14. Three-way conformance CI workflow (`.github/workflows/spec-conformance.yml`) lands alongside this amendment, running TS + Go-native + Go-WASM validators against the fixture suite + a cross-validation gate. PROVISIONAL banner removes from `docs/spec/fixtures/bundle-format-v1/README.md` at session close after the four trigger conditions are verified: (1) v1.0.7 amendment lands ✓; (2) all three implementations conform to amended spec via 3-way CI passes; (3) fixture suite results.json aligns with amended spec (no changes required — schema was already aligned); (4) 3-way CI passes against committed fixtures. **Phase 5.5 Session 5.5.1C closure: Session 5.5.1 arc closes at this amendment + 3-way CI + DropZone primitive + /verify route WASM enhancement landing.**
- **2026-05-12 (v1.0.6)** — Amendment: new §7.5.3 added formally documenting the `TriggerSchema` recursive structure + the 15-element closed-vocabulary predicate set + the field-path expression grammar in YAML pseudocode + path expression syntax (dot-access + bracketed positional + bracketed filter with AND-joined clauses) + path evaluation semantics. Closes the v1.0.5 §7.5.1 deferred-bookmark "Trigger DSL deferred to v1.0.6" (M-2 from the deferred-arc-#1 crypto-integrity-reviewer batch). Pre-amendment text directed external implementers to read `packages/policy/src/types.ts` for trigger DSL validation; v1.0.6 makes the trigger DSL implementable from spec text alone (full Standards-Track Posture §"The moat is not the spec" externalizability for the entire `pack_body_hash` canonical pre-image). No on-disk file shape changes for any conformant bundle; the TS reference impl already had `.strict()` posture at every trigger schema level + closed-vocabulary `.superRefine` predicate-count enforcement per the Arc #1 fix-up (commit `cb84023`). The v1.0.6 amendment is **spec text only** — it formalizes what the TS reference impl has emitted byte-for-byte since v1.0.5. Cross-implementation parity: a competent Python developer reading §7.5 + §7.5.1 + §7.5.3 + §7.5.2 alone, with no NuWyre source available, can produce a conformant trigger DSL validator + path expression parser + path evaluator. Existing v1.0.5-conformant bundles remain conformant unchanged; verifiers SHOULD accept bundles produced by any v1.0.x-conformant writer (forward-compat tolerance per §1). The §7.5.1 cross-references on lines 588 + 615 are updated to point to the now-landed §7.5.3 formalization. The Phase 4 acceptance fixture suite is not regenerated for v1.0.6 (no canonical pre-image bytes change); a new TS-only conformance fixture suite at `packages/policy/tests/fixtures/triggers/` exercises the trigger DSL closed-vocabulary + boolean composition + strict-mode rejection + path expression grammar + path evaluation semantics surfaces. **v1.0.6 first-fix-up batch (consolidated reviewer-triad closure):** crypto-integrity-reviewer **H-V1.0.6-1** (Scalar number branch accepts ±Infinity at parse time while spec §7.5.3.1 rejects them — Arc #1 H1 defect-class parallel) closed by `.refine(Number.isFinite)` on the Scalar number branch at `packages/policy/src/types.ts`; spec-conformance-reviewer **L-SC-1** (`not_equals`/`not_in` empty-array vacuous-true vs short-circuit-false divergence) closed by new "Empty-result short-circuit" paragraph in §7.5.3.1 (spec amended to match impl operational semantic); spec-conformance-reviewer **L-SC-3** (literal precedence ordering) closed by new "Literal precedence" paragraph in §7.5.3.3; spec-conformance-reviewer **L-SC-4** (positional-vs-filter disambiguation) closed by new "Positional-vs-filter disambiguation" paragraph in §7.5.3.3; spec-conformance-reviewer **L-SC-6** (path-string verbatim preservation) closed by new "Path-string byte preservation" paragraph in §7.5.3.5; crypto-integrity-reviewer **M-V1.0.6-2** (number-formatting edge cases) closed by new "Numeric-operand edge cases" paragraph in §7.5.3.5; code-reviewer **M-1** + crypto-integrity-reviewer **M-V1.0.6-3** cross-corroborated float-grammar-and-fixture gap closed by adding `float` to the `literal` BNF alternative in §7.5.3.3 + new `path-parse-06-accept-float-literal` fixture; spec-conformance-reviewer **NOT-IMPLEMENTABLE** §7.5.3.9 fixture-inventory drift closed by rewriting §7.5.3.9 to match the on-disk fixture suite + adding 7 priority-subset fixtures (`schema-09-reject-empty-any-array`, `schema-10-reject-scalar-infinity`, `path-parse-05..08`, `path-eval-05..06`); code-reviewer **M-2** + crypto-integrity-reviewer **L-V1.0.6-2** §7.5.3.7/§7.5.3.4 prose precision closed inline; crypto-integrity-reviewer **M-V1.0.6-1** + code-reviewer **L-2** cross-corroborated "14 predicates" comment drift in `types.ts:38` closed inline; crypto-integrity-reviewer **L-V1.0.6-1** path-evaluator.ts comment mislabeling closed inline. Reviewer-batch folding ADOPTED at n=5 (third-instance after Arc #3 + v1.0.6 first-fix-up) with the refined discriminant "≥3 of {code, DB, spec, UI-copy, RLS-policy, infra}" confirmed: v1.0.6 first-fix-up surface = {code (types.ts + path-evaluator.ts), spec (§7.5.3 + revision history), fixtures} = 3 surfaces, single consolidated commit. spec-conformance-reviewer first-natural-invocation composition test with crypto-integrity-reviewer PASSES the partition discriminant (different lenses on shared surface).
- **2026-05-12 (v1.0.5)** — Amendment: §7.5 substantially expanded with Standards-Track Posture hardening surfaced by the D4c6d crypto-integrity-reviewer + code-reviewer batch and deferred to a dedicated session (deferred arc #1; this amendment). Eight closures land together: **(H1)** Strict required-fields posture for `PackMetadataSchema` — Zod `.default()` on `applies_to.optional_industry_match` removed at `packages/policy/src/types.ts:161`; `.strict()` added at every sub-schema level (CompatibilitySchema + AuthoringSchema + AppliesToSchema + EvaluatorConfigSchema + CrossValidationConfigSchema + PackRuleSchema + PackMetadataSchema). Defaults applied at parse-time leaked into the canonical pre-image; external Python/Rust/Go/Java implementers parsing the same pack.yaml without Zod-equivalent defaults computed a different `pack_body_hash`. Strict required-fields posture closes the externalizability gap. All three starter packs (tcpa-v1, hipaa-aligned-v1, off-script-v1) already set the field explicitly so the change incurs zero pack-regen cost. **(M1)** New §7.5.2 added documenting verifier discipline for pre-v1.0.4 bundles (era-detection strategy via reproducibility test). **(M2)** §7.5 pre-image construction text clarified: `canonical_input.pack` is the YAML-parsed-then-Zod-validated metadata object, NOT raw YAML bytes; defaults are NOT applied (strict required-fields posture per H1). **(M3)** New duplicate-key handling note added to §7.5; reference implementation `packages/policy/src/loader.ts` now passes explicit `uniqueKeys: true` to the yaml parser to reject duplicate keys at parse time (defends against future library default regression). **(M4)** New file byte stability note added to §7.5; `.gitattributes` repo policy pins prompts + schemas + packs files to LF line endings to prevent Windows clone CRLF normalization from breaking hash reproducibility. **(S1)** §7.5 pre-image text clarified: the outer `pack_format_version` field is the LITERAL STRING `"1"`, NOT the numeric `1` from `pack.compatibility.pack_format_version`; reference impl uses the `PACK_FORMAT_VERSION` string constant at `PACK_FORMAT_VERSION` constant in `packages/policy/src/types.ts`. **(S2)** New §7.5.1 added formally documenting the `PackMetadataSchema` structure (field names, types, optionality, validation rules) so external implementers can reproduce pack.yaml validation from spec alone, without reading TS source. **(L1)** §7.5 canonicalization reference + reference impl `packages/schema/src/canonical.ts:canonicalizeString` now reject lone UTF-16 surrogates (high without paired low; low without preceding high) — they are valid JS strings but invalid Unicode, producing implementation-specific UTF-8 bytes. L3 from the same D4c6d batch was closure-via-non-reproduction (original reviewer text not preserved; honest skip). Reference impl tests: `packages/schema/tests/canonical.test.ts` extended with 8 lone-surrogate scenarios (56 → 89 schema tests); `packages/policy/tests/loader.test.ts` extended with 3 H1 strict-required-fields tests + 1 M3 duplicate-key test (110 → 114 policy tests). No on-disk file shape changes from v1.0.4 → v1.0.5 except (a) reference impl now rejects packs that omit `optional_industry_match` (which all three starter packs already set explicitly), (b) reference impl now rejects packs with duplicate YAML keys (defensive; no prior production pack exercised this path). External implementers SHOULD adopt the strict required-fields posture (no defaults) for their PackMetadataSchema equivalents; verifiers SHOULD accept bundles produced by any v1.0.x-conformant writer (forward-compat tolerance per §1).
- **2026-05-12 (v1.0.4)** — Amendment: §7.5 added formalizing the precise pre-image construction for `pack_body_hash` / `manifest.pack_subscriptions[].body_hash` (the bundle-side B-style canonical pack-identity hash). Closes the Standards-Track Posture externalizability gap surfaced at Phase 5 Session 1.2.C via crypto-integrity-reviewer report §3 + §7.2 (Coupling 3 reconciliation arc) + §10 Resolution operator decision (commit `0c77bbb`; A × E + JCS-fix-now). Pre-amendment text at §7 + §3 left the precise pre-image silent ("SHA-256 of the policy pack body" / "SHA-256 of the pack's canonicalized body"); external implementers in Python/Rust/Java could not reproduce the hash from spec alone. Implementation defect at `packages/policy/src/loader.ts:205` used `JSON.stringify(schemaContent)` (non-canonical; JS-engine-specific own-property insertion order) which produced bytes that non-JavaScript implementers could not reproduce from `schemas/*.json` files. v1.0.4 amendment + fix at loader.ts now uses `canonicalize(schemaContent)` from `@nuwyre/schema` (RFC 8785 JCS-conformant; lexicographic key ordering; deterministic across implementations). §7.5 also clarifies the distinction between bundle-side `pack_body_hash` (B-style) and issuer-side DB column `policy_packs.body_yaml_hash` (A-style row-provenance hash; added at D4c6a; **not** a verifier chain participant). v1.0.3 → v1.0.4 migration note: pre-fix bundles carry JS-engine-specific bytes and are non-portable; post-fix bundles are bytes-portable across all conformant JCS implementers. Verifiers SHOULD accept either era's hash semantic on v1.0.x-stamped bundles (forward-compat tolerance per §1). Phase 4 acceptance fixtures regenerated at this revision; the example-bundle pipeline now emits the v1.0.4-conformant hash. No `bundle_format` change (still `nuwyre-bundle/v1`); no on-disk file shape changes; the hash value at `pack_subscriptions[].body_hash` + `evaluations.jsonl[].pack_body_hash` is the only material change in bytes-on-disk.
- **2026-05-10 (v1.0.3)** — Amendment: §6.3 rewritten to document **decoded-hex `event_hash` byte** signature semantics matching the post-Path-A implementation reality (`apps/api/src/lib/keys.ts:120-141` production signing path with explicit comment "we sign the RAW event_hash bytes, NOT the hex string"). Pre-amendment text described "Ed25519 signature over the canonicalized event payload (the JCS-serialized JSON object minus the `ingestion_signature` field itself)" — production has never signed a canonicalized JSON payload; the writer signs the 32-byte decoded form of the `event_hash` field directly. Verifier discipline section added explicitly: MUST decode the hex string to 32 bytes; MUST NOT pass the hex string, raw line bytes, or any canonicalized form. Forward-compatibility rationale (writer extension fields don't affect the signature because `event_hash` derivation only reads the four canonical fields per §6.2). Path A.1 reconciliation closure: this amendment closes the second of the two intentional spec/code divergences flagged during Phase 4 Session 2 implementation. No `bundle_format` change; no on-disk file shape changes; existing per-event signatures (post-Path-A production output, plus the regenerated example bundle) are conformant unchanged.
- **2026-05-10 (v1.0.2)** — Amendment: §6.2 rewritten to document **per-organization** chain semantics matching the post-Path-A implementation reality (Phase 4 Prereq Session A's `organization_chain_state` migration). Pre-amendment text described "ONE GLOBAL CHAIN ordered by `(session_id, sequence_number)`" — production ingestion since Path A emits a single per-organization chain with `session_id` as a column tag participating in queries but NOT in chain construction. Verifier discipline section added explicitly to prevent third-party implementations from reproducing the per-session-group-and-walk pattern that the pre-Path-A example bundle generator (`packages/example-bundle/scripts/lib/compose-events.ts`) emitted and the pre-Path-A verifiers (TS `verify-bundle.ts`, Go `check3_chain.go`) validated. Path A.1 reconciliation (2026-05-10): all six consumer surfaces brought in line with per-organization semantics; example bundle regenerated; both reference verifiers updated; spec amended. No `bundle_format` change (still `nuwyre-bundle/v1`); no on-disk file shape changes; existing per-organization-chain bundles (post-Path-A production output) are conformant unchanged. Pre-Path-A bundles (per-session chains) are non-conformant and correctly fail post-amendment verifiers.
- **2026-05-10 (v1.0.1)** — Amendment: documented `evaluations.jsonl` row schema as new §7. Old §7-§14 renumbered to §8-§15. Closes a Phase 4 Session 1 D3c1 reviewer-surfaced gap (the spec lacked a per-line schema for evaluations even though §3 required the file and §4.1 required aggregate counts). Additive: bundle_format remains `nuwyre-bundle/v1`; on-disk file shapes unchanged; no cryptographic computation changes. Cross-implementation parity: TS reference implementation (`packages/example-bundle/scripts/lib/canned-evaluator.ts`) was already producing the canonical schema; Go reader (`apps/cli/internal/bundle/types.go:EvaluationJSONL`) was reviewer-aligned to it during D3c1. The amendment documents what bundles already carry.
- **2026-05-09 (v1.0)** — Initial publication. Locked cross-language contract for Phase 3+ TS writer + Phase 4 Go verifier.

This document is normative for both the TypeScript writer and the Go verifier. Where this document and the Phase 2 example bundle generator's output disagree, the example bundle is right and this document must be amended; that's a documentation question. Where this document and actual bundle content (missing artifact, wrong field) disagree, that's a Phase 2 regression and must be fixed in code. Both readers and writers MUST reject any bundle whose `manifest.json:bundle_format` is not exactly `"nuwyre-bundle/v1"`.

A conformance fixture suite lives at `docs/spec/fixtures/bundle-format-v1/` (10 fixtures landed Phase 5.5 Session 5.5.1B; status: CANONICAL as of v1.0.7 — see revision history above). Three **conformance harnesses** validate the reference Go verifier source code (at `apps/cli/internal/checks/`) under different invocation patterns: Go-native in-process via `conformance_test.go`; TS-driven subprocess harness via `validate-ts.ts` (invokes the compiled native binary and parses its JSONOutput); Go-WASM-via-Node harness via `validate-wasm.ts` (loads the WASM module compiled from the same Go source). All three MUST pass every fixture's structural conformance contract per §14.1–§14.6, validated by the `.github/workflows/spec-conformance.yml` CI workflow. A fourth implementation — TS-native verifier emitting JSONOutput from independent TS source — is a future arc (heavy-bookmarked); the historical TS verifier at `packages/example-bundle/scripts/verify-bundle.ts` is preserved as-is for the marketing demo terminal and is NOT part of the conformance contract.

-----

## Table of contents

1. [Overview](#1-overview)
2. [Format identifier](#2-format-identifier)
3. [Directory layout](#3-directory-layout)
4. [`manifest.json` schema](#4-manifestjson-schema)
5. [`signature.sig`](#5-signaturesig)
6. [`events.jsonl`](#6-eventsjsonl)
7. [`evaluations.jsonl`](#7-evaluationsjsonl)
8. [`merkle_proofs.json`](#8-merkle_proofsjson)
9. [`daily_roots.json`](#9-daily_rootsjson)
10. [OpenTimestamps receipts (`ots_receipts/`)](#10-opentimestamps-receipts)
11. [RFC 3161 receipts (`rfc3161_receipts/`)](#11-rfc-3161-receipts)
12. [GitHub anchor refs (`github_anchors/`)](#12-github-anchor-refs)
13. [Audio files (`audio/`)](#13-audio-files)
14. [Verification procedure — the seven checks](#14-verification-procedure)
15. [Versioning](#15-versioning)
16. [Audit-log-export bundle type (v1.0.10)](#16-audit-log-export-bundle-type-v1010)
17. [Bundle format v1.0.10 compatibility](#17-bundle-format-v1010-compatibility)

-----

## 1. Overview

A NuWyre bundle is a self-contained zip archive that allows an external party — compliance officer, forensic reviewer, regulator, plaintiff's counsel, journalist — to independently verify the integrity of a sequence of AI agent interactions without contacting NuWyre's servers.

Each bundle covers a single organization's events for a single time window (typically one calendar day, but the spec does not assume that). It contains, in canonical order:

- The events themselves, line-delimited JSON, ordered by `sequence_number` ascending within a single per-organization hash chain (see §6.2).
- Evaluations produced for those events by NuWyre's policy-pack runtime.
- A Merkle tree over the day's events, with per-event proofs.
- A daily root and three independent anchor witnesses for that root: OpenTimestamps (Bitcoin), RFC 3161 (≥2 of 3 commercial TSAs), and an optional GitHub commit reference (production bundles).
- An Ed25519 signature over `manifest.json` by NuWyre's issuer key.
- A human-readable cover sheet (`cover.pdf`), a verification narrative (`verify.md`), and (in example bundles) a `scenario_index.json` mapping events to public validation scenarios.
- For events that reference recorded audio, the audio files themselves under `audio/<sha256>.<ext>`, content-addressed and bound into the per-event `content_hash`.

Verification means recomputing every cryptographic claim the bundle makes and confirming each one independently. The seven checks in §14 are exhaustive: a bundle that passes them has not been tampered with after generation under any threat model the chain protects against. None of the checks require trusting NuWyre.

The spec is **descriptive of behavior**, not aspirational. Where this document describes a field, an artifact, or a check, the Phase 2 example bundle generator already produces it and the example bundle's `verify.md` already exercises it manually. Phase 4's verification CLI automates the seven checks against this spec; Phase 3's customer-bundle pipeline produces bundles per this spec.

**Forward-compat tolerance.** Writers MAY emit additional fields beyond what this spec documents (e.g., a future `content.attachment_hash` field). Readers MUST silently tolerate unknown fields — drop them on parse, do not error. This applies to JSON objects throughout the bundle (manifest, events, evaluations, github_anchors, scenario_index). The forward-compat property is what lets a v1.x writer add a field without breaking a v1.0 reader. See §15.1 for sub-version increment policy.

-----

## 2. Format identifier

Every conforming bundle MUST set `manifest.json:bundle_format` to one of:

```
nuwyre-bundle/v1
nuwyre-bundle/v2
```

The TypeScript writer (`packages/evidence`) emits `nuwyre-bundle/v1` (single-Ed25519 signing) for v1.0.x bundle generation until Phase 7.F.2 lands the v2.0.0-rc1 writer extension; v2.0.0-rc1 writer emits `nuwyre-bundle/v2` (ML-DSA-65 + Ed25519 dual signing per §18). The Go verifier (`apps/cli/internal/bundle`) MUST dispatch on the `bundle_format` string: v1 bundles route through the v1.0.x single-signature verification path (legacy bundles MUST continue to verify per SPEC_GOVERNANCE.md §3.2 forensic-record-preservation invariant); v2 bundles route through the dual-signature verification path (§18.7). Both writer and verifier MUST reject any bundle with a `bundle_format` value not in the enumerated set above. Verification MUST fail on the format-identifier check before any other check runs — a v1 reader pretending to verify a v2 bundle by silently ignoring the second signature is a worse failure mode than refusing to verify it; conversely, a v2 reader pretending to verify a v1 bundle by emitting a fake ML-DSA-65 verdict against a non-existent second signature is equally wrong.

Implementations MUST also set `manifest.json:schema_version` to the matching integer per the dispatch table:

| `bundle_format` | `schema_version` (integer) | Signing topology | Status |
|---|---|---|---|
| `"nuwyre-bundle/v1"` | `1` | Single Ed25519 over canonical manifest bytes (§5) | LOCKED across v1.0.x |
| `"nuwyre-bundle/v2"` | `2` | Dual Ed25519 + ML-DSA-65 over identical canonical manifest bytes (§18) | **LOCKED at v2.0.0 (2026-05-22; Phase 7.F.4 promotion gate session 102; build-plan v3.1.55)** |

The two fields are redundant by design: `bundle_format` is the human-readable + multi-version branch identifier; `schema_version` is the machine-readable ordinal that increments per bundle-format major-version change. Verifiers SHOULD check both; readers and writers MUST. A mismatch between `bundle_format` and `schema_version` (e.g., `bundle_format = "nuwyre-bundle/v2"` paired with `schema_version = 1`) MUST be rejected with a "Check 1 FAIL (structural)" error per §18.7 failure taxonomy.

**Forward-compat for v3+**: future major versions (`nuwyre-bundle/v3` and beyond) MUST extend this enumerated set + the dispatch table; a v2 reader encountering `nuwyre-bundle/v3` MUST refuse to verify (not silently dispatch through v2 path). The same "fail-loudly rather than misverify" discipline that governs the v1-vs-v2 dispatch above applies recursively to future major versions.

-----

## 3. Directory layout

A v1 bundle, when extracted, contains the following file tree. Files marked **required** MUST be present in every bundle. Files marked **conditional** are present only when the predicate holds. Files marked **example-only** appear only when `bundle_type: "example-demo"`.

```
<bundle-root>/
├── manifest.json                                       (required)
├── signature.sig                                       (required)
├── cover.pdf                                           (required)
├── verify.md                                           (required)
├── events.jsonl                                        (required)
├── evaluations.jsonl                                   (required)
├── merkle_proofs.json                                  (required)
├── daily_roots.json                                    (required)
├── ots_receipts/
│   └── <YYYY-MM-DD>.ots                                (required, one per day)
├── rfc3161_receipts/
│   ├── <YYYY-MM-DD>__<tsa_name>.tsr                    (one per TSA that returned a valid receipt)
│   └── <YYYY-MM-DD>__<tsa_name>.chain.pem              (one per TSA that returned a valid receipt; pairs with the .tsr)
├── github_anchors/
│   └── <YYYY-MM-DD>.json                               (required when production-anchored; example bundles MAY include a placeholder per §12)
├── audio/
│   └── <sha256>.<ext>                                  (conditional — one file per audio_ref hash referenced by events)
├── scenario_index.json                                 (example-only)
└── legal/                                              (Phase 5+, conditional per bundle_type)
    ├── records-retention-policy.pdf
    ├── system-description.pdf
    └── custodian-declaration-template.pdf
```

**Naming rules.**

- All filenames are lowercase ASCII; the only allowed punctuation in filename stems is `-`, `_`, and `.`.
- The `<YYYY-MM-DD>` prefix on per-day artifacts MUST be the UTC calendar date the daily root covers.
- The `<tsa_name>` segment in RFC 3161 filenames MUST be a lowercase identifier matching the TSA name in `manifest.json:anchors.rfc3161[].tsa_name`. Default values: `freetsa`, `sectigo`, `digicert`.
- Each `.tsr` MUST have a paired `.chain.pem` of the same date and TSA — half-pairs are a generation bug.
- Audio filenames are content-addressed: `<sha256>.<ext>` where `<sha256>` is the 64-char lowercase hex SHA-256 of the file's bytes, and `<ext>` is the file extension matching the recorded MIME type. Audio paths inside the bundle MUST exactly equal the value in `manifest.json:artifacts[].path` for that file.

**Path discipline.** Bundle artifact paths in `manifest.json:artifacts[].path` are bundle-relative (`events.jsonl`, `rfc3161_receipts/2026-04-22__freetsa.tsr`). The v3.1.8 anchor-repo `root.json` schema uses bare filenames inside a `daily-roots/<date>/` directory in the anchors repo (`2026-04-22.ots`, `2026-04-22__freetsa.tsr`); the two layouts are intentionally distinct. See `packages/evidence/src/anchor-schema.ts` for the anchor-repo schema and §12 below.

-----

## 4. `manifest.json` schema

`manifest.json` is the single source of truth a verifier consults first. It declares the format, the artifact set with SHA-256 hashes, the daily root, anchor status, and signing key fingerprint. The signature in `signature.sig` covers the byte content of `manifest.json` exactly as it appears on disk.

The reference shape (descriptive — types per the Phase 2 example bundle staging output):

```jsonc
{
  "schema_version": 1,
  "bundle_format": "nuwyre-bundle/v1",
  "bundle_id": "EB-2026-04-22-CDG-DEMO-001",
  "bundle_type": "example-demo",                        // or "customer-export" in production
  "generated_at": "2026-05-08T02:17:04Z",               // ISO 8601 UTC, no fractional seconds
  "demo_day_utc": "2026-04-22",                         // for single-day bundles; YYYY-MM-DD UTC
  "organization_id": "00000000-0000-4000-8000-000000000001",
  "agent_id": "00000000-0000-4000-8000-000000000010",
  "agent_attestation_id": "00000000-0000-4000-8000-000000000020",

  "event_count": 37,
  "evaluation_count": 11,
  "flagged_count": 7,
  "clean_count": 4,
  "evaluation_source": "validation-canned",             // "live-evaluator" in production

  "daily_root": "220c62b6bae6...4868c4",                // 64-char lowercase hex SHA-256

  "signing": {
    "algorithm": "ed25519",
    "key_fingerprint_spki_b64": "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=",
    "key_purpose": "DEMO ONLY — example evidence bundle. Production customer bundles use a separate Phase 5 KMS-managed key."
  },

  "anchor_status": {
    "ots_status":     "pending",                        // "pending" | "confirmed" | "failed"
    "rfc3161_status": "verified",                       // "not_attempted" | "partial" | "verified" | "failed"
    "github_status":  "not_attempted"                   // "not_attempted" | "anchor-pending" | "anchored" | "failed"
  },

  "anchors": {
    "opentimestamps": {
      "receipt_path":  "ots_receipts/2026-04-22.ots",
      "status":        "submitted-pending-bitcoin-confirmation",
      "submitted_at":  "2026-05-08T02:17:02Z"
    },
    "rfc3161": [
      {
        "tsa_name":        "freetsa",
        "receipt_path":    "rfc3161_receipts/2026-04-22__freetsa.tsr",
        "receipt_sha256":  "889cccc2...685a09",
        "chain_path":      "rfc3161_receipts/2026-04-22__freetsa.chain.pem",
        "chain_sha256":    "1175041e...2aed7b",
        "submitted_at":    "2026-05-08T02:17:02Z",
        "tsa_time":        "2026-05-08T02:17:02Z"
      },
      // ... one entry per TSA that returned a valid receipt
    ],
    "github": {
      "schema_version":  1,
      "repo":            "https://github.com/NuWyre/anchors",
      "date":            "2026-04-22",
      "commit_sha":      null,                          // null when mirror_status != "anchored"
      "path":            null,                          // e.g., "daily-roots/2026-04-22/root.json" when anchored
      "anchored_at":     null,
      "mirror_status":   "anchor-pending",              // "anchor-pending" | "anchored" | "not_attempted"
      "note":            "..."
    }
  },

  "artifacts": [
    { "path": "events.jsonl",                         "bytes": 58759,  "sha256": "f58b1737...e84b41" },
    { "path": "evaluations.jsonl",                    "bytes": 11151,  "sha256": "a7c25811...fa1de8" },
    { "path": "merkle_proofs.json",                   "bytes": 29485,  "sha256": "0270a0ef...d0caa6" },
    { "path": "daily_roots.json",                     "bytes": 165,    "sha256": "4b9a40dd...3600cca" },
    { "path": "ots_receipts/2026-04-22.ots",          "bytes": 560,    "sha256": "ad5fefb3...7f182d" },
    { "path": "github_anchors/2026-04-22.json",       "bytes": 492,    "sha256": "45df7016...e41600" },
    { "path": "scenario_index.json",                  "bytes": 7316,   "sha256": "0085f833...e303dc" },
    { "path": "cover.pdf",                            "bytes": 435222, "sha256": "e7fafb2c...80c6ca" },
    { "path": "verify.md",                            "bytes": 6826,   "sha256": "32b47a76...62dc11" },
    { "path": "rfc3161_receipts/2026-04-22__freetsa.tsr",       "bytes": 4641, "sha256": "889cccc2...685a09" },
    { "path": "rfc3161_receipts/2026-04-22__freetsa.chain.pem", "bytes": 5106, "sha256": "1175041e...2aed7b" },
    // ... one .tsr + one .chain.pem entry per TSA in anchors.rfc3161
    { "path": "audio/6f34baca...32c335c.wav",         "bytes": 335794, "sha256": "6f34baca...32c335c" }
    // ... one entry per audio file under /audio
  ],

  "audio_records": [
    {
      "sha256":       "6f34baca...32c335c",            // matches the filename stem
      "storage_path": "audio/6f34baca...32c335c.wav",  // matches artifacts[].path for this file
      "bytes":        335794,
      "duration_ms":  7613,
      "mime_type":    "audio/wav"
    }
    // ... one entry per audio file
  ],

  "pack_subscriptions": [
    {
      "pack_id":       "tcpa-v1",
      "pack_version":  "1.0.0",
      "body_hash":     "1fc3dd49...afeca9"             // SHA-256 of canonicalize_jcs({pack_format_version, pack: metadata, prompts: prompt_hashes, schemas: schema_hashes}) — see §7.5
    }
    // ... one entry per pack the agent's organization had subscribed at the time of evaluation
  ],

  "binding": {
    "methodology_doc":            "docs/methodology/05-policy-evaluation.md",
    "methodology_section":        "5.7 Pack-validation suite binding",
    "validation_scenarios_dir":   "validation/scenarios/"
  }
}
```

### 4.1 Required and conditional fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | integer | yes | MUST equal `1` for v1 bundles OR `2` for v2.0.0-rc1+ bundles; the value MUST match `bundle_format` per the §2 dispatch table |
| `bundle_format` | string | yes | MUST equal `"nuwyre-bundle/v1"` (single-Ed25519 v1.0.x topology per §5) OR `"nuwyre-bundle/v2"` (dual-signature v2.0.0-rc1+ topology per §18) |
| `bundle_id` | string | yes | Stable identifier for this bundle. Format is implementation-defined. |
| `bundle_type` | string | yes | One of `"customer-export"`, `"example-demo"`, `"sandbox-preview"` (v1.0.9), or `"audit-log-export"` (v1.0.10). Selects the issuer key the verifier expects (see §5) + the verifier-discipline path per §16 (when `audit-log-export`). |
| `bundle_subtype` | string | conditional | REQUIRED when `bundle_type = "audit-log-export"`; FORBIDDEN otherwise. Closed vocabulary at v1.0.10: `"customer-scoped"` (customer self-service evidence surface for the customer's own audit log events) OR `"operator-only"` (operator-side SOC 2 + regulatory inquiry response artifact). See §16.5 for full semantics + verifier discipline. |
| `generated_at` | string | yes | ISO 8601 UTC, **no fractional seconds** (e.g., `2026-05-08T02:17:04Z`) |
| `demo_day_utc` | string | conditional | YYYY-MM-DD UTC. Required for single-day bundles. Multi-day bundles use a different field set in a future v1.x. |
| `organization_id` | string | yes | UUID |
| `agent_id` | string | yes | UUID |
| `agent_attestation_id` | string | yes | UUID — the `agent_attestations` row that bound the agent's identity at ingestion time |
| `event_count` | integer | yes | Must equal the number of lines in `events.jsonl` |
| `audit_log_event_count` | integer | conditional | REQUIRED when `bundle_type = "audit-log-export"` (v1.0.11 amendment per F2). MUST equal the number of lines in `audit_log_events.jsonl`. FORBIDDEN when `bundle_type != "audit-log-export"` (pre-v1.0.10 bundles omit field per forward-compat tolerance §1). |
| `evaluation_count` | integer | yes | Must equal the number of lines in `evaluations.jsonl` |
| `flagged_count` | integer | yes | Convenience aggregate; MUST equal the count of evaluations with `verdict != "clean"` |
| `clean_count` | integer | yes | Convenience aggregate; MUST equal the count of evaluations with `verdict == "clean"` |
| `evaluation_source` | string | yes | `"validation-canned"` (example bundles use canned evaluator), `"live-evaluator"` (production), or implementation-defined for forward compatibility |
| `daily_root` | string | yes | 64-char lowercase hex SHA-256 of the day's merkle root. MUST equal the `root` field in `daily_roots.json` for that day AND `merkle_proofs.json:root` |
| `signing` | object | yes | v1 bundles: flat object per §5 v1.0.x baseline (`{algorithm, key_fingerprint_spki_b64, key_purpose}` + optional `topology` + `ephemeral_sessions[]` per v1.0.9). v2.0.0-rc1+ bundles: container object per §18.1 (`{schema_version: 1, signatures: [Ed25519 entry @ index 0, ML-DSA-65 entry @ index 1]}`). The dispatch is by `bundle_format` per §2; a v2 bundle carrying a v1-shaped `signing` field MUST be rejected with a "Check 1 FAIL (structural): signing shape does not match bundle_format" error per §18.7. |
| `anchor_status` | object | yes | Per-leg anchor-status enums; see §4.2 |
| `anchors` | object | yes | Per-leg anchor metadata; see §§10-12 |
| `artifacts` | array | yes | Every file in the bundle except `manifest.json` and `signature.sig` MUST appear here, with byte size and SHA-256 |
| `audio_records` | array | conditional | Required when any event has `content.audio_ref`; otherwise MAY be omitted or empty |
| `pack_subscriptions` | array | yes | Pack identity at evaluation time. Empty array when no packs were subscribed. |
| `binding` | object | yes | Methodology document binding (see §1, last paragraph) |

### 4.2 `anchor_status` enum semantics

Three independent legs, three independent enums. A verifier MUST treat each leg's failure independently — partial-anchor states are valid bundle states, not fatal errors.

- **`ots_status`** — `"pending"` (submitted to OTS calendars; awaiting Bitcoin block confirmation; expected within ~24h), `"confirmed"` (upgrade complete; OTS receipt now contains a Bitcoin block proof), `"failed"` (submission or verification failed).
- **`rfc3161_status`** — `"not_attempted"` (no TSAs called), `"partial"` (≥1 valid receipt, but <2 verified), `"verified"` (≥2 of 3 default TSAs returned valid receipts whose chain validation passes), `"failed"` (≥1 TSA called, none returned a valid receipt).
- **`github_status`** — `"not_attempted"` (offline generation, no anchor commit attempted), `"anchor-pending"` (manual signed-commit human action queued; not yet landed), `"anchored"` (commit landed; `commit_sha` populated), `"failed"` (anchor attempt failed).

Phase 1.1 schema columns (`daily_roots.rfc3161_status`, `daily_roots.github_status`) are the authoritative ground truth for these values; the bundle reflects the row at bundle-generation time.

### 4.3 Field discipline notes

- **No fractional seconds in any ISO 8601 timestamp** anywhere in the bundle (including manifest, daily_roots.json, github_anchors/<date>.json, anchor-repo root.json). The v3.1.8 anchor schema enforces this; the bundle MUST too.
- **All hashes are 64-char lowercase hex SHA-256.** Other algorithms or other encodings are a generation bug.
- **All UUIDs are lowercase canonical form** (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
- The `artifacts` array MUST be exhaustive: a verifier checks that every file in the bundle is either `manifest.json`, `signature.sig`, OR appears in `artifacts[]`. An unlisted file is a tampering signal.
- The `artifacts` array order is implementation-defined; verification is order-independent.
- `manifest.json` itself is canonicalized via RFC 8785 JCS before signing. Both writer and verifier MUST canonicalize identically.
- **Bidirectional set-equality invariant (v2.0.0-rc1 amendment per §18.5; pre-existing in spirit at v1 but made explicit at v2)**: the bundle ZIP file-set MUST equal `{manifest.json, signature.sig} ∪ {artifacts[].path}` — no extra files (extra files fail Check 2 per §18.7 + §14), no missing files (missing files also fail Check 2). The manifest is signed BEFORE the signature container exists; therefore `manifest.artifacts[]` MUST NOT include `signature.sig` (the manifest cannot describe its own signature container's bytes; the artifacts[] entry for signature.sig would be circular). Verifiers MUST enforce both directions of the set equality.

-----

## 5. `signature.sig`

`signature.sig` is a small JSON document (not a raw signature byte string) that wraps the manifest signature(s) with verification metadata so a verifier never has to guess what was signed or with which key. The shape varies by `bundle_format` (§2 dispatch):

- **v1 (`nuwyre-bundle/v1`)** — single-Ed25519 wrapper; reference shape below; this section's prose preserved verbatim from v1.0.7 + v1.0.9 baseline.
- **v2.0.0-rc1+ (`nuwyre-bundle/v2`)** — multi-signature JSON container with EXACTLY two signature entries (Ed25519 + ML-DSA-65 positional); the multi-sig container itself MUST be RFC 8785 JCS-canonicalized when written into the bundle ZIP. Full schema at §18.2. The remainder of this §5 documents the v1 shape; §18 is the authoritative source for v2 shape + verifier discipline.

### 5.0 v1 reference shape (single Ed25519; preserved verbatim from v1.0.x baseline)

Reference shape:

```json
{
  "schema_version": 1,
  "algorithm": "ed25519",
  "key_fingerprint_spki_b64": "MCowBQYDK2VwAyEAIdvXBrE70QSF8Tmo7Kct7gU66qRRxu45gTxGOj8OpjE=",
  "signed_artifact": "manifest.json",
  "signature_b64": "T+jZZdFnNUcl5aMEo573XbO5F7h/kVuLqTuueYTAxPobkgXfB2ACTrSGgUpIAssjR9UHfZMRooW8YvlU29HGAA=="
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | integer | yes | `1` for v1 |
| `algorithm` | string | yes | `"ed25519"` for v1; future versions MAY add other curves |
| `key_fingerprint_spki_b64` | string | yes | Base64 of the SubjectPublicKeyInfo (SPKI) DER encoding of the public key |
| `signed_artifact` | string | yes | `"manifest.json"` for v1 |
| `signature_b64` | string | yes | Base64 of the raw 64-byte Ed25519 signature |

**Manifest `signing` block.** The `manifest.json:signing` object carries the signing metadata that pairs with `signature.sig`. The reference shape (v1.0.7 baseline):

```jsonc
"signing": {
  "algorithm": "ed25519",
  "key_fingerprint_spki_b64": "<base64 SPKI DER of the manifest-signing pinned issuer key>",
  "key_purpose": "<human-readable description>"
}
```

**v1.0.9 amendment — optional `topology` + `ephemeral_sessions[]` fields.** Two new optional fields land at v1.0.9 to support sandbox-preview ephemeral session signing (§6.5):

```jsonc
"signing": {
  "algorithm": "ed25519",
  "key_fingerprint_spki_b64": "<base64 SPKI DER of the pinned KMS issuer key that attests the ephemeral SPKI>",
  "key_purpose": "<human-readable description>",
  "topology": "single-key",            // OPTIONAL; closed vocabulary; default "single-key"
  "ephemeral_sessions": [              // CONDITIONAL — REQUIRED iff topology == "ephemeral-sessions"
    {
      "schema_version": 1,
      "session_id":               "<UUID — cryptographic session identifier>",
      "started_at_ns":            "<decimal string nanosecond epoch>",
      "session_seed_bytes_b64":   "<base64 of canonical-JSON session seed bytes; see §6.5>",
      "kms_attestation_b64":      "<base64 Ed25519 signature over session_seed_bytes by the pinned KMS issuer key>",
      "ephemeral_spki_b64":       "<base64 SPKI DER of the HKDF-derived ephemeral Ed25519 public key>"
    }
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `algorithm` | string | yes | `"ed25519"` |
| `key_fingerprint_spki_b64` | string | yes | Under `topology = "single-key"` (or absent): SPKI of the pinned issuer key that signs per-event hashes + manifest bytes. Under `topology = "ephemeral-sessions"`: SPKI of the **pinned KMS issuer key** that attests each `ephemeral_sessions[i].kms_attestation_b64` AND signs the manifest itself — the ephemeral keys sign per-event hashes only, NOT manifest bytes. |
| `key_purpose` | string | yes | Human-readable string |
| `topology` | string | conditional | Closed vocabulary `"single-key"` (legacy; default if omitted) OR `"ephemeral-sessions"` (sandbox-only at v1.0.9). Pre-v1.0.9 verifiers encountering an unknown topology MUST fail loudly with a specific error (no fallback to `single-key` dispatch). |
| `ephemeral_sessions` | array | conditional | REQUIRED non-empty array when `topology = "ephemeral-sessions"`; FORBIDDEN (MUST NOT be present) otherwise. v1.0.9 sandbox-preview bundles carry EXACTLY ONE entry (one ephemeral session per bundle); v2+ MAY generalize to N>1. |

**Topology-vs-bundle_type discipline (v1.0.9).** The `topology` field is constrained by `bundle_type`:

| `bundle_type` | Permitted `topology` values | Notes |
|---|---|---|
| `"customer-export"` | `"single-key"` (or field absent) | Production signing format unchanged at v1.0.9. A customer-export bundle with `topology = "ephemeral-sessions"` MUST be rejected by conformant verifiers with a topology/bundle-type mismatch error (§15.2 v2 condition not yet met). |
| `"example-demo"` | `"single-key"` (or field absent) | Example bundles continue to use the dev key + single-key topology. |
| `"sandbox-preview"` | `"single-key"` OR `"ephemeral-sessions"` | Sandbox-preview bundles MAY adopt ephemeral-sessions at v1.0.9. Pre-v1.0.9 sandbox-preview bundles emitted `topology = "single-key"` (implicit) and remain conformant. |

**Per-topology role-tag clarification for `key_fingerprint_spki_b64` (spec-conformance-reviewer M2 closure 2026-05-15).** The `manifest.signing.key_fingerprint_spki_b64` field's semantic varies by topology:

- **Under `topology = "single-key"` (or field absent):** SPKI of the pinned issuer key that signs BOTH the manifest bytes (via `signature.sig`) AND per-event `ingestion_signature` values per §6.3 single-key topology. One key, two roles.
- **Under `topology = "ephemeral-sessions"`:** SPKI of the **pinned KMS issuer key** that (a) signs the manifest bytes (via `signature.sig`) AND (b) attests each `ephemeral_sessions[i].kms_attestation_b64` over the canonical session seed bytes. The pinned KMS key does **NOT** sign per-event `ingestion_signature` values — those are signed by the per-session ephemeral keys (whose SPKIs are recorded in `ephemeral_sessions[i].ephemeral_spki_b64`). One pinned KMS key, two roles (manifest signer + attestation issuer); N ephemeral keys (per-event signers).

External implementers MUST route per-event signature verification per the topology (single-key → pinned key in `key_fingerprint_spki_b64`; ephemeral-sessions → recomputed `ephemeral_spki_b64` from §6.5.6). Mis-routing produces signature-verification failures that look like tampering but are actually verifier-discipline bugs.

**Key discipline.** Two pinned issuer keys exist (build plan §"Issuer key directory"):

- `issuer-prod-v1` — production signing key, KMS-backed (Phase 5+), used for `bundle_type: "customer-export"` bundles.
- `issuer-dev-v1` — development signing key, file-based, used for `bundle_type: "example-demo"` bundles.

The verifier MUST select the expected key by `manifest.json:bundle_type`:

- `bundle_type: "customer-export"` → MUST verify against `issuer-prod-v1` (or whichever production key was active at bundle creation time per the CLI's pinned-key directory and effective-period table).
- `bundle_type: "example-demo"` → MUST verify against `issuer-dev-v1`. The verifier emits a clear `"DEVELOPMENT BUNDLE — verified with dev key, not for production trust"` warning even on success.
- `bundle_type: "sandbox-preview"` → MUST verify against `issuer-prod-v1` under v1.0.9 ephemeral-sessions topology (the pinned KMS issuer key attests ephemeral SPKIs + signs manifest bytes; per-event signatures route to per-session ephemeral keys per §6.5). Under `topology = "single-key"` (or field absent): same as customer-export's key dispatch.
- `bundle_type: "audit-log-export"` → MUST verify against `issuer-prod-v1` (production) OR `issuer-dev-v1` (development). The key dispatch is bundle-type-driven, NOT bundle-subtype-driven; both `customer-scoped` and `operator-only` subtypes use the same signing key per §16.6.1. (v1.0.11 amendment — F4 closure: pre-v1.0.11 spec text did not include this row, leaving external implementers without a canonical key selection for audit-log-export bundles.)

Cross-key verification (e.g., a bundle claiming `customer-export` but signed with the dev key) MUST fail with a specific error pointing at the bundle-type / key mismatch.

**Multi-key support.** As production keys rotate, the CLI's pinned-key directory accumulates multiple keys with effective-period metadata. Verification of older bundles continues to work against the key active at the bundle's `generated_at`. See `apps/cli/internal/keys/` (Phase 4) and `docs/cli-key-rotation.md`.

-----

## 6. `events.jsonl`

`events.jsonl` is the canonicalized line-delimited JSON record of every event in the bundle's window. One event per line. UTF-8 encoded, LF line endings, trailing LF on the last line. Each line is a JSON object that has been canonicalized via RFC 8785 JCS — verifiers MUST canonicalize identically when recomputing hashes.

### 6.1 Per-line shape

```jsonc
{
  "schema_version": 1,
  "event_id":               "dd2588db-c25d-5a32-b1e6-afbe83435933",   // UUID v5 derived from session + sequence
  "agent_attestation_id":   "00000000-0000-4000-8000-000000000020",

  "identity": {
    "organization_id":   "00000000-0000-4000-8000-000000000001",
    "agent_id":          "00000000-0000-4000-8000-000000000010",
    "session_id":        "f3a2818b-2ad7-559a-a018-b69e23240119",
    "model_id":          "claude-sonnet-4-6",
    "model_version":     "claude-sonnet-4-6-20260101",
    "deployment_id":     null
  },

  "content": {
    "role":                  "system",                 // "system" | "user" | "assistant" | "tool"
    "content":               "...",
    "content_hash":          "d8eb68b2...b0de1",       // SHA-256 of the canonicalized content payload
    "tool_calls":            [],                       // tool-call records (when role="assistant")
    "prompt_hash":           null,                     // SHA-256 of resolved-prompt JCS bytes (when applicable)
    "system_prompt_hash":    null
    // "audio_ref" is added when this event references audio (see §6.4)
  },

  "forensic": {
    "timestamp_iso":        "2026-04-22T09:00:00Z",
    "timestamp_unix_ns":    "1776848400000000000",     // string, not number — JSON numbers lose nanoseconds
    "sequence_number":      0,
    "prev_event_hash":      "0000000000000000000000000000000000000000000000000000000000000000",
    "event_hash":           "3f034dbf...049057d0",
    "ingestion_signature":  "nHBo2C3jb12...rraDQ=="    // Ed25519 signature over the 32-byte decoded form of event_hash, base64; see §6.3
  },

  "compliance_metadata": {
    "jurisdiction":           "US",
    "retention_class":        "default",
    "legal_hold":             false,
    "consent_state":          "unknown",               // "obtained" | "denied" | "unknown" | "revoked" | ...
    "classification_labels":  ["validation-suite-bundle"],
    "redaction_applied":      false,
    "redaction_method":       "none",
    "pii_detected":           [],
    "phi_detected":           []
  },

  "provenance": {
    "source_adapter":        "validation-suite-bundle",
    "source_version":        "1.0.0",
    "ingestion_timestamp":    "2026-04-22T09:00:00Z"
  }
}
```

### 6.2 Hash chain semantics — per-organization

Each event in `events.jsonl` carries a `prev_event_hash` field referencing the previous event in the same organization's chain. **The chain is per-organization, not platform-global and not per-session:**

- Sequence numbers are gap-free per `(organization_id, sequence_number)`. The first event in an organization's chain has `sequence_number = 0` and `prev_event_hash = GENESIS_PREV_HASH` (see `packages/schema` `EventV1`).
- `prev_event_hash` on event N references event N-1's `event_hash`, where both N and N-1 belong to the same organization. Multiple sessions may interleave within an organization's chain; `prev_event_hash` references span session boundaries.
- `session_id` is a column tag, not a chain identifier. The chain's order is by `sequence_number`, not by session boundary.
- `event_hash = SHA-256( canonicalize({ prev_event_hash, content_hash, sequence_number, timestamp_unix_ns }) )`.
- The genesis sentinel `GENESIS_PREV_HASH` is the all-zero 64-char hex string (`"0" × 64`). Implementations MUST treat it as the predecessor of the first event in an organization's chain (sequence 0).

This chain semantic is the v1 canonical; **no `bundle_type` variant exists.** `example-demo` bundles use the same chain semantic as `customer-export` bundles. Future implementations of `bundle-format-v1` in any language MUST implement per-organization chain semantics; bundles emitted under divergent semantics (per-session chains, platform-global chains) are non-conformant regardless of `bundle_type`.

The chain construction prevents **whole-session deletion attacks**: deleting an entire session would leave a sequence gap (event N+1's `prev_event_hash` would no longer match event N-1's `event_hash`, and the gap-free invariant on `sequence_number` would catch the missing event explicitly). Per-organization (rather than per-session) chain construction also prevents **whole-session substitution attacks**: an attacker who replaces every event in a session with synthetic events of the same shape would have to recompute every subsequent event's `prev_event_hash` and `event_hash` across all later sessions in that organization, then re-anchor the daily root — which fails check 4 (Merkle proof verification) and checks 5/6/7 (anchor cross-checks against OpenTimestamps Bitcoin, RFC 3161, and the GitHub anchor). A per-session-chain design would let an attacker substitute one session's events without disturbing other sessions' chains, defeating substitution detection at the chain layer.

Cross-organization isolation is enforced via RLS at the database level + the chain's per-organization sequence space at the cryptographic level. A bundle exported for one organization contains only that organization's events; the chain reconstructs from the bundle's `events.jsonl` alone, with `prev_event_hash` references resolving against earlier rows in the same file.

**Verifier discipline.** Verifiers MUST sort all events by `sequence_number` ascending across the bundle and walk the chain in sequence order. Verifiers MUST NOT group by `session_id` or compute per-session chains — doing so accepts bundles that production ingestion would never produce (per-session-chain bundles where each session restarts at `GENESIS_PREV_HASH`) AND rejects bundles that conformant implementations would emit (per-organization-chain bundles where session B's first event references session A's last event_hash).

For each event, the chain-walk verifier:

1. Asserts `sequence_number` equals the expected next position in the chain (gap-free monotonic starting at 0; a gap is the canonical signal of whole-event deletion or reordering).
2. Recomputes `content_hash` from the canonical content payload; mismatch fails check 3 (§14).
3. Asserts `prev_event_hash` equals the prior event's `event_hash` (or `GENESIS_PREV_HASH` for sequence 0).
4. Recomputes `event_hash` from `{prev_event_hash, content_hash, sequence_number, timestamp_unix_ns}`; mismatch fails check 3.

Any mismatch — content drift, sequence gap, prev-hash mismatch, event-hash mismatch — fails check 3 with a specific error naming the offending event. Per-event signature verification (`ingestion_signature`) is a separate concern owned by §6.3 and may be performed alongside the chain walk or in a separate pass.

### 6.3 Per-event signature (`ingestion_signature`)

Each event carries an Ed25519 signature in the `forensic.ingestion_signature` field. **The signature input is the 32-byte decoded form of the event's `event_hash` field — NOT the 64-character hex string, NOT the raw line bytes from `events.jsonl`, NOT a canonicalized JSON form of the event content.** Production ingestion (`apps/api/src/lib/keys.ts:signEventHash`) signs `Buffer.from(eventHashHex, "hex")` (32 bytes) with the issuer's Ed25519 private key; verifiers MUST decode the hex string to 32 bytes and pass those bytes to `Ed25519.Verify` with the issuer's public key.

The decoded-hex `event_hash` signature input is the load-bearing property:

- `event_hash` is itself a SHA-256 over the canonical event structure (`{prev_event_hash, content_hash, sequence_number, timestamp_unix_ns}` per §6.2). Signing `event_hash` binds the signature to the canonical-form derivation that produced `event_hash`; tampering with any input to that hash changes `event_hash` which changes the signed bytes.
- 32 bytes (the decoded form, not the 64-character hex string) is the cryptographic primitive's natural input. Signing the hex string would add an encoding round-trip without changing the security property.
- **Forward compatibility.** Writer extension fields outside the `event_hash` computation don't affect the signature. Readers tolerate extension fields per §1 + §14; the signature remains valid because `event_hash` derivation only reads the four canonical fields above. A re-canonicalization-then-sign approach would lose extension fields on round-trip and silently break signature equality at verification time.

The signing key is selected by `manifest.signing.topology` per §5:

- **`topology = "single-key"` (default; customer-export + example-demo + legacy sandbox-preview).** Every event in the bundle is signed by the bundle-type-dispatched pinned issuer key (`customer-export` → `issuer-prod-v1`; `example-demo` → `issuer-dev-v1`; pre-v1.0.9 `sandbox-preview` → `issuer-dev-v1` via the §5 KeyForBundle dispatch). Reference implementations: `apps/api/src/lib/keys.ts:signEventHash` (production signing — explicit comment "we sign the RAW event_hash bytes, NOT the hex string"); `packages/example-bundle/scripts/lib/compose-events.ts:265-269` `signEd25519` function body (`cryptoSign(null, Buffer.from(eventHashHex, "hex"), key)`); `apps/cli/internal/checks/check3_chain.go` `Check3Chain.Run` (Go verifier — `ed25519.Verify(pub, eventHashBytes, sig)` where `eventHashBytes` is `hex.DecodeString(EventHash)`).

- **`topology = "ephemeral-sessions"` (v1.0.9 sandbox-preview only).** Every event in the bundle is signed by the **ephemeral private key** corresponding to the bundle's single `manifest.signing.ephemeral_sessions[0]` entry. The ephemeral public key (`ephemeral_sessions[0].ephemeral_spki_b64`) is the verifier-side input to `Ed25519.Verify`. The chain-of-trust binding from the pinned KMS issuer key to the ephemeral key is established by `ephemeral_sessions[0].kms_attestation_b64` (verified by Check 8 per §14 before Check 3 routes through). For v1.0.9, all events in a sandbox-preview ephemeral bundle are signed by the SAME ephemeral key — there is exactly one entry in `ephemeral_sessions[]` and per-event routing is trivial (look up `ephemeral_sessions[0].ephemeral_spki_b64`; no event-to-session mapping needed). Reference implementation: `apps/api/src/lib/session-signing.ts` `EphemeralSigningContext.sign` (writer-side); `apps/cli/internal/checks/check3_chain.go` Check3Chain.Run topology-aware branch (verifier-side); `apps/cli/internal/checks/check8_ephemeral_session.go` Check 8 (KMS attestation + HKDF re-derivation + SPKI cross-check). See §6.5 for the full protocol.

**Verifier discipline.** Verifiers MUST decode the `event_hash` hex string to its 32-byte form and pass those bytes to `Ed25519.Verify` with the **topology-dispatched** public key (single-key topology → pinned issuer key per §5; ephemeral-sessions topology → `ephemeral_sessions[0].ephemeral_spki_b64`). Verifiers MUST NOT pass the hex string, the raw `events.jsonl` line bytes, or any canonicalized form of the event content to `Ed25519.Verify` — those inputs would diverge from the signing primitive and either reject conformant bundles or accept tampered ones.

Per-event signature verification is independent from manifest signature verification (§5). The manifest's signature attests to bundle integrity at export time; per-event signatures attest to event integrity at ingestion time. A bundle with a valid manifest signature but an invalid per-event signature indicates events were already tampered at ingestion or the signing key changed mid-chain; a bundle with valid per-event signatures but an invalid manifest signature indicates bundle assembly was tampered with after individual events were signed. Both checks are required.

A failed per-event signature is a tampering signal even when the chain reconstruction (§6.2) passes — a sophisticated attacker who recomputed `content_hash` + `event_hash` (and thus passed chain reconstruction) would still need access to the signing key to produce a valid signature over the new `event_hash` bytes.

### 6.4 Audio reference (`content.audio_ref`)

When an event references recorded audio, its `content` object has an `audio_ref` sub-object:

```jsonc
"content": {
  "role": "user",
  "content": "<transcript or empty>",
  "content_hash": "...",
  "audio_ref": {
    "hash":       "6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c",
    "mime_type":  "audio/wav",
    "duration_ms": 7613
  },
  "tool_calls": [],
  "prompt_hash": null,
  "system_prompt_hash": null
}
```

`audio_ref.hash` is the SHA-256 of the audio file's bytes. **Crucially**, `audio_ref` is part of the canonical content payload, so it participates in `content_hash` and therefore in `event_hash` and in the merkle leaf. Modifying the audio bytes after ingestion changes the file's SHA-256, which would no longer equal `audio_ref.hash`, which would no longer match the chain — the audio recording itself is tamper-evident through the same chain that protects every other event field.

Audio retention can differ from event retention (some regulatory regimes require longer audio retention than text). When audio is purged before its referencing events expire, the `audio_ref` stays in the event record and the file is absent from the bundle's `audio/` directory; the verifier reports check 2 as "audio file purged per retention policy" rather than "missing artifact" iff the bundle's manifest has a documented `retention_state` indicating the policy. The `audio/` directory's contents are a snapshot at bundle generation time.

### 6.5 Sandbox session-scoped ephemeral signing keys (v1.0.9 amendment; sandbox-preview only)

Added in **v1.0.9** to mitigate KMS Sign API latency on the sandbox wizard surface (one sandbox-preview bundle = up to 500 events; per-event KMS Sign at ~80 ms each = 40 s wall-clock, violating the 30 s wizard target). Strategy A: one KMS Sign per sandbox session attests the SPKI of an HKDF-derived ephemeral Ed25519 keypair; the ephemeral private key then signs every event in the session locally (sub-millisecond per call). The chain of trust from the pinned KMS issuer key to each per-event signature traverses the KMS attestation + HKDF derivation; verifiers reconstruct the ephemeral SPKI from the canonical inputs (session seed bytes + KMS attestation) and confirm the writer's claimed SPKI byte-equals the recomputed value, then verify each per-event signature against the (now-trusted) ephemeral SPKI.

**Applicability.** v1.0.9 ephemeral-session signing is restricted to `bundle_type = "sandbox-preview"` (see §5 topology-vs-bundle_type table). Customer-export + example-demo bundles MUST continue to use `topology = "single-key"` at v1.0.9; future application of ephemeral-session signing to those bundle types would trigger §15.2's "signing-format change" v2 condition and is explicitly out of scope for v1.0.9.

**Cardinality.** A v1.0.9 sandbox-preview bundle with `topology = "ephemeral-sessions"` carries EXACTLY ONE entry in `manifest.signing.ephemeral_sessions[]`. All events in the bundle are signed by that one ephemeral key. The bundle's "cryptographic session" corresponds to one `ingestSandboxJsonl` call; the events' forensic `identity.session_id` fields (per §6.1) are independent forensic labels and DO NOT participate in the cryptographic session boundary. Future v2.x MAY generalize to N>1 ephemeral sessions per bundle with event-to-session routing; v1.0.9 sandbox-preview is N=1.

#### 6.5.1 Session seed construction

The **session seed bytes** are the RFC 8785 JCS canonical bytes of the following object, in UTF-8:

```json
{
  "schema_version": 1,
  "session_id": "<UUID v4 lowercase canonical form>",
  "started_at_ns": "<decimal-string nanosecond epoch>",
  "key_id": "<logical KMS key identifier, e.g. 'issuer-dev-v1' or 'issuer-prod-v1'>"
}
```

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | MUST be `1` for v1.0.9. Pins the seed-construction format for forward-compatibility. |
| `session_id` | string | UUID v4 lowercase canonical form (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`); generated server-side at session-begin time. This UUID also appears verbatim in `manifest.signing.ephemeral_sessions[i].session_id`. |
| `started_at_ns` | string | Decimal-string nanosecond epoch, server-stamped at session-begin time. MUST NOT include leading zeros, sign characters, or decimal points. |
| `key_id` | string | Logical identifier of the pinned KMS issuer key that produces the attestation (e.g., `"issuer-dev-v1"`, `"issuer-prod-v1"`). |

The canonical JCS bytes (the JSON object lexicographically key-sorted, with no insignificant whitespace, per RFC 8785) are then base64-encoded (no line wrapping; standard alphabet per RFC 4648 §4 — NOT URL-safe alphabet §5; `=` padding) and recorded in `ephemeral_sessions[i].session_seed_bytes_b64`. Verifiers decode this field directly to recover the raw seed bytes; they do NOT reconstruct the seed object from its individual fields (any drift between the bundle's `session_id` / `started_at_ns` / `key_id` fields and the canonical seed bytes is a tampering signal caught by Check 8's KMS-attestation verification).

**JCS lex-sort ordering (spec-conformance-reviewer M3 closure 2026-05-15).** The example object literal above lists fields in declaration order `{schema_version, session_id, started_at_ns, key_id}` for readability; RFC 8785 JCS sorts keys lexicographically before serialization. The canonical bytes are therefore key-sorted as `{"key_id":"...","schema_version":1,"session_id":"...","started_at_ns":"..."}` (UTF-8; no insignificant whitespace; integer 1 as `1`; strings UTF-8). External implementers MUST apply RFC 8785 canonicalization (lexicographic key sort + ECMA-262 number formatting + RFC 8785 §3.2.2.1 string escaping); naive declaration-order serialization produces bytes that fail attestation verification under cross-language byte-equivalence.

#### 6.5.2 KMS attestation

The pinned KMS issuer key (the SPKI in `manifest.signing.key_fingerprint_spki_b64`) produces a single Ed25519 signature over the **raw decoded** session seed bytes:

```
kms_attestation = Ed25519.Sign(pinned_kms_private_key, session_seed_bytes)
```

The signature is base64-encoded and recorded in `ephemeral_sessions[i].kms_attestation_b64`. Verifiers decode the base64 to 64 raw signature bytes, decode `session_seed_bytes_b64` to raw seed bytes, and verify:

```
Ed25519.Verify(pinned_kms_public_key, session_seed_bytes, kms_attestation) == true
```

A failure means EITHER (a) the seed bytes have been tampered with (the operator-supplied `session_id` / `started_at_ns` / `key_id` fields no longer match the canonical bytes the writer signed), OR (b) the `kms_attestation_b64` field has been tampered with, OR (c) the bundle's pinned KMS key has been substituted. All three cases are tampering signals.

#### 6.5.3 HKDF-SHA-256 derivation

The 32-byte Ed25519 seed for the ephemeral keypair is derived via HKDF-SHA-256 (RFC 5869) from the concatenation of `(session_seed_bytes ‖ kms_attestation)`:

```
ephemeral_seed = HKDF-SHA-256(
    ikm  = session_seed_bytes ‖ kms_attestation,    // concatenation of raw bytes
    salt = "",                                      // empty salt (per RFC 5869 §3.1: salt is OPTIONAL; empty → zero-byte salt)
    info = "nuwyre/v1.0.9-ephemeral-session-key",   // UTF-8 bytes of this exact literal string
    L    = 32                                       // output length in bytes
)
```

The `info` string MUST be exactly the UTF-8 bytes of the literal `"nuwyre/v1.0.9-ephemeral-session-key"` (35 bytes; no trailing newline; no NUL terminator; case-sensitive). This domain separator pins the derivation to the v1.0.9 amendment; a future v2 amendment with different derivation semantics will use a different `info` string so an attacker cannot trivially cross-replay attestation+seed pairs across spec versions.

**Explicit ikm concatenation discipline (spec-conformance-reviewer M4 closure 2026-05-15).** The `ikm` byte string is the byte-concatenation of `session_seed_bytes` (variable length, the raw JCS bytes — NOT the base64 form) followed by `kms_attestation` (exactly 64 bytes — the raw Ed25519 signature, NOT the base64 form). Total `ikm` length = `len(session_seed_bytes) + 64` bytes. Order is **seed-then-attestation**; reversing the order produces different ephemeral key bytes and breaks cross-implementation parity. Both halves are decoded from their base64 representations BEFORE concatenation; no length-prefix or separator byte is inserted between them.

**HKDF availability:** Node has `crypto.hkdfSync` (since 15.0); WebCrypto subtle has `deriveBits` with `{name:"HKDF", hash:"SHA-256", salt, info}` (Node 20+ and modern browsers); Go has `golang.org/x/crypto/hkdf`. All three produce byte-identical output for identical inputs per RFC 5869.

#### 6.5.4 Ed25519 keypair from 32-byte seed

Per RFC 8032 §5.1.5, an Ed25519 private key is derived from a 32-byte seed via:

```
h = SHA-512(ephemeral_seed)                         // 64 bytes
prefix       = h[0..32]                             // first 32 bytes (used as scalar source)
prefix[0]   &= 0xF8                                 // clamp: clear bits 0,1,2
prefix[31]  &= 0x7F                                 // clamp: clear bit 7 of byte 31
prefix[31]  |= 0x40                                 // clamp: set  bit 6 of byte 31
secret_scalar = prefix interpreted as little-endian integer mod the Ed25519 curve order
ephemeral_public_key = secret_scalar * base_point   // Ed25519 scalar multiplication
```

The 32-byte ephemeral public key is then wrapped in SPKI DER per RFC 8410 (OID `1.3.101.112` for Ed25519; standard `SubjectPublicKeyInfo` encoding) and base64-encoded:

```
ephemeral_spki_b64 = base64( DER_encode_spki( ephemeral_public_key ) )
```

The result is recorded in `ephemeral_sessions[i].ephemeral_spki_b64`. The DER-encoded SPKI for Ed25519 is exactly 44 bytes; base64 with `=` padding is 60 characters.

**Literal SPKI DER bytes (spec-conformance-reviewer M1 closure 2026-05-15).** The DER-encoded SPKI for an Ed25519 public key is exactly 44 bytes with the literal 12-byte prefix `30 2a 30 05 06 03 2b 65 70 03 21 00` (hex) followed by the 32-byte raw public key. Byte-by-byte breakdown:

| Bytes | Hex | Meaning |
|---|---|---|
| 0-1 | `30 2a` | SEQUENCE, length 42 (the rest of the SPKI) |
| 2-3 | `30 05` | SEQUENCE, length 5 (AlgorithmIdentifier) |
| 4-8 | `06 03 2b 65 70` | OID 1.3.101.112 (Ed25519); parameters ABSENT per RFC 8410 §3 |
| 9-10 | `03 21` | BIT STRING, length 33 |
| 11 | `00` | 0 unused bits |
| 12-43 | (32 raw bytes) | Ed25519 public key |

External implementers MAY use this literal prefix directly when no SPKI marshaller is available in their target language (e.g., Rust's `ed25519-dalek` does not ship an SPKI encoder; Python's `cryptography.hazmat.primitives.serialization` does but verifies the prefix shape). A conformant implementation MUST emit exactly these 44 bytes — implementations that emit a different AlgorithmIdentifier encoding (e.g., explicit NULL parameters `05 00` instead of absent parameters) are non-conformant and produce SPKI bytes that fail Check 8's byte-equality cross-check.

Implementations MUST use a conformant Ed25519 library that performs the RFC 8032 §5.1.5 derivation correctly. The TypeScript reference impl uses `@noble/ed25519`; the Go reference impl uses `crypto/ed25519` (`ed25519.NewKeyFromSeed`); both produce byte-identical SPKI bytes for byte-identical seeds. A cross-language conformance test at `apps/api/src/lib/__tests__/session-signing.cross-language.test.ts` emits a fixture JSON containing `{seed_b64, attestation_b64, expected_ephemeral_spki_b64}` and a Go-side test at `apps/cli/internal/checks/check8_ephemeral_session_test.go` reads the fixture and recomputes the SPKI; mismatch fails CI.

#### 6.5.5 Per-event signing primitive

Once the ephemeral private key is derived, per-event signing is identical in form to §6.3 but with the ephemeral private key in place of the pinned issuer private key:

```
ingestion_signature = Ed25519.Sign(ephemeral_private_key, decoded_hex(event_hash))
```

The signature input is the 32-byte decoded `event_hash` (NOT the hex string; NOT canonicalized event bytes); same primitive as §6.3, same forward-compat property (writer extension fields outside `event_hash` derivation don't affect the signature).

#### 6.5.6 Verifier discipline (Check 8 + Check 3 routing)

**Check 8 (`ephemeral-session`; v1.0.9 amendment).** A verifier processing a bundle with `manifest.signing.topology = "ephemeral-sessions"` MUST execute Check 8 BEFORE Check 3:

1. **Cardinality check.** `manifest.signing.ephemeral_sessions[]` MUST be a non-empty array. For v1.0.9, it MUST contain exactly one entry. Other cardinalities fail Check 8 with a specific error.
2. **Bundle-type check.** `manifest.bundle_type` MUST be `"sandbox-preview"` when `topology = "ephemeral-sessions"` (per §5 topology-vs-bundle_type table). Any other bundle_type fails Check 8.
3. **Per-session KMS attestation verification.** For each `ephemeral_sessions[i]`:
   - Decode `session_seed_bytes_b64` to raw seed bytes (base64-decode failure fails Check 8).
   - Decode `kms_attestation_b64` to 64 raw signature bytes (failure or wrong length fails Check 8).
   - Verify `Ed25519.Verify(pinned_kms_public_key, seed_bytes, attestation)` succeeds (the pinned KMS public key is the one declared in `manifest.signing.key_fingerprint_spki_b64`, validated against the verifier's compile-time-pinned issuer key directory per §5 bundle_type dispatch). Failure means the seed bytes or attestation have been tampered with.
4. **Per-session SPKI recomputation.** For each `ephemeral_sessions[i]`:
   - Compute `ephemeral_seed = HKDF-SHA-256(seed_bytes ‖ attestation, salt="", info="nuwyre/v1.0.9-ephemeral-session-key", L=32)`.
   - Derive the Ed25519 public key from `ephemeral_seed` via RFC 8032 §5.1.5.
   - Encode the public key as SPKI DER per RFC 8410.
   - Base64-encode the SPKI DER.
   - Confirm the base64 string byte-equals `ephemeral_sessions[i].ephemeral_spki_b64` (string equality on the base64 strings is sufficient; bytes equality on the decoded SPKI DER is equivalent). Mismatch fails Check 8 with the recomputed-vs-declared SPKI mismatch error — a tampering signal: the writer may have substituted a different ephemeral key whose attestation appears valid for an unrelated session.
5. **Build the session_id → ephemeral_pubkey map.** Successful per-session verification populates a map keyed by `ephemeral_sessions[i].session_id` with the recomputed ephemeral public key. Check 3 consults this map (under ephemeral-sessions topology) to route per-event signature verification.

**Check 3 routing (v1.0.9 amendment).** When `manifest.signing.topology = "ephemeral-sessions"`, Check 3's per-event signature verification step (§6.3) routes through the Check 8-populated map rather than the pinned issuer key:

- For v1.0.9 sandbox-preview (N=1), Check 3 looks up the single entry in the map (the bundle's one ephemeral SPKI) and verifies every event's `ingestion_signature` against it.
- A bundle with `topology = "ephemeral-sessions"` but ZERO entries in the post-Check-8 map (Check 8 having short-circuited on a prior assertion) MUST NOT have Check 3 fall back to single-key dispatch. Check 3 instead emits a verifier-internal-state error explaining that Check 8 must run successfully first.

**Verification ordering.** Check 1 (manifest signature; §5) runs FIRST as always — the manifest itself is signed by the pinned KMS issuer key under ephemeral-sessions topology. Check 8 runs BEFORE Check 3 (the new ordering at v1.0.9 for ephemeral-sessions bundles); under single-key topology Check 8 is `skipped` (no ephemeral material to verify). Check 2 (artifact integrity) is independent of topology and runs in its usual position.

#### 6.5.7 Forward-secrecy claim (scoping)

The v1.0.9 ephemeral-session protocol provides a **bounded** forward-secrecy property — bounded by what the writer's runtime environment can actually achieve:

**Claimed (provable):**
- **No persistence of ephemeral private keys.** Ephemeral private keys are NEVER written to disk OR database. The writer's data path never observes the private key bytes; only the writer process's memory holds them transiently.
- **No DB-/file-state recovery after session close.** After the writer process exits (or, for long-lived processes, after the session's containing transaction completes), no DB row or on-disk file contains the ephemeral private key OR the seed bytes from which it could be re-derived (the session seed bytes are recorded in the bundle's `session_seed_bytes_b64` field, but those bytes alone are insufficient to derive the private key without the `kms_attestation_b64` AND the HKDF derivation — and even with both, the derivation is one-way HKDF-then-Ed25519). An adversary obtaining the bundle bytes post-session-close CANNOT forge events that would have been signed during the session.

**NOT claimed (scoping):**
- **Live-process memory inspection during the session window.** Node's `crypto.KeyObject` (and the underlying OpenSSL `EVP_PKEY` handle) do NOT admit explicit byte-zeroing. The application can drop its reference to the ephemeral key, but the underlying private key bytes may remain in process memory until garbage collection eventually zeroes them. An adversary obtaining a coredump or performing a live-memory-image attack DURING the session window (between session-begin and session-close) CAN extract the ephemeral private key and forge events. This window is bounded by the duration of a single `ingestSandboxJsonl` call (typically < 1 second for a 500-event sandbox session); the threat model for v1.0.9 sandbox-preview does not include defending against in-process-memory attacks during this sub-second window.
- **KMS-side key compromise.** The pinned KMS issuer private key never leaves the KMS HSM boundary; v1.0.9 inherits the same KMS-trust assumption as the pre-v1.0.9 single-key topology. A KMS compromise voids both pre- and post-v1.0.9 bundles signed under the compromised key.

**Reference implementation discipline.** `apps/api/src/lib/session-signing.ts` drops its reference to the ephemeral `KeyObject` at session-close time and explicitly avoids passing the key bytes to any logging surface. Best-effort hygiene; not a substitute for the spec-level scoping above.

#### 6.5.8 Reference implementations + cross-language equivalence

| Surface | TypeScript | Go |
|---|---|---|
| HKDF-SHA-256 derivation | `crypto.hkdfSync` (Node built-in) | `golang.org/x/crypto/hkdf` |
| Ed25519 seed → keypair | `@noble/ed25519` library | `crypto/ed25519.NewKeyFromSeed` |
| Ed25519 sign / verify | `crypto.sign` / `crypto.verify` (Node built-in) | `crypto/ed25519.Sign` / `Verify` |
| KMS attestation Sign | `@aws-sdk/client-kms` `SignCommand` (writer-side only) | n/a (verifier reads attestation from bundle) |
| Writer-side primitive | `apps/api/src/lib/session-signing.ts` `EphemeralSigningContext` | n/a (Go-side is verifier-only) |
| Verifier-side primitive | `packages/example-bundle/scripts/verify-bundle.ts` (TS reference verifier) | `apps/cli/internal/checks/check8_ephemeral_session.go` + `check3_chain.go` topology branch |

**Cross-language equivalence.** A cross-language conformance test at `apps/api/src/lib/__tests__/session-signing.cross-language.test.ts` writes a fixture JSON (`docs/spec/fixtures/bundle-format-v1/cross-lang-ephemeral.json`) containing `{seed_b64, attestation_b64, expected_ephemeral_spki_b64}`; a Go test at `apps/cli/internal/checks/check8_ephemeral_session_test.go` reads the fixture and recomputes the SPKI. Mismatch fails CI on either side. Same byte-equivalence contract as the existing TS/Go cross-implementation oracle for `content_hash` + `event_hash` (§6.1, §6.2).

-----

## 7. `evaluations.jsonl`

`evaluations.jsonl` is the canonicalized line-delimited JSON record of every policy-pack evaluation produced for the events in this bundle's window. One evaluation per line. UTF-8 encoded, LF line endings, trailing LF on the last line. Each line is a JSON object that has been canonicalized via RFC 8785 JCS — verifiers MUST canonicalize identically when recomputing `row_hash`.

A bundle MAY have fewer evaluations than events: not every event triggers a policy-pack rule. Bundles MAY have multiple evaluations per event when more than one rule fires on the same content. Writers SHOULD emit rows in event-id ascending then rule-id ascending order for human-readability; readers MUST NOT depend on order for any verification check. **However:** the file's SHA-256 is fixed at bundle-generation time and verified by check 2 against `manifest.artifacts[].sha256`, so reordering rows after generation breaks check 2. `row_hash` is recomputable from a single row in isolation regardless of position (forensic-audit primitive), but bundle-level integrity rests on file-bytes immutability post-generation.

The aggregate counts in `manifest.json` (`evaluation_count`, `flagged_count`, `clean_count`) MUST match this file's contents per spec §4.1; check 2 (artifact integrity) verifies the file's SHA-256 against `manifest.artifacts[].sha256`. Check 3 (events.jsonl chain reconstruction, §14) is event-only; per-evaluation `row_hash` re-derivation is not currently a normative check (see §7.3 for the recommended Phase 4 Session 2-3 forensic backstop).

The `manifest.evaluation_source` field (per spec §4.1) declares HOW the verdicts were produced. v1 defines two canonical values:

- `"validation-canned"` — example bundles; the canned evaluator at `packages/example-bundle/scripts/lib/canned-evaluator.ts` reproduces each scenario's documented `expected.primary_flag` verbatim.
- `"live-evaluator"` — production bundles; verdicts come from a live LLM call.

Implementations MAY use other `evaluation_source` values for forward-compat, but doing so MUST NOT alter the row-schema requirements in §7.2; the only conditional behavior keyed off `evaluation_source` is the population of `derived_from_scenario_id` (see §7.4). A future spec amendment may register additional canonical values; until then, readers SHOULD warn (not fail) on unknown `evaluation_source` values.

### 7.1 Per-line shape

```jsonc
{
  "content_hash":              "c0507a6d6e49a0ed04e193c6c3a8c3bb449ec41d339fed8b624669148da2e67e",
  "event_id":                  "888608b0-c696-5d87-a919-20451df46711",
  "rule_id":                   "hipaa.identity_verification_before_phi",
  "pack_id":                   "hipaa-aligned-v1",
  "pack_body_hash":            "6bdea00edbae1f40a02674da92fce32c4b448796af32e0edb713911cfea07a94",  // illustrative; see manifest.json + actual fixture for bundle-specific values
  "verdict":                   "flagged",                        // "flagged" | "clean" | "uncertain"
  "severity":                  "high",                           // "info" | "low" | "medium" | "high" | "critical"
  "reasoning":                 "...",                            // human-readable rationale
  "evaluator_runtime_version": "1.0.0-canned",
  "derived_from_scenario_id":  "hipaa-001-phi-to-unverified-caller",  // present when manifest.evaluation_source == "validation-canned"
  "row_hash":                  "d6dec36455d7f5d22194f823921641f46b772affb4fbfe1d84e9e308bba54d31"
}
```

### 7.2 Field semantics

| Field | Type | Required? | Description |
|---|---|---|---|
| `content_hash` | string | yes | 64-char lowercase hex SHA-256 — MUST equal the referenced event's `content.content_hash` (cross-reference to `events.jsonl`). Pins the evaluation to the exact content evaluated; if the event's content drifts, this hash diverges and the link breaks. |
| `event_id` | string | yes | UUID — MUST match exactly one row in `events.jsonl` (the event being evaluated). Multiple evaluations MAY share the same `event_id` when multiple rules fire on one event. |
| `rule_id` | string | yes | The specific policy-pack rule that produced this verdict. Format is implementation-defined; production NuWyre rules use `<pack-prefix>.<rule-name>` (e.g., `hipaa.identity_verification_before_phi`). |
| `pack_id` | string | yes | The policy pack the rule belongs to. References a `manifest.pack_subscriptions[].pack_id`. |
| `pack_body_hash` | string | yes | 64-char lowercase hex SHA-256 of the canonical pack-identity bytes — see §7.5 for the precise pre-image construction. MUST equal `manifest.pack_subscriptions[].body_hash` for the matching `pack_id`. Cross-version drift is a tampering signal: a pack whose metadata, prompt templates, or output schemas changed after the evaluation was produced would have a different `body_hash`. (Note: this bundle field is the B-style canonical pack-identity hash; it is **distinct** from the issuer-side DB column `policy_packs.body_yaml_hash` which is a separate A-style row-provenance hash. The two share neither input space nor value; they are different hashes serving different purposes. See §7.5.) |
| `verdict` | enum | yes | One of `"flagged"`, `"clean"`, `"uncertain"`. The aggregate counts in `manifest.json` use `verdict != "clean"` as flagged (per spec §4.1). `"uncertain"` is reserved for live evaluators that explicitly model abstention; the canned evaluator does not produce it. |
| `severity` | enum | yes | One of `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`. Severity ordering is informational; the spec does not impose a numeric mapping. |
| `reasoning` | string | yes | Human-readable rationale for the verdict. For canned evaluators, this is a deterministic narrative derived from the scenario's documented expected outcome. For live evaluators, this is the evaluator's actual output. The `reasoning` field is bytes-stable across the same scenario+pack version pair when produced by the canned evaluator. |
| `evaluator_runtime_version` | string | yes | Identifies the evaluator software that produced this row. Canonical forms: `"1.0.0-canned"` (canned evaluator), `"<model>:<version>"` for live evaluators. |
| `derived_from_scenario_id` | string | conditional | Present when `manifest.evaluation_source == "validation-canned"`; references the validation scenario the verdict was derived from (matches `scenario_index.json:scenarios[].scenario_id` for example bundles). Absent when `manifest.evaluation_source == "live-evaluator"`. Implementation-defined values of `evaluation_source` define their own population rule for this field. |
| `row_hash` | string | yes | 64-char lowercase hex SHA-256 of the canonicalized row minus `row_hash` itself (see §7.3). Forensic chain-of-custody anchor: tampering that changes ANY field's bytes causes file SHA-256 to diverge and check 2 to fail; `row_hash` enables a verifier to localize WHICH row diverged. Recommended Phase 4 verifier behavior: on check-2 SHA-256 mismatch for `evaluations.jsonl`, walk rows and report the first row whose recomputed `row_hash` mismatches as `evaluations.jsonl row N row_hash mismatch — tampering signal at row N`. The mismatch surface is byte-level: an attacker who substitutes a re-canonicalized row whose every field re-canonicalizes to the same JCS bytes cannot exist, since JCS is a function of bytes-in to bytes-out. |

Verifiers MUST reject rows where any required field is missing or empty, where `verdict` or `severity` are not in their enum sets, where `content_hash` or `pack_body_hash` or `row_hash` are not 64-char lowercase hex, or where the cross-reference to `events.jsonl` via `event_id` doesn't resolve. Forward-compat tolerance applies: writer-emitted extension fields beyond this set are silently tolerated by readers (per spec §1).

### 7.3 `row_hash` computation

The verifier reproduces the writer's `row_hash` as follows:

```
partial = { all row fields EXCEPT row_hash, in any order }
row_hash = hex_lowercase( SHA-256( canonicalize_jcs(partial) ) )
```

The conditional `derived_from_scenario_id` field IS included in `partial` when present — RFC 8785 JCS canonicalization sorts keys lexicographically, so the canonical bytes are deterministic regardless of writer-side field-emission order. When `derived_from_scenario_id` is absent (live-evaluator bundles), it is omitted from `partial` entirely (NOT included as `null` or empty string).

Reference implementation: `packages/example-bundle/scripts/lib/canned-evaluator.ts:97` (TypeScript writer); `apps/cli/internal/bundle/types.go` (Go reader, types only — Phase 4 Session 2 implements the recomputation).

### 7.4 Cross-references

- `event_id` resolves to exactly one row in `events.jsonl`.
- `content_hash` MUST equal the referenced event's `content.content_hash`.
- `pack_body_hash` MUST equal `manifest.pack_subscriptions[].body_hash` for the matching `pack_id` (both are the same B-style canonical pack-identity hash per §7.5; cross-equality is bundle-internal).
- `derived_from_scenario_id` (when present) MUST match a `scenarios[].scenario_id` in `scenario_index.json` for example-demo bundles. Customer-export bundles do not include `scenario_index.json` and SHOULD NOT include this field (writers using `evaluation_source == "live-evaluator"` omit it).

The aggregate counts in `manifest.json:evaluation_count` (total rows), `flagged_count` (count of rows with `verdict != "clean"`), and `clean_count` (count of rows with `verdict == "clean"`) MUST match this file's contents exactly. The Go reader's `TestLoadCrossChecksManifestCounts` (`apps/cli/internal/bundle/load_test.go`) is one regression guard; Phase 4 Session 2's check 2 implementation is the verifier-side authoritative check.

### 7.5 `pack_body_hash` / `body_hash` computation (canonical pack-identity hash)

Added in **v1.0.4** to close the Standards-Track Posture externalizability gap surfaced at Phase 5 Session 1.2.C (commit `0c77bbb` Coupling 3 A × E + JCS-fix-now resolution). Substantially expanded in **v1.0.5** with eight Standards-Track Posture hardening closures (H1 + M1 + M2 + M3 + M4 + S1 + S2 + L1; deferred arc #1).

The `pack_body_hash` field in `evaluations.jsonl` rows and the `manifest.pack_subscriptions[].body_hash` field carry the **same** value: the SHA-256 of the RFC 8785 JCS canonical bytes of a 4-field structured pre-image. The pre-image is constructed as follows:

```
canonical_input = {
  "pack_format_version": "1",         // literal STRING "1"; see S1 note below
  "pack": <validated pack metadata>,  // strict-required-fields; see M2 note below
  "prompts": {
    "<rule.id>": <sha256_hex of UTF-8 bytes of prompts/<rule-name>.md>,
    ...
  },
  "schemas": {
    "<rule.id>": <sha256_hex of JCS canonical bytes of parse(schemas/<rule-name>.json)>,
    ...
  }
}

pack_body_hash = sha256_hex( jcs_canonicalize(canonical_input) )
```

**(S1) `pack_format_version` is a string literal, not a number.** The outer `pack_format_version` field in `canonical_input` is the literal string `"1"` (UTF-8 bytes `0x22 0x31 0x22` in JCS output). It is NOT the numeric `1` (which JCS would serialize as `0x31` without quotes). The TypeScript reference impl emits the `PACK_FORMAT_VERSION` constant from `PACK_FORMAT_VERSION` constant in `packages/policy/src/types.ts` (typed as `"1" as const`); the `pack.compatibility.pack_format_version` field on the parsed metadata is a separate numeric `1` (typed as `z.literal(1)`) and MUST NOT be substituted into the outer pre-image. External implementers MUST emit the string literal.

**(M2 + H1) `pack` is the validated metadata, not raw YAML.** The `pack` field in `canonical_input` is the result of (a) parsing the `pack.yaml` UTF-8 bytes as a JSON-compatible object, (b) running the `PackMetadataSchema` validator (see §7.5.1 for the formal schema), (c) substituting the validated object into the canonical pre-image. The schema is **strict required-fields**: defaults MUST NOT be applied at parse time; unknown fields at any nesting level MUST be rejected. This is a v1.0.5 strengthening from v1.0.4 — the prior reference impl applied a Zod `.default(false)` on `applies_to.optional_industry_match`, which leaked into the pre-image and produced different bytes across implementations. v1.0.5 reference impl removes the default + adds `.strict()` at every sub-schema level. External implementers MUST match the strict posture: a `pack.yaml` that omits any required field, or carries any unknown field, is non-conformant and MUST be rejected before hashing.

**(M3) Duplicate YAML keys are rejected at parse time.** A `pack.yaml` whose source contains duplicate keys at the same mapping level (e.g., two `name:` declarations at the top level, two `industries:` inside `applies_to:`) is non-conformant and the parser MUST reject it at every nesting depth. Silent last-wins behavior would make the canonical pre-image dependent on key-ordering in the source bytes — a Standards-Track Posture externalizability gap. The TypeScript reference impl pins `uniqueKeys: true` explicitly at every `parseYaml` call site (`packages/policy/src/loader.ts` for runtime load + `apps/admin/src/app/(authenticated)/policy-packs/actions.ts` for admin publish + `apps/admin/src/app/(authenticated)/policy-packs/[id]/page.tsx` for detail-surface validation) so the rejection is not silently regressed by a future yaml library default change. **Note on `schemas/<rule-name>.json`:** the `schemas/*.json` files are parsed via `JSON.parse`, which silently keeps the last value when duplicate keys are present (per ECMA-262 §24.5.1.1 + RFC 8785 §3.2.3 — last-wins is the universal JSON spec behavior across all conformant parsers). The canonical pre-image bytes therefore remain deterministic across implementations even if a `schemas/*.json` source contains duplicate keys. The asymmetric treatment (YAML rejects, JSON last-wins) is acceptable because the cross-implementation determinism property holds for both paths; implementations MAY tighten the JSON path to reject duplicate keys as an additional quality signal, but it is not required for spec conformance.

**(M4) Prompt and schema file bytes are read verbatim with no normalization.** Implementations read `prompts/<rule-name>.md` UTF-8 bytes directly from disk; SHA-256 is applied to the bytes as-read. Identical applies to `schemas/<rule-name>.json` parsing — the JSON is parsed first, then re-serialized via JCS, then SHA-256 (see below). Because the bytes are load-bearing for hash reproducibility, repositories storing packs MUST configure Git `.gitattributes` to prevent line-ending normalization: `prompts/** text eol=lf`, `schemas/** text eol=lf`, and `packs/** text eol=lf` (or equivalent). Writers building bundles on Windows with `core.autocrlf=true` will produce different bytes from Unix-host writers operating on the same pack.yaml source unless the `.gitattributes` policy is honored at clone time. External implementers SHOULD verify that their clone's prompt/schema file bytes match the canonical writer-side bytes (e.g., via a CI check that hashes the files and compares against the writer's expected values).

Per-rule input rules:

- `<rule.id>` is the `id` field of each rule object in the parsed pack metadata. Format: `"<namespace>.<rule-name>"`. The `<rule-name>` portion (after the dot) names the prompt + schema file (`prompts/<rule-name>.md` + `schemas/<rule-name>.json`).
- `prompts[<rule.id>]`: implementation reads the raw UTF-8 bytes of `prompts/<rule-name>.md` verbatim (no normalization; see M4 above), applies SHA-256, encodes as 64-char lowercase hex.
- `schemas[<rule.id>]`: implementation first parses `schemas/<rule-name>.json` as JSON, then **re-serializes via RFC 8785 JCS canonicalization** (lexicographic key ordering; no insignificant whitespace; ECMA-262 number formatting; RFC 8785 §3.2.2.1 string escaping), then applies SHA-256, encodes as 64-char lowercase hex. **Implementations MUST NOT hash the schema file bytes directly** — schema files may contain non-canonical whitespace or non-lexicographic key ordering; bytes-of-file is not the canonical input.

Outer canonicalization rules:

- The 4-field object is canonicalized via RFC 8785 JCS (same algorithm used for `events.jsonl` and `evaluations.jsonl` row_hash composition).
- Final hash is SHA-256 of the UTF-8 bytes of the JCS output, hex-encoded lowercase.

**(L1) Lone UTF-16 surrogates are rejected.** The reference JCS implementation MUST reject input strings containing lone surrogates (a high surrogate U+D800–U+DBFF without a paired low surrogate U+DC00–U+DFFF, or a low surrogate without a preceding high surrogate). JavaScript strings are UTF-16 and admit such lone surrogates; encoding to UTF-8 produces implementation-specific bytes (TextEncoder substitutes U+FFFD; raw-byte handling diverges across runtimes). Rejection makes the canonical pre-image UTF-8 well-formed by construction. External implementers operating on UTF-16 strings (Java, .NET) MUST apply the same validation; implementers operating on UTF-8 byte strings (Python `bytes`, Rust `&[u8]`) are unaffected — their canonicalization input is already a valid UTF-8 sequence or fails to decode upstream.

Reference implementations:

- TypeScript: `packages/policy/src/body-hash.ts:computeBodyHash` + `packages/policy/src/loader.ts` (operative path).
- JCS canonicalization: `packages/schema/src/canonical.ts` (RFC 8785-conformant; includes L1 lone-surrogate rejection per v1.0.5).
- Strict PackMetadataSchema: `packages/policy/src/types.ts` (formal schema definition in §7.5.1 below).

**Distinction from `policy_packs.body_yaml_hash` (issuer-side DB column).** The DB column `policy_packs.body_yaml_hash` introduced at Phase 5 Session 1.2.C D4c6a is a **separate hash** with **different semantics** — it is SHA-256 of the operator-pasted `body_yaml` UTF-8 bytes (A-style row-provenance), used only for issuer-side dedup/audit/corruption detection. It does NOT participate in the bundle verification chain. Verifiers MUST NOT compare `policy_packs.body_yaml_hash` against bundle `pack_body_hash`; they are not the same hash. See `docs/session-1-2-c-coupling-3-body-hash-recon-findings.md` §10 for the architectural reasoning (Candidate A × Option E resolution).

### 7.5.1 PackMetadataSchema (canonical pack input schema)

Added in **v1.0.5** (S2 closure) to make `pack.yaml` validation reproducible from spec alone, without consulting TypeScript source. External implementers SHOULD implement a validator with identical semantics in their target language.

The schema is **strict required-fields**: every field listed below is required (no `.default()` substitutions); unknown fields at any nesting level MUST be rejected.

**Regex pattern semantics.** All `<string matching /.../>` patterns below are **full-match** (anchored start-to-end). The TypeScript reference impl uses Zod's `.regex()` which is full-match by default but the regexes themselves do not carry explicit `^` and `$` anchors. External implementers writing these patterns in languages where regex defaults to substring-match (Python's `re.match`, Java's `Pattern.matcher().find()`, etc.) MUST anchor the patterns explicitly (`^pattern$`) to match the reference impl behavior. A pack with `id: "my-pack-v1-EXTRA"` MUST be rejected (`/^[a-z][a-z0-9-]*-v\d+$/`'s anchored equivalent rejects trailing characters); a non-anchored regex would admit it.

**`applies_to.industries` minimum:** the array MUST contain at least one industry string. An empty `industries: []` is non-conformant (operator state "match nothing" is rejected explicitly at spec layer + reference impl Zod `.min(1)`).

**Trigger DSL formalized in §7.5.3 (v1.0.6).** The `trigger` field inside each rule object is governed by `TriggerSchema` — a recursive union of `BooleanGroupSchema` over `FieldPredicateSchema` formally documented in §7.5.3 below. The TS schemas use `.strict()` at every level (per arc #1 fix-up) so unknown trigger fields are rejected; v1.0.6 closes the prior deferred-bookmark by reproducing the trigger DSL schema + 15-element predicate vocabulary + path expression grammar in YAML pseudocode. External implementers can now reproduce trigger DSL validation + path expression parsing + path evaluation from §7.5.3 alone (Standards-Track Posture §"The moat is not the spec" externalizability now applies to the entire `pack_body_hash` canonical pre-image).

```yaml
# Top-level PackMetadataSchema
id: <string matching /^[a-z][a-z0-9-]*-v\d+$/>          # "<namespace>-<short-name>-v<major>"
name: <non-empty string>
version: <string matching /^\d+\.\d+\.\d+$/>             # semver MAJOR.MINOR.PATCH

compatibility:                                            # CompatibilitySchema (strict)
  event_schema_version: 1                                 # numeric literal 1
  pack_format_version: 1                                  # numeric literal 1 (numeric, not string)

authoring:                                                # AuthoringSchema (strict)
  authored_by: <non-empty string>
  authored_at: <string matching /^\d{4}-\d{2}-\d{2}$/>   # YYYY-MM-DD
  reviewed_by: <non-empty string>
  legal_disclaimer: <non-empty string>

applies_to:                                               # AppliesToSchema (strict)
  industries: [<non-empty string>, ...]                   # array of industry strings
  optional_industry_match: <boolean>                      # REQUIRED (no default); true | false

rules:                                                    # array of PackRuleSchema; min 1
  - id: <string matching /^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/>   # "<namespace>.<rule-name>"
    severity: <enum: info | low | medium | high | critical>
    title: <non-empty string>
    description: <non-empty string>
    trigger: <TriggerSchema; see §7.5.3>                           # closed predicate DSL
    evaluator:                                             # EvaluatorConfigSchema (strict)
      prompt_template: <string matching /^prompts\/[\w-]+\.md$/>
      model_family: <non-empty string>
      model_version_pin: <non-empty string>
      temperature: 0                                       # numeric literal 0; mandatory zero
      max_output_tokens: <positive integer>
      output_schema: <string matching /^schemas\/[\w-]+\.json$/>
    cross_validation:                                      # CrossValidationConfigSchema (strict)
      enabled: <boolean>
      validator_model_family: <non-empty string>           # OPTIONAL (may be omitted entirely)
      validator_model_pin: <non-empty string>              # OPTIONAL
```

Note on optional fields: an "OPTIONAL" field (e.g., `cross_validation.validator_model_family`) is one that may be **omitted entirely** from the YAML source. When omitted, it MUST NOT appear in the parsed metadata; implementations MUST NOT substitute a default value or a `null` literal. The canonical pre-image then has zero bytes for the omitted key (JCS object serialization omits absent keys). This is critical: any default substitution would produce non-portable bytes across implementations.

_See §7.5.3 below for the trigger sub-schema + path expression grammar formalization (added v1.0.6)._

### 7.5.2 Verifier discipline for pre-v1.0.4 bundles

Added in **v1.0.5** (M1 closure). Bundles produced by writer implementations that pre-date the v1.0.4 JCS fix used `JSON.stringify(schemaContent)` for `schemas[<rule.id>]` pre-hashing rather than `canonicalize(schemaContent)` per RFC 8785; their `pack_body_hash` values are bytes-reproducible only from the same JS engine and not portable across implementations.

Verifiers encountering a bundle stamped `bundle_format: "nuwyre-bundle/v1"` cannot distinguish its writer era (pre-v1.0.4 vs post-v1.0.4) from metadata alone — both eras carry the same format identifier. Recommended verifier strategy:

1. **Reproduce attempt.** Compute the v1.0.4-conformant `pack_body_hash` per §7.5 against the bundled prompts + schemas files. If the result matches the bundle's `pack_body_hash`, the bundle is v1.0.4-conformant + bytes-portable (forward-compat path).
2. **Era fallback (verifier choice).** If the reproduction fails, the bundle may be pre-v1.0.4 (non-portable). Verifiers MAY:
   - **Strict mode:** reject the bundle as non-conformant.
   - **Forward-compat mode:** emit a diagnostic warning ("pre-v1.0.4 writer era; pack_body_hash not bytes-reproducible from spec") and continue verification of the remaining bundle components. The Merkle proof + signature + OTS + RFC 3161 + GitHub anchor checks remain valid independent of the pack-hash reproducibility.

Production verifiers SHOULD implement both modes + expose the choice as a CLI flag or configuration option. The forward-compat mode is the recommended default during the v1.0.x era; strict mode becomes the recommended default in v2.0.x when pre-v1.0.4 bundles are out-of-support.

Pre-v1.0.4 bundles MUST NOT be reissued as v1.0.4-conformant. Writers MUST commit to the v1.0.4-or-later semantic for all new bundle emissions. The Phase 4 acceptance fixture suite at `/spec/fixtures/bundle-format-v1/` regenerated at v1.0.4 is the canonical reference for the post-fix semantic; v1.0.5 regenerates the fixtures again after the H1 strict-required-fields posture change (no `pack_body_hash` value change is expected because all three starter packs already carry the `optional_industry_match` field explicitly, but the regeneration confirms cross-implementation parity end-to-end). The v1.0.6 amendment (§7.5.3 TriggerSchema formalization) does NOT regenerate the Phase 4 acceptance fixtures (no canonical pre-image bytes change between v1.0.5 and v1.0.6 — the TS reference impl already had strict-required-fields trigger schemas at v1.0.5 per Arc #1 fix-up); a new TS-only trigger DSL conformance fixture suite lives at `packages/policy/tests/fixtures/triggers/`.

### 7.5.3 TriggerSchema (canonical trigger DSL schema + path expression grammar)

Added in **v1.0.6** (closes the v1.0.5 §7.5.1 deferred-bookmark "Trigger DSL deferred to v1.0.6"). Makes the trigger DSL implementable from spec alone, completing the Standards-Track Posture externalizability of the entire `pack_body_hash` canonical pre-image. External implementers SHOULD implement a validator + path expression parser + path evaluator with identical semantics in their target language.

The schema is **strict required-fields** at every nesting level (matching the §7.5.1 PackMetadataSchema posture): no `.default()` substitutions; unknown fields at any level MUST be rejected. The predicate vocabulary is **closed** (15 named predicates listed in §7.5.3.1 below); predicates outside this vocabulary MUST be rejected at parse time. Boolean composition is **exactly-one** of `all`/`any`/`not`; declaring zero or multiple operator keys is non-conformant.

The `trigger` field inside each rule object is recursive:

```
TriggerSchema      ::= BooleanGroupSchema | FieldPredicateSchema
BooleanGroupSchema ::= { all:  [TriggerSchema, ...] }     // exactly one of all/any/not
                     | { any:  [TriggerSchema, ...] }     // arrays MUST be non-empty
                     | { not:   TriggerSchema       }
FieldPredicateSchema ::= { field: <path expression>, <one of the 15 predicate keys>: <value> }
```

#### 7.5.3.1 The 15-element predicate vocabulary

A `FieldPredicateSchema` declares exactly one predicate key from this closed list (parse error if zero or more than one predicate key is present):

| # | Predicate key | Value type | Semantic |
|---|---|---|---|
| 1 | `equals` | Scalar (string \| number \| boolean \| null) | At least one path-resolved value equals (deep-equal) the operand. |
| 2 | `not_equals` | Scalar | All path-resolved values are not-equal (deep-equal) to the operand. |
| 3 | `in` | array of Scalar | At least one path-resolved value is in the operand set. |
| 4 | `not_in` | array of Scalar | All path-resolved values are absent from the operand set. |
| 5 | `contains` | string | At least one path-resolved value is a string that includes the operand substring. |
| 6 | `contains_any` | array of string | At least one path-resolved value is a string that includes at least one of the operand substrings. |
| 7 | `contains_all` | array of string | At least one path-resolved value is a string that includes every operand substring. |
| 8 | `exists` | boolean | If `true`, requires at least one path-resolved value; if `false`, requires zero path-resolved values. |
| 9 | `not_exists` | boolean | If `true`, requires zero path-resolved values; if `false`, requires at least one path-resolved value. |
| 10 | `greater_than` | number | At least one path-resolved value is a number strictly greater than the operand. |
| 11 | `less_than` | number | At least one path-resolved value is a number strictly less than the operand. |
| 12 | `greater_or_equal` | number | At least one path-resolved value is a number greater-or-equal to the operand. |
| 13 | `less_or_equal` | number | At least one path-resolved value is a number less-or-equal to the operand. |
| 14 | `length_greater_than` | non-negative integer | At least one path-resolved value has length strictly greater than the operand. |
| 15 | `length_less_than` | non-negative integer | At least one path-resolved value has length strictly less than the operand. |

**Length semantic for predicates 14-15:** strings → character count (UTF-16 code units in the reference impl; external implementers MAY use code points if they document the choice in their conformance notes — character-count is a token approximation; precise tokenization is out of scope for the v1.0.x trigger DSL); arrays → element count; everything else → length is undefined and the predicate fails. Reference impl behavior: `lengthOf` returns -1 for non-string non-array values, which fails the strict `>` / `<` comparison against any non-negative operand.

**Scalar definition:** A `Scalar` value is one of: a JSON string, a JSON number (integer or float; finite; not NaN; not ±Infinity), a JSON boolean (`true` or `false`), or `null`. Arrays and objects are NOT scalars for the trigger DSL.

**Predicate keys 1-2 (`equals` / `not_equals`) deep-equal semantic:** values compared structurally (strings by codepoint sequence; numbers by IEEE-754 strict equality where NaN equals nothing; booleans by identity; null by identity). Type mismatch (e.g., comparing a string `"42"` to a number `42`) is NOT equal.

**Predicate keys 8-9 (`exists` / `not_exists`) symmetry:** `exists: true` is equivalent to `not_exists: false`; `exists: false` is equivalent to `not_exists: true`. Both are admitted to preserve operator-readable trigger DSL.

**Empty-result short-circuit (predicates 1-7, 10-15).** For all predicates EXCEPT `exists` / `not_exists`, an empty path-resolved value array MUST cause the predicate to evaluate to `false`. The `not_equals` and `not_in` predicates do NOT evaluate to vacuous-true on the empty array under universal-quantifier interpretation; they MUST evaluate to `false` because there is no value to test. This rule applies uniformly: a `field: x.absent_field` with `equals: foo` returns `false`; the same `field` with `not_equals: foo` ALSO returns `false`; the same `field` with `contains: "foo"` returns `false`; etc. `exists` / `not_exists` are the sole arity-zero predicates that evaluate against the empty array directly (`exists: false` returns `true` on empty; `exists: true` returns `false` on empty; mirror semantics for `not_exists`).

#### 7.5.3.2 BooleanGroupSchema rules

A `BooleanGroupSchema` is a JSON object declaring exactly one of:
- `all: [trigger, trigger, ...]` — boolean AND across the listed triggers; non-empty array required.
- `any: [trigger, trigger, ...]` — boolean OR across the listed triggers; non-empty array required.
- `not: trigger` — boolean negation of the inner trigger.

Declaring zero operator keys, or two or more operator keys, MUST be rejected at parse time. Empty `all: []` and `all: any:` MUST be rejected (the semantic "match nothing" via AND-over-empty / OR-over-empty is operator-error-prone; reference impl rejects to surface the error at parse time).

#### 7.5.3.3 Path expression grammar

The `field` value inside a `FieldPredicateSchema` is a **path expression** describing how to navigate from a `TriggerContext` root to the values the predicate checks. The grammar is:

```
path        = segment ( "." segment )*
segment     = identifier ( bracket_expr )*
bracket_expr= "[" ( positional | filter ) "]"
positional  = "first" | "last" | <non-negative-integer>
filter      = filter_clause ( "AND" filter_clause )*
filter_clause = identifier "=" literal
identifier  = [a-zA-Z_][a-zA-Z0-9_]*
literal     = quoted_string | "true" | "false" | float | integer | bare_identifier
quoted_string = '"' <any chars except '"'> '"' | "'" <any chars except "'"> "'"
integer     = "-"? <digit>+
float       = "-"? <digit>+ "." <digit>+
```

**Grammar rules:**
- A path MUST start with an identifier (not a `.` or `[`).
- Identifiers MUST match `[a-zA-Z_][a-zA-Z0-9_]*`.
- Multiple bracket expressions MAY chain on a single segment without `.` separators (e.g., `events[role=assistant][first]`).
- Filter clauses are joined by the literal token `AND` (uppercase; whitespace MUST surround it).
- Filter operator is exactly `=` (strict equality; no `!=`, `<`, `>`, regex, or substring inside path filters — those operators live at the predicate layer above the path).
- Empty paths MUST be rejected at parse time. Trailing `.`, unclosed `[`, and empty `[]` MUST be rejected at parse time.
- Regex inside filters is NOT supported (D1.1 closed-vocabulary rationale).
- Temporal operators (before/after/since/until) are NOT supported (D1.3 — temporal questions answered by the LLM evaluator, not the trigger DSL).

**Filter literal parsing:**
- `"foo"` or `'foo'` → string `"foo"`
- `42` → integer 42
- `-3.14` → float -3.14
- `true` / `false` → boolean
- `foo` (bare identifier) → string `"foo"` (operator convenience for common identifier-shaped values; no escape needed)

**Literal precedence.** When parsing the right-hand side of a filter clause, implementations MUST attempt matches in this strict order; the first match wins:
  1. quoted string (single or double quotes) → string
  2. `true` / `false` literal → boolean
  3. integer (`/^-?\d+$/`) → integer
  4. float (`/^-?\d+\.\d+$/`) → float (number)
  5. bare identifier matching `/^[a-zA-Z_][a-zA-Z0-9_]*$/` → string

Therefore `[x=true]` parses as boolean `true`, NOT string `"true"`; `[x=42]` parses as integer `42`, NOT string `"42"`; only `[x="true"]` with explicit quotes parses as string. This precedence is load-bearing for the strict-equality semantic in §7.5.3.4 — comparing string `"42"` (filter value with bare-identifier-but-numeric form would be ambiguous without precedence) to numeric `42` event value is NOT a match.

**Positional-vs-filter disambiguation.** Positional segments (`[first]` / `[last]` / `[N]`) are recognized by EXACT-STRING match against the trimmed bracket contents only. Any bracket contents NOT matching exactly `first`, `last`, or a non-negative integer literal MUST be parsed as a filter clause, even if the contents BEGIN with `first` or `last`. Example: `events[first=2]` parses as a filter clause (`key=first`, `value=2`), NOT as a positional `first` segment with extra characters. Example: `events[lastly]` parses as a malformed filter (no `=` separator) and is rejected at parse time.

**Examples:**
- `agent.industry` — top-level `agent` object's `industry` field.
- `events[role=assistant].content` — content fields of all events whose `role` equals `"assistant"`.
- `events[role=assistant AND severity=high].content` — content fields of events whose role is assistant AND severity is high.
- `events[last].content` — content field of the last event.
- `events[0].content` — content field of the first event.
- `agent.call_metadata.direction` — nested field path.

#### 7.5.3.4 Path evaluation semantics

A path expression evaluates against a `TriggerContext` root and returns an **array of matching values**. The trigger predicate evaluator then applies the predicate operator over the returned array.

The `TriggerContext` root carries (at minimum):
- `agent` — object with at least `industry: string | null` plus customer-defined fields.
- `session_id` — string.
- `events` — readonly array of `TriggerEvent` records. Each `TriggerEvent` carries at least `sequence: number`, `role: enum`, `content: string | null`, plus optional `metadata: object`.

**Evaluation rules:**
- Start with `current = [TriggerContext]` (a single-element array of the root).
- For each segment of the path, transform `current` via the rules below. Each rule is described as a per-element operation over `current`; let `v` denote the iterated value.
  - **`field` segment** (identifier without brackets): for each value `v` in `current`: (a) if `v` is a non-null object containing the key, append `v[key]` to the result; (b) if `v` is an array, recurse `descendField(v, key)` into each element and append the recursion result; (c) otherwise append nothing. The new `current` is the concatenation of all per-element results (flat-map semantic).
  - **`filter` segment** (`[key=value AND key=value]`): require `current` to be an array; return only the elements whose object property at `key` strictly equals `value` for every clause (clauses joined by AND). If `current` is not an array, return `[]`.
  - **`positional` segment** (`[first]` | `[last]` | `[N]`): require `current` to be an array. `[first]` returns `[current[0]]` if non-empty else `[]`. `[last]` returns `[current[current.length-1]]` if non-empty else `[]`. `[N]` returns `[current[N]]` if `0 ≤ N < length` else `[]`.
- After consuming all segments, the array of values is passed to the predicate evaluator.

**Strict-equality semantics in filter clauses:** filter clause `[role=assistant]` compares against the event's `role` value via strict type-and-value equality. The reference impl resolves `assistant` as a string (per the bare-identifier literal rule §7.5.3.3); event records have `role: string`; the comparison is `"assistant" === eventRole`. Comparing a string `"42"` filter value to a number `42` event value is NOT a match.

**Empty-result propagation:** if any segment produces an empty array, all subsequent segments propagate the empty array. The predicate evaluator then sees `values.length === 0`, and the predicate semantics determine the boolean result (e.g., `exists: false` returns true on empty; `equals: foo` returns false on empty).

#### 7.5.3.5 Canonical pre-image rules

The `trigger` field flows into the `pack_body_hash` canonical pre-image via the `pack.rules[].trigger` path of the validated PackMetadataSchema (see §7.5 + §7.5.1). The JCS canonicalization rules apply recursively:
- Object keys are sorted lexicographically at every nesting level (so `{any: [...], not: ...}` would be impossible per §7.5.3.2 — but if both keys were present, JCS would emit `any` before `not`).
- Omitted predicate keys MUST NOT appear in the canonical pre-image. Reference impl behavior: Zod `.strict()` rejects unknown keys at parse time; omitted optional predicate keys are simply not present in the parsed object.
- Omitted boolean operator keys MUST NOT appear in the canonical pre-image (same rule).
- Path expression `field` values are emitted as JSON strings verbatim (the path string itself is not canonicalized — it is opaque to JCS; the predicate evaluator parses it at runtime).
- Scalar predicate operand values follow JCS Scalar rules (RFC 8785 §3.2 for number formatting; §3.2.2.1 for string escaping; lone-surrogate rejection per §7.5 (L1)).

**Numeric-operand edge cases (inherited from JCS RFC 8785 §3.2; explicit for cross-implementation clarity).** Scalar number predicate operands flowing into the canonical pre-image MUST adhere to JCS number formatting:
- Negative zero normalizes: `-0` → canonical bytes `"0"`. A pack with `equals: -0` produces identical canonical pre-image bytes to `equals: 0`.
- Integer-precision range: JCS preserves exact representation for integers in `[-(2^53−1), +(2^53−1)]`. Outside that range, ES6 `ToString` rounds to nearest IEEE-754 representation; cross-implementation parity for such operands is NOT guaranteed. Pack authors SHOULD constrain numeric operands to the safe-integer range.
- Float trailing zeros: JCS strips trailing zeros. `1.10` and `1.1` produce identical canonical bytes; pack authors writing `equals: 1.10` get `equals: 1.1` in the pre-image.
- Finiteness enforced: NaN and ±Infinity are rejected at the schema layer (Zod refinement at `packages/policy/src/types.ts` Scalar definition; equivalent reject at parse time recommended in external impls). JCS would otherwise produce implementation-specific bytes.

**Path-string byte preservation.** The `field` string is preserved verbatim from the YAML source into the canonical pre-image. Implementations MUST NOT normalize whitespace, case, operator notation, or any other content inside the path string. Two pack.yaml files differing only in internal whitespace within a `field` string (e.g., `events[role=assistant AND severity=high]` vs `events[role=assistant  AND  severity=high]`) produce DIFFERENT `pack_body_hash` values by design — the path string is operator-author bytes. Pack authors SHOULD adopt a single internal-whitespace convention (single-space-around-AND is recommended); the reference impl emits this form in operator-facing documentation.

**Cross-implementation note (parallel to §7.5.1 line 629):** an "OPTIONAL" predicate key or boolean operator key is one that MAY be **omitted entirely** from the YAML source. When omitted, it MUST NOT appear in the parsed metadata; implementations MUST NOT substitute a default value or a `null` literal. The canonical pre-image then has zero bytes for the omitted key (JCS object serialization omits absent keys). This is critical: any default substitution would produce non-portable bytes across implementations.

#### 7.5.3.6 YAML pseudocode

```yaml
# FieldPredicateSchema — leaf node in a trigger tree.
# Exactly ONE of the 15 predicate keys MUST be present (parse error otherwise).
field: <path expression matching §7.5.3.3 grammar>      # e.g. "events[role=assistant].content"
equals: <Scalar>                                         # OPTIONAL (one of 15)
not_equals: <Scalar>                                     # OPTIONAL
in: [<Scalar>, ...]                                      # OPTIONAL
not_in: [<Scalar>, ...]                                  # OPTIONAL
contains: <string>                                       # OPTIONAL
contains_any: [<string>, ...]                            # OPTIONAL
contains_all: [<string>, ...]                            # OPTIONAL
exists: <boolean>                                        # OPTIONAL
not_exists: <boolean>                                    # OPTIONAL
greater_than: <number>                                   # OPTIONAL
less_than: <number>                                      # OPTIONAL
greater_or_equal: <number>                               # OPTIONAL
less_or_equal: <number>                                  # OPTIONAL
length_greater_than: <integer >= 0>                      # OPTIONAL
length_less_than: <integer >= 0>                         # OPTIONAL

# BooleanGroupSchema — internal node in a trigger tree.
# Exactly ONE of all/any/not MUST be present (parse error otherwise).
all: [<TriggerSchema>, <TriggerSchema>, ...]             # OPTIONAL (non-empty array)
any: [<TriggerSchema>, <TriggerSchema>, ...]             # OPTIONAL (non-empty array)
not: <TriggerSchema>                                     # OPTIONAL

# TriggerSchema — the recursive union.
# A trigger is either a BooleanGroupSchema (with one of all/any/not)
# OR a FieldPredicateSchema (with one of the 15 predicate keys).
```

#### 7.5.3.7 Worked examples

**Example 1: simple field predicate.**
```yaml
trigger:
  field: agent.industry
  equals: healthcare
```
Matches when `context.agent.industry === "healthcare"`.

**Example 2: nested boolean composition.**
```yaml
trigger:
  all:
    - field: agent.call_metadata.direction
      equals: outbound
    - any:
        - field: events[role=assistant].content
          contains: "consent"
        - field: events[role=user].content
          contains: "agreed"
```
Matches when (a) the call is outbound AND (b) either an assistant message contains "consent" OR a user message contains "agreed".

**Example 3: filter with multiple clauses.**
```yaml
trigger:
  field: events[role=assistant AND sequence=1].content
  not_exists: false
```
Matches when there exists an event with `role === "assistant"` AND `sequence === 1` AND its `content` field is present (resolves to at least one value — the field is present, regardless of whether the value is `null`; `not_exists: false` semantically means "predicate path resolves to a non-empty value array").

#### 7.5.3.8 Reference implementations

- TypeScript: `packages/policy/src/types.ts` (`TriggerSchema` + `BooleanGroupSchema` + `FieldPredicateSchema` + `PREDICATE_KEYS`); `packages/policy/src/trigger.ts` (predicate evaluator); `packages/policy/src/path-parser.ts` + `packages/policy/src/path-evaluator.ts` (path expression grammar + evaluator).
- Go: NOT IMPLEMENTED. The Go CLI (`apps/cli/internal/`) is a bundle verifier, not a runtime evaluator; it consumes `pack_body_hash` as a manifest field for cross-reference checks against `evaluations.jsonl` rows, and does NOT recompute the hash from `pack.yaml` or parse trigger DSL. Cross-implementation parity for trigger DSL applies to hypothetical external evaluator-runner implementations (Python / Rust / Java), not to the NuWyre Go CLI.

#### 7.5.3.9 Conformance fixtures

A TS-only conformance fixture suite at `packages/policy/tests/fixtures/triggers/` exercises (per the README inventory in that directory):

**Schema surface (10 fixtures):**
- `schema-01-accept-simple-equals` — accept FieldPredicateSchema with `equals`
- `schema-02-accept-nested-boolean` — accept nested all/any/not composition
- `schema-03-reject-zero-predicates` — reject FieldPredicateSchema with zero predicate keys
- `schema-04-reject-two-predicates` — reject FieldPredicateSchema with two predicate keys
- `schema-05-reject-zero-operators` — reject BooleanGroupSchema with zero operator keys
- `schema-06-reject-empty-all-array` — reject `all: []`
- `schema-07-reject-unknown-predicate` — reject unknown predicate (`matches_regex`)
- `schema-08-reject-unknown-field` — reject unknown sibling field (strict-mode)
- `schema-09-reject-empty-any-array` — reject `any: []` (mirror of schema-06; closes L-SC-2 from v1.0.6 first-fix-up)
- `schema-10-reject-scalar-infinity` — reject `equals: .inf` (codifies H-V1.0.6-1 closure; impl rejects ±Infinity at schema layer)

**Path-parse surface (8 fixtures):**
- `path-parse-01-accept-dotted` — accept `agent.call_metadata.direction`
- `path-parse-02-accept-positional` — accept `events[last].content`
- `path-parse-03-accept-filter-multi` — accept multi-clause AND filter
- `path-parse-04-reject-empty` — reject empty path
- `path-parse-05-accept-chained-brackets` — accept `events[role=assistant][first]` (chained brackets without dot)
- `path-parse-06-accept-float-literal` — accept float in filter literal (`events[score=3.14]`)
- `path-parse-07-accept-positional-vs-filter` — accept `events[first=2]` as filter clause (positional disambiguation per §7.5.3.3)
- `path-parse-08-reject-trailing-dot` — reject `agent.` (trailing dot)

**Path-eval surface (6 fixtures):**
- `path-eval-01-simple-field` — navigate `agent.industry`
- `path-eval-02-positional-last` — positional `[last]`
- `path-eval-03-filter-single` — filter `[role=assistant]`
- `path-eval-04-empty-propagation` — empty result propagates through subsequent segments
- `path-eval-05-not-equals-empty-path` — empty-array short-circuit: `not_equals` against absent field returns false (per §7.5.3.1 "Empty-result short-circuit" rule)
- `path-eval-06-literal-precedence-true` — filter `[flag=true]` against `{flag: true}` matches; against `{flag: "true"}` does NOT match (verifies §7.5.3.3 literal precedence)

External implementers SHOULD adopt parallel fixture suites in their target language to verify cross-implementation parity. The fixture inventory above MUST stay in sync with the on-disk fixture set; v1.0.6 first-fix-up closed an inventory-vs-shipped drift (spec-conformance-reviewer NOT-IMPLEMENTABLE finding) where prose claimed fixtures that the suite did not ship.

-----

## 8. `merkle_proofs.json`

`merkle_proofs.json` declares the daily merkle root and a per-event proof of membership.

```jsonc
{
  "root": "220c62b6bae6...4868c4",                     // 64-char lowercase hex
  "proofs": [
    {
      "event_id": "dd2588db-c25d-5a32-b1e6-afbe83435933",
      "leaf":     "3f034dbf...e649057d0",              // = event_hash for that event
      "path": [
        { "position": "left",  "sibling": "2f939c16...c75ae" },
        { "position": "left",  "sibling": "ef5e4916...524b53" },
        { "position": "left",  "sibling": "5a09b563...c689ed" },
        { "position": "right", "sibling": "ff9412d0...637869" },
        { "position": "right", "sibling": "2db6553f...3d0d1" },
        { "position": "right", "sibling": "88f09dc7...074843f" }
      ],
      "root": "220c62b6bae6...4868c4"
    }
    // ... one proof entry per event in events.jsonl
  ]
}
```

### 8.1 Tree construction

- Leaves are `event_hash` values from `events.jsonl`, in event-id ascending sort order.
- `padded_leaf_count = max(1, next_power_of_two(leaf_count))` per v1.0.12 F-SC-9 closure. Specifically:
  - For `leaf_count == 0` (empty subtree): the §16.3.1 empty-subtree composition applies — `subtree_root = "0"*64` (32-byte all-zero genesis sentinel) and no internal-node hashing occurs.
  - For `leaf_count == 1`: `padded_leaf_count == 1`; the tree is depth-0; `subtree_root == leaf_hash` directly with NO internal-node hashing. Proof path is the empty array `[]`.
  - For `leaf_count >= 2`: the leaf list is padded to the next power of two with the genesis sentinel hash (64 zero hex chars); internal-node hashing per the formula below proceeds bottom-up.
- Each internal node is `SHA-256( decoded_left || decoded_right )` (raw byte concatenation per v1.0.12 F-SC-10 MUST-language: decoded 32-byte left operand followed by decoded 32-byte right operand; NOT hex strings; NO RFC 6962 leaf/internal prefix bytes). The result is re-encoded as 64-char lowercase hex.
- The root is the single hash at the top of the tree.

The bundle's `daily_roots.json:roots[].leaf_count` and `padded_leaf_count` make the padding explicit so a verifier can reconstruct the tree without guessing pad strategy.

**RFC 6962 incompatibility note** (v1.0.12 F-SC-10 closure). The Merkle tree construction here is intentionally NOT RFC 6962-compatible: there is no leaf-vs-internal-node domain separation (no `0x00` leaf prefix; no `0x01` internal prefix). Second-preimage resistance derives from leaf `event_hash` values themselves being SHA-256 outputs with chain-internal context binding per §6.2 + §16.2.2 chain isolation, not from leaf/internal node domain separation. External implementers familiar with RFC 6962 MUST NOT introduce the leaf/internal prefix bytes.

### 8.2 Per-event proof verification

```
current = leaf
for step in path:
    if step.position == "left":
        current = sha256(decode_hex(step.sibling) || decode_hex(current))
    else:  # "right"
        current = sha256(decode_hex(current) || decode_hex(step.sibling))
    current = hex_encode_lowercase(current)
assert current == proof.root
```

Each proof's `root` MUST equal the tree's `root`. The relationship to `daily_roots.json:roots[<date>].root` and `manifest.json:daily_root` depends on the bundle's composition mode:

- **Single-tree composition** (pre-v1.0.10 bundle types: `customer-export`, `example-demo`, `sandbox-preview`): each proof's `root` MUST equal `daily_roots.json:roots[<date>].root` AND `manifest.json:daily_root` directly (single-tree identity).
- **Dual-subtree composition** (v1.0.10+ `bundle_type = "audit-log-export"`; v1.0.11 amendment per crypto-int H1 closure): each proof's `root` equals the **subtree root** — primary-event proofs' `root` equals `manifest.merkle_subtrees.events_root` (NOT `manifest.daily_root`); audit-log proofs' `root` (carried in `audit_log_subtree.json:subtree_root` per §16.8) equals `manifest.merkle_subtrees.audit_log_root`. The `manifest.daily_root` is the SHA-256 composition of the two subtree roots per §16.3 dual-subtree composition formula. Verifiers MUST check the bundle's composition mode via presence/absence of `manifest.merkle_subtrees` BEFORE comparing proof root to daily_root.

Any disagreement at the applicable invariant fails check 4. The dual-subtree composition adds Check 9 (audit-log-merkle) which verifies the daily_root composition independently per §16.9.

### 8.3 Notes

- Proof path length is `log2(padded_leaf_count)` for every event in the same tree.
- Proofs are independent of each other; verifying one proof does not require verifying any others.
- The first event in a fresh chain has the genesis sentinel as its `prev_event_hash`; the corresponding leaf in the merkle tree is the event's actual `event_hash`, NOT the sentinel. The sentinel only appears in the merkle padding slots.

-----

## 9. `daily_roots.json`

Per-day root data for every day the bundle covers. Single-day bundles have one entry; multi-day bundles have one per UTC date.

```json
{
  "schema_version": 1,
  "roots": [
    {
      "date":               "2026-04-22",
      "leaf_count":         37,
      "padded_leaf_count":  64,
      "root":               "220c62b6bae6...4868c4"
    }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | `1` for v1 |
| `roots` | yes | Array; one entry per UTC date |
| `roots[].date` | yes | YYYY-MM-DD UTC |
| `roots[].leaf_count` | yes | Number of real events in the merkle tree (= number of events for that date in `events.jsonl`) |
| `roots[].padded_leaf_count` | yes | `roots[].leaf_count` rounded up to the next power of two |
| `roots[].root` | yes | 64-char lowercase hex SHA-256 of the merkle root |

The `daily_roots.json` is the artifact whose root values get anchored: the OTS receipt's `messageImprint` is a `roots[<date>].root`; each RFC 3161 receipt's `TSTInfo.messageImprint` is the same value; the GitHub anchor commit's `root.json:root_hash` is the same value. If any anchor disagrees with this file, verification fails.

-----

## 10. OpenTimestamps receipts

Per-day `.ots` receipts under `ots_receipts/<YYYY-MM-DD>.ots`. Binary OTS proof files produced by submitting `daily_roots.roots[<date>].root` to the OpenTimestamps calendar operators.

### 10.1 Lifecycle

- **Submission** (Phase 3 daily-root cron): the daily root is submitted to multiple OTS calendars (default: all four free public calendars). The cron writes the resulting pending `.ots` file.
- **Pending state**: the `.ots` has a calendar attestation but no Bitcoin block proof yet. `manifest.json:anchor_status.ots_status` is `"pending"` and `manifest.json:anchors.opentimestamps.status` is `"submitted-pending-bitcoin-confirmation"`. Bundles MAY be exported in this state.
- **Upgrade** (`ots upgrade`, typically within ~24h of submission): the cron re-checks the pending receipt. Once OTS calendars publish the Bitcoin block proof, `ots upgrade` folds it into the `.ots` and the receipt becomes self-verifying against the public Bitcoin chain.
- **Confirmed state**: `ots_status: "confirmed"`. Verification works permanently against any Bitcoin source (default Esplora; user-pinned `--bitcoin-rpc-url <url>` for self-hosted bitcoind).

### 10.2 Verification

- Compute `daily_roots.roots[<date>].root`.
- `ots verify ots_receipts/<date>.ots --hash <root_hex>` (using the open-source OpenTimestamps Go client embedded in the Phase 4 CLI).
- Pending receipts pass with a warning under default `--allow-pending-ots`; they fail under `--strict-ots`.
- `--offline` skips this check (Bitcoin lookup requires network); the CLI exits non-zero unless `--offline` is set explicitly.

Single-receipt scope: there is one `.ots` per daily root. OTS itself routes the same proof to multiple calendars; the resulting receipt embeds that diversity.

-----

## 11. RFC 3161 receipts

Per-day, per-TSA `.tsr` + `.chain.pem` pairs under `rfc3161_receipts/<YYYY-MM-DD>__<tsa_name>.tsr` (RFC 3161 TimeStampResp) and `rfc3161_receipts/<YYYY-MM-DD>__<tsa_name>.chain.pem` (the TSA's signing certificate chain captured at stamping time).

### 11.1 Three TSAs attempted, two required

Per build plan §"three-TSAs-attempted-two-required":

- **Default TSAs:** FreeTSA, Sectigo, DigiCert.
- The Phase 3 cron submits the daily root to all three concurrently.
- `rfc3161_status: "verified"` requires ≥2 of 3 to return valid receipts whose chain validation passes.
- The third (when present) is logged as "extra confirmation"; its absence does NOT fail the check.
- A single-TSA failure does NOT fail the bundle unless it drops the verified count below 2.

### 11.2 Embedded `.chain.pem` per build plan v3.1.2

Each `.tsr` ships with the TSA's signing certificate chain (`.chain.pem`) **captured at stamping time**. This is critical: TSA root CAs rotate over time (sometimes years after stamping), and a bundle whose chain validation depends on the TSA's currently-published chain would silently break years later for entirely fictional reasons. By capturing the chain at stamping time and shipping it in the bundle, the bundle remains verifiable indefinitely against any future verifier with the captured chain plus the system trust store.

The CLI's chain-validation code (`apps/cli/internal/rfc3161/`) uses Go's `crypto/x509` and standard PKCS#7 timestamp parsing — no live TSA infrastructure is required at verification time.

### 11.3 Verification

For each `.tsr` present in the bundle:

1. Parse the `.tsr` to extract `TSTInfo.messageImprint`.
2. Confirm `TSTInfo.messageImprint` equals `daily_roots.roots[<date>].root`.
3. Verify the CMS signature against the captured `.chain.pem`.
4. Confirm the chain's signer cert subject CN includes the expected TSA name (e.g., a FreeTSA chain's signer is FreeTSA's signing cert).

Aggregate threshold: **at least two distinct TSAs MUST verify.** If a third receipt is present and verifies, it's reported as extra confirmation. If a present receipt fails verification, the specific TSA name and reason are reported in the check 6 output; the bundle still passes if ≥2 of the 3 verified.

### 11.4 Schema cross-reference

Phase 1.1's `daily_roots.rfc3161_receipts` jsonb column documents the per-row schema:

> Array of `{tsa_name, receipt_path, chain_path, tsa_time, verified_at}`. `chain_path` references the captured `.chain.pem` in the `rfc3161-receipts` storage bucket and is non-null after a successful TSA stamp.

The bundle's `manifest.json:anchors.rfc3161` array is the same shape minus the verified_at field plus the `submitted_at` and `*_sha256` fields. The two are intentionally aligned.

-----

## 12. GitHub anchor refs

Production bundles include a third independent witness: a signed commit in NuWyre's public anchor repository (`https://github.com/NuWyre/anchors`) that records the daily root in a public, append-only, third-party-hosted location.

### 12.1 `github_anchors/<YYYY-MM-DD>.json`

Per-day file recording the anchor state.

```jsonc
{
  "schema_version":     1,
  "repo":               "https://github.com/NuWyre/anchors",
  "date":               "2026-04-22",
  "commit_sha_format":  "sha1",                          // "sha1" | "sha256" — Phase 4 prereq Session B Item 4
  "commit_sha":         null,                            // null when mirror_status != "anchored"; 40 hex (sha1) or 64 hex (sha256) when populated
  "path":               null,                            // e.g., "daily-roots/<organization_id>/2026-04-22/root.json" when anchored
  "anchored_at":        null,                            // ISO 8601 UTC, no fractional seconds, when anchored
  "mirror_status":      "anchor-pending",                // "not_attempted" | "anchor-pending" | "anchored" | "failed" — canonical 4-state per §4.2
  "note":               "Anchor commit is a manual human action..."
}
```

When `mirror_status: "anchored"`:

- `commit_sha` is the hex SHA of the SSH-signed commit in the anchor repo whose tree contains `daily-roots/<organization_id>/<date>/root.json`. Length matches `commit_sha_format`: 40-char lowercase hex for sha1, 64-char lowercase hex for sha256.
- `path` is the repo-relative path to that file (typically `"daily-roots/<organization_id>/<date>/root.json"` per Phase 4 prereq Session A's per-org extension).
- `anchored_at` is the UTC time the commit was made.

**`commit_sha_format` (Phase 4 prerequisites Session B Item 4).** The bundle format is hash-algorithm-agnostic via this discriminator. V1 emits `"sha1"` because Git's SHA-256 mode is opt-in per repo and not yet default — the V1 anchor repo created during Phase 5 deploy-bootstrap uses Git's default (SHA-1). When Git's SHA-256 transition matures and a future anchor repo migrates, bundles emitted before the migration carry `"sha1"` and bundles emitted after carry `"sha256"`; the verifier dispatches per the declared format. **No coordinated cutover required** — old and new bundles coexist with their own format declarations.

Verifier responsibility (Phase 4 Go CLI's check 7): read `commit_sha_format`; validate `commit_sha` length matches (40 chars for sha1, 64 for sha256); fetch the commit via the appropriate Git protocol (SHA-1 commits via standard fetch; SHA-256 commits via Git's SHA-256 mode when supported by the verifier's Git library).

### 12.2 Anchor repo `root.json` schema (v3.1.8 + Phase 4 prereq per-org extension)

The file at `daily-roots/<organization_id>/<date>/root.json` in the anchor repo follows the v3.1.8 schema with the Phase 4 prereq per-org extension (see `packages/evidence/src/anchor-schema.ts`):

```jsonc
{
  "schema_version":          1,
  "bundle_format_version":   1,
  "date":                    "2026-04-22",
  "organization_id":         "11111111-2222-3333-4444-555555555555",  // canonical lowercase UUID
  "produced_by":             "nuwyre-example-bundle-generator/3.1",
  "root_hash":               "220c62b6bae6...4868c4",
  "event_count":             37,
  "merkle":                  { "leaf_count": 37, "padded_leaf_count": 64, "hash_algorithm": "sha256" },
  "anchors": {
    "opentimestamps":        { "receipt_path": "2026-04-22.ots", "receipt_sha256": "...", "submitted_at": "..." },
    "rfc3161":               [{ "tsa_name": "freetsa", "receipt_path": "2026-04-22__freetsa.tsr", "chain_path": "2026-04-22__freetsa.chain.pem", "receipt_sha256": "...", "chain_sha256": "...", "tsa_time": "..." }, ...]
  },
  "computed_at":             "2026-04-22T23:59:59Z",
  "issuer":                  { "key_fingerprint_spki_b64": "...", "key_purpose": "..." }
}
```

**Phase 4 prereq per-org extension.** Pre-Path-A V1 used a platform-aggregate root (one root per UTC date across all customers' events); the anchor repo path was `daily-roots/<date>/root.json`. This contradicted bundle-export verifiability under multi-tenant production: the platform-anchored receipts couldn't be reproduced from one org's events, so Phase 4 CLI checks 5/6 would fail by design. Path A migration (`packages/database/supabase/migrations/20260509200000_daily_roots_per_org.sql`) adopted per-(organization_id, root_date) rows. The anchor repo path adds the `<organization_id>` segment; root.json carries the `organization_id` field; receipt_path / chain_path stay as bare filenames inside the per-(org, date) directory.

`organization_id` is validated as a canonical lowercase UUID. Path-traversal attacks (`organization_id = "../etc/passwd"`) are blocked at the schema-validator level since the UUID regex rejects path separators.

Note the **path discipline divergence**: anchor-repo `receipt_path` and `chain_path` are bare filenames (`2026-04-22.ots`, `2026-04-22__freetsa.tsr`) **inside the anchor repo's `daily-roots/<date>/` directory**, while bundle-side `manifest.json:artifacts[].path` values are bundle-relative (`ots_receipts/2026-04-22.ots`). The anchor repo and the bundle are two different consumers of the same receipts; their path conventions diverge intentionally.

### 12.3 v3.1.9 byte-stability dependency

**Load-bearing.** The cross-check between the bundle's `*_sha256` values and the anchor-repo file SHA-256s depends on the anchor repo files being byte-stable across clone environments. Per build plan v3.1.9, the anchor repo MUST contain a root-level `.gitattributes` file declaring `daily-roots/** binary` and `*.md text` BEFORE any anchor data commits land. Without it, Windows clones with default `core.autocrlf=true` re-hash `root.json` and `*.chain.pem` differently from Linux/Mac clones, and the cross-checks in check 7 fail for entirely fictional reasons.

The Phase 3 anchor-repo bootstrap MUST commit `.gitattributes` as the first commit. Phase 4 verifier MUST clone the anchor repo with attribute handling that preserves byte content (or fetch the file via raw GitHub API to bypass git's smudge filter entirely).

### 12.4 Verification

Online-by-default (network required to fetch from GitHub):

1. Fetch the public anchor repo at the recorded `commit_sha` via the protocol selected by `commit_sha_format` (per §12.1) — SHA-1 commits use standard `git fetch`; SHA-256 commits require Git's SHA-256 mode capability on the verifier's Git library.
2. Confirm `daily-roots/<organization_id>/<date>/root.json` exists and parses per the v3.1.8 schema. The `<organization_id>` segment is the bundle's `manifest.json:organization_id`; mismatch is a verification failure (bundle's organization can't unilaterally read another org's anchor file).
3. Confirm `root.json:organization_id` matches the bundle's `manifest.json:organization_id` AND `root.json:root_hash` matches the bundle's `daily_roots.json:roots[<date>].root` AND `manifest.json:daily_root`.
4. Confirm `root.json:anchors.opentimestamps.receipt_sha256` matches the bundle's `ots_receipts/<date>.ots` SHA-256.
5. For each TSA in `root.json:anchors.rfc3161[]`: confirm `receipt_sha256` matches the bundle's `rfc3161_receipts/<date>__<tsa>.tsr` SHA-256, and `chain_sha256` matches the bundle's `<date>__<tsa>.chain.pem` SHA-256.
6. Verify the commit's SSH signature against the pinned issuer SSH key.

`--offline` skips this check; the CLI exits non-zero unless `--offline` is set explicitly. Anchor verification is fundamentally an external cross-check, not an internal bundle property.

-----

## 13. Audio files

Audio files live under `audio/<sha256>.<ext>` inside the bundle, where `<sha256>` is the 64-char lowercase hex SHA-256 of the file's bytes and `<ext>` matches the recorded MIME type (e.g., `.wav` for `audio/wav`, `.mp3` for `audio/mpeg`).

### 13.1 Path discipline

- Bundle-relative path: `audio/<sha256>.<ext>` exactly. NOT `/audio/...`, NOT `audio/<sha256>` (no extension), NOT a customer-supplied filename.
- The path in `manifest.json:artifacts[].path` MUST equal the actual bundle path.
- `manifest.json:audio_records[].storage_path` MUST equal the same path.
- `manifest.json:audio_records[].sha256` MUST equal the path's `<sha256>` segment AND the file's actual SHA-256.

### 13.2 Audio ↔ event binding

The load-bearing check is **`audio_ref.hash` == file SHA-256 == path stem**. The convenience metadata in `manifest.json:audio_records[]` (bytes, duration_ms, mime_type) helps verifiers and indexers but is not authoritative; the per-event `audio_ref.hash` equality with the file at `audio/<hash>.<ext>` is.

Modifying the audio bytes after ingestion: changes the file's SHA-256 → no longer matches `audio_ref.hash` → check 2 fails → verification fails. The audio recording is as tamper-evident as any other event field.

### 13.3 Retention

Audio retention MAY differ from event retention. When audio is purged ahead of its referencing events expiring:

- `audio_ref` STAYS in the event record (the chain doesn't move; rewriting the event would break the chain).
- The audio file is ABSENT from the bundle's `audio/` directory.
- `manifest.json:artifacts[]` does NOT list the absent file.
- `manifest.json:audio_records[]` does NOT list the absent file.

Phase 4 verifier behavior: a missing audio file referenced by `audio_ref` is reported per check 2 as "audio file purged per retention policy" if the manifest documents the policy; otherwise as "missing artifact" (a tampering signal). The exact retention-policy declaration shape is TBD in v1.x; v1.0 verifiers MAY treat all missing audio as a check-2 warning.

-----

## 14. Verification procedure

The seven checks per build plan §"Phase 4 Step 4: The seven checks". Each check fails with a specific error pointing at the corrupted artifact and which check failed.

### Check 1 — Manifest signature

**Dispatch by `bundle_format` per §2** (v2.0.0-rc1 amendment):

- **v1 (`nuwyre-bundle/v1`) path**: Ed25519 signature in `signature.sig:signature_b64` verifies against the pinned issuer key (selected by `manifest.json:bundle_type` per §5) over the byte content of `manifest.json`. Fails if: signature byte string is malformed, key fingerprint mismatch, signature doesn't validate.

- **v2.0.0-rc1+ (`nuwyre-bundle/v2`) path**: dual-signature verification per §18.7. Both Ed25519 signature (signatures[0]) AND ML-DSA-65 signature (signatures[1]) MUST verify against the pinned issuer keys (selected by `manifest.json:bundle_type` + the cross-environment-slot discipline of §18.6) over the byte content of `manifest.json` (identical canonical bytes; both signatures cover the same message). Failure taxonomy per §18.7: (Check 1 FAIL structural) malformed base64; wrong schema_version; unparseable JSON in signature.sig; signature.sig itself not RFC 8785 JCS-canonicalized; cardinality != 2; positional ordering swapped (signatures[0].algorithm != "ed25519" OR signatures[1].algorithm != "ml-dsa-65"). (Check 1 FAIL schema-cross-check) manifest.signing vs signature.sig disagreement on algorithm / key_id / key_fingerprint_spki_b64 / key_purpose at either position; environment-slot mismatch between positions[0] + positions[1] (one slot prod + other slot dev rejected); key-lookup failure in verifier's pinned-key directory. (Check 1 FAIL cryptographic) Ed25519 verification fails OR ML-DSA-65 verification fails OR both. Check 1 step 5 (cryptographic verification) does NOT short-circuit per signature; verifier reports ALL crypto failures so operator sees both. Steps 1-4 (structural → schema-cross-check → key-lookup → canonicalization) DO short-circuit in order — a structural failure at signature.sig parsing means the schema-cross-check is undefined and is not run. The full per-step short-circuit + multi-signature reporting discipline is at §18.7.

### Check 2 — Artifact integrity

Every file referenced in `manifest.json:artifacts[]` is present in the bundle and its SHA-256 equals the declared value. Includes audio: for each event with `content.audio_ref.hash`, the file at `audio/<sha256>.<ext>` is present and its SHA-256 matches `audio_ref.hash`. Fails if: missing file (except documented retention purge per §13.3), SHA-256 mismatch.

### Check 3 — Hash chain reconstruction

Sort all events in `events.jsonl` by `sequence_number` ascending across the bundle (do NOT group by `session_id`; the chain is per-organization spanning session boundaries per §6.2). Execute the §6.2 chain-walk in sequence order:

1. **Gap-free monotonic check.** `sequence_number` equals the expected next position (starting at 0); a gap is the canonical signal of whole-event deletion or reordering.
2. **content_hash recompute.** From the canonicalized content payload; confirm it equals the row's declared `content_hash`.
3. **prev_event_hash linkage.** Equals the prior event's `event_hash`, or `GENESIS_PREV_HASH` for sequence 0.
4. **event_hash recompute.** `SHA-256(canonicalize({prev_event_hash, content_hash, sequence_number, timestamp_unix_ns}))`; confirm it equals the row's declared `event_hash`.

Per spec §6.3, also verify the row's `ingestion_signature` (the per-event Ed25519 signature) against the pinned issuer key.

Fails if: any content_hash drifts, any sequence gap, any chain link breaks, any event_hash drifts, any per-event signature fails. Each error names the offending event by `sequence_number` (and optionally `session_id` for forensic localization).

**v1.0.10/v1.0.11 amendment for audit-log-export bundles (F11 closure).** When `manifest.bundle_type = "audit-log-export"`, Check 3 walks BOTH the primary event chain (over `events.jsonl`) AND the audit log event chain (over `audit_log_events.jsonl`) **independently**. Each chain MUST verify per the §6.2 semantics above; the chains are disjoint per §16.2.2 (independent sequence_number namespaces; independent prev_event_hash linkages). Audit log event content_hash derivation follows §16.2.1 canonical content payload (`canonicalize({actor, subject, event_type})`) rather than the primary event's §6.4 content payload (which references `{role, content, content_hash, audio_ref}`). Failure in EITHER chain produces Check 3 `fail`; error messages name the chain (primary vs audit log) AND the offending event. The audit log chain MAY be empty (when `bundle_subtype = "operator-only"` AND no operator-internal events occurred in the window — a degenerate but conformant case); empty-chain handling per §16.3.1 empty-subtree composition.

### Check 4 — Merkle proof verification

For each entry in `merkle_proofs.json:proofs[]`, walk the proof path from leaf to root per §8.2 and confirm the resulting hash equals `proofs[].root` AND `merkle_proofs.json:root`. Under **single-tree composition** (pre-v1.0.10 bundle types), the walked root MUST additionally equal `daily_roots.json:roots[<date>].root` AND `manifest.json:daily_root`. Under **dual-subtree composition** (v1.0.10+ audit-log-export per §8.2 v1.0.11 amendment), the walked root for primary-event proofs MUST equal `manifest.merkle_subtrees.events_root` (NOT `manifest.daily_root` directly); the composition into daily_root is verified by Check 9 (§16.9). Fails on any disagreement or missing proof for any event in `events.jsonl`.

**v1.0.10/v1.0.11 amendment for audit-log-export bundles (F11 closure).** When `manifest.bundle_type = "audit-log-export"`, Check 4 ALSO walks each entry in `audit_log_subtree.json:proofs[]` per §8.2 semantics + the v1.0.11 §16.8 reconciled `path[i].position` field name (NOT `"side"`; the F1 closure aligns audit_log_subtree.json with §8 walker). The walked root MUST equal `audit_log_subtree.json:subtree_root` AND `manifest.merkle_subtrees.audit_log_root`. Both subtrees verified independently; failure in either subtree fails Check 4. Empty audit log subtree (when `audit_log_events.jsonl` is empty) is conformant per §16.3.1; Check 4 emits `status: "pass"` with a synthetic empty-subtree note.

### Check 5 — OpenTimestamps Bitcoin anchor

For each daily root with an `.ots` receipt, verify against the public Bitcoin chain per §10. Pending receipts pass with a warning under default `--allow-pending-ots`; fail under `--strict-ots`. `--offline` skips this check. Fails if: receipt malformed, message imprint disagrees with daily root, Bitcoin proof fails to verify (in confirmed state).

### Check 6 — RFC 3161 timestamp anchor

Per §11. Fails if: fewer than 2 of the 3 default TSAs have valid receipts whose chain validation passes. A single-TSA failure does NOT fail this check unless it drops verification below the 2-of-3 threshold. Specific failures (which TSA, which validation step) are reported in the CLI output.

### Check 7 — GitHub anchor cross-check

Per §12.4. Online-by-default; `--offline` skips. Fails if: anchor commit doesn't exist or doesn't reach the recorded `commit_sha`, `root.json` is missing or malformed, any of the four hash cross-checks (root_hash, ots receipt_sha256, rfc3161 per-TSA receipt_sha256 + chain_sha256) disagree, or the commit's SSH signature fails to verify against the pinned issuer SSH key.

### Check 8 — Ephemeral session attestation (v1.0.9 amendment; sandbox-preview only)

**Conditionally executed.** Check 8 runs when `manifest.signing.topology = "ephemeral-sessions"`; otherwise it produces `status: "skipped"` with `skip_reason: "bundle uses single-key signing topology; ephemeral-session attestation not applicable"`. Under `topology = "ephemeral-sessions"`, Check 8 runs BEFORE Check 3 — Check 3's per-event signature step depends on the session_id → ephemeral_pubkey map Check 8 builds.

Per §6.5.6: for each entry in `manifest.signing.ephemeral_sessions[]`,

1. Decode `session_seed_bytes_b64` to raw seed bytes.
2. Decode `kms_attestation_b64` to 64 raw signature bytes.
3. Verify `Ed25519.Verify(pinned_kms_public_key, seed_bytes, attestation) == true` against the pinned KMS public key declared in `manifest.signing.key_fingerprint_spki_b64` (cross-checked against the verifier's compile-time-pinned issuer key directory per §5).
4. Recompute `ephemeral_seed = HKDF-SHA-256(seed_bytes ‖ attestation, salt="", info="nuwyre/v1.0.9-ephemeral-session-key", L=32)`.
5. Derive the ephemeral Ed25519 public key from `ephemeral_seed` per RFC 8032 §5.1.5, wrap in SPKI DER per RFC 8410, base64-encode.
6. Confirm the recomputed base64 SPKI byte-equals `ephemeral_sessions[i].ephemeral_spki_b64`.

Additional preconditions verified by Check 8:
- `manifest.bundle_type = "sandbox-preview"` (topology/bundle_type mismatch fails Check 8 per §5).
- `ephemeral_sessions[]` is non-empty; for v1.0.9 it contains EXACTLY ONE entry (other cardinalities fail Check 8 per §6.5).

Fails if: any base64 decode fails, any field has wrong byte length, any KMS attestation verification fails, any SPKI recomputation mismatches, topology/bundle_type mismatch, or cardinality violation.

On success, Check 8 populates the verifier-internal session_id → ephemeral_pubkey map that Check 3 consults under ephemeral-sessions topology.

### Aggregate semantics

- All seven checks (eight when `topology = "ephemeral-sessions"` per §6.5) MUST pass for the verifier to report "verified."
- Any check failure produces a specific error message naming the check and the specific artifact / field / reason.
- `--check <name>` runs only the named check.
- Pending OTS does not fail check 5 by default; `--strict-ots` makes it fatal.
- `--offline` skips checks 5-7 (Bitcoin, RFC 3161 chain validation if relying on system trust, GitHub fetch); the CLI exits non-zero unless `--offline` is set explicitly. Anchor verification is fundamentally an external cross-check; "verified offline" is an incomplete guarantee.
- Check 8 (ephemeral-session) is `skipped` for bundles with `topology = "single-key"` (or topology field absent); offline mode does NOT skip Check 8 (its KMS attestation verification is local-only — no network calls — and remains in scope under `--offline`).

### Tampering fixture suite

The conformance suite at `docs/spec/fixtures/bundle-format-v1/` (15 fixtures: 10 v1.0.7 fixtures landed Phase 5.5 Session 5.5.1B + 1 v1.0.9 cross-language primitive fixture + 4 v1.0.10 audit-log-export fixtures landed Phase 6.2.A; v1.0.10 fixtures ship as metadata-only at Phase 6.2.A with `bundle.zip` generation deferred to Phase 6.2.B) is the **normative conformance contract** for v1 verifiers. Each fixture is a directory containing `bundle.zip` + `results.json` (expected verifier output per §14.1) + `verification_options.json` (the flag set per §14.5) + `tamper.json` (for tampered variants — describes the bytewise modification). The v1.0.9 cross-language primitive fixture (`cross-lang-ephemeral.json`) is a single JSON file (not a directory) carrying HKDF + Ed25519 derivation byte-equivalence inputs per §6.5.

| Fixture | Tamper | Verdict (per §14.2) | Failing/warn check(s) |
|---|---|---|---|
| `valid-bundle/` | (none — verbatim base) | `partial_verification` | check 6 emits `tsa_surplus` warn (no opt-in flag folds it) |
| `tampered-event/` | event_hash hex byte flipped (last char) | `fail` | check 2 + check 3 + check 4 |
| `tampered-audio/` | audio file byte XOR'd at midpoint | `fail` | check 2 |
| `swapped-event/` | two adjacent same-session events swapped in file order | `fail` | check 2 only (V1 check 3 walks chains via prev_event_hash; file-line order not enforced — Phase 5+ tightening tracked) |
| `forged-merkle/` | merkle_proofs.json proof sibling hex byte flipped | `fail` | check 2 + check 4 |
| `forged-ots/` | OTS receipt byte XOR'd past magic header | `fail` | check 2 only (V1 check 5 does NOT cryptographically verify pending-state receipts — Phase 5+ tightening tracked) |
| `forged-rfc3161/` | one .tsr token byte XOR'd | `fail` | check 2 only (3-of-3 TSAs verified; 1 invalidated still leaves ≥2 verifying per spec §11) |
| `forged-rfc3161-chain/` | one .chain.pem character flipped within base64 alphabet | `fail` | check 2 only (same multi-TSA tolerance) |
| `mismatched-github/` | github_anchors/<date>.json mirror_status mutated to "anchored" with zeroed commit_sha | `fail` | check 2 + check 7 |
| `pending-ots/` | (none — verbatim base; verification_options omits allow_pending_ots) | `partial_verification` | check 5 + check 6 emit unfolded warns |
| `cross-lang-ephemeral.json` (v1.0.9 primitive) | (n/a — derivation byte-equivalence inputs) | n/a (cross-language byte-equivalence contract) | TS + Go reference impls MUST recompute identical ephemeral SPKI byte-for-byte per §6.5 |
| `valid-audit-log-export/` (v1.0.10; metadata-only at 6.2.A; bundle.zip at 6.2.B) | (none — verbatim base) | `pass` (per declared results.json; v1.0.10/v1.0.11 audit-log-export bundle with Checks 1-4 + 9 active) | checks 5-7 follow normal anchor semantics |
| `tampered-audit-log-event/` (v1.0.10) | single audit log event content modified post-signing | `fail` | check 2 + check 3 (audit log chain) |
| `audit-log-missing-events/` (v1.0.10) | manifest declares N audit log events; only N-1 present in audit_log_events.jsonl | `fail` | check 2 (artifact integrity; line count mismatch against `manifest.audit_log_event_count` per F2 closure) |
| `forged-audit-log-merkle-subtree/` (v1.0.10) | audit log subtree merkle proof byte mutated; primary subtree untouched | `fail` | check 2 + check 4 (audit log subtree path) + check 9 (audit-log-merkle composition) |
| `valid-v2-bundle/` (v2.0.0; bundle_type=example-demo — fixture-name reconciliation per spec-conf H2 closure session 102: customer-export was the originally PLANNED fixture name, but v2.0.0-rc1's production ML-DSA-65 key is a placeholder pending Phase 7.F.4 deploy-bootstrap; only dev-slot dispatch resolves to real pinned keys, so the canonical valid-v2 fixture is example-demo subtype — mirrors v1 valid-bundle precedent) | (none — verbatim v2 base; `bundle_format: "nuwyre-bundle/v2"` + `schema_version: 2`; dual-signature manifest) | `partial_verification` | check 1 dev_key warn (foldable via --allow-dev-key) + checks 5+7 anchor-pending/pending-OTS warns (foldable); checks 2,3,4,6 pass; checks 8+9 skipped (single-key topology + non-audit-log) |
| `tampered-ed25519-sig/` (v2.0.0) | signatures[0].signature_b64 first base64 char flipped post-canonicalization | `fail` | check 1 cryptographic (Ed25519 verification fails; ML-DSA-65 still verifies — verifier reports BOTH per §18.10 no-short-circuit; algorithm_verdicts=[ed25519=fail, ml-dsa-65=pass]) |
| `tampered-ml-dsa-sig/` (v2.0.0) | signatures[1].signature_b64 first base64 char flipped post-canonicalization | `fail` | check 1 cryptographic (ML-DSA-65 verification fails; Ed25519 still verifies — algorithm_verdicts=[ed25519=pass, ml-dsa-65=fail]) |
| `tampered-both-sigs/` (v2.0.0) | both signature byte strings first-char-tampered | `fail` | check 1 cryptographic (both algorithms fail; both reported per §18.10; algorithm_verdicts=[ed25519=fail, ml-dsa-65=fail]) |
| `wrong-pq-key-id/` (v2.0.0) | signatures[1].key_id mutated to attacker-supplied value while manifest.signing.signatures[1].key_id preserved | `fail` | check 1 step 7(c) schema-cross-check (signature.sig vs manifest.signing key_id disagreement) → failV2 short-circuit → algorithm_verdicts=[ed25519=fail, ml-dsa-65=fail] (both fail per spec §18.10 conformance contract; failure is at policy/structural layer not crypto) |
| `malformed-pq-sig-length/` (v2.0.0) | signatures[1].signature_b64 truncated by 100 base64 chars (4412 → 4312; decodes to 3234 bytes ≠ FIPS 204 mandated 3309) | `fail` | check 1 verifyMlDsa65Leg length check fires BEFORE crypto verify; Ed25519 unaffected; algorithm_verdicts=[ed25519=pass, ml-dsa-65=fail] |
| `manifest-signing-mismatch/` (v2.0.0) | signature.sig.signatures[1].key_fingerprint_spki_b64 first-char flipped; manifest.signing.signatures[1] preserved | `fail` | check 1 step 7(b) schema-cross-check (signature.sig vs manifest.signing fingerprint disagreement) → failV2 → algorithm_verdicts=[fail, fail] |
| `swapped-signature-slots/` (v2.0.0) | signatures[0] = ML-DSA-65 entry; signatures[1] = Ed25519 entry (positional discipline violated per §18.8) | `fail` | check 1 step 1d positional algorithm pin (signatures[0].algorithm != "ed25519") → failV2 short-circuit → algorithm_verdicts=[fail, fail] |
| `mixed-environment-keys/` (v2.0.0) | manifest.signing.signatures[0].key_id mutated to "issuer-prod-v2-ed25519" while bundle_type=example-demo dispatches to dev-slot pinned key | `fail` | check 1 step 7(d) pinned cross-check (signing.signatures[0].key_id != pinnedKey.KeyID) → failV2 → algorithm_verdicts=[fail, fail]. NOTE: spec §18.6 step-3 cross-environment-slot check is currently UNREACHABLE under v2.0.0 dispatch (KeyForBundleEd25519V2 + KeyForBundleMlDsa65 both derive role from bundle_type identically); step 7(d) pinned cross-check is the practical detection path. The §18.6 step-3 check remains as defense-in-depth for future v2.x amendments that may introduce algorithm-specific bundle_type→role overrides; empirically unverifiable by fixture until such divergence exists. |
| `dev-keys-claiming-prod/` (v2.0.0) | manifest.bundle_type mutated "example-demo" → "customer-export"; manifest.signing carries dev SPKIs; dispatch resolves to prod-slot placeholder | `fail` | check 1 step 5 placeholder check (n=20 closure: ML-DSA-65 OR Ed25519 v2 placeholder match) → failV2 → algorithm_verdicts=[fail, fail]. Plus check 3 hash chain fails on v1 KeyForBundle prod placeholder dispatch. |
| `extra-file-smuggled/` (v2.0.0) | bundle ZIP contains stray `smuggled.txt` file not in manifest.artifacts[] | `fail` | check 2 v2 bidirectional set-equality per §18.5 (extra file in ZIP not described by manifest.artifacts[] ∪ {manifest.json, signature.sig}); check 1 PASSES (manifest signed bytes unchanged) — illustrates valid signatures + tampered bundle ≠ valid bundle |
| `valid-v2-audit-log-export/` (v2.0.0; bundle_type=audit-log-export + bundle_subtype=customer-scoped) | (none — verbatim v2 audit-log base; dual-signature manifest + audit-log subtree + dual-subtree daily_root composition) | `partial_verification` | check 1 dev_key warn (foldable) + checks 5+7 anchor warns + check 3 skipped (empty events.jsonl per audit-log-export pattern) + check 8 skipped (single-key topology); checks 2,4,6,9 pass — validates v2 dual-sig + audit-log dual-subtree composition end-to-end |
| `dev-keys-claiming-operator-only-audit-log/` (v2.0.0; bundle_type=audit-log-export + bundle_subtype=operator-only + dev-slot keys; sentinel UUIDs per §16.5) | (none — structurally valid operator-only bundle signed with dev keys) | `fail` | check 1 step 10 path (b) per spec §18.6 audit-log clause + security-auditor H1 closure: dev_key warn ELEVATED TO FAIL (NOT foldable via --allow-dev-key) — algorithm_verdicts=[pass, pass] (crypto verifies); Check 1 overall fail at policy-layer elevation, not crypto-layer. n=21+ inverse-direction closure (spec-mandated defense implementation lacked pre-session-102) |

The 13 v2.0.0 fixtures are SHIPPED at Phase 7.F.4 sub-arcs A-D (sessions 98-101); their declared `results.json` outputs are normative + empirically verified by all three reference verifiers at the v2.0.0 promotion gate (session 102).

All three reference verifiers (TS + Go-native + Go-WASM) MUST produce structurally-identical `results.json`-matching output for each fixture under the fixture's declared `verification_options.json`. **Structural identity** compares: `verdict`, `exit_code`, per-check `check_id` + `check_slug` + `status`, summary counts (`passed`/`failed`/`warned`/`skipped`/`warns_opted_into_pass`). Implementation-localized fields (`errors[]`, `warnings[]`, `reason`, `duration_ms`, optional `check_name`, optional `warn_category` string content when `null`) are IGNORED by the conformance contract.

The CI workflow `.github/workflows/spec-conformance.yml` enforces the conformance contract on every commit. Divergence in any structural field between any two of the three implementations fails the build.

**V1 verifier baseline encoded.** Several fixtures pin the current V1 Go-native verifier's limitations as the expected status (forged-ots, forged-rfc3161, forged-rfc3161-chain — check 2 only; swapped-event — check 2 only). A stricter Phase 5+ verifier that tightens these checks would emit different per-check statuses; fixtures will be regenerated at the tightening session and the spec amended to a v1.0.8+ revision. The fixtures' `tamper.json` `notes` arrays document the per-fixture expected behavior under a tightened verifier.

### 14.1 JSONOutput shape

Conformant verifiers MUST emit a single top-level JSON object matching this shape when invoked with `--json` (CLI) or `verify()` (WASM/TS):

```json
{
  "output_format_version": "1",
  "verdict": "pass" | "fail" | "partial_verification",
  "exit_code": 0 | 1,
  "reason": "(implementation-specific natural-language string; ignored by conformance contract)",
  "checks": [
    {
      "check_id": 1..9,
      "check_name": "(optional human-readable label; ignored by contract)",
      "check_slug": "manifest-signature" | "artifact-integrity" | "hash-chain" | "merkle-proof" | "opentimestamps" | "rfc3161" | "github" | "ephemeral-session" | "audit-log-merkle",
      "status": "pass" | "fail" | "warn" | "skipped",
      "warn_category": "dev_key" | "pending_ots" | "anchor_pending" | "tsa_surplus" | "",
      "errors": ["(zero or more implementation-specific error strings)"],
      "warnings": ["(zero or more implementation-specific warning strings)"],
      "skip_reason": "(empty string when not skipped; implementation-specific natural-language string when skipped)",
      "duration_ms": 0..N
    }
    // Cardinality (v1.0.11-unified omit-inapplicable pattern):
    //   - 7 entries for single-key topology AND non-audit-log-export bundle_type (checks 1..7)
    //   - 8 entries for ephemeral-sessions topology AND non-audit-log-export bundle_type (checks 1..7 + 8)
    //   - 8 entries for single-key topology AND audit-log-export bundle_type (checks 1..7 + 9; Check 8 OMITTED)
    //   - ephemeral-sessions + audit-log-export forbidden by §16.6.1 single-key topology requirement
  ],
  "summary": {
    "passed": 0..9,
    "failed": 0..9,
    "warned": 0..9,
    "skipped": 0..9,
    "warns_opted_into_pass": 0..9
  }
}
```

**Field semantics:**

- `output_format_version` MUST equal `"1"` for v1 bundles. Future v1.x amendments MAY add fields but MUST NOT change `output_format_version`. A v2 verifier emits `"2"`; v1 consumers MUST fail loudly on `output_format_version != "1"` rather than silently accept extended-schema output.
- `verdict` is the overall verdict per §14.2.
- `exit_code` is the process exit code (CLI) or the conceptual exit code (WASM, where the Promise-resolved result carries this field for CI tooling). 0 for `pass`; 1 for `fail` or `partial_verification`. Exit code 2 (invocation error: missing path, unknown flag, contradictory flag combination per §14.5) is out-of-scope for `JSONOutput` — **verifiers MUST NOT emit `JSONOutput` when the exit code would be 2.** The invocation-error path produces stderr-only output (human-readable description; CLI) or a rejected Promise carrying an `Error` (WASM/API). This separation lets CI tooling reliably gate on `output_format_version` presence: if the field is present, the verifier ran and the verdict is meaningful; if absent, the verifier rejected the invocation.
- `reason` MUST be present as a non-null string (MAY be empty `""` when no operator-relevant rationale exists). Its content is implementation-localized and IGNORED by the conformance contract; its presence is required for schema conformance.
- `checks[]` is the per-check verdict array in spec §14 order. Length depends on `manifest.signing.topology` (§5 + §6.5) AND `manifest.bundle_type` (§16). The **omit-inapplicable pattern** applies uniformly across both axes (v1.0.11 unification per F5):
  - **single-key topology AND non-audit-log-export** — Exactly **7 entries** (checks 1..7). Check 8 + Check 9 both OMITTED. v1.0.7 + v1.0.9 customer-export + example-demo reference verifiers emit 7 entries verbatim.
  - **ephemeral-sessions topology AND non-audit-log-export** — Exactly **8 entries** (checks 1..8). Check 9 OMITTED. v1.0.9 sandbox-preview ephemeral bundles.
  - **single-key topology AND audit-log-export** — Exactly **8 entries** (checks 1..7 + 9; Check 8 OMITTED). v1.0.10/v1.0.11 audit-log-export bundles.
  - **ephemeral-sessions topology AND audit-log-export** — FORBIDDEN at v1.0.11; §16.6.1 mandates single-key topology for audit-log-export. A future amendment lifting this restriction would emit 9 entries (checks 1..9).
  - Each entry's `check_id` matches §14 Check N; `check_slug` per §14.6; `check_name` is optional human-readable label (MAY be omitted by a conformant verifier).
- `summary.passed + summary.failed + summary.warned + summary.skipped == len(checks)` (7 / 8 / 8 per the cardinality cases above). `summary.warns_opted_into_pass` is the subset of `passed` that was originally `warn` status but folded into pass via an opt-in flag (see §14.4).

**Structural conformance contract.** Cross-implementation conformance compares: `output_format_version`, `verdict`, `exit_code`, per-check `check_id` + `check_slug` + `status`, summary counts. Implementation-localized fields (`reason` text content, per-check `check_name` + `errors` + `warnings` + `skip_reason` text content + `duration_ms`) are IGNORED — verifiers in different languages produce different natural-language strings without breaking conformance. The `warn_category` field is structural (matches the enum per §14.4); implementations MUST emit `""` (empty string) for warnings that don't match an opt-in category, NOT JSON `null`.

A JSON Schema document at `docs/spec/fixtures/bundle-format-v1/results.schema.json` formalizes this shape. The schema's `$id` references this v1.0.7 amendment as the normative source.

### 14.2 Verdict enum

The overall `verdict` value is a closed vocabulary of three values:

- **`pass`** — every check is `pass`-equivalent (raw `pass` status OR `warn` status folded into pass via an opt-in flag per §14.4). Exit code 0.
- **`fail`** — at least one check is `fail` status. Exit code 1. **Terminal:** a `fail` verdict cannot be downgraded to `pass` by any opt-in flag; a definitive check failure is always definitive.
- **`partial_verification`** — no check failed, but at least one check is incomplete relative to the operator's expectation: a `warn` status NOT folded into pass via an opt-in flag, OR a `skipped` status without `--offline`. Exit code 1. **Operator-actionable:** the operator may opt INTO accepting the warn/skip via the corresponding flag (per §14.5) to convert this to `pass`, OR accept the partial verification as-is.

Verdict precedence (computed by the aggregator): `fail` > `partial_verification` > `pass`. Any check `fail` produces `fail` overall; any unfolded `warn` OR unskipped `skipped` produces `partial_verification`; otherwise `pass`.

### 14.3 Per-check status enum

Each check's `status` value is a closed vocabulary of four values:

- **`pass`** — every assertion in the check held.
- **`fail`** — at least one assertion failed; the bundle does not verify under this check's contract.
- **`warn`** — the check held its required assertions but surfaced something operationally meaningful (informational dev-key disclosure per §5, pending-OTS receipt awaiting Bitcoin confirmation per §10, V1 anchor-pending state per §12, surplus-TSA case per §11). A warn is paired with a `warn_category` value per §14.4 if it's an opt-in-category warn.
- **`skipped`** — the check did NOT run because preconditions were not met (`--offline` flag disables checks 5/6/7 from doing network calls; etc.). `skip_reason` is populated with a human-readable explanation.

**Status vs verdict.** Status is per-check (4 values); verdict is overall (3 values). A check's status is the input; the aggregator (§14.4) computes the overall verdict from the status array + the operator's flag set (§14.5).

### 14.4 Warn-fold mechanic + `warn_category` field

A `warn` status may be **folded into `passed`** in the summary counts when the operator has explicitly opted INTO accepting that warn category via an opt-in flag (per §14.5). Folded warns:

- Still surface in `checks[i].status = "warn"` and in `checks[i].warnings[]` per-check output (the operator sees the warning).
- Contribute to `summary.passed` (not `summary.warned`).
- Contribute to `summary.warns_opted_into_pass` for transparent disclosure.

**Summary arithmetic** (load-bearing for cross-implementation conformance):

```
summary.passed              = (count of checks[] with status='pass') + summary.warns_opted_into_pass
summary.warned              = (count of checks[] with status='warn') - summary.warns_opted_into_pass
summary.failed              =  count of checks[] with status='fail'
summary.skipped             =  count of checks[] with status='skipped'
summary.passed + summary.failed + summary.warned + summary.skipped == 7  (for v1 bundles)
```

**`warn_category` field** (NEW in v1.0.7; additive — pre-v1.0.7 verifiers MAY emit `""` for all warn entries OR omit the field entirely; v1.0.7+ verifiers MUST emit the field on every check for shape stability AND MUST populate with a named category when the warn matches an opt-in category):

```
warn_category := "dev_key" | "pending_ots" | "anchor_pending" | "tsa_surplus" | ""
```

The empty string `""` is the sentinel for "not in an opt-in warn category" — this aligns spec text + `results.schema.json` enum + the Go reference impl's `output.CheckJSON.WarnCategory string` zero-value behavior. JSON `null` is NOT permitted; verifiers MUST emit `""` for non-category warns. (Pre-amendment draft text used `null`; reconciled to `""` at the v1.0.7 first fix-up batch per spec-conformance-reviewer F4 + code-reviewer #5 + security-auditor H1 + crypto-integrity-reviewer #3 cross-corroborated finding.)

- **`dev_key`** — Check 1 emits this on every bundle signed with the dev key (`bundle_type = "example-demo"`). Folded into pass when `--allow-dev-key` is set. Spec §5 mandates the warn even when opted-in; the operator MUST see the per-check `warn` text for visibility, but the verdict-layer folds.
- **`pending_ots`** — Check 5 emits this when the OTS receipt has calendar attestations but no Bitcoin block proof yet (V1 example-demo bundles are typically in this state). Folded into pass when `--allow-pending-ots` is set.
- **`anchor_pending`** — Check 7 emits this when `github_anchors/<date>.json:mirror_status` is `"anchor-pending"` (V1 deploy-bootstrap state). Folded into pass when `--allow-anchor-pending` is set.
- **`tsa_surplus`** — Check 6 emits this when 3 distinct TSAs verify (extra confirmation beyond the spec §11 ≥2-of-3 requirement). **NOT folded into pass by any current V1 opt-in flag** (no `--allow-tsa-surplus` exists in V1); a future v1.x MAY introduce one. Tracked as a Phase 5+ verifier-tightening bookmark. The `valid-bundle` fixture's overall verdict is `partial_verification` (not `pass`) as a direct consequence; a future v1.x will close this gap.
- **`""`** (empty string) — All other warn cases (non-opt-in-category warns; never folded into pass; always contribute to `summary.warned`). JSON `null` is NOT permitted; emit `""` instead.

**External implementer guidance.** A conformant verifier MUST emit `warn_category` matching this enum when the warn corresponds to an opt-in category. A verifier emitting `warn_category: ""` for a warn that SHOULD be one of the named categories (e.g., a dev-key warning that emits `""` instead of `"dev_key"`) is structurally non-conformant — the warn-fold logic won't fire and `summary.warns_opted_into_pass` will diverge from the contract. Verifiers MAY use any natural-language warning text in `warnings[]` (that field is implementation-localized and IGNORED); the conformance contract operates on the structured `warn_category` field.

**Multi-warning safety invariant** (load-bearing): a verifier MAY emit MULTIPLE warnings in a single check's `warnings[]` array. When tagging `warn_category` on such a check, the verifier MUST emit a named category ONLY when EVERY warning in the array corresponds to that category. If the array contains a mix of opt-in-category warns and other warns (e.g., one pending-OTS warn + one transient-network warn), `warn_category` MUST be `""` (so the aggregator does NOT fold the mixed result into pass under the opt-in flag). This preserves the V1.0.6 substring-fallback's "conservative: only opt INTO Pass when EVERY warning is in the allowed category" semantic.

**Migration note.** Pre-v1.0.7 verifiers (including v1.0.6 and earlier) determined warn-fold via warning-text substring matching against stable markers ("DEVELOPMENT BUNDLE — verified with dev key", "pending Bitcoin confirmation", "--allow-anchor-pending opt-in"). Those substring matchers remain valid AS A FALLBACK PATH for verifiers consuming pre-v1.0.7 output; new verifiers MUST emit `warn_category` directly. The Go-native verifier (`apps/cli`) and the Go-WASM verifier (`apps/cli/cmd/nuwyre-wasm`) emit `warn_category` from v1.0.7.

### 14.5 Flag set

Conformant verifiers MUST honor a closed vocabulary of five flags:

- **`offline`** (boolean; default `false`) — skip checks 5/6/7 (network-dependent). Under `offline: true`, checks 5/6/7 produce `status: "skipped"` with `skip_reason: "..."`. `--offline` accepts `skipped` as part of an overall `pass` verdict (the operator explicitly opted INTO skipping external-anchor checks; the bundle is "verified offline," a weaker guarantee than full verification). Without `--offline`, a `skipped` check produces `partial_verification`.

  **Transient-network semantics under `offline: false`** (gap acknowledged at v1.0.7 first fix-up batch per spec-conformance-reviewer F5; future v1.x amendment will tighten): when the operator passes `offline: false` but the network call required by check 5 (Esplora/Bitcoin), check 6 (no network needed — local TSA verification), or check 7 (GitHub raw) fails (timeout, DNS error, HTTP non-2xx with definitive-but-non-business-logic failure), verifier implementations MAY emit `status: "warn"` with `warnings[]` describing the network failure (under default fold-into-partial-verification semantics), OR `status: "fail"` with `errors[]` (when the network failure is interpretable as a definitive verification failure — e.g., GitHub returns 404 for the anchor commit, which is NOT transient). The V1 reference Go verifier (`apps/cli/internal/checks/check7_github.go`) emits `warn` for transient `IsTransient` failures and `fail` for definitive failures. A future v1.x MAY pin this behavior more tightly (e.g., explicit `--allow-transient-network` opt-in flag); tracked as Phase 5+ refinement. Preservation surfaces: (i) this spec paragraph; (ii) Session 5.5.1C closure ops log entry; (iii) `apps/cli/internal/checks/check7_github.go` `handleAnchored` code comments at the `IsTransient` branches.

- **`strict_ots`** (boolean; default `false`) — treat pending-OTS receipts as `fail` rather than `warn`. Mutually exclusive with `allow_pending_ots`; mutually exclusive with `offline` (the latter skips check 5 entirely). A conformant verifier MUST reject `strict_ots: true` combined with `allow_pending_ots: true` OR `offline: true` as an invocation error.

- **`allow_pending_ots`** (boolean; default `false`) — fold the `pending_ots` warn category into `passed`. Pending OTS receipts (calendar attestations present, no Bitcoin block proof yet) are common in V1 example-demo and fresh production bundles; this flag opts INTO accepting them.

- **`allow_anchor_pending`** (boolean; default `false`) — fold the `anchor_pending` warn category into `passed`. V1 deploy-bootstrap state has `mirror_status: "anchor-pending"` on GitHub anchor refs; this flag opts INTO accepting them.

- **`allow_dev_key`** (boolean; default `false`) — fold the `dev_key` warn category into `passed`. Example-demo bundles signed with the dev key emit `dev_key` warn (per-check status `warn`, with `warn_category: "dev_key"`); this flag opts INTO accepting them. **WITHOUT** this flag, the dev-key warn does NOT fold, so the check 1 status remains `warn` (NOT `fail` — spec §5 mandates the warn even when dev-key verification structurally succeeds) and the overall verdict becomes `partial_verification` (per §14.2 verdict precedence). The flag only affects the verdict-aggregator's fold decision; the per-check status is `warn` either way. (Pre-amendment draft text said "check 1 produces `fail`"; reconciled at the v1.0.7 first fix-up batch per spec-conformance-reviewer F12.)

**Flag-interaction validation.** Conformant verifiers MUST reject contradictory flag combinations as invocation errors (exit code 2; not part of `JSONOutput`):

| Flag combination | Verifier behavior |
|---|---|
| `offline + strict_ots` | REJECT (exit 2) — offline skips check 5; strict_ots requires check 5 to run + treat pending as fail |
| `strict_ots + allow_pending_ots` | REJECT (exit 2) — strict_ots makes pending → fail; allow_pending_ots folds pending warn INTO pass; mutually exclusive opt-ins |
| `offline + allow_pending_ots` | ACCEPT — allow_pending_ots is no-op when offline skips check 5 |
| `offline + allow_anchor_pending` | ACCEPT — allow_anchor_pending is no-op when offline skips check 7 |
| `offline + allow_dev_key` | ACCEPT — dev_key warn is from check 1 (local-only), still emitted under offline |

CLI representation: each flag maps to `--<flag-name>` with hyphen-separated kebab-case (e.g., `--allow-pending-ots`). JSON object representation (used by WASM/TS verifiers): underscore-separated snake_case keys matching this list verbatim.

**API surface variations.** The native CLI rejects contradictory flags via `os.Exit(2)` + stderr message. The WASM verifier (per `apps/cli/cmd/nuwyre-wasm/main.go`) MUST reject contradictory flags via a rejected Promise carrying an `Error` whose `.message` describes the contradiction — same conformance contract, surfaced through the JS Promise rejection channel rather than process-exit. Future verifier implementations (TS-native, Python, Rust) follow the surface idiom appropriate to their host environment but MUST reject the same two contradictory combinations.

### 14.6 Check slug enum

Each check has a stable slug used in `checks[i].check_slug` AND in `--check <slug>` CLI filter flags. Slugs are hyphen-separated kebab-case (NOT underscores). The seven slugs are:

| `check_id` | Check (per §14) | `check_slug` |
|---|---|---|
| 1 | Manifest signature | `manifest-signature` |
| 2 | Artifact integrity | `artifact-integrity` |
| 3 | Hash chain reconstruction | `hash-chain` |
| 4 | Merkle proof verification | `merkle-proof` |
| 5 | OpenTimestamps Bitcoin anchor | `opentimestamps` |
| 6 | RFC 3161 timestamp anchor | `rfc3161` |
| 7 | GitHub anchor cross-check | `github` |
| 8 | Ephemeral session attestation (v1.0.9) | `ephemeral-session` |
| 9 | Audit-log Merkle dual-subtree composition (v1.0.10) | `audit-log-merkle` |

The §14 Check headings ("Manifest signature", "Artifact integrity", etc.) are descriptive prose; the `check_slug` column is the canonical conformance identifier. Implementations SHOULD use the §14 headings verbatim as `check_name` when populating it (the reference Go verifier does so), but MAY use any human-readable label since `check_name` is optional + ignored by the conformance contract. `check_slug` MUST be drawn from the closed vocabulary above.

Slugs are stable across v1 — the v1.0.9 amendment adds `ephemeral-session` (check_id: 8); the v1.0.10 amendment adds `audit-log-merkle` (check_id: 9); the v1.0.11 amendment formalizes the closed-enum row for `audit-log-merkle` (F6 closure — pre-v1.0.11 the slug was referenced in §16.9 prose but missing from this enum table). Further v1.x amendments may add additional checks but MUST NOT rename existing slugs. A v2 spec MAY introduce a new slug naming convention. Implementations matching on slug (vs. matching on `check_id` integer) provide more readable CI / operator output but the same conformance contract holds either way.

-----

## 15. Versioning

### 15.1 v1 lock-in

v1 is locked. The fields documented above are stable for the life of v1. Backward-compatible additions (new optional fields) are permitted within v1; backward-incompatible changes (renaming a field, changing its type, removing a required field, changing the canonicalization rules) require a bundle-format version bump.

**v2.0.0-rc1 cohabitation (2026-05-21 Phase 7.F.1 amendment)**: v1 lock-in remains in force; the v1 contract documented in §§4-17 is the canonical specification for `bundle_format = "nuwyre-bundle/v1"` bundles indefinitely. The v2.0.0-rc1 amendment at §18 introduces a sibling contract for `bundle_format = "nuwyre-bundle/v2"` bundles; v1 bundles continue to verify under the v1 contract per SPEC_GOVERNANCE.md §3.2 forensic-record-preservation invariant + the 12-month-deprecation-window discipline. The 12-month deprecation window is operationally moot pre-customer-#1 (zero v1.0.17 customer bundles exist at the time of the v2.0.0-rc1 amendment); the multi-version discipline is enforced for forensic-record-preservation invariant integrity rather than customer-migration management. Pre-v2.0.0-rc1 verifiers encountering v2.0.0-rc1+ bundles MUST fail-loudly at the §2 `bundle_format` enumeration gate (the value `"nuwyre-bundle/v2"` is not in their permitted set) rather than misverify. Post-v2.0.0-rc1 verifiers MUST handle both v1.x bundles (via single-Ed25519 dispatch) AND v2.x bundles (via dual-signature dispatch per §18.7); cross-version dispatch is by the `bundle_format` string per §2 dispatch table.

A "v1.x" sub-version increment indicates a forward-compatible field addition that older v1 verifiers SHOULD ignore gracefully. v1.x writers SHOULD only emit additions when `bundle_type` semantics require them.

**v1.0.9 amendment (Pre-Phase 6 Item 2 closure 2026-05-15).** A v1.x amendment that introduces a topology-discriminator field (`signing.topology`) whose absence defaults to the pre-amendment semantic IS v1.x-eligible — legacy bundles remain conformant unchanged; legacy verifiers process them identically. Pre-v1.0.9 verifiers encountering v1.0.9 ephemeral-sessions bundles fall through forward-compat tolerance to the single-key path and FAIL Check 3 (per-event signature mismatch — the dev key cannot verify ephemeral-key-signed events); the fail-loudly outcome holds even though the diagnostic is generic rather than topology-specific. The amendment is therefore non-breaking for legacy verifiers reading legacy bundles AND non-misleading for legacy verifiers reading new bundles (they fail rather than misverify).

**v1.0.10 amendment (Phase 6.2.A closure 2026-05-15).** A v1.x amendment that introduces a new closed-enum value (`bundle_type = "audit-log-export"`) + a conditional required field (`bundle_subtype`) + a conditional required field (`audit_log_event_count` per v1.0.11 F2 closure) + a conditional `merkle_subtrees` manifest object + new artifacts (`audit_log_events.jsonl` + `audit_log_subtree.json`) IS v1.x-eligible — pre-v1.0.10 bundle types (customer-export + example-demo + sandbox-preview) emit no new fields + carry no new artifacts; pre-v1.0.10 verifiers process pre-v1.0.10 bundles identically. Pre-v1.0.10 verifiers encountering a v1.0.10 audit-log-export bundle fail at the §4.1 closed-enum `bundle_type` validation gate — pre-v1.0.10 verifiers don't know the `"audit-log-export"` enum value; the gate rejects it with a specific "unknown bundle_type" diagnostic BEFORE any downstream check runs. Fail-loudly outcome; pre-v1.0.10 verifiers do NOT misverify v1.0.10 bundles. The amendment is therefore non-breaking for legacy verifiers reading legacy bundles AND non-misleading for legacy verifiers reading new bundles. v1.0.10 verifiers accept all prior versions per §17 compatibility surface. (F14 closure 2026-05-15 — parallel paragraph structure to v1.0.9 paragraph above.)

**v1.0.11 amendment (Phase 6.2.A first-fix-up batch closure 2026-05-15).** A spec-clarity amendment that pins NOT_IMPLEMENTABLE + IMPLEMENTABLE-WITH-LEAK reconciliations against v1.0.10 BEFORE Phase 6.2.B implementation. v1.0.11 makes NO byte-shape changes to any prior bundle type (customer-export + example-demo + sandbox-preview + audit-log-export); the spec text reconciliations only ensure that an external implementer reading §§4-17 (+ SPEC_GOVERNANCE.md + fixture suite) at v1.0.11 produces a byte-identical audit-log-export bundle to NuWyre's TS reference impl at Phase 6.2.B. No prior bundle is invalidated by v1.0.11; no prior verifier is invalidated. Forward-compat tolerance preserved.

### 15.2 Conditions for v2

A v2 is justified when one or more of the following becomes true:

- The Ed25519 signature scheme requires replacement (post-quantum migration; specific compromise of Ed25519 in a forensic-relevance window).
- The hash algorithm requires replacement (SHA-256 weakened to a forensic-relevance threshold).
- The merkle tree construction or the canonicalization rules need to change.
- A new anchor leg is added that reshapes `manifest.json:anchors`.
- A signing-format change (e.g., COSE_Sign1 instead of detached Ed25519 over JCS bytes).

Routine additions (a new optional field, a new TSA in the default set, a new audio MIME type) do NOT justify a v2.

**v2.0.0-rc1 trigger condition (Phase 7.F.1 amendment, 2026-05-21)**: v2.0.0-rc1 is justified under BOTH the **"signing-format change"** condition (manifest.signing flat object → container with signatures[] array; signature.sig single-Ed25519 wrapper → JSON multi-signature container) AND the **"Ed25519 signature scheme requires replacement (post-quantum migration)"** condition framed as **post-quantum HEDGE rather than REPLACEMENT** (the Ed25519 signature is preserved in v2 alongside ML-DSA-65; both signatures cover identical canonical manifest bytes; both MUST verify per §18.7). The hedge framing is institutionally important: Ed25519 has not been compromised in any forensic-relevance window at the time of this amendment; the v2.0.0-rc1 amendment exists to **future-proof against CRQC threat models** (NIST projections for cryptographically-relevant quantum computers capable of breaking Curve25519 discrete-log range from ~2035 through ~2040+; bundles emitted under v1 single-Ed25519 in 2026 could face hostile-re-verification from 2031+ litigation under threat models that did not exist at emission time). The dual-signature topology means any single algorithm being broken in the future does not invalidate v2 bundles' integrity — both Ed25519 AND ML-DSA-65 would need to be simultaneously broken to forge a v2 bundle. This is procurement-claim-defensible (compliance-buyer's general counsel reading "NuWyre ships post-quantum dual signing" can verify both signatures byte-by-byte against the conformance fixture suite once Phase 7.F.4 promotes) AND threat-model-honest (v1 bundles remain valid under their v1 contract; v2 bundles add the hedge without invalidating v1).

The v2.0.0-rc1 amendment does NOT touch: hash algorithm (SHA-256 preserved); Merkle tree construction (preserved per §8); canonicalization rules (RFC 8785 JCS preserved per §§4.3 + 7.5); anchor legs (OTS + RFC 3161 + GitHub all preserved per §§10-12; GitHub anchor leg explicitly preserved per Phase 7.F "explicitly NOT in scope" boundary); per-event ingestion_signature topology (Ed25519 single-sig preserved at v2.0.0; per-event ML-DSA-65 deferred to v2.1+ if procurement signal warrants the ~3KB-per-event cost). The amendment scope is bounded to the manifest-level signing topology + the cross-language byte-equivalence contract for the dual-sig conformance fixture suite at Phase 7.F.4.

Future v2.x amendments MAY extend the conditions above (e.g., a v2.1 amendment that adds per-event ML-DSA-65 signing alongside per-event Ed25519); each future v2.x amendment follows the same SPEC_GOVERNANCE.md §3.2 deprecation discipline + Phase-7-style sub-arc planning.

**v1.0.9 amendment scoping posture (2026-05-15).** The v1.0.9 sandbox-only ephemeral-session signing amendment introduces a signing-format change THAT WOULD trigger the v2 condition above IF it applied to customer-export bundles — but it is explicitly scoped to `bundle_type = "sandbox-preview"` only (per spec §5 topology-vs-bundle_type table). Customer-export production signing format is UNCHANGED at v1.0.9 (single-key topology preserved verbatim per §5 + §6.3). A future extension of ephemeral-session signing to customer-export WOULD trigger this v2 condition and is explicitly out of scope for v1.0.9; the §6.5.7 forward-secrecy threat model would also tighten under such an extension (in-process key zeroization; possibly hardware-backed ephemeral keys) before customer-export adoption could be defensible.

### 15.3 CLI multi-version support

The Phase 4 CLI MUST support every produced format version forever. A v2 CLI SHOULD verify v1 bundles produced before the v2 cutover; a v2 reader MUST NOT silently coerce v1 bundles. The CLI's `nuwyre version` output SHOULD list the format versions it supports.

A reader / verifier MUST reject any unknown `bundle_format` value. A reader that doesn't recognize `nuwyre-bundle/v2` MUST refuse to verify a v2 bundle, not pretend to verify it under v1 rules.

### 15.4 Spec governance

Per Standards-Track Posture (build plan §"Standards-Track Posture"): the bundle format spec is public, the conformance suite is public, customer-specific structural customization is forbidden. Substantive changes to this spec require:

- A draft RFC-style change document with rationale.
- Conformance fixture updates (positive + at least one negative for any new check).
- Both implementations updated to pass the new fixture set.
- A version bump if the change is backward-incompatible.
- A spec changelog entry.

Spec changelog lives at the top of this document under a "Revision history" section once the first amendment lands. v1.0 is initial publication.

-----

## 16. Audit-log-export bundle type (v1.0.10)

Added in **v1.0.10** to provide operator-side + customer self-service audit-log evidence surfaces. Closes Phase 6.2.A authoring per build plan v3.1.18 §"Sub-arc 6.2 — `audit_log_export.generate_artifact`" + operator manual §9 Decisions Made archive (Option B: extend `packages/evidence` with audit-log-export bundle type via bundle-format-v1 spec amendment + cross-implementation conformance fixtures; locked).

**Applicability.** v1.0.10 audit-log-export ships under `bundle_type = "audit-log-export"` (§4.1 closed-enum extension) + `bundle_subtype ∈ {"customer-scoped", "operator-only"}` (§4.1 conditional REQUIRED field). Customer-export + example-demo + sandbox-preview bundle types are UNCHANGED at v1.0.10 (continue to operate under their v1.0.7 + v1.0.9 contracts respectively). Future application of audit-log-export-style semantics (e.g., dual-subtree Merkle composition) to other bundle types would trigger §15.2 v2 condition + is out of scope here.

### 16.1 Purpose + scope

An **audit-log-export bundle** is a forensic artifact of operational events recorded outside the customer's primary AI agent interaction stream. Audit log events include:

- **Customer-visible events** (`bundle_subtype = "customer-scoped"`): API key issuance + rotation; user invite + role change; policy pack assignment changes; evidence-export requests + approvals; sandbox session lifecycle (creation + purge); audit-log-export request lifecycle (request → approve → generate). All scoped to the requesting customer's organization (RLS enforced per §16.6).
- **Operator-internal events** (`bundle_subtype = "operator-only"`): admin authentication events; cross-tenant administrative actions; KMS key rotation; signing-key fingerprint changes; cron job lifecycle (success + failure); cost-ceiling alarm-emits; integration-secret rotation. Scoped to operator administrative actions; NOT customer-accessible.

Both subtypes share the v1.0.10 bundle layout + Merkle composition + signing topology + retention semantics described below; they differ only in `bundle_subtype` discriminator + the scope of audit log events included.

### 16.2 Audit-log event schema

Audit log events share `schema_version` + `event_id` + `forensic` top-level shape with event-v1; the remaining fields (`event_type` + `actor` + `subject` + top-level `content_hash`) are audit-log-specific and NOT present in event-v1. Conversely, event-v1's `agent_attestation_id` + `identity` + `content` + `compliance_metadata` + `provenance` are NOT present in audit-log-event-v1. The audit-log event is NOT a structural subset of event-v1; the two are siblings sharing common forensic-chain fields. **Machine-readable validation contract for audit-log events lives at `docs/spec/audit-log-event-v1.schema.json` (Phase 7.D session 85 adoption per BACKLOG 1.48 A.2; v1.0.17 amendment)** — external implementers MUST validate audit-log event payloads against the companion schema in addition to the prose contract below. The two schemas (event-v1 + audit-log-event-v1) are independent + locked at `schema_version: 1` across v1.x amendments.

Each audit log event:

```jsonc
{
  "schema_version": 1,
  "event_id":          "uuid-v5 — see §16.2 derivation rule",
  "event_type":        "audit-log:<category>:<verb>",  // e.g., "audit-log:api-key:rotated"
  "actor":             { "type": "user|admin|system|cron", "id": "uuid-or-system-id" },
  "subject":           { "type": "customer|user|api-key|policy-pack|...", "id": "uuid", "organization_id": "uuid-or-null" },
  "content_hash":      "<sha256 of canonical event payload — see §16.2.1>",
  "forensic": {
    "timestamp_iso":      "ISO 8601 UTC no fractional",
    "timestamp_unix_ns":  "decimal-string nanoseconds",
    "sequence_number":    <int>,
    "prev_event_hash":    "<hex>",
    "event_hash":         "<hex>",
    "ingestion_signature":"<base64>"
  }
}
```

**`event_id` derivation (v1.0.11 F4 + v1.0.12 F-SC-1/F-SC-2/F-SC-3 closures).** Audit log event `event_id` is a UUID v5 deterministic identifier derived as:

- **Namespace UUID**: `urn:nuwyre:audit-log-event` resolved per RFC 4122 §4.3 — the fixed namespace UUID for this purpose is `7b6c5d4e-3a2b-5c4d-8e9f-0a1b2c3d4e5f` (canonical 16-byte input; pre-computed once + pinned in spec text to remove implementer-namespace ambiguity).
- **Name input**: the canonical string `<organization_id>:<sequence_number>:<timestamp_unix_ns>` (e.g., `"a7c3e8f1-1234-4abc-89ab-1234567890ab:42:1715760000000000000"`). For `bundle_subtype = "operator-only"`, `<organization_id>` is the all-zero sentinel UUID per §16.5.
  - **`<organization_id>` MUST be lowercase canonical RFC 4122 §3 UUID** (v1.0.12 F-SC-2 closure): 8-4-4-4-12 hex chars with hyphens; all lowercase. Uppercase or mixed-case inputs MUST be normalized to lowercase BEFORE name-string construction. Implementations MUST reject malformed inputs.
  - **`<sequence_number>` MUST be the canonical decimal ASCII representation** (v1.0.12 F-SC-1 closure): no leading zeros for positive values; the literal string `0` for zero; no sign prefix. This is the canonical form Python `str(int)` / Go `strconv.FormatInt(n, 10)` / Rust `n.to_string()` / JS template literal interpolation produces for non-negative integers.
  - **`<timestamp_unix_ns>` is the canonical decimal ASCII representation** of the nanosecond epoch (no leading zeros; no sign prefix).
- **UUID v5 output**: standard RFC 4122 §4.3 derivation (v1.0.12 F-SC-3 closure):
  - SHA-1 over (16-byte network-byte-order namespace UUID bytes || UTF-8 encoded name string bytes). The namespace UUID is concatenated as RAW BYTES (NOT the 36-char ASCII string).
  - Truncate to first 128 bits (16 bytes).
  - Set octet 6 high nibble to `0x5` (version 5 bits).
  - Set octet 8 high two bits to `0b10` (RFC 4122 variant bits).
  - Format as canonical 8-4-4-4-12 lowercase hex per RFC 4122 §3.

**`actor.type` + `subject.type` closed vocabulary** (v1.0.12 F-SC-6 closure). Writers MUST emit only the enumerated values; verifiers MAY tolerate unknown values per §1 forward-compat (writer-side strictness; reader-side tolerance):
- `actor.type`: `{user, admin, system, cron}`
- `subject.type`: `{customer, user, api-key, policy-pack, admin-action, cross-tenant, system, cron}`

**`sequence_number` range constraint** (v1.0.12 F-SC-11 closure). `sequence_number` is a non-negative integer in the range `[0, 2^63 - 1]` (Postgres `bigserial` ceiling). JCS canonicalizes integers per RFC 8785 §3.2.2.3 (decimal ASCII; no leading zeros; no fractional part). Implementations using fixed-precision integer types (Go `int64`, Rust `u64`, Java `long`) handle the full range natively; implementations using JS `number` MUST validate `sequence_number <= Number.MAX_SAFE_INTEGER` (`2^53 - 1`) and either reject or escalate to a bigint representation when exceeded.

Audit log events form an **independent chain** distinct from the primary event chain (§6.2); see §16.2.2 for chain isolation rules. The chain integrity properties (gap-free sequence; prev_event_hash linkage; canonical content_hash; per-event ingestion_signature) apply equivalently to audit log events. Verifiers MUST verify audit log chain integrity per §6.2 semantics with the audit-log subtree as the chain root rather than the primary event chain root.

### 16.2.1 Audit log event canonical content_hash derivation (v1.0.11 F4 closure)

Pre-v1.0.11 the audit log event `content_hash` derivation was undocumented — §16.2 said "subset of event-v1 schema" but the primary event's §6.4 content payload (`{role, content, content_hash, audio_ref}`) does not apply to audit log events (which have no `role` or `audio_ref` semantic). v1.0.11 pins the canonical derivation:

```
audit_log_event.content_hash = SHA-256( JCS(canonical_content_payload) )
  where canonical_content_payload = {
    "actor":      { "type": <actor.type>, "id": <actor.id> },
    "subject":    { "type": <subject.type>, "id": <subject.id>, "organization_id": <subject.organization_id> },
    "event_type": <event_type>
  }
```

The canonical content payload is canonicalized per RFC 8785 JCS (lexicographic key ordering; deterministic across implementations); SHA-256 of canonicalized UTF-8 bytes is encoded as 64-char lowercase hex per §4.3. The payload deliberately excludes `forensic` (which carries `content_hash` itself + `event_hash` + signatures — circular if included) and `schema_version` (a layer-discriminator; not content). External implementers MUST produce byte-identical `content_hash` for the same `(actor, subject, event_type)` triple given the spec's RFC 8785 JCS canonicalization rules.

**Strict-fields posture** (v1.0.12 F-SC-4 closure — Arc #1 H1 defect-class parallel). The canonical content payload MUST contain EXACTLY the named field set:
- The `actor` sub-object contains EXACTLY the keys `{type, id}` (no additional fields).
- The `subject` sub-object contains EXACTLY the keys `{type, id, organization_id}` (no additional fields).
- The top-level object contains EXACTLY the keys `{actor, subject, event_type}` (no additional fields).

Implementations MUST NOT include additional fields in the canonical payload even when the source audit log row carries extension fields per §1 forward-compat tolerance. The strict-fields posture closes the cross-implementation divergence risk identified at Arc #1 H1 (Zod `.default()` leak) — extension fields at the row level are valid per forward-compat, but they MUST NOT be reflected in the canonical pre-image bytes. Lowercase hex output is required at content_hash per §4.3; uppercase or mixed-case content_hash values are rejected by downstream chain-walk discipline (per §6.2 + §16.2.2 chain-walk regex `^[0-9a-f]{64}$`).

### 16.2.2 Audit log event chain isolation (v1.0.11 F4 + DUAL-corroborated closure)

Audit log events form an **independent chain** per `(organization_id, bundle_subtype)`. Specifically:

- For `bundle_subtype = "customer-scoped"`: ONE chain per `organization_id` (the customer's organization UUID). All customer-scoped audit log events for one organization form a single chain ordered by `sequence_number` ascending.
- For `bundle_subtype = "operator-only"`: ONE chain per operator-UUID (the all-zero sentinel UUID per §16.5). All operator-only audit log events form a single chain ordered by `sequence_number` ascending.

The primary event chain (§6.2) and audit log chains are **DISJOINT sequence spaces**. `sequence_number` is per-chain not shared. A customer's primary event chain at position 12345 and their customer-scoped audit log chain at position 678 are unrelated sequence positions; the chains are independent in linkage + verification.

`prev_event_hash` linkage for audit log events references the prior AUDIT LOG event in the same chain, NOT the prior primary event. The genesis sentinel (`GENESIS_PREV_HASH` per §6.2) is the prev_event_hash for the first audit log event in each chain.

**Audit log `event_hash` derivation** (v1.0.12 F-SC-5 closure). Audit log event `event_hash` is computed per the §6.2 primary-event formula applied verbatim with the audit-log-specific `content_hash` (per §16.2.1):

```
event_hash = SHA-256( JCS({
  prev_event_hash:    <64-char lowercase hex>,
  content_hash:       <64-char lowercase hex>,
  sequence_number:    <int>,
  timestamp_unix_ns:  <decimal-string>
}) )
```

The canonical pre-image field set is the SAME 4 fields as primary events. **`event_type`, `actor`, and `subject` are NOT in the event_hash pre-image** — they participate in the content_hash pre-image per §16.2.1 + are bound into event_hash via content_hash. External implementers MUST use exactly these 4 fields; including or excluding any other field is a defect.

### 16.2.3 PII handling in audit log content (v1.0.11 sec-aud H3 closure)

Audit log event content is bundle-byte-level — once a bundle is generated + anchored, the content is permanent + cross-anchored to OTS/RFC 3161/GitHub witnesses. Free-text PII embedded in `actor.id` or `subject.id` (when those fields are otherwise opaque UUIDs) OR in `event_type` (which is a closed-vocabulary discriminator, NOT a free-text field) is **permanently leaked into the bundle bytes**. Therefore:

- `actor.id` and `subject.id` MUST be opaque identifiers (UUIDs for user/admin/customer/api-key/policy-pack types; canonical system identifiers like `"cron:<job-name>"` for system/cron types). MUST NOT be email addresses, full names, phone numbers, or other PII.
- `event_type` is a closed-vocabulary discriminator (`audit-log:<category>:<verb>`); MUST NOT be a free-text description. The category + verb together identify the event class; the actor + subject identify the involved entities.
- The PII-bearing user record itself (email address, full name, etc.) lives in the operator's database (RLS-scoped per §16.6.2) and is NEVER embedded in audit log event content. Auditors needing PII context perform a lookup at audit time via the operator's database, NOT by reading bundle bytes.

External implementers building audit log writers MUST enforce this discipline at write time. Verifiers MUST NOT validate PII discipline (PII detection is heuristic + out of scope); the discipline is a writer-side invariant.

### 16.3 Merkle composition (single daily root + dual subtrees)

Per operator Decision 1 at 2026-05-15 recon-pass: audit-log-export bundles use a **dual-subtree Merkle composition under a shared daily root**:

```
daily_root = SHA-256( events_subtree_root_bytes || audit_log_subtree_root_bytes )
```

Where:
- `events_subtree_root` is the Merkle root of the primary event chain for the day (computed identically to v1.0.7 single-tree semantics per §8).
- `audit_log_subtree_root` is the Merkle root of the audit log event chain for the day (computed per §8 semantics but over `audit_log_events.jsonl` rather than `events.jsonl`; see §16.3.2 for the audit log subtree leaf-ordering rule).
- The concatenation operator `||` is byte-concatenation per **MUST-language** (v1.0.11 F3 closure + crypto-int H2 closure): both subtree root operands are 32 **raw bytes** EACH (decoded from the 64-character lowercase hex in `manifest.merkle_subtrees.events_root` + `audit_log_root` respectively; NOT the hex strings themselves; NOT base64; NOT any other encoding). The SHA-256 input is therefore EXACTLY 64 raw bytes (32 || 32 byte concatenation).
- **Input ordering MUST-language (v1.0.11 F3 closure):** `events_subtree_root_bytes` MUST precede `audit_log_subtree_root_bytes` in the concatenation. Swapping the operand order produces a different `daily_root` value and is a generation defect. Verifiers MUST NOT accept the swapped order; bundles generated with the swapped order fail Check 9 (audit-log-merkle composition recomputation mismatch).
- **Merkle byte-order discipline (v1.0.11 DUAL-corroborated sec-aud H4 + crypto-int H3 closure):** within each subtree's internal-node hashing (§8.1), the left-sibling-first rule is preserved (per the existing §8.1 single-tree contract); `path[i].position` (NOT `path[i].side` — see §16.8 F1 closure) dispatches the walker per §8.2. All concatenations are raw byte concatenations of 32-byte decoded operands.
- The resulting `daily_root` is 32 raw bytes; encoded as 64-character lowercase hex in `manifest.daily_root` per §4.1 + `daily_roots.json` per §9 (same encoding as v1.0.7 single-tree daily roots — the encoding is preserved; only the composition changes).

Manifest carries `merkle_subtrees` object when `bundle_type = "audit-log-export"`:

```jsonc
"merkle_subtrees": {
  "events_root":     "<64-char lowercase hex SHA-256 of primary event subtree>",
  "audit_log_root":  "<64-char lowercase hex SHA-256 of audit log subtree>"
}
```

Pre-v1.0.10 bundles (customer-export + example-demo + sandbox-preview) emit `merkle_subtrees` field as ABSENT (forward-compat tolerance per §1; v1.0.10 verifiers tolerate the absent field as single-tree composition per the pre-v1.0.10 contract).

### 16.3.1 Empty-subtree composition (v1.0.11 F3 + crypto-int H5 closure)

When EITHER subtree's leaf list is empty (legitimate at `bundle_subtype = "operator-only"` where `events.jsonl` MAY be empty; theoretically possible at any subtype where `audit_log_events.jsonl` is empty though §16.5 customer-scoped subtype requires ≥1 audit log event in production), the subtree's `*_root` is the **32-byte all-zero genesis sentinel** (`0x00 * 32`; equivalently the 64-character hex string `"0000...0000"`). The rule applies symmetrically to both subtrees.

Specifically:
- If `events.jsonl` is empty: `events_subtree_root_bytes = 0x00 * 32`; `manifest.merkle_subtrees.events_root = "00..00"` (64 zero hex chars). The primary-event Merkle proof list (`merkle_proofs.json:proofs[]`) is empty `[]`; `merkle_proofs.json:root = "00..00"`.
- If `audit_log_events.jsonl` is empty: `audit_log_subtree_root_bytes = 0x00 * 32`; `manifest.merkle_subtrees.audit_log_root = "00..00"`. The audit log subtree proof list (`audit_log_subtree.json:proofs[]`) is empty `[]`; `audit_log_subtree.json:subtree_root = "00..00"`.
- The dual-subtree composition still computes `daily_root = SHA-256(0x00 * 32 || other_root_bytes)` per §16.3 formula; the resulting `daily_root` is NOT the genesis sentinel (it's the SHA-256 of the input).

Verifiers MUST accept the all-zero subtree root when the corresponding `.jsonl` file is empty (line count = 0). The synthetic empty-subtree note in Check 4 (§14 amendment) records the empty-state path.

**`audit_log_subtree.json` REQUIRED even when empty** (v1.0.12 F-SC-7 closure). When `audit_log_events.jsonl` is empty, `audit_log_subtree.json` is STILL emitted in the bundle with `{schema_version: 1, subtree_root: "0...0" (64 zero chars), proofs: []}`. The file is REQUIRED for all `bundle_type = "audit-log-export"` bundles regardless of leaf count. Verifiers MUST find the file present + parse-validate even when leaf count is zero.

**§16.5 cross-tenant invariant null-permit clarification** (v1.0.12 F-SC-12 closure). Per §16.5 cross-tenant invariant: EVERY audit log event's `subject.organization_id` MUST be either NULL (subject is org-agnostic — e.g., a built-in policy pack or a global resource) OR equal to `manifest.organization_id` (subject scoped to the manifest's customer organization). Cross-tenant subject linkage (`subject.organization_id != null AND != manifest.organization_id`) is forbidden under `bundle_subtype = "customer-scoped"`.

### 16.3.2 Audit log subtree leaf ordering (v1.0.11 F9 closure)

Pre-v1.0.11 the audit log subtree leaf ordering was unspecified — §16.3 said "computed identically to §8 semantics" but §8.1 pins `event_id` ascending sort order, which is implementation-unsafe for audit log events because audit log `event_id` is UUID v5 deterministic and depends on the namespace UUID + name input (which v1.0.11 §16.2 pins explicitly; pre-v1.0.11 was implementer-namespace-divergent).

v1.0.11 pins the audit log subtree leaf ordering to **`forensic.sequence_number` ascending**:

- Leaves are `forensic.event_hash` values from `audit_log_events.jsonl`, in **`forensic.sequence_number` ascending sort order** (NOT `event_id` ascending per §8.1 primary-event rule).
- The leaf list is padded to the next power of two with the genesis sentinel hash (64 zero hex chars; same padding rule as §8.1).
- All other §8.1 Merkle construction rules apply unchanged (internal node hashing; root computation; padded_leaf_count discipline).

The rationale: audit log event sequence_number is the canonical per-chain ordering (per §16.2.2 chain isolation); using sequence_number ordering for leaves preserves the chain-vs-tree invariant (i'th chain event = i'th tree leaf). Primary events at §8.1 use event_id sort because event_id is UUID v4 random (sort-stable across implementations) AND the primary chain is per-organization spanning sessions where sequence_number is also canonical — both orderings happen to be implementation-stable for primary events. For audit log events the only implementation-stable ordering is sequence_number ascending.

### 16.4 Daily root anchoring (inherits §10/§11/§12 semantics)

The composed `daily_root` (32 raw bytes; 64-char hex) is anchored via the existing three-leg anchor witness pattern unchanged:

- **OpenTimestamps (§10)**: OTS receipt over `daily_root` bytes; submitted to OTS calendar(s); Bitcoin block confirmation upgrade pattern preserved.
- **RFC 3161 (§11)**: ≥2 of 3 commercial TSA receipts over `daily_root` bytes; signing certificate chain validation preserved.
- **GitHub anchor (§12)**: optional production-bundles-only commit anchor; `daily_root` recorded in anchor commit body.

**Same-day cross-bundle anchor coexistence (v1.0.11 F12 + DUAL-corroborated closure).** Pre-v1.0.11 §16.4 prose ("audit-log-export bundle MUST anchor against the same `daily_root` that the customer-export bundle... anchors against") was incoherent: the customer-export bundle's `daily_root` is the single-tree events_root, while the audit-log-export bundle's `daily_root` is the dual-subtree composition `SHA-256(events_subtree_root || audit_log_subtree_root)`. These are LITERALLY DIFFERENT HASH VALUES; "anchor against the same daily_root" is impossible by construction.

v1.0.11 reconciles: when BOTH a customer-export bundle AND an audit-log-export bundle exist for the same UTC day for the same `organization_id`, they are **SEPARATE BUNDLES** with **SEPARATE `daily_root` values**, each anchored **INDEPENDENTLY**:

- The customer-export bundle's `daily_root` is the single-tree events_root (per §8 single-tree composition); its OTS/RFC 3161/GitHub anchors witness THAT value.
- The audit-log-export bundle's `daily_root` is the dual-subtree composition (per §16.3); its OTS/RFC 3161/GitHub anchors witness THAT (different) value.
- There is no cross-bundle daily_root sharing. Generating an audit-log-export bundle AFTER the customer-export bundle for the same day does NOT require re-anchoring the customer-export bundle (which would be a retroactive change to a signed manifest — forbidden).
- The primary event chain `events.jsonl` content in the audit-log-export bundle MAY be byte-identical to the customer-export bundle's `events.jsonl` for the same day; the bundles share the primary-event content but differ in `daily_root` because the audit-log-export bundle's daily_root is composed with the audit log subtree.

### 16.5 Bundle subtypes (`bundle_subtype` field semantics)

Per operator Decision 4 at 2026-05-15 recon-pass: v1.0.10 ships both customer-scoped + operator-only subtypes.

**`bundle_subtype = "customer-scoped"`**:
- Audit log events filtered to the customer's organization scope (RLS-enforced at query layer per §16.6).
- Customer can request via `POST /v1/audit-log-exports` API; admin approval workflow same as evidence-export requests (per Phase 5 Session 1.3 substrate).
- Use case: compliance officer requests audit log artifact for SOC 2 internal audit; customer-facing data subject access request (DSAR) for audit events touching their data.
- `manifest.organization_id` SET to the requesting customer's organization_id.
- `agent_id` MAY be NULL (audit log events are organizational, not per-agent).

**`bundle_subtype = "operator-only"`**:
- Audit log events filtered to operator-internal scope (admin actions; cross-tenant administrative events; system events).
- Operator admin generates via internal tooling (NOT customer-accessible API).
- Use case: SOC 2 Type 1 audit posture (per operator manual §11 Pre-Launch Checklist under revised Tenant 1 framing); regulatory inquiry response; internal audit committee review.
- `manifest.organization_id` SET to the **all-zero RFC 4122 UUID sentinel**: exactly `"00000000-0000-0000-0000-000000000000"` (v1.0.11 F8 + TRIPLE-corroborated crypto-int C1 + sec-aud H1 + spec-conf F8 closure). Pre-v1.0.11 spec text deferred this sentinel to the operator manual ("or a sentinel value documented in operator manual") — that deferral was a Standards-Track Posture §1 "the moat is not the spec" leak: two conformant implementations would produce different bundle bytes for the same operator-only audit log content. v1.0.11 pins the sentinel in spec text so external implementers produce byte-identical operator-only bundle manifests.
- `agent_id` MUST be NULL (operator-only events have no agent scope).
- `agent_attestation_id` MUST be the all-zero sentinel UUID (consistent with `agent_id = NULL` + the cross-tenant scope absence).

Verifier MUST validate `bundle_subtype ∈ {customer-scoped, operator-only}` at parse time; any other value fails the closed-enum gate at §4.1. Cross-validation: when `bundle_type = "audit-log-export"`, `bundle_subtype` MUST be present; when `bundle_type != "audit-log-export"`, `bundle_subtype` MUST be absent (FORBIDDEN).

**Cross-tenant subject linkage invariant (v1.0.11 sec-aud C2 closure).** Under `bundle_subtype = "customer-scoped"`, EVERY audit log event's `subject.organization_id` (when non-null) MUST equal `manifest.organization_id`. Cross-tenant subject linkage in a customer-scoped audit log bundle is a bundle-byte-level invariant violation: a customer requesting their own audit log export MUST NOT receive audit log events referencing subjects from other customers' organizations.

Verifiers MUST enforce this invariant at parse time:
- For each audit log event in `audit_log_events.jsonl`: if `subject.organization_id != null` AND `bundle_subtype = "customer-scoped"`: MUST equal `manifest.organization_id`; mismatch is a Check 2 (artifact integrity) `fail` with error message identifying the offending event by `sequence_number` + the leaking subject.organization_id value.
- For `bundle_subtype = "operator-only"`: this invariant does NOT apply (operator-only bundles legitimately reference cross-tenant administrative actions); `subject.organization_id` MAY be any value or null.

External implementers building customer-scoped audit log writers MUST enforce this at write time (filter audit log events by `subject.organization_id IN (manifest.organization_id, NULL)` before bundle generation). The verifier check is a defense-in-depth gate; the primary enforcement is writer-side scoping via RLS per §16.6.2.

### 16.6 Signing topology + RLS at audit log event access

v1.0.11 splits this section into §16.6.1 (signing topology — unchanged from v1.0.10) + §16.6.2 (NEW; RLS at audit log event access). The v1.0.10 prose at §16.1 + §16.5 referenced "(RLS enforced per §16.6)" but §16.6 contained signing topology content with zero RLS material — that cross-reference was a spec-text-absent defect (sec-aud C1 closure).

### 16.6.1 Signing topology (v1.0.10 baseline; unchanged at v1.0.11)

Per operator Decision 2 at 2026-05-15 recon-pass: audit-log-export bundles preserve single-key signing topology per Pre-Phase 6 Item 1 closure (single prod KMS key signs per-event hashes + bundle manifest bytes). v1.0.8 two-key topology amendment remains evidence-gated; not bundled into v1.0.10/v1.0.11.

Audit-log-export bundles use the same `issuer-prod-v1` key (for `customer-export`-class production trust) or `issuer-dev-v1` (for dev environment) per the §5 key-dispatch table. The key dispatch is bundle_type-driven, not bundle_subtype-driven; both audit-log-export subtypes use the same signing key as customer-export.

**Topology constraint.** Under `bundle_type = "audit-log-export"`, `manifest.signing.topology` MUST equal `"single-key"` (or field absent → defaults to single-key per §5). The ephemeral-sessions topology (v1.0.9) is FORBIDDEN for audit-log-export bundles. Verifiers MUST reject `bundle_type = "audit-log-export"` combined with `topology = "ephemeral-sessions"` as a topology/bundle_type mismatch error (per the §5 v1.0.9 dispatch table extended at v1.0.11 with the audit-log-export row).

### 16.6.2 RLS at audit log event access (v1.0.11 NEW; sec-aud C1 closure)

Audit log event access is gated by Postgres Row Level Security (RLS) policies at the `audit_log` table per the standard NuWyre customer-scoping pattern. The RLS policy set:

- **`select_admin`**: admins see all rows (cross-tenant; `auth.uid() IN (SELECT id FROM admins)`).
- **`select_customer_member`**: customer members see rows scoped to their organization (`organization_id IN (SELECT customer_ids())`).
- **`no_update_trigger`**: append-only invariant; `audit_log_no_core_update` trigger rejects any UPDATE on forensic columns (`forensic.sequence_number`, `forensic.prev_event_hash`, `forensic.event_hash`, `forensic.ingestion_signature`, `forensic.timestamp_unix_ns`, `content_hash`).
- **`no_delete_outside_purge`**: DELETE permitted only via the documented retention-purge code path (per §16.7 retention semantics); ad-hoc DELETE rejected.

**Bundle generation scope gate.** When generating an audit-log-export bundle, the writer pipeline executes its `audit_log` query under the requesting principal's RLS context:

- For `bundle_subtype = "customer-scoped"`: query runs under the customer's RLS context; RLS scopes the result set to the customer's organization_id. The writer additionally filters audit log events by `subject.organization_id IN (organization_id, NULL)` (defense-in-depth against future RLS regressions — see §16.5 cross-tenant invariant).
- For `bundle_subtype = "operator-only"`: query runs under admin RLS context; admin sees all rows; writer additionally filters by `actor.type IN ('admin', 'system', 'cron')` AND `subject.type IN ('admin-action', 'cross-tenant', 'system', 'cron')` to produce the operator-internal scope.

The RLS-at-query-layer is the **primary scope gate**; the §16.5 cross-tenant invariant verifier check is defense-in-depth.

**Operator-only access boundary.** Operator-only bundles MUST NOT be served via customer-facing API endpoints. The API gate at `/v1/audit-log-exports` rejects `bundle_subtype = "operator-only"` requests from customer principals; admin-internal tooling (NOT exposed to customers) generates operator-only bundles. If an operator-only bundle's `bundle_id` leaks to a customer (e.g., via mis-permissioned storage URL), the customer-facing download API MUST verify the requesting principal's role + the bundle's `manifest.bundle_subtype` before serving — bundle-byte-level access control is enforced at the API gate, not at bundle bytes (which are static once generated). (sec-aud H2 closure 2026-05-15 — heavy-bookmarked at BACKLOG; full implementation lands at Phase 6.2.B apps/api endpoint extension.)

### 16.7 Retention semantics

Per operator Decision 3 at 2026-05-15 recon-pass: audit-log-export retention defaults to **7 years**, customer-configurable upward per contract terms. Rationale: aligns with SOC 2 retention pattern + Type 1 readiness assessment per operator manual §11 Pre-Launch Checklist under revised Tenant 1 framing ("long-term correctness over short-term convenience").

Specific retention semantics:
- **Default retention**: 7 years from `manifest.generated_at`.
- **Customer-configurable**: customers MAY contract for longer retention (e.g., 10-year, indefinite); operator MUST NOT contract for shorter than 7 years (regulatory floor per operator manual §11).
- **Cold storage transition**: bundles ≥3 years old MAY be transitioned to cold storage (e.g., S3 Glacier Deep Archive); retrieval latency tolerance documented in customer contract.
- **Deletion**: after retention expiry + 30-day grace period, bundles MAY be deleted; deletion MUST be logged in operator-only audit-log-export (`audit-log:bundle:deleted` event type).

Verifier discipline: retention semantics are **operator-side policy**, not bundle-byte-level invariant. Verifiers MUST NOT validate retention via spec text; retention is documented for operator + customer contract reference.

### 16.8 Bundle file layout

Audit-log-export bundles extend the v1.0.7 bundle layout (§3) with two new files:

```
<bundle.zip>/
  manifest.json                    (§4)
  signature.sig                    (§5)
  events.jsonl                     (§6; MAY be empty for operator-only subtype)
  evaluations.jsonl                (§7; MAY be empty for operator-only subtype)
  audit_log_events.jsonl           (NEW §16.8; per-line audit log event schema per §16.2)
  audit_log_subtree.json           (NEW §16.8; Merkle tree over audit_log_events.jsonl)
  merkle_proofs.json               (§8; for primary events; MAY be empty for operator-only)
  daily_roots.json                 (§9)
  ots_receipts/<YYYY-MM-DD>.ots    (§10)
  rfc3161_receipts/<YYYY-MM-DD>__<tsa>.tsr  (§11)
  rfc3161_receipts/<YYYY-MM-DD>__<tsa>.chain.pem  (§11)
  github_anchors/<YYYY-MM-DD>.json (§12; optional production)
  audio/<sha256>.<ext>             (§13; audio bound to primary events only; audit log events do not reference audio)
  cover.pdf                        (§3)
  verify.md                        (§3)
```

**`audit_log_subtree.json` shape** (parallel to `merkle_proofs.json` per §8; v1.0.11 F1 closure reconciles proof-step field names to match §8 verbatim):

```jsonc
{
  "schema_version": 1,
  "subtree_root": "<64-char lowercase hex SHA-256 of audit log subtree root>",
  "proofs": [
    {
      "event_id": "<uuid v5 per §16.2 derivation>",
      "leaf_index": <int>,
      "leaf":  "<hex>",                                                                                       // parallel to merkle_proofs.json proof.leaf at §8
      "path": [ {"position": "left|right", "sibling": "<hex>"}, ... ],                                        // v1.0.11 F1: field names "position" + "sibling" match §8 + §8.2 walker verbatim
      "root": "<64-char lowercase hex SHA-256 — equals audit_log_subtree.json:subtree_root>"
    },
    ...
  ]
}
```

The proof verification semantics match §8.2 (Check 4) exactly; the only difference is the subtree root identifier (`audit_log_subtree.json:subtree_root` parallels `merkle_proofs.json:root`). v1.0.11 F1 closure: pre-v1.0.11 the proof-step field names were `{"sibling_hash": "<hex>", "side": "left|right"}` — that conflicts with the §8.2 walker which dispatches on `step.position` (NOT `step.side`) AND reads `step.sibling` (NOT `step.sibling_hash`). v1.0.11 reconciles audit_log_subtree.json to use the §8-verbatim field names so the §8.2 walker pseudocode applies BYTE-IDENTICALLY without parsing-layer dispatch.

The §16.8 file's `subtree_root` MUST equal `manifest.merkle_subtrees.audit_log_root` (the subtree root carried in two places + cross-checked by Check 4). Each per-proof `root` MUST equal `subtree_root` per the §8.2 invariant (extended for dual-subtree composition per §8.2 v1.0.11 amendment — the per-proof root equals the SUBTREE root, NOT the daily_root).

### 16.9 Verification semantics extension

Verifiers process audit-log-export bundles via the existing seven checks (§14) PLUS optional Check 9 (audit-log-merkle) when `bundle_type = "audit-log-export"`:

- **Check 1 (manifest signature)**: unchanged; signing topology per §16.6.
- **Check 2 (artifact integrity)**: unchanged; verifies `audit_log_events.jsonl` + `audit_log_subtree.json` per `manifest.artifacts[]` declarations.
- **Check 3 (hash chain)**: applies to BOTH primary event chain (`events.jsonl`) AND audit log event chain (`audit_log_events.jsonl`) independently. Each chain verified per §6.2 semantics.
- **Check 4 (merkle proof)**: applies to BOTH `merkle_proofs.json` (primary) AND `audit_log_subtree.json` (audit log) independently. Each subtree verifies leaves against its own subtree root.
- **Check 5 (OpenTimestamps), Check 6 (RFC 3161), Check 7 (GitHub anchor)**: unchanged; all anchor against the composed `manifest.daily_root` (dual-subtree composition per §16.3).
- **Check 9 (audit-log-merkle; NEW)**: verifies dual-subtree composition: decodes `manifest.merkle_subtrees.events_root` + `manifest.merkle_subtrees.audit_log_root` from hex to 32-byte each; computes `SHA-256(events_subtree_root_bytes || audit_log_subtree_root_bytes)` per §16.3 MUST-language ordering; confirms equals `manifest.daily_root` (after hex-decoding). Runs conditionally when `bundle_type = "audit-log-export"`; **OMITTED otherwise** per v1.0.11 unification (DUAL-corroborated crypto-int M1 + sec-aud M3 + spec-conf F5 closure — pre-v1.0.11 prose said "skipped otherwise" which contradicts the §14.1 omit-inapplicable v1.0.9 pattern; v1.0.11 reconciles to OMITTED).

Check 9 `check_slug` = `"audit-log-merkle"`; `check_id` = 9. JSONOutput shape (§14.1) cardinality per the unified omit-inapplicable pattern: 7 entries for single-key + non-audit-log-export (v1.0.7 baseline); 8 entries for ephemeral-sessions + non-audit-log-export (v1.0.9); 8 entries for single-key + audit-log-export (v1.0.10/v1.0.11 — Check 8 OMITTED); ephemeral-sessions + audit-log-export FORBIDDEN per §16.6.1.

### 16.10 Cross-version compatibility

v1.0.10 is **additive** per §15.1 forward-compat tolerance. Specifically:

- **Pre-v1.0.10 bundles unchanged**: customer-export + example-demo + sandbox-preview bundles emitted by pre-v1.0.10 writers continue to verify identically under v1.0.10 verifiers (no field-shape changes; `merkle_subtrees` field absent → single-tree composition path preserved).
- **Pre-v1.0.10 verifiers + v1.0.10 audit-log-export bundles**: fail at §4.1 `bundle_type` closed-enum validation (pre-v1.0.10 verifiers don't know `"audit-log-export"` value; closed-enum gate rejects unknown value with specific "unknown bundle_type" error). Fail-loudly outcome; pre-v1.0.10 verifiers do NOT misverify v1.0.10 audit-log-export bundles.
- **v1.0.10 verifiers + pre-v1.0.10 bundles**: full backward-compat; v1.0.10 verifiers accept all prior versions per §17 compatibility surface.

-----

## 17. Bundle format v1.0.10 compatibility

This section formalizes the cross-version compatibility surface introduced by the v1.0.10 amendment.

### 17.1 `bundle_format` field stability

The major-version-stable contract per §15.1 holds: `bundle_format` MUST equal `"nuwyre-bundle/v1"` for all v1.x amendments (including v1.0.7, v1.0.9, v1.0.10). Implementations that read `bundle_format` and reject any other value continue to operate correctly across all v1.x amendments.

### 17.2 `bundle_type` enum extension

v1.0.10 extends the closed enum from the v1.0.9 set:

```
v1.0.7 set:  {"customer-export", "example-demo"}
v1.0.9 set:  {"customer-export", "example-demo", "sandbox-preview"}
v1.0.10 set: {"customer-export", "example-demo", "sandbox-preview", "audit-log-export"}
```

Verifiers MUST validate `bundle_type` against their supported enum set. Pre-v1.0.10 verifiers reject `"audit-log-export"` as unknown value (§16.10 forward-incompatibility path).

### 17.3 `bundle_subtype` + `audit_log_event_count` + `merkle_subtrees` fields (v1.0.10/v1.0.11 amendments)

New fields land at v1.0.10/v1.0.11:

- **`bundle_subtype`** (v1.0.10): REQUIRED when `bundle_type = "audit-log-export"`; closed vocabulary `{"customer-scoped", "operator-only"}`. FORBIDDEN when `bundle_type != "audit-log-export"`; pre-v1.0.10 bundles omit field per forward-compat tolerance (§1).
- **`audit_log_event_count`** (v1.0.11 F2 closure): integer; REQUIRED when `bundle_type = "audit-log-export"`; MUST equal the line count in `audit_log_events.jsonl`. FORBIDDEN when `bundle_type != "audit-log-export"`; pre-v1.0.10 bundles omit field. Fixture-asserted at `audit-log-missing-events/tamper.json` BEFORE spec text included the field — v1.0.11 reconciles spec text to fixture per Standards-Track Posture §3 fixtures-are-the-standard.
- **`merkle_subtrees`** (v1.0.10): object with `events_root` + `audit_log_root` fields (both 64-char lowercase hex SHA-256). REQUIRED when `bundle_type = "audit-log-export"`; FORBIDDEN otherwise; pre-v1.0.10 bundles omit field.

### 17.4 Implementation declarations

Reference implementations SHOULD declare their supported amendment versions via a `SUPPORTED_BUNDLE_FORMATS` constant or equivalent:

```typescript
// TS reference impl (packages/evidence)
export const SUPPORTED_BUNDLE_FORMATS = ["1.0.0", "1.0.7", "1.0.9", "1.0.10"] as const;
```

```go
// Go reference impl (apps/cli)
var SupportedBundleFormats = []string{"1.0.0", "1.0.7", "1.0.9", "1.0.10"}
```

The declaration is for operator + auditor inspection; not a manifest field (no `supported_versions` field in `manifest.json`). The constant documents which amendments the implementation understands.

### 17.5 Deprecation timeline

v1.0.10 is a **purely additive amendment** per §15.1. No prior version (v1.0.0 / v1.0.7 / v1.0.9) is deprecated. No deprecation timeline applies; all prior bundle types + signing topologies continue indefinitely.

Future v2 amendment per §15.2 (signing-format change OR structural Merkle change to existing bundle types OR canonicalization rule change) would deprecate prior versions; v1.0.10 does not trigger §15.2.

### 17.6 Conformance fixture suite v1.0.10 extension

v1.0.10 extends the conformance fixture suite at `docs/spec/fixtures/bundle-format-v1/` per operator Decision 5 (minimum viable):

- **`valid-audit-log-export/`** — conforms to v1.0.10 exactly; PASS all checks (Checks 1-4 + 9 active; Checks 5-7 follow normal anchor semantics).
- **`tampered-audit-log-event/`** — single audit log event content modified post-signing; FAIL Check 3 (hash chain) for audit log subtree.
- **`audit-log-missing-events/`** — manifest declares N audit log events; only N-1 present in `audit_log_events.jsonl`; FAIL Check 2 (artifact integrity).
- **`forged-audit-log-merkle-subtree/`** — audit log Merkle subtree root altered; primary subtree untouched; FAIL Check 4 (merkle proof) + FAIL Check 9 (audit-log-merkle composition).

Full conformance fixture coverage parallel to v1.0.7 + v1.0.9 extends across Phase 6.2.B + 6.2.C sub-arcs per documented timeline. The v1.0.10 fixture set ships at 6.2.A as minimum viable conformance contract; pre-v1.0.10 fixture set (10 v1.0.7 fixtures + 1 v1.0.9 cross-lang-ephemeral) remains valid.

-----

## 18. Bundle format v2.0.0-rc1 amendment (Phase 7.F.1, 2026-05-21)

**RELEASE-CANDIDATE POSTURE**. v2.0.0-rc1 is the cross-language contract for `bundle_format = "nuwyre-bundle/v2"` bundles pending Phase 7.F.4 cross-language byte-equivalence promotion to v2.0.0 final. The 9 sub-sections below are the **authoritative source** for v2 manifest signing topology + signature.sig multi-signature container + verifier discipline. v1 prose at §§4-17 remains authoritative for `bundle_format = "nuwyre-bundle/v1"` bundles (legacy; preserved per SPEC_GOVERNANCE.md §3.2 forensic-record-preservation invariant + §15.1 v1 lock-in cohabitation note).

The 9 sub-sections correspond to the 9 reviewer-discipline points carried forward from Phase 7.F sounding-board analysis with spec-conformance-reviewer + crypto-integrity-reviewer + security-auditor passes. Each sub-section uses normative MUST / MUST NOT / SHOULD language per RFC 2119 + RFC 8174 (the BCP 14 capitalized-keywords-only convention).

### 18.1 `manifest.signing` container schema

For v2.0.0-rc1+ bundles (`bundle_format = "nuwyre-bundle/v2"`), `manifest.json:signing` MUST be a container object with the following schema:

```jsonc
"signing": {
  "schema_version": 1,                                     // signing-container schema version (NOT bundle schema_version)
  "signatures": [
    {                                                       // signatures[0] — Ed25519
      "algorithm":                "ed25519",
      "key_id":                   "issuer-prod-v2-ed25519",         // matches verifier's pinned-key directory entry
      "key_fingerprint_spki_b64": "<base64 SPKI DER of Ed25519 public key>",
      "key_purpose":              "Ed25519 manifest signature; v2.0.0-rc1+ dual-sig topology"
    },
    {                                                       // signatures[1] — ML-DSA-65
      "algorithm":                "ml-dsa-65",
      "key_id":                   "issuer-prod-v2-ml-dsa-65",       // matches verifier's pinned-key directory entry
      "key_fingerprint_spki_b64": "<base64 SPKI DER of ML-DSA-65 public key — see §18.4 canonical DER byte construction; expected SPKI DER total ~1974 bytes>",
      "key_purpose":              "ML-DSA-65 manifest signature; v2.0.0-rc1+ dual-sig topology"
    }
  ]
}
```

**Cardinality**: signatures[] MUST contain EXACTLY 2 entries. Cardinality != 2 (including 0, 1, 3+) MUST be rejected with a "Check 1 FAIL (structural): manifest.signing.signatures cardinality != 2" error per §18.7.

**Positional ordering**: signatures[0] MUST be the Ed25519 entry (signatures[0].algorithm == "ed25519"); signatures[1] MUST be the ML-DSA-65 entry (signatures[1].algorithm == "ml-dsa-65"). Swapped positions are a structural fail per §18.8.

**Field discipline within each signatures[i] entry**: each entry MUST contain EXACTLY the keys `{algorithm, key_id, key_fingerprint_spki_b64, key_purpose}` (no additional fields; strict-fields posture per v1.0.12 F-SC-4 cross-implementation precedent). Verifiers MAY tolerate unknown fields per §1 forward-compat tolerance for v2.x amendments; v2.0.0-rc1+ writers MUST emit exactly the named field set.

**`key_purpose` field normative pin (spec-conformance M4 closure 2026-05-21)**: writers MUST emit the literal string `"Ed25519 manifest signature; v2.0.0-rc1+ dual-sig topology"` for `signatures[0].key_purpose` AND the literal string `"ML-DSA-65 manifest signature; v2.0.0-rc1+ dual-sig topology"` for `signatures[1].key_purpose`. Verifiers MUST byte-equal `key_purpose` against the literal strings at Check 1 step 2 schema-cross-check (extending the §18.7 cross-check inventory). Pinning the literal strings prevents cross-language byte-divergence on the manifest.json bytes (otherwise TS writer's English wording could differ from Go writer's English wording, breaking the §18.7 step 4 manifest canonicalization cross-check). Future v2.x amendments updating the topology description MAY introduce new normative literals via the §15.1 minor-amendment cadence.

**`key_id` field opaqueness pin (security-auditor L1 closure 2026-05-21)**: the example key_id strings (`issuer-prod-v2-ed25519`, `issuer-prod-v2-ml-dsa-65`, etc.) are illustrative defaults; verifier implementations MUST treat `key_id` strings as **opaque identifiers** looked up against the pinned-key directory + effective-period table per §5 v1 "Multi-key support" prose. The `v2` infix in the example names is NOT a verifier-required convention; verifiers MUST NOT pattern-match on the `v2` substring to discriminate v1-vs-v2 dispatch (that dispatch is by `bundle_format` per §2). Implementations MAY adopt different key_id naming conventions per organization (e.g., `nuwyre-prod-2026-ml-dsa-65` OR `customer-A-prod-rotation-3-ed25519`); the conformance contract operates on the `key_fingerprint_spki_b64` byte sequence + effective-period metadata, not on key_id string structure.

**Lexicographic key ordering within signatures[i] objects**: per RFC 8785 JCS, the canonical key order within each signatures[i] object is `{algorithm, key_fingerprint_spki_b64, key_id, key_purpose}` (alphabetical). Implementations that serialize via Go `encoding/json` (which sorts map keys lexicographically) + implementations that serialize via TS `JSON.stringify(canonicalizeJCS(...))` MUST produce byte-identical signatures[i] bytes; the §18.4 signature.sig canonicalization is built atop this invariant.

### 18.2 `signature.sig` multi-signature container schema

For v2.0.0-rc1+ bundles, `signature.sig` MUST be a JSON multi-signature container with the following schema, **itself RFC 8785 JCS-canonicalized** when written into the bundle ZIP:

```jsonc
{
  "schema_version": 1,                                      // signature.sig container schema version
  "signed_artifact": "manifest.json",                       // fixed for v2.0.0-rc1
  "signatures": [
    {                                                        // signatures[0] — Ed25519
      "algorithm":                "ed25519",
      "key_fingerprint_spki_b64": "<base64 SPKI DER — MUST match manifest.signing.signatures[0].key_fingerprint_spki_b64>",
      "key_id":                   "<MUST match manifest.signing.signatures[0].key_id>",
      "signature_b64":            "<base64 of raw 64-byte Ed25519 signature over canonical manifest.json bytes>"
    },
    {                                                        // signatures[1] — ML-DSA-65
      "algorithm":                "ml-dsa-65",
      "key_fingerprint_spki_b64": "<base64 SPKI DER — MUST match manifest.signing.signatures[1].key_fingerprint_spki_b64>",
      "key_id":                   "<MUST match manifest.signing.signatures[1].key_id>",
      "signature_b64":            "<base64 of raw 3309-byte ML-DSA-65 signature over canonical manifest.json bytes — see §18.4>"
    }
  ]
}
```

**Identical canonical manifest bytes**: both signatures[i].signature_b64 entries MUST be signatures over the SAME canonical RFC 8785 JCS-encoded `manifest.json` byte sequence. The byte sequence is the bundle's `manifest.json` file content exactly as written to disk (which itself MUST be RFC 8785 JCS-canonicalized per §4.3). Implementations MUST NOT sign different canonicalizations of the manifest for the two signatures — both signatures cover the IDENTICAL message bytes.

**JCS canonicalization of signature.sig itself**: signature.sig as written to the bundle ZIP MUST be the RFC 8785 JCS-canonicalized form of the JSON object documented above. The canonicalization applies AT signature.sig write time (after both signatures are computed).

**Per RFC 8785 §3.2.3, property names within all objects MUST be sorted in ascending order based on their UTF-16 code points (which is identical to UTF-8 lexicographic byte order for the ASCII subset used in JSON key names).** Applied to the signature.sig schema:

- **Top-level container key ordering**: `{schema_version, signatures, signed_artifact}`. Worked verification — compare `signatures` vs `signed_artifact` codepoint-by-codepoint: position 0-3 `s-i-g-n` equal; position 4 `a` (U+0061) vs `e` (U+0065); 0x61 < 0x65, therefore `signatures` < `signed_artifact` (NOT the other way around). Confirm: `schema_version` < `signatures` < `signed_artifact` is the alphabetical (codepoint-sort) result.
- **signatures[i] sub-object key ordering**: `{algorithm, key_fingerprint_spki_b64, key_id, signature_b64}`. Worked verification — `algorithm` starts with `a` (0x61); `key_*` start with `k` (0x6B); `signature_b64` starts with `s` (0x73). Compare `key_fingerprint_spki_b64` vs `key_id`: position 0-3 `k-e-y-_` equal; position 4 `f` (0x66) vs `i` (0x69); 0x66 < 0x69, therefore `key_fingerprint_spki_b64` < `key_id`. Confirm: alphabetical result is `{algorithm, key_fingerprint_spki_b64, key_id, signature_b64}`.

Without this discipline, naïve JSON serializers in Go (`encoding/json` orders STRUCT field tags by declaration order; for `map[string]interface{}` orders lexicographically by default; the two behaviors diverge depending on the implementer's data model choice) and TS (`JSON.stringify` orders by insertion order, which varies per writer implementation) produce byte-divergent signature.sig sequences. v2 implementations MUST invoke a **JCS-conformant canonicalizer library** rather than relying on language-native JSON encoders. Recommended libraries (cross-language byte-equivalence proven against RFC 8785 reference test vectors):

- Go: `gibson042/canonicaljson-go` (a Go port of `cyberphone/json-canonicalization`) — already used by `apps/cli` for manifest.json canonicalization at v1.0.x baseline.
- TypeScript / JavaScript: `@truestamp/canonify` OR `canonicaljson-jcs` — already used by `packages/evidence` for manifest.json canonicalization at v1.0.x baseline.
- Python: `jcs` (PyPI; reference implementation by Anders Rundgren, the RFC 8785 editor).
- Rust: `canonical-json` OR `rfc8785` (verify upstream maintenance + test-vector conformance).

**Integer-emit pin (crypto-integrity M3 cascade)**: integer fields (`schema_version: 1`) MUST emit as bare integer `1` per RFC 8785 §3.2.2.3 (integer-as-decimal rule); MUST NOT emit as `1.0` OR `1.0e0` OR `1e0` (the float-formatting pathways that some JCS canonicalizer libraries route through if they go through their language's Number/float type). The Phase 7.F.5 KAT vectors at `apps/cli/internal/checks/testdata/` pin the expected signature.sig byte sequence (including the bare-integer emission for `schema_version`) so cross-language canonicalizer drift surfaces at fixture-time.

The JCS-canonicalization-of-signature.sig discipline is the load-bearing invariant that makes cross-language signature.sig SHA-256 byte-equivalence possible.

**Field discipline**: top-level container MUST contain EXACTLY the keys `{schema_version, signed_artifact, signatures}`. Each signatures[i] entry MUST contain EXACTLY the keys `{algorithm, key_fingerprint_spki_b64, key_id, signature_b64}`. Strict-fields posture per v1.0.12 F-SC-4 cross-implementation precedent; verifiers MAY tolerate unknown fields per §1 forward-compat for v2.x amendments; v2.0.0-rc1+ writers MUST emit exactly the named field sets.

**`signed_artifact` constraint**: MUST equal `"manifest.json"` for v2.0.0-rc1. Future amendments MAY extend this to signed-artifact-other-than-manifest (e.g., signing the entire bundle ZIP rather than just the manifest); such amendments would land at a v2.1+ minor amendment per §15.1 cadence.

### 18.3 ML-DSA-65 FIPS 204 framing pin (deterministic variant)

Implementations MUST use FIPS 204 deterministic-variant ML-DSA-65 signing per **FIPS 204 §5.2 (ML-DSA.Sign external API, Algorithm 2), §6.2 (Sign_internal, Algorithm 7), and §3.7 (deterministic-vs-hedged mode definition)** of the standard (FIPS 204 final published August 2024; cf. NIST.FIPS.204), invoked as:

```
ML-DSA.Sign(sk, M, ctx)
  where:
    sk  = the ML-DSA-65 private key (raw 4032-byte FIPS 204 ML-DSA-65 secret key — size per §4 Table 1; encoding per §7.2 Algorithm 24 `skEncode`)
    M   = the canonical RFC 8785 JCS-encoded manifest.json byte sequence (§18.2 invariant)
    ctx = b"" (empty byte string; pinned for v2.0.0-rc1; ZERO bytes)
```

The internal `Sign_internal` framing per FIPS 204 §5.2 Algorithm 2 line 12-14 applies:

```
M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M
```

Where `IntegerToBytes(n, 1)` encodes integer `n` as a single octet. The **first octet** (`0x00`) is the **mode discriminator** distinguishing pure ML-DSA.Sign (§5.2) from HashML-DSA (§5.4, which uses `0x01`). The **second octet** is the length of `ctx` as a single octet (`|ctx|`); FIPS 204 §5.2 line 4 constrains `|ctx| ≤ 255` as input validation. For v2.0.0-rc1 with `ctx = b""` (length 0), `IntegerToBytes(0, 1)` yields `0x00`, so the concatenation evaluates to:

```
M' = 0x00 || 0x00 || M
```

The two leading `0x00` octets are coincidentally identical because (a) the mode discriminator for pure ML-DSA.Sign is `0x00` AND (b) the empty-ctx length octet is `0x00`. Future v2.x amendments using non-empty ctx (up to 255 bytes per FIPS 204 §5.2 input validation) would change the second octet accordingly to `|ctx|`; the prefix would no longer be `0x00 || 0x00`.

Implementations MUST NOT use HashML-DSA (the prehashed variant per FIPS 204 §5.4 + Algorithm 4) for v2.0.0-rc1; HashML-DSA-based libraries are non-conformant. HashML-DSA prehashes the message with a context-bound SHAKE-256 invocation BEFORE the pure-mode framing, which produces byte-divergent signature inputs.

**Deterministic-variant pinning** (load-bearing for cross-language byte-equivalence):

- `rnd` parameter (FIPS 204 §3.7 + §6.2 Algorithm 7 lines 14-16 randomness derivation in `Sign_internal`): MUST be **32 zero bytes** for v2.0.0-rc1 (`rnd = 0x00 × 32`). The deterministic variant per FIPS 204 §3.7 informative note sets `rnd` to a fixed value (the zero-bytes-of-length-32 canonical choice per §6.2 Algorithm 7 line 16 alternative); the hedged variant per FIPS 204 §6.2 Algorithm 7 line 14 derives `rnd` from a cryptographically-secure random source (`rnd ← rand(32)`). v2.0.0-rc1 mandates the DETERMINISTIC VARIANT. A library that only exposes the hedged variant MUST be rejected by implementations claiming v2.0.0-rc1 conformance; cross-language byte-equivalence is impossible under hedged-mode randomness.
- `ctx` parameter: MUST be the empty byte string `b""` for v2.0.0-rc1 (zero length; pinned per spec). Future v2.x amendments MAY use a non-empty ctx (e.g., domain-separation prefix; up to 255 bytes); v2.0.0-rc1 leaves ctx empty for byte-equivalence with the FIPS 204 standard's reference test vectors.
- Hashing: ML-DSA-65 internally uses SHAKE-256 per FIPS 204 §3.6; no SHA-256 prehashing of M is required or permitted in pure mode.

**Side-channel mitigation discipline (security-auditor M1 closure 2026-05-21)**: deterministic-mode signatures are more vulnerable to power-analysis side-channel attacks than hedged-mode signatures (per FIPS 204 §3.7 informative note); repeated signings over similar messages reveal more secret-key bits per observation under deterministic mode than under hedged mode. Deterministic-mode pinning at v2.0.0-rc1 is **required for cross-language byte-equivalence** (the load-bearing conformance contract at Phase 7.F.4); operators deploying NuWyre signing in side-channel-vulnerable environments (multi-tenant cloud VMs without dedicated host; co-tenant-Spectre-vulnerable hypervisors; insider-with-physical-access threat models) MUST use KMS-backed signing for ML-DSA-65 (where the secret key never leaves the HSM boundary; the side-channel attack surface is contained within the HSM's defenses). The dev-slot file-based signing path is acceptable only in trusted single-tenant development environments per §5 v1 prose. The cross-language byte-equivalence contract does NOT relax the side-channel discipline; operator deployment posture MUST account for the trade-off.

**Library-selection conformance evidence** (per §18.9): an implementation MUST verify that its chosen ML-DSA-65 library: (a) exposes a deterministic-variant API (or accepts a `rnd` parameter that can be pinned to 32 zero bytes); (b) implements FIPS 204 §5.2 + §6.2 pure-mode signing; (c) does NOT pre-hash M (no HashML-DSA fallback). Implementations MUST cross-validate signature bytes against the FIPS 204 Appendix B reference test vectors before claiming v2.0.0+ conformance. **Library API call shape pinning is now closed** at §18.3.1 below (Phase 7.F.5 session 103 closure of heavy-bookmark `spec-conf H5`).

### 18.3.1 Library API call shapes (informative registry)

**Status**: informative (non-normative); landed at Phase 7.F.5 session 103 (build-plan v3.1.56) per heavy-bookmark `spec-conf H5` closure. Pure additive amendment per SPEC_GOVERNANCE.md §3.1 third-dot cadence (first v2.0.1 additive after v2.0.0 LOCKED at Phase 7.F.4 session 102). No on-wire byte change; cross-language byte-equivalence contract unchanged.

**Purpose**: a third-party implementer in Python, Rust, Java, or any post-v2.0.0 language MUST be able to identify the deterministic-variant API call shape for their chosen ML-DSA-65 library without reading NuWyre reference-implementation source. This sub-section enumerates the API call shape per library that implements §18.3 deterministic-variant invocation byte-for-byte equivalently.

**Registry of evaluated libraries** (organized by language; alphabetical within language):

**Go — `github.com/cloudflare/circl/sign/mldsa/mldsa65` (v1.6.3+)**:

```go
import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

var sig [mldsa65.SignatureSize]byte // 3309 bytes per FIPS 204 §4 Table 1
if err := mldsa65.SignTo(sk, msg, nil, false, sig[:]); err != nil {
    // err != nil only on len(ctx) > 255; ctx==nil here so unreachable
    // but assignment + check is required to catch future regressions.
}
```

- `sk *mldsa65.PrivateKey` — the secret key (loaded via `mldsa65.NewKeyFromSeed(&seed)` for deterministic key derivation from a 32-byte seed)
- `msg []byte` — the canonical message bytes (RFC 8785 JCS-canonicalized manifest.json bytes for v2.0.0+)
- `nil` (3rd positional arg, `ctx []byte`) — pinned to `nil` for v2.0.0; semantically equivalent to `[]byte{}` (empty context) per §18.3 — the cloudflare/circl v1.6.3 implementation handles both as zero-length ctx with identical byte output
- `false` (4th positional arg, `randomized bool`) — pinned to `false` to select FIPS 204 §6.2 deterministic variant
- `sig[:]` — caller-allocated 3309-byte output buffer
- Returns `error` only when `len(ctx) > 255` — unreachable in v2.0.0 but MUST be checked

**TypeScript / Node — `@noble/post-quantum/ml-dsa` (v0.6.1+)**:

```typescript
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

const sig: Uint8Array = ml_dsa65.sign(
  M,                              // canonical message bytes
  sk,                             // 4032-byte secret key from ml_dsa65.keygen(seed)
  { extraEntropy: false }         // FIPS 204 §6.2 deterministic variant (rnd=32 zero bytes)
);
// sig.length === 3309 per FIPS 204 §4 Table 1
```

- `M: Uint8Array` — canonical message bytes
- `sk: Uint8Array` — 4032-byte secret key (loaded via `ml_dsa65.keygen(seed)` where `seed: Uint8Array` is 32 bytes per FIPS 204 §6.1)
- `{ extraEntropy: false }` — selects deterministic-variant per noble convention (semantically equivalent to passing `rnd = new Uint8Array(32).fill(0)` in libraries that expose rnd directly). Reference impl wrapper at `packages/evidence/src/ml-dsa-65.ts` `signDeterministic(message, secretKey)` enforces this.
- Returns `Uint8Array` of exactly 3309 bytes; throws on invalid input

**Empirical-proof artifact**: KAT-V2-2 at `apps/cli/internal/checks/testdata/v2_dual_sig_kats_v1.json` pins the SHA-256 of the 3309-byte signature produced by BOTH the cloudflare/circl + @noble/post-quantum API call shapes above when given identical seed (`000102…1e1f`) + identical message (`0011…ffff`): SHA-256 = `047cc486867498a6154f2b2de425b5d7dabcc100676bcff971f227289cbc90a1`. A third-party library implementing FIPS 204 §6.2 deterministic-variant correctly MUST produce a byte-identical signature for these inputs.

**Future libraries**: as additional ML-DSA-65 libraries land (Python `pqcrypto-mldsa`, Rust `pqcrypto-dilithium`, Java Bouncy Castle, etc.), this registry SHOULD be amended per SPEC_GOVERNANCE.md §3.1 additive-amendment cadence with the per-library API call shape + reference to KAT-V2-2 as the byte-equivalence anchor. Adding a library row is non-breaking; removing/renaming a library row would be breaking and requires §3.2 major-amendment governance.

**Heavy-bookmark `spec-conf H5` closed**: this sub-section satisfies the closure criterion documented at §18.3 + §18.9.

### 18.4 ML-DSA-65 SPKI wrapping + signature byte format

**Public-key SPKI encoding** per RFC 5280 SubjectPublicKeyInfo:

- **AlgorithmIdentifier OID**: `2.16.840.1.101.3.4.3.18` (id-ml-dsa-65 per NIST CSOR — the Computer Security Objects Register at https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration).
- **AlgorithmIdentifier parameters**: ABSENT (omitted entirely; NOT a NULL value). The RFC 5280 §4.1.1.2 distinction between "parameters omitted" and "parameters present with NULL value" is load-bearing for the byte-equivalence contract — ML-DSA-65 SPKI encoding follows the IETF LAMPS WG draft + NIST CSOR registration, which both specify parameters ABSENT.
- **BIT STRING subject public key**: raw 1952-byte ML-DSA-65 public key (size per FIPS 204 §4 Table 1; encoding per §7.2 Algorithm 22 `pkEncode`) with ZERO unused bits. Per X.690 §8.6.2 DER encoding, the BIT STRING is `tag (0x03) || length || unused-bits-octet || content`; the **unused-bits octet** — the first content octet immediately after the DER tag-and-length prefix — MUST be `0x00`, indicating zero unused trailing bits in the final content octet.

**Public-key SPKI total byte count + DER length-encoding pin (spec-conformance H2 closure 2026-05-21)**: DER length encoding admits multiple valid forms (short form for content length < 128; long form for content length ≥ 128). Without a normative pin, cross-implementation libraries could produce SPKI DER bytes of byte-distinct lengths even though both forms are DER-valid. v2.0.0-rc1 pins the **canonical SPKI DER byte construction** for ML-DSA-65:

```
SPKI DER byte sequence (total 1974 bytes for ML-DSA-65):

  30 82 07 B2                                           # outer SEQUENCE; long-form length 0x82 0x07 0xB2 = 1970 content octets
                                                         # (outer header = 4 bytes: tag 0x30 + length-prefix 0x82 + 2-byte length 0x07B2)
  30 0B                                                 # AlgorithmIdentifier SEQUENCE; short-form length 0x0B = 11 content octets
    06 09 60 86 48 01 65 03 04 03 12                    # OID 2.16.840.1.101.3.4.3.18 (id-ml-dsa-65) — tag 0x06 + length 0x09 + 9 OID-content bytes = 11 bytes total
                                                         #   (parameters field ABSENT — no NULL octet sequence; no extra bytes after the OID)
  03 82 07 A1                                           # BIT STRING tag + long-form length 0x82 0x07 0xA1 = 1953 content octets
                                                         # (BIT STRING header = 4 bytes: tag 0x03 + length-prefix 0x82 + 2-byte length 0x07A1)
    00                                                  # unused-bits octet (0 unused bits)
    <1952 raw public-key bytes>                         # ML-DSA-65 public key per FIPS 204 §7.2 Algorithm 22 pkEncode
```

**Byte count arithmetic** (implementer-verifiable):

- AlgorithmIdentifier SEQUENCE: tag (1) + length (1, short-form 0x0B) + content (11 OID bytes) = **13 bytes**
- BIT STRING: tag (1) + length (3, long-form 0x82 0x07 0xA1) + unused-bits octet (1) + raw key (1952) = **1957 bytes**
- Outer SEQUENCE content = AlgorithmIdentifier (13) + BIT STRING (1957) = **1970 bytes** (matches the outer length 0x07B2 = 1970)
- Outer SEQUENCE total = tag (1) + length (3, long-form 0x82 0x07 0xB2) + content (1970) = **1974 bytes total SPKI DER**

Implementations MUST produce SPKI DER bytes byte-equal to this construction (1974 bytes total). The long-form length encoding (`0x82` prefix + 2 length octets) is REQUIRED for any content length ≥ 128 octets per X.690 §8.1.3.5 + §8.1.3.4; ML-DSA-65 SPKI's outer SEQUENCE content (1970 bytes) and BIT STRING content (1953 bytes) both exceed 128 octets so both REQUIRE long-form length encoding. The cross-implementation byte-equivalence contract is enforced at the **KAT vector layer at Phase 7.F.5** where the regenerated test vectors at `apps/cli/internal/checks/testdata/` pin the exact byte sequences with hex dumps for cross-language libraries to validate against.

**Signature byte format (crypto-integrity H1 closure 2026-05-21 — FIPS 204 final ML-DSA-65 SIGBYTES = 3309, NOT 3293)**: ML-DSA-65 signatures are raw **3309-byte sequences** per FIPS 204 §4 Table 1 (the `ML-DSA-65.SIGBYTES` constant; not configurable). The pre-FIPS-204 Dilithium3 academic-paper signature size of 3293 bytes is **non-conformant**; FIPS 204 finalization (August 2024) added the `tr = H(pk)` binding into the signature framing per §6.2 Algorithm 7 line 6 + expanded the commitment-hash encoding, which grew the total signature size by 16 bytes. Implementations using libraries that produce 3293-byte signatures (pre-FIPS-204 Dilithium3 academic-reference impls) MUST be rejected; libraries claiming v2.0.0-rc1 conformance MUST emit FIPS 204 final signatures of exactly 3309 bytes.

Encoded for transport in `signature.sig:signatures[1].signature_b64` as base64 (RFC 4648 §4 standard alphabet — uppercase A-Z + lowercase a-z + digits 0-9 + `+` + `/`). **Padding semantics (crypto-integrity L1 closure)**: because 3309 is divisible by 3 (3309 = 3 × 1103) — the base64 encoding emits **NO `=` padding characters**. Expected base64 string length for a 3309-byte signature is `4 × 1103 = 4412` characters with no trailing `=`. This is a real divergence from Ed25519 (whose 64-byte signature always emits `==` two-character padding because 64 mod 3 ≠ 0). Implementations MUST validate base64 decode produces exactly 3309 bytes; implementations MUST NOT emit phantom `=` padding for ML-DSA-65 entries (a stray `=` would yield base64-decode failure under strict decoders OR a 3310-byte decode under permissive decoders — both reject at §18.7 structural failure).

**Ed25519 signature byte format**: preserved verbatim from v1 — raw 64-byte sequences per RFC 8032 §5.1.6, encoded for transport in `signature.sig:signatures[0].signature_b64` as base64 (RFC 4648 §4 standard alphabet) WITH `==` padding (88-character total length; the `==` padding is mandatory because 64 mod 3 = 1). Implementations MUST validate base64 decode produces exactly 64 bytes for the Ed25519 entry.

**Cross-validation of `key_fingerprint_spki_b64`**: the value in `manifest.signing.signatures[i].key_fingerprint_spki_b64` MUST byte-equal the value in `signature.sig:signatures[i].key_fingerprint_spki_b64` at each position. Disagreement is a Check 1 schema-cross-check failure per §18.7. Both values MUST byte-equal the SPKI DER of the public key in the verifier's pinned-key directory entry referenced by `key_id`.

### 18.5 `manifest.artifacts[]` excludes signature.sig + bidirectional set-equality invariant

**Exclusion rule**: `manifest.artifacts[]` MUST NOT contain an entry whose `path` is `"signature.sig"`. The manifest is signed BEFORE the signature container exists; therefore the manifest cannot describe its own signature container's bytes (the entry for signature.sig would be circular — signing manifest bytes requires the manifest's artifacts[] to be defined, but artifacts[].signature.sig.sha256 would depend on the signature.sig bytes which depend on the signature which depends on the manifest bytes). Verifiers MUST reject any v2 manifest whose artifacts[] contains a `path == "signature.sig"` entry with a "Check 1 FAIL (structural): manifest.artifacts[] includes signature.sig (circular reference)" error.

**Bidirectional set-equality invariant**: the bundle ZIP file-set MUST equal:

```
ZIP_files = {manifest.json, signature.sig} ∪ {manifest.artifacts[].path for all i}
```

**Duplicate-filename ZIP pre-check (spec-conformance M1 closure 2026-05-21)**: ZIP archive format permits multiple entries with identical filenames (the same `path` field appearing twice in the central directory; entries' content bytes can differ). This is an attacker-controllable surface that a naïve `set(zip_paths) == set(artifacts ∪ {manifest, signature.sig})` check would silently absorb (the duplicate-second-entry's bytes go unverified). Verifiers MUST enumerate ZIP entries with duplicate-detection BEFORE computing set equality: any duplicate filename in the ZIP central directory MUST fail Check 2 with `"Check 2 FAIL: ZIP contains duplicate filename entry <path>"` error. Duplicate-filename detection precedes the set-equality computation; only after duplicate-filename validation passes does the verifier compute the file-set for set-equality.

The set-equality is BIDIRECTIONAL: (a) every file in the bundle ZIP MUST be either `manifest.json`, `signature.sig`, or appear in `manifest.artifacts[].path`; (b) every entry in `manifest.artifacts[].path` MUST correspond to a file present in the bundle ZIP. Extra files in the ZIP (file present in ZIP, not in artifacts[] ∪ {manifest.json, signature.sig}) MUST fail Check 2 with an "extra file smuggled into bundle" error. Missing files (path in artifacts[], not in ZIP) MUST fail Check 2 with a "missing file declared in manifest" error.

**v1 + v2 parallel discipline**: v1.0.x specifications already enforce the EXCLUSION rule (signature.sig is not in artifacts[]) implicitly via the §4.3 prose "every file in the bundle is either `manifest.json`, `signature.sig`, OR appears in `artifacts[]`". v2.0.0-rc1 makes the discipline EXPLICITLY BIDIRECTIONAL and pins the rejection-on-circular-reference behavior for v2 verifiers. v1 verifiers MAY continue to use the v1.0.x prose interpretation; v2 verifiers MUST enforce the bidirectional set-equality per §18.7.

### 18.6 Cross-environment-slot discipline + bundle-type-to-key-slot mapping

**Environment slot definition**: each pinned issuer key in the verifier's key directory carries an environment-slot tag in `{prod, dev}`. The slot tag is part of the verifier's compile-time configuration + the operator-side `apps/cli/internal/keys/` directory layout. v2.0.0-rc1 introduces TWO key-pairs per environment slot: Ed25519 + ML-DSA-65. The default key directory layout for v2.0.0-rc1:

- `issuer-prod-v2-ed25519` (prod slot; Ed25519)
- `issuer-prod-v2-ml-dsa-65` (prod slot; ML-DSA-65)
- `issuer-dev-v2-ed25519` (dev slot; Ed25519)
- `issuer-dev-v2-ml-dsa-65` (dev slot; ML-DSA-65)

**Cross-slot rule**: `manifest.signing.signatures[0].key_id` AND `manifest.signing.signatures[1].key_id` MUST belong to the SAME environment slot (both prod OR both dev; never one prod and one dev). A bundle with signatures[0].key_id = `issuer-prod-v2-ed25519` paired with signatures[1].key_id = `issuer-dev-v2-ml-dsa-65` (or any other mixed-slot combination) MUST fail Check 1 with a "schema-cross-check: environment-slot mismatch between signature slots" error per §18.7.

**Bundle-type-to-key-slot mapping** (extends §5 v1 prose for v2.0.0-rc1):

- `bundle_type = "customer-export"` (v2 dispatch) → MUST verify against `{issuer-prod-v2-ed25519, issuer-prod-v2-ml-dsa-65}` (or whichever production keys were active at bundle creation time per the verifier's pinned-key directory + effective-period table).
- `bundle_type = "example-demo"` (v2 dispatch) → MUST verify against `{issuer-dev-v2-ed25519, issuer-dev-v2-ml-dsa-65}`. Verifier emits a clear `"DEVELOPMENT BUNDLE — verified with dev keys, not for production trust"` warning even on success (the v1 `--allow-dev-key` flag + `dev_key` warn category per §14.4 extend naturally to v2 dual-sig).
- `bundle_type = "sandbox-preview"` (spec-conformance H4 closure 2026-05-21) → at v2.0.0-rc1, sandbox-preview bundles MUST continue to use `bundle_format = "nuwyre-bundle/v1"` (NOT v2); the v1.0.9 ephemeral-sessions topology per §§5 + 6.5 is preserved verbatim. v2 dispatch is NOT YET available for sandbox-preview bundles; a v2 sandbox-preview path would require reconciling the dual-signature topology with the ephemeral-session per-event signing topology, which is OUT OF SCOPE for v2.0.0-rc1 (see Phase 7.F "explicitly NOT in scope" boundary). A future v2.x amendment MAY introduce a v2 sandbox-preview dispatch with dual-sig + ephemeral-sessions composition.
- `bundle_type = "audit-log-export"` (v2 dispatch; security-auditor H1 closure 2026-05-21) → MUST verify against the production-slot key-pair (`{issuer-prod-v2-ed25519, issuer-prod-v2-ml-dsa-65}`) when `manifest.signing.signatures[i].key_id` references prod-slot keys, OR the dev-slot key-pair (`{issuer-dev-v2-ed25519, issuer-dev-v2-ml-dsa-65}`) when key_id references dev-slot keys. The verifier infers the slot from key_id; the per-§18.6 cross-environment-slot invariant remains in force (both signature positions MUST belong to same env slot). **Dev-slot acceptance for audit-log-export bundles MUST surface a Check 1 `dev_key` warning** (parallel to the §5 example-demo warning) so the operator sees that the bundle was emitted under a development-slot key-pair, NOT a production-slot key-pair; the dev-slot warn folds into pass only when `--allow-dev-key` is explicitly set per §14.4. **Bundle-subtype constraint**: `bundle_subtype = "customer-scoped"` MAY emit under EITHER prod OR dev slot (development environments commonly emit customer-scoped audit-log-export for testing); `bundle_subtype = "operator-only"` SHOULD emit under prod slot only in production deployments — operator-only audit-log-export bundles signed with dev-slot keys MUST surface the dev_key warning AND verifiers SHOULD treat the resulting bundle with elevated suspicion (the operator-only subtype carries SOC 2 + regulatory-inquiry-response evidence weight per §16.1; dev-slot emission of an operator-only bundle is a red flag for a leaked-dev-key-claiming-prod-evidence attack scenario). The fixture suite at §14.4 SHOULD include a `dev-keys-claiming-operator-only-audit-log/` tamper variant at Phase 7.F.4 to lock in this discipline.

**Cross-key verification reject discipline**: a v2 bundle claiming `bundle_type = "customer-export"` but signed with dev-slot keys (signatures[0].key_id = `issuer-dev-v2-ed25519`) MUST fail Check 1 with a specific "schema-cross-check: bundle-type-to-key-slot mismatch — customer-export expects prod slot, found dev slot" error per §18.7. Both signatures' key-slot tags MUST match the bundle_type's expected slot. The audit-log-export bundle type is the only v2 dispatch that accepts BOTH slots; the `dev_key` warn surfaces the dev-slot acceptance to the operator.

### 18.7 Check 1 failure taxonomy + ordered short-circuit

Check 1 (Manifest signature) for v2.0.0-rc1+ bundles dispatches through FIVE steps in strict order. Steps 1-4 short-circuit (a failure at step N halts the check; subsequent steps are not run; their per-step status fields are undefined). Step 5 (cryptographic verification) does NOT short-circuit per-signature (the verifier MUST verify BOTH Ed25519 + ML-DSA-65 and report ALL crypto failures so the operator sees both algorithm verdicts).

**Step 1 — Structural**:
- `signature.sig` parses as valid JSON.
- `signature.sig:schema_version == 1`.
- `signature.sig:signed_artifact == "manifest.json"`.
- `signature.sig:signatures[]` is an array of EXACTLY 2 entries.
- `signature.sig:signatures[0].algorithm == "ed25519"` AND `signature.sig:signatures[1].algorithm == "ml-dsa-65"` (positional ordering per §18.8).
- Each signatures[i] entry contains EXACTLY the keys `{algorithm, key_fingerprint_spki_b64, key_id, signature_b64}` (strict-fields).
- `signatures[0].signature_b64` base64-decodes to EXACTLY 64 bytes (Ed25519 raw signature length per RFC 8032).
- `signatures[1].signature_b64` base64-decodes to EXACTLY 3309 bytes (ML-DSA-65 raw signature length per FIPS 204 §4 Table 1).
- `signature.sig` is RFC 8785 JCS-canonicalized (the file bytes on disk match the canonical encoding of the parsed object; non-canonical signature.sig fails this step).
- `manifest.signing` matches the §18.1 container schema (signatures[] cardinality 2; positional ordering; strict-fields).
- `manifest.artifacts[]` does NOT contain a `"signature.sig"` entry per §18.5 exclusion rule.

(Note (spec-conformance M3 closure 2026-05-21): the `bundle_format == "nuwyre-bundle/v2"` / `schema_version == 2` cross-check is performed at the §2 format-identifier dispatch boundary BEFORE Check 1 step 1 runs — §2 mandates that verification MUST fail on the format-identifier check before any other check. By the time Check 1 step 1 runs, the bundle has already been routed through the §2 dispatch to the v2 verification path. The signature.sig + manifest.signing structural validation at step 1 assumes the v2 routing has succeeded.)

Failure at step 1 produces `"Check 1 FAIL (structural): <specific reason>"`. Step 2-5 not run.

**Step 2 — Schema-cross-check (manifest.signing ↔ signature.sig consistency)**:
- For each i ∈ {0, 1}: `manifest.signing.signatures[i].algorithm == signature.sig.signatures[i].algorithm`.
- For each i ∈ {0, 1}: `manifest.signing.signatures[i].key_id == signature.sig.signatures[i].key_id`.
- For each i ∈ {0, 1}: `manifest.signing.signatures[i].key_fingerprint_spki_b64 == signature.sig.signatures[i].key_fingerprint_spki_b64` (byte-equal).
- Cross-environment-slot discipline per §18.6: signatures[0].key_id and signatures[1].key_id belong to the same env slot.
- Bundle-type-to-key-slot discipline per §18.6: env slot of signatures[i].key_id matches the expected slot for `manifest.bundle_type`.

Failure at step 2 produces `"Check 1 FAIL (schema-cross-check): <specific reason>"`. Step 3-5 not run.

**Step 3 — Key lookup**:
- For each i ∈ {0, 1}: the verifier's pinned-key directory contains an entry whose `key_id == manifest.signing.signatures[i].key_id`.
- For each i ∈ {0, 1}: the pinned-directory entry's SPKI DER (when re-base64-encoded) byte-equals `manifest.signing.signatures[i].key_fingerprint_spki_b64`.

Failure at step 3 produces `"Check 1 FAIL (schema-cross-check): key-lookup failure for <key_id>"`. Step 4-5 not run. (Key lookup failures are categorized under "schema-cross-check" because they represent a manifest declaration that the verifier cannot resolve — a manifest-vs-verifier-config disagreement — not a structural or cryptographic failure.)

**Step 4 — Canonicalization**:
- The verifier recomputes the RFC 8785 JCS canonicalization of `manifest.json` and confirms it byte-equals the manifest.json file bytes as read from the bundle ZIP.
- Both signatures cover the IDENTICAL canonical byte sequence (§18.2 invariant); the verifier uses the recomputed canonical manifest bytes as the verification message M for both Ed25519 and ML-DSA-65.

Failure at step 4 produces `"Check 1 FAIL (structural): manifest.json is not RFC 8785 JCS-canonicalized"`. Step 5 not run. (Canonicalization failures are categorized as structural because they indicate a writer that did not produce canonical bytes; the manifest is unverifiable without canonical input.)

**Step 5 — Cryptographic verification** (NO short-circuit per-signature):
- Verify `Ed25519.Verify(pk_ed25519, M, signatures[0].signature_b64) == true` where `pk_ed25519` is the Ed25519 public key from the pinned-directory entry for signatures[0].key_id.
- Verify `ML-DSA-65.Verify(pk_ml_dsa, M, signatures[1].signature_b64) == true` where `pk_ml_dsa` is the ML-DSA-65 public key from the pinned-directory entry for signatures[1].key_id, per FIPS 204 §5.3 (ML-DSA.Verify) + §6.3 (Verify_internal) verification procedure with `ctx = b""` (matching the signing-time ctx per §18.3).

Both verifications run independently. The normative reporting format for the dual-algorithm verdict at step 5 (security-auditor M2 closure 2026-05-21 + spec-conformance H1 closure 2026-05-21) is the per-check `algorithm_verdicts` sub-field (NEW in v2.0.0-rc1 JSONOutput extension; see §18.10 below). The verifier MUST populate `checks[0].algorithm_verdicts` with a structured per-algorithm pass/fail array regardless of the step-5 outcome — this prevents operator-confusion attacks where the surface format ambiguity ("error message string OR errors[] array") could mislead an investigator into misclassifying a both-algorithm tampered bundle as a single-algorithm transient failure (the misclassification could permit an attacker who tampered with both signatures to convince the operator to re-fetch the still-tampered bundle).

Specifically:

- **Both pass** → Check 1 status `pass`; `checks[0].algorithm_verdicts = [{"algorithm": "ed25519", "status": "pass"}, {"algorithm": "ml-dsa-65", "status": "pass"}]`; `checks[0].errors[]` empty; `checks[0].warnings[]` MAY carry an OPTIONAL operator-disclosure string like `"Ed25519 + ML-DSA-65 both verified against pinned issuer keys"`.
- **Both fail** → Check 1 status `fail`; `checks[0].algorithm_verdicts = [{"algorithm": "ed25519", "status": "fail"}, {"algorithm": "ml-dsa-65", "status": "fail"}]`; `checks[0].errors[]` carries `["Check 1 FAIL (cryptographic): Ed25519 verification failed", "Check 1 FAIL (cryptographic): ML-DSA-65 verification failed"]` (BOTH error entries; reporting MUST be exhaustive).
- **Ed25519 fails, ML-DSA-65 passes** → Check 1 status `fail`; `checks[0].algorithm_verdicts = [{"algorithm": "ed25519", "status": "fail"}, {"algorithm": "ml-dsa-65", "status": "pass"}]`; `checks[0].errors[]` carries `["Check 1 FAIL (cryptographic): Ed25519 verification failed; ML-DSA-65 verification passed; this is a single-algorithm failure that nonetheless invalidates the bundle's dual-sig integrity"]`.
- **Ed25519 passes, ML-DSA-65 fails** → symmetric to above with algorithms swapped.

The non-short-circuit discipline is load-bearing: an operator investigating a Check 1 failure needs to know whether the failure is one algorithm or both, because the diagnostic + remediation paths differ (single-algorithm failure may indicate a corrupted-during-transport bundle that should re-verify on re-fetch; both-algorithm failure indicates a tampered bundle that re-fetch will not fix). The structured `algorithm_verdicts` field is the canonical-source for operator-tooling parsers; the `errors[]` natural-language strings are implementation-localized (per §14.1 conformance contract).

**Step 5 success**: Check 1 status `pass`; both signatures verified; `algorithm_verdicts` populated with `[{ed25519, pass}, {ml-dsa-65, pass}]`.

### 18.8 Positional ordering pin (Ed25519@0, ML-DSA-65@1)

Implementations MUST emit signatures in the fixed positional order:

- `manifest.signing.signatures[0]` = Ed25519 entry
- `manifest.signing.signatures[1]` = ML-DSA-65 entry
- `signature.sig:signatures[0]` = Ed25519 entry (matching manifest.signing[0])
- `signature.sig:signatures[1]` = ML-DSA-65 entry (matching manifest.signing[1])

A bundle with swapped positions (signatures[0].algorithm == "ml-dsa-65" OR signatures[1].algorithm == "ed25519") MUST fail Check 1 structural per §18.7 step 1. The structural-fail-not-cryptographic-fail framing is load-bearing: swapped positions are detected BEFORE any cryptographic verification runs, so a malicious bundle attempting to confuse the verifier by swapping slots (e.g., to hide a forged ML-DSA-65 signature behind a valid Ed25519 signature at position 0) is rejected at structural-validation time.

**Future positional expansion (spec-conformance M2 closure 2026-05-21)**: future amendments adding a third algorithm (e.g., a hypothetical SPHINCS+ amendment) have TWO architectural paths, each with different version-cadence implications:

- **Path A — major-version v3.0 bump**: cardinality != 2 is a breaking change for v2.0 verifiers per §18.1 MUST cardinality 2. A v3.0 bundle with `signatures[].length == 3` would carry `bundle_format = "nuwyre-bundle/v3"` per §2 dispatch; v2.0 verifiers reject at §2 enumeration gate (fail-loudly per §15.1 cohabitation discipline) BEFORE reaching §18.1 cardinality validation. This path is the cleanest reading of the SPEC_GOVERNANCE.md §3.2 breaking-amendment cadence.
- **Path B — additive v2.x minor amendment via SIBLING container**: add the third algorithm at a NEW manifest field (e.g., `manifest.signing.signatures_v3_extension: [SPHINCS+ entry]`) preserving the existing `signatures[]` cardinality 2 at v2.x. v2.0 verifiers gracefully tolerate the new field per §1 forward-compat tolerance (drop on parse); v2.x-aware verifiers verify all three signatures. This path is forward-compatible at the schema level but requires verifier-side dispatch on the new field's presence.

The current v2.0.0-rc1 spec text does NOT pin which path future amendments will take; both are architecturally valid. A future v2.1 amendment author MUST choose explicitly (with SPEC_GOVERNANCE.md §2.2 reviewer-pass approval) and pin the rationale in the v2.1 amendment's revision-history entry.

**v2.0 verifiers encountering bundles claiming cardinality != 2**: MUST reject at §18.1 structural validation. The §18.1 cardinality 2 MUST is invariant for the v2.0.0+ versions; future v2.x amendments adding optional sibling-container fields preserve the invariant at signatures[].

### 18.9 Library-selection conformance criteria + atomic key rotation

**ML-DSA-65 library-selection conformance criteria** (per FIPS 204 §3.4 + §5.2 + §5.4 framing pin at §18.3):

An implementation's chosen ML-DSA-65 library MUST satisfy ALL of:

1. **FIPS 204 conformance evidence**: library documentation OR upstream test vectors confirm conformance with FIPS 204 §3.4 + §5.2 + §5.4. Libraries that only claim "Dilithium" (the pre-FIPS-204 academic name) without explicit FIPS 204 alignment evidence MUST be cross-validated against the FIPS 204 standard's reference test vectors before claiming v2.0.0-rc1 conformance.

2. **Deterministic-variant API exposure**: library MUST expose either (a) an explicit deterministic-mode API distinct from the hedged-mode API, OR (b) an API that accepts a `rnd` parameter that can be pinned to the 32-zero-bytes value per §18.3. A library that only exposes hedged-mode signing (no `rnd` control) is NON-CONFORMANT for v2.0.0-rc1.

3. **Pure-mode signing**: library MUST implement `ML-DSA.Sign(sk, M, ctx)` per FIPS 204 §5.2 (pure mode; ctx-only framing). Libraries that only implement HashML-DSA (the prehashed variant per FIPS 204 §5.4) are NON-CONFORMANT.

4. **Cross-language availability**: a library MUST be available (or have a verified byte-equivalent counterpart) in the npm ecosystem (for the TS reference writer at Phase 7.F.2) AND the Go ecosystem (for the Go reference verifier at Phase 7.F.3). Implementations using different libraries across languages MUST cross-validate against the Phase 7.F.5 KAT vectors before claiming conformance.

5. **Active maintenance**: library MUST show ≥1 substantive commit per quarter in its upstream repository at the time of v2.0.0-rc1 → v2.0.0 final promotion. Abandoned libraries (no commits in the past 6 months) MUST be replaced or forked before relying on them in production.

6. **License compatibility**: library MUST be licensed under Apache-2.0, MIT, or BSD-3-Clause (or any other OSI-approved permissive license without copyleft obligations on consumers). Strong copyleft licenses (GPL-3.0, AGPL-3.0) are NON-CONFORMANT for the v2.0.0-rc1 reference implementation distribution model (the conformance fixtures + KAT vectors must be redistributable under the NuWyre spec's CC-BY-4.0 license per SPEC_GOVERNANCE §5.1; copyleft-licensed library dependencies would create distribution complications).

7. **SPKI wrapping conformance**: library MUST either (a) implement RFC 5280 SPKI wrapping with the §18.4 byte-layout pin (OID + parameters ABSENT + raw 1952-byte public key as BIT STRING with zero unused bits), OR (b) expose raw 1952-byte public-key bytes that the implementation MUST wrap manually per §18.4.

**Candidate libraries** (each implementation's library choice is documented at the implementing package — e.g., `packages/evidence/docs/ml-dsa-65-library-selection.md` at Phase 7.F.2; `apps/cli/docs/ml-dsa-65-library-selection.md` at Phase 7.F.3). Library candidates listed below are **illustrative; inclusion in this list is NOT an endorsement**. Each candidate's conformance criteria evaluation MUST be performed at Phase 7.F.2 / 7.F.3 selection time per the seven criteria above (security-auditor L2 closure 2026-05-21):

- `@noble/post-quantum` (TypeScript; npm) — well-maintained as of 2026-05; audited by reputable cryptographers; may require manual SPKI wrapping. Verify deterministic-variant API exposure at evaluation time.
- `pqcrypto-mldsa65` (Node binding) — verify FIPS 204 conformance + deterministic-variant API + active maintenance at evaluation; the npm registry shows variable maintenance history for this candidate per spec-conformance L2 + security-auditor L2 cross-referenced concern.
- `liboqs-node` (WASM binding to liboqs / Open Quantum Safe) — verify deterministic-variant API + cross-language byte-equivalence with Go counterpart at evaluation time.
- `cloudflare/circl/sign/mldsa` (Go) — well-maintained; Cloudflare-stewarded; defines `SignatureSize = 3309` matching FIPS 204 §4 Table 1; verify FIPS 204 alignment at evaluation time. Per crypto-integrity reviewer H1 cross-check at this spec amendment.
- Custom binding to `liboqs` (Open Quantum Safe; C library) — fallback if npm + Go candidates do not pass conformance criteria. Operational complexity (build toolchain + cross-platform Windows/macOS/Linux support + liboqs version pinning) is non-trivial; library-selection design note at Phase 7.F.2 + 7.F.3 SHOULD enumerate the build-system burden before adopting this fallback (security-auditor L6 heavy-bookmark; defer to 7.F.2 selection session).

The v2.0.0-rc1 spec does NOT mandate a specific library; Phase 7.F.2 + 7.F.3 implementing sessions are responsible for library selection per the above criteria. The Phase 7.F.5 KAT vectors are the load-bearing cross-language byte-equivalence contract; whichever libraries are chosen, they MUST produce byte-identical signatures + SPKI bytes against the KAT vectors.

**License-compatibility criterion clarification (security-auditor L2 / crypto-integrity L2 closure)**: criterion #6 above (license compatibility) is an **operator-side deployment consideration** for NuWyre's SaaS go-to-market — it does NOT make a GPL-3.0 library cryptographically non-conformant. External implementers (Python, Rust, Java, etc.) writing their own conformant ML-DSA-65 + Ed25519 dual-sig writer/verifier MAY use libraries under any license compatible with their own distribution model (including strong-copyleft licenses where compatible). Criterion #6 applies specifically to NuWyre's reference TS writer (`packages/evidence`) + Go verifier (`apps/cli`) distribution where copyleft library dependencies would create downstream complications for the conformance-fixtures + KAT-vectors distribution under the CC-BY-4.0 NuWyre-spec license per SPEC_GOVERNANCE.md §5.1.

**Atomic key rotation across both algorithms**: bundle emission MUST block during the rotation transition window so that a bundle signed at time T does not pair an old Ed25519 key with a new ML-DSA-65 key (or vice versa). The rotation discipline:

- Key rotation events MUST be atomic with respect to both algorithms: either BOTH key-pairs (Ed25519 + ML-DSA-65) rotate to new versions, OR neither does.
- Bundle-emission code MUST hold a key-rotation-lock during the dual-signing operation; the lock MUST be acquired BEFORE either signature is computed and released AFTER both signatures are committed to signature.sig + manifest.signing is finalized.
- The operator-side key-rotation procedure MUST: (a) provision new Ed25519 + new ML-DSA-65 key-pairs simultaneously; (b) update the pinned-key directory entries atomically (both `issuer-prod-v2-ed25519` and `issuer-prod-v2-ml-dsa-65` references repoint to the new keys in a single operation); (c) drain in-flight bundle-emission operations using old keys; (d) signal bundle-emission code that the new keys are now active. A partial-rotation state (new Ed25519 + old ML-DSA-65, or old Ed25519 + new ML-DSA-65) MUST NOT be observable by bundle-emission code at any point.

**Cross-implementation key-id stability**: when keys rotate, the verifier's pinned-key directory carries effective-period metadata for each (algorithm, key_id, key_fingerprint_spki_b64) tuple. Old bundles continue to verify against old keys; new bundles use new keys; the bundle's `manifest.signing.signatures[i].key_id` + `generated_at` together select the correct effective-period key from the verifier's directory. The §5 v1 prose at "Multi-key support" applies recursively at v2.0.0-rc1 with dual-algorithm extension.

**Heavy-bookmarked discipline (security-auditor H2; re-open trigger: Phase 7.F.2 OR 7.F.3 implementing session)**: two refinements to the rotation discipline are deferred to whichever implementing session first surfaces the operational semantic — cross-process rotation atomicity (the in-process key-rotation-lock above addresses the single-process case; a multi-process / multi-environment NuWyre deployment with apps/api emission + apps/cli emission running concurrently requires a shared coordination primitive — DB advisory lock, KMS rotation-state version, etc. — to prevent disjoint key-pair version observation across an Ed25519 + ML-DSA-65 boundary), AND effective-period boundary semantics (whether effective_after / effective_until intervals are inclusive-start half-open `[effective_from, effective_until)` OR inclusive-end half-open `(effective_from, effective_until]`; whether both Ed25519 and ML-DSA-65 rotations MUST share the same effective_from timestamp to prevent split-algorithm-effective-period ambiguity; what the verifier does when `manifest.generated_at` is exactly on a boundary microsecond). These two refinements are not blockers for v2.0.0-rc1 spec text (no production bundles exist; no key rotation has occurred); they are blockers for v2.0.0 final promotion at Phase 7.F.4 if implementing-session code surfaces the semantic ambiguity. A v2.0.0-rc2 spec amendment OR a §18.9 in-place tightening at Phase 7.F.4 will close this heavy-bookmark.

### 18.10 v2.0.0-rc1 JSONOutput extension (`algorithm_verdicts` field)

v2.0.0-rc1 extends the §14.1 JSONOutput shape with ONE new normative per-check field at `checks[0]` (the Check 1 manifest-signature check) to address the §18.7 step 5 dual-algorithm reporting requirement (spec-conformance H1 + security-auditor M2 closures 2026-05-21):

```jsonc
{
  // ... existing v1 JSONOutput shape preserved verbatim per §14.1
  "checks": [
    {
      "check_id": 1,
      "check_name": "Manifest signature",                  // optional human-readable; ignored by conformance contract
      "check_slug": "manifest-signature",
      "status": "pass" | "fail",
      "warn_category": "",                                  // or "dev_key" when audit-log-export or example-demo dev-slot
      "errors": [...],                                      // implementation-localized natural-language; ignored
      "warnings": [...],                                    // implementation-localized natural-language; ignored
      "skip_reason": "",
      "duration_ms": 0..N,

      // v2.0.0-rc1 NEW STRUCTURAL FIELD (normative; required at checks[0] for v2 bundles ONLY):
      "algorithm_verdicts": [
        { "algorithm": "ed25519",   "status": "pass" | "fail" },
        { "algorithm": "ml-dsa-65", "status": "pass" | "fail" }
      ]
    },
    // ... checks[1] through checks[N] (Check 2-9) preserved verbatim per §14.1
  ],
  // ... summary preserved verbatim per §14.1
}
```

**`algorithm_verdicts` field discipline**:

- **Presence**: REQUIRED at `checks[0]` (the Check 1 manifest-signature check) for v2.0.0-rc1+ bundles. FORBIDDEN at `checks[1]` through `checks[N]` (those checks do not have dual-algorithm verdicts). FORBIDDEN entirely for v1 bundles (the v1 single-Ed25519 path emits the v1.0.x JSONOutput shape unchanged; no algorithm_verdicts field).
- **Cardinality**: EXACTLY 2 entries per `checks[0].algorithm_verdicts`, positional matching `manifest.signing.signatures[]` order — `algorithm_verdicts[0].algorithm = "ed25519"`; `algorithm_verdicts[1].algorithm = "ml-dsa-65"`.
- **Field shape within each entry**: each entry contains EXACTLY the keys `{algorithm, status}` (strict-fields posture). `algorithm` is the algorithm identifier matching `signature.sig:signatures[i].algorithm`; `status` is one of `"pass"` | `"fail"` (closed enum; "skipped" / "warn" / "not_applicable" are NOT permitted at this field since Check 1 dispatches to BOTH algorithms unconditionally for v2 bundles).
- **Conformance contract scope**: the `algorithm_verdicts` field IS load-bearing for cross-implementation structural conformance per §14.1 "Structural conformance contract". A verifier emitting `checks[0]` without `algorithm_verdicts` for a v2 bundle, OR with malformed cardinality (≠2), OR with non-pass-non-fail status values, is structurally non-conformant.

**`output_format_version` field semantic at v2.0.0-rc1**: the `output_format_version` field per §14.1 remains `"1"` for v1 bundles AND `"2"` for v2.0.0-rc1+ bundles. v1 consumers reading v2 output MUST fail loudly on `output_format_version != "1"` per §14.1 prose. The structural delta from v1 to v2 output is the single `algorithm_verdicts` field added at `checks[0]`; no other structural changes. A future v2.x amendment may extend `output_format_version` semantic further (e.g., adding a top-level `bundle_format_version` echoing the bundle's bundle_format string for tooling convenience); v2.0.0-rc1 introduces only the algorithm_verdicts field.

**External-implementer guidance**: a conformant v2.0.0-rc1 verifier (TS, Go, Python, Rust, Java) MUST emit `checks[0].algorithm_verdicts` per the schema above. Tooling consuming the JSONOutput (CI gates, operator dashboards, dispute-investigation tools) SHOULD parse `algorithm_verdicts` as the canonical-source for dual-algorithm verdict; the natural-language strings in `errors[]` and `warnings[]` are implementation-localized and IGNORED by the structural-conformance contract. The Phase 7.F.4 conformance fixtures' declared `results.json` outputs MUST include `algorithm_verdicts` populated per the §14.4 PLANNED fixture row declarations.

-----

## 19. Cumulative reviewer-protocol track posture for v2.0.0-rc1

This sub-section is institutional discipline documentation; it does NOT add normative content for external implementers.

v2.0.0-rc1 ships under Phase 7.F.1 Tier B 3-reviewer pass per `docs/reviewer-protocol-calibration.md` + SPEC_GOVERNANCE.md §2.2:
- spec-conformance-reviewer (primary)
- crypto-integrity-reviewer (cryptographic-substrate review)
- security-auditor (key-handling + cross-environment-slot + atomic-rotation review)

**Reviewer-pass closures pre-commit at Phase 7.F.1 (2026-05-21)**: the three reviewers collectively surfaced **8 HIGH + 12 MEDIUM + 12 LOW findings**; **20 closed inline** (8 HIGH + 9 MEDIUM + 3 LOW) + **12 heavy-bookmarked** (0 HIGH at sub-arc-internal triggers, 2 HIGH at Phase 7.F.4/7.F.5 triggers, 5 MEDIUM at Phase 7.F.4/7.F.5/7.F.7 triggers, 5 LOW at Phase 7.F.4/7.F.5/7.F.7/7.F.8 triggers). Substantive close-inline batches: (a) **crypto-integrity H1** ML-DSA-65 SIGBYTES corrected 3293 → 3309 per FIPS 204 §4 Table 1 final (August 2024; tr=H(pk) framing added at standardization) — cascade across §18.4 + §18.7 + §14.4; (b) **crypto-integrity H2** Sign_internal framing semantic re-grounded to `IntegerToBytes(0,1) || IntegerToBytes(|ctx|,1) || ctx || M` per FIPS 204 §5.2 Algorithm 2 (NOT the previous "0x00 || 0x00 pure-mode discriminator" oversimplification); (c) **crypto-integrity H3** FIPS 204 section references re-grounded throughout (§5.2 external API, §6.2 Sign_internal, §3.7 deterministic-vs-hedged); (d) **spec-conformance H1 + security-auditor M2** v2 JSONOutput structural extension via new §18.10 `algorithm_verdicts` field (closed-enum normative per-algorithm verdict at `checks[0]`); (e) **spec-conformance H2** DER long-form length encoding pin at §18.4 with canonical SPKI DER byte construction worked example; (f) **spec-conformance H4** sandbox-preview v2 dispatch row reframed (v1.0.9 ephemeral-sessions topology preserved verbatim at v1 dispatch; v2 sandbox-preview path explicitly OUT OF SCOPE for v2.0.0-rc1); (g) **security-auditor H1** audit-log-export dev-keys-claiming-prod ambiguity closed via explicit dev_key warn surfacing + bundle-subtype-aware operator-only suspicion discipline; (h) **security-auditor M1** side-channel mitigation note at §18.3 (deterministic-mode pinning vs power-analysis trade-off; KMS-backed signing mandate for side-channel-vulnerable environments).

**Heavy-bookmark inventory with explicit re-open triggers**:
- (HIGH) **security-auditor H2** cross-process rotation atomicity + effective-period boundary semantics → re-open at Phase 7.F.2 OR 7.F.3 implementing session whichever surfaces the semantic first; bookmarked at §18.9 final paragraph
- (HIGH) **spec-conformance H5** library API shape pinning per candidate library → **CLOSED at Phase 7.F.5 session 103** (build-plan v3.1.56) via new §18.3.1 "Library API call shapes (informative registry)" enumerating cloudflare/circl Go API + @noble/post-quantum TS API with KAT-V2-2 cross-language byte-equivalence anchor. Closure rehearses SPEC_GOVERNANCE.md §3.1 third-dot additive amendment cadence (first v2.0.1 additive after v2.0.0 LOCKED at Phase 7.F.4 session 102).
- (HIGH) **spec-conformance H6** cross-language ML-DSA-65 primitive KAT fixture (no analog to v1.0.9 `cross-lang-ephemeral.json` yet planned) → re-open at Phase 7.F.5 to add `cross-lang-ml-dsa-65.json` primitive fixture
- (MEDIUM) **spec-conformance M5** SPEC_GOVERNANCE.md §3.2 in-place vs separate-file directive reconciliation → re-open at Phase 7.F.7 SPEC_GOVERNANCE.md amendment
- (MEDIUM) **spec-conformance M6** audit-log-export v2 fixture coverage → re-open at Phase 7.F.4 promotion gate (adds `valid-v2-audit-log-export/` + `tampered-v2-audit-log-merkle-subtree/`)
- (MEDIUM) **spec-conformance M7** "post-quantum hedge vs replacement" category gap in SPEC_GOVERNANCE.md §3.2 → re-open at Phase 7.F.7
- (MEDIUM) **spec-conformance M8** §18 cross-reference reading-order guide → re-open at Phase 7.F.8 polish session
- (MEDIUM) **spec-conformance M9** fixture suite bundle_format discriminator at fixture-row level → re-open at Phase 7.F.7 CI workflow extension
- (MEDIUM) **crypto-integrity M3** JCS canonicalizer library requirement (closed inline at §18.2 worked-codepoint paragraph; the heavy-bookmark surface is the Phase 7.F.5 KAT-vector cross-validation against canonicalizer drift)
- (MEDIUM) **crypto-integrity M4** writer-vs-verifier canonicalization-disagreement diagnostic at §18.7 step 4 → re-open at Phase 7.F.4 if fixture-level disagreement surfaces during cross-language byte-equivalence verification
- (MEDIUM) **crypto-integrity M5** verifier-side effective-period boundary semantics (companion to security-auditor H2) → re-open at Phase 7.F.3 Go verifier implementation OR first production key rotation
- (LOW) various § cross-reference + cosmetic refinements at §18 throughout → re-open at Phase 7.F.8 polish

All blocker findings closed inline before commit per `docs/reviewer-protocol-calibration.md` Tier B discipline. Heavy-bookmarked findings preserved with three preservation surfaces (this §19 + revision-history v2.0.0-rc1 entry + build-plan §"Phase 7.F" sub-arc breakdown). **0 shipped defects discipline preserved across 97 sessions through this amendment**; cumulative reviewer-protocol track increments to 157/.../9XX+5+6+6+8+0+8+8+9+2+20/0 at session 97 (20 close-inline-blocker-finding closures appended to the track).

v2.0.0-rc1 → v2.0.0 final promotion at Phase 7.F.4 runs under **Tier A 5-reviewer composition** (build-plan §"Phase 7.F.4" amendment 2026-05-21) — the promotion-gate session is where the 10 PLANNED tamper variants enumerated at §14.4 land as runnable fixtures; cross-language byte-equivalence is the load-bearing acceptance criterion; the heavy-bookmark inventory above's Phase-7.F.4-triggered items close inline at that session under Tier A composition.

-----

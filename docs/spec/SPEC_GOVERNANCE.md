# NuWyre Spec Governance Framework

**Version**: v0.1 (draft)
**Status**: Draft for institutional adoption. Adopted at session-author level pending Year-3 formalization (per operator manual §9 Decisions Ahead "draft SPEC_GOVERNANCE.md published Year 2 in draft, formally adopted Year 3").
**Last revised**: 2026-05-15 (Phase 6.2.A authoring session)

## Purpose

This document formalizes the governance framework for NuWyre's published technical specifications — primarily `bundle-format-v1.md` + `event-v1.schema.json` + the conformance fixture suite at `docs/spec/fixtures/`. The framework is institutional preparation for the spec to outlive NuWyre Inc. as a corporate entity, per Standards-Track Posture §4 ("Spec governance — the spec is public; the conformance suite is public; customer-specific structural customization is forbidden").

The framework answers four institutional questions:

1. **How are amendments proposed + adopted?** (§2 below)
2. **What counts as breaking vs additive change?** (§3 below)
3. **What deprecation timeline applies when breaking changes are unavoidable?** (§4 below)
4. **What provisions ensure the spec survives a successor entity (acquisition; wind-down; transfer to standards body)?** (§5 below)

## §1. Scope

This framework governs amendments to:

- `docs/spec/bundle-format-v1.md` — the bundle format specification (currently at **v1.0.17 (v1 path) + v2.0.1 (v2 path)**; v2.0.0 final promoted from v2.0.0-rc1 at Phase 7.F.4 session 102; v2.0.1 additive amendment at Phase 7.F.5 session 103 added §18.3.1 library-API-shape registry — pure informative, no on-wire byte change; 27/27 conformance fixtures (14 v1 + 13 v2) shipped at `docs/spec/fixtures/bundle-format-v1/`; CI gating extended to all 27 + KAT vectors at Phase 7.F.7 session 104)
- `docs/spec/event-v1.schema.json` — the event-v1 JSON Schema (currently at schema_version=1; locked across v1.x amendments)
- `docs/spec/audit-log-event-v1.schema.json` — the audit-log-event-v1 JSON Schema companion (Phase 7.D session 85 adoption per BACKLOG 1.48 A.2; schema_version=1; locked across v1.x amendments; closes the "if/when adopted" forward-bookmark from prior governance text)
- `docs/spec/fixtures/bundle-format-v1/` — the conformance fixture suite (currently 10 v1.0.7 customer-export bundles WITH bundle.zip + 4 v1.0.10/v1.0.17 audit-log-export fixture scaffolds WITHOUT bundle.zip pending generation in Phase 7.D session 86-87 per BACKLOG 1.48 A.1; the 4 scaffolds carry results.json + verification_options.json + tamper.json declaring the eventual bundle.zip's expected verifier output)
- Methodology document Section 3 "Evidence Format Specification" cross-references

The framework does NOT govern:

- Internal NuWyre code structure (apps/api + packages/evidence + apps/cli implementation details)
- Per-customer policy pack content (customer-authored; bound by spec §7 evaluations contract but not subject to spec governance)
- Operator-side runbook + operations documentation (operational, not normative)

## §2. Amendment process

### §2.1 Proposing an amendment

Amendments may be proposed by:

- **NuWyre engineering** (during Phase work; via session-prompt + recon-pass class (a) decisions surface to operator)
- **External implementers** (via GitHub issue at the spec repo + reviewer engagement; v0.1 draft pending Year-3 formalization defers external proposal path to Year 3 institutional readiness)
- **Reviewer protocol surfaces** (spec-conformance-reviewer findings at any session; promoted to formal amendment via session-prompt at subsequent session)

Each amendment proposal MUST include:

1. **Substantive change rationale** — why the amendment is load-bearing for the long-term spec contract; reference to the use case the amendment enables.
2. **Backward-compatibility analysis** — additive (§3.1) OR breaking (§3.2); cite specific cross-version compatibility implications.
3. **Conformance fixture impact** — does the amendment require new fixtures? new tamper variants? full fixture-suite regeneration?
4. **Cross-implementation impact** — TS reference impl + Go-native + Go-WASM verifier changes required; estimated session count.
5. **Versioning classification** — v1.x minor amendment (§3.1) OR v2.0 major amendment (§3.2); cite the specific §15 condition triggered.

### §2.2 Reviewing an amendment

Each amendment MUST pass reviewer composition per the tier framework at `docs/reviewer-protocol-calibration.md`:

- **Tier A — substantive engineering sessions**: 5-reviewer pass (code-reviewer + security-auditor + crypto-integrity-reviewer + spec-conformance-reviewer + policy-evaluation-quality-reviewer OR domain-appropriate substitute)
- **Tier B — documentation + spec-amendment + cross-implementation sessions**: 3-reviewer pass (spec-conformance-reviewer + crypto-integrity-reviewer + security-auditor)
- **Tier C — backlog closure + isolated config changes**: 1-reviewer pass (domain-appropriate)

Amendment classification per the work surface determines tier. Spec-amendment sessions (v1.0.7 → v1.0.9 → v1.0.10 pattern) operate as Tier B per the Phase 6.2.A calibration test outcome (pending evaluation at session-close).

### §2.3 Adopting an amendment

An amendment is adopted when:

1. Reviewer pass complete; all findings closed inline OR heavy-bookmarked with three preservation surfaces
2. Conformance fixture suite extended (or explicitly deferred per Decision 5 minimum-viable pattern)
3. Cross-document reconciliation complete (build-plan + operator manual + methodology cross-references)
4. Session ops log entry documents the amendment closure + cumulative track increment
5. Spec file revision history entry added at top (per the v1.0.7 + v1.0.9 + v1.0.10 pattern)

Adoption is operator-confirmed at session-close commit; the operator manual §9 Decisions Made archive captures the adoption decision.

## §3. Breaking vs additive change

### §3.1 Additive (v1.x minor amendment)

Additive amendments MUST satisfy ALL of:

- **Field shape stability**: NO existing field is renamed, removed, or has its type/format changed for pre-existing bundle types.
- **Closed-enum extension only**: enum values MAY be added (e.g., new bundle_type at v1.0.9 sandbox-preview + v1.0.10 audit-log-export); existing enum values MUST NOT be removed.
- **Optional field addition**: new fields MAY be added as OPTIONAL OR CONDITIONALLY-REQUIRED (gated by other field values; e.g., bundle_subtype REQUIRED iff bundle_type=audit-log-export at v1.0.10).
- **Verifier behavior**: pre-v1.x verifiers processing pre-v1.x bundles continue to verify identically (no field-shape changes to pre-existing bundle types). Pre-v1.x verifiers processing v1.x bundles either tolerate unknown fields (per §1 forward-compat tolerance) OR fail loudly at closed-enum gate (per §15.1 unknown-value discipline) — they MUST NOT misverify.

Examples of additive amendments to date:
- **v1.0.7** (Phase 5.5 Session 5.5.1B): conformance fixture suite landing + JSONOutput schema canonicalization
- **v1.0.9** (Phase 6.1 — Pre-Phase 6 Item 2): sandbox-only ephemeral session signing (new topology field + ephemeral_sessions[] manifest section; gated by bundle_type=sandbox-preview)
- **v1.0.10** (Phase 6.2.A): audit-log-export bundle type (new bundle_type enum value + bundle_subtype field + merkle_subtrees field; gated by bundle_type=audit-log-export)

### §3.2 Breaking (v2.0 major amendment)

Breaking amendments are required when ANY of:

- **Signing-format change**: e.g., COSE_Sign1 replaces detached Ed25519 over JCS bytes; existing manifest.signature is no longer interpretable.
- **Canonicalization rule change**: e.g., RFC 8785 JCS replaced with a different canonicalization algorithm; existing content_hash values would not reproduce.
- **Existing-bundle-type structural change**: e.g., daily_root composition changed for customer-export bundles (dual-subtree applied retroactively); existing customer-export bundles would not verify under v2.0 verifier.
- **Field removal**: existing required field removed from manifest (e.g., bundle_id removed; existing tooling that depends on the field breaks).
- **Cryptographic algorithm replacement**: e.g., SHA-256 replaced with SHA-3 OR Ed25519 replaced with Ed448; existing hash chain + signature verification breaks.

Per Standards-Track Posture §6 (versioning discipline), breaking amendments trigger:

1. **12-month deprecation window**: v1.x verifiers continue to operate against v1.x bundles for 12 months post-v2.0 publication.
2. **Migration documentation**: bundle-format-v2.md authored alongside bundle-format-v1.md; both maintained until v1.x deprecation completes.
3. **Conformance fixture suite split**: v1.x fixtures preserved; v2.0 fixture suite published separately.
4. **Implementation parallelism**: reference impls (TS + Go-native + Go-WASM) maintain both v1.x + v2.0 paths until deprecation completes.

**v2.0.0 amendment status (Phase 7.F.4 promotion gate session 102 closure 2026-05-22 — spec-conf H1 closure)**: v2.0.0 was published as v2.0.0-rc1 at Phase 7.F.1 (2026-05-21; build-plan v3.1.54) per the breaking-amendment criteria above ("Signing-format change" + "Cryptographic algorithm replacement (post-quantum migration)" per §15.2 of bundle-format-v1.md). v2.0.0-rc1 → v2.0.0 final promotion landed at Phase 7.F.4 session 102 (build-plan v3.1.55) — 27/27 conformance fixtures (14 v1 + 13 v2) PASS across TS writer + Go-native verifier + Go-WASM verifier; Tier A 5-reviewer pass closed with 0 CRITICAL findings + 6 HIGH findings closed inline pre-promotion. **Cumulative reviewer-protocol track preserved at 0 shipped defects through the promotion gate**. The 12-month-deprecation-timeline framing at §4 below is **moot pre-customer-#1**: NuWyre has zero v1.0.17 customer bundles in flight at the time of v2.0.0 publication; the customer-contract amendment + migration notification surfaces will activate at first-customer signing.

**v1.x amendment cadence post-v2.0.0**: v1.0.x amendments remain available for v1-side bug-fix / spec-clarity work that targets the legacy v1 bundle path. v1.0.7 + v1.0.9 + v1.0.10 + v1.0.11 + v1.0.12 + v1.0.13 + v1.0.14 + v1.0.15 + v1.0.16 + v1.0.17 are all additive per §3.1; v1.0.18+ as future v1-side maintenance requires.

**rc → final promotion-gate criteria** (spec-conf L2 closure 2026-05-22 — formalization of the rc1 → final transition per Phase 7.F.4 precedent):

For any future spec amendment shipped as a release-candidate per the Phase 7.F.1 precedent, the rc → final promotion gate MUST satisfy:

1. **Cross-language byte-equivalence verified** across all reference verifier implementations (currently: TS writer + Go-native + Go-WASM).
2. **All PLANNED conformance fixtures shipped** with declared `results.json` outputs reproduced by every reference verifier (byte-identical structural fields per the conformance contract at §14.1 of bundle-format-v1.md).
3. **Tier A 5-reviewer pass** (spec-conformance + crypto-integrity + code-reviewer + security-auditor + performance-auditor — crypto-integrity LOAD-BEARING per dual-sig promotion gate; matches Phase 7.C.B + 7.F.3 precedent) with 0 CRITICAL + 0 unresolved HIGH findings. HIGH findings MAY land inline pre-promotion via batch-closure pattern.
4. **Reference implementations shipped**: writer (TS) + verifier (Go-native + Go-WASM) for the new schema.
5. **Spec-text "PLANNED" markers removed** from the relevant §14.4 + §18 + revision-history sections; revision history adds a "final" entry pinning the promotion date + commit hash.

The Phase 7.F.4 session 102 promotion landed all 5 criteria. Future rc → final promotions reuse this enumeration.

## §4. Deprecation timeline

When v2.0 amendment is adopted (per §3.2), deprecation timeline applies:

- **Month 0**: v2.0 published; v1.x verifiers continue to accept v1.x bundles; v2.0 verifiers accept both v1.x + v2.0 bundles.
- **Month 6**: customers + integration partners notified of v1.x deprecation timeline via operator manual + customer-contract amendments; bundle generation paths migrate to v2.0 emission.
- **Month 12**: v1.x deprecation completes; new bundle emission MUST be v2.0+; existing v1.x bundles continue to verify under retained v1.x verifier paths indefinitely (forensic-record preservation invariant — bundles never lose verifiability post-publication).

The 12-month deprecation window aligns with customer-contract renewal cycles + SOC 2 audit windows + regulatory inquiry response timelines.

## §5. Successor-entity provisions

The spec is institutional preparation for NuWyre Inc. as a corporate entity to NOT be the sole guardian of bundle integrity verification. Per Standards-Track Posture §5 ("Multiple independent implementations as a goal"), spec governance provisions ensure the contract survives NuWyre Inc.:

### §5.1 Public archival

- **Spec repository**: `docs/spec/bundle-format-v1.md` + fixture suite + this governance framework published to a public archive accessible without NuWyre infrastructure dependency.
- **Reference impls**: TS reference impl (`packages/evidence` + `packages/policy` portions) + Go-native verifier (`apps/cli`) source code published under open-source license permitting independent maintenance.
- **Cryptographic anchors**: existing bundles' OTS receipts + RFC 3161 receipts + GitHub anchor commits remain verifiable via public Bitcoin chain + public TSA infrastructure + public Git history, independent of NuWyre infrastructure.

### §5.2 Multi-implementation parity

- Per Standards-Track Posture §5 (heavy-bookmarked at Phase 5.5 Session 5.5.1C; pending TS-native verifier work tracked at Sub-arc 6.4 Architectural-closure items): the conformance fixture suite is the load-bearing artifact that defines bundle-format-v1 across implementations. Multiple implementations (TS + Go-native + Go-WASM today; Python + Rust + Java implementations as community-contributed work in successor-entity scenarios) MUST all pass the fixture suite to claim conformance.
- Successor entities (whether commercial acquirer, foundation, OR community fork) inherit the conformance contract via the fixture suite + spec text; no NuWyre-internal documentation OR runtime is required to validate conformance.

### §5.3 Transfer of stewardship

Should NuWyre Inc. wind down OR transfer spec stewardship:

- The spec + fixture suite + reference impls remain accessible at the published public archive.
- Spec governance MAY transfer to a successor entity (foundation; standards body; community-elected maintainers); the v0.1 framework documented here is the transfer baseline.
- Existing bundles' verifiability is unaffected by stewardship transfer; bundles depend only on public infrastructure (Bitcoin chain + commercial TSAs + GitHub) + the published spec + the published reference impls.

### §5.4 No NuWyre-specific verification paths

Per Standards-Track Posture §5 (existing invariant): NO bundle MAY require NuWyre infrastructure to verify. Verifier discipline at §14 of bundle-format-v1.md MUST be implementable from spec text + fixture suite alone. The conformance fixture suite is the empirical proof of this invariant.

## §6. Versioning policy summary

Per §3:
- **v1.x minor amendments**: additive; backward-compatible; pre-existing bundles + verifiers unaffected. Cadence: per substantive Phase work that requires spec changes (v1.0.7 at Phase 5.5; v1.0.9 at Phase 6.1; v1.0.10 at Phase 6.2.A; v1.0.11 at Phase 6.2.A Tier B first-fix-up; v1.0.12 at Phase 6.2.B Sub-arc 2 Tier A first-fix-up; v1.0.13 at Phase 6.2.B-B Sub-arc 3 Tier A first-fix-up; v1.0.14 at Phase 6.2.B-D session 67 (composed with v1.0.15); v1.0.15 at Phase 6.2.B-D session 67 BACKLOG 1.26 architectural decision; v1.0.16 at Phase 6.2.B-F session 69 BACKLOG 1.30 windowing reconciliation closure; v1.0.17 at Phase 7.D session 85 audit-log fixture-suite + schema-companion closure; future v1.0.18+ as ongoing v1-side maintenance requires).
- **v2.x major amendments**: breaking; deprecation cadence per §3.2 + §4 above. **v2.0.0 final** at Phase 7.F.4 session 102 (build-plan v3.1.55) per the ML-DSA-65 + Ed25519 dual-signature topology amendment (build-plan v3.1.54 Phase 7.F.1 → v3.1.55 Phase 7.F.4 promotion gate). Sub-arc breakdown: 7.F.1 spec amendment v2.0.0-rc1; 7.F.2-A/B/C/D TS reference writer + ml-dsa-65 primitive + apps/api wiring + verify-md narrative; 7.F.3 Go reference verifier + WASM rebuild; 7.F.4 sub-arcs A/B/C/D conformance fixture regeneration (1 valid + 5 sig-tampers + 5 structural-tampers + 1 valid audit-log + 1 audit-log operator-only tamper = 13 v2 fixtures); 7.F.4 session 102 promotion gate (Tier A 5-reviewer + spec status flip rc1 → final). **v2.0.1 additive amendment** at Phase 7.F.5 session 103 (build-plan v3.1.56) added §18.3.1 "Library API call shapes (informative registry)" closing heavy-bookmark spec-conf H5 at the designated session; pure informative — no on-wire byte change. **CI gating extended at Phase 7.F.7 session 104** (build-plan v3.1.57) — `.github/workflows/spec-conformance.yml` now gates all 27 fixtures (was 10; never updated for audit-log nor v2 pre-104) + KAT vector tests + cross-implementation divergence check across TS + Go-native + Go-WASM. Future v2.0.2+ for additive amendments to the v2 path; future v3.0.0 for the next breaking amendment (none planned).
- **v2.0 major amendments**: breaking; 12-month deprecation window; migration documentation; conformance fixture split; parallel reference impls. Cadence: rare; only when §3.2 conditions are unavoidable.

**Version-number cadence** (v1.0.11 F10 closure — rewritten to match de facto v1.0.x amendment naming history; pre-v1.0.11 prose contradicted itself by labelling v1.0.10 an "additive amendment" per §3.1 while §6 said additive amendments increment the second dot — yet v1.0.10's bump was at the third dot). The corrected cadence rule:

- **First dot (1.x.x → 2.x.x)** — MAJOR version bump per §3.2 (breaking amendments; signing-format change; canonicalization rule change; merkle construction change; hash/signature algorithm replacement). 12-month deprecation window applies.
- **Second dot (1.0.x → 1.1.x)** — RESERVED for a future delineation (e.g., a non-breaking-but-substantial restructure that warrants signaling beyond third-dot patch granularity). Not used by any v1.x amendment to date.
- **Third dot (1.0.10 → 1.0.11)** — ADDITIVE amendment per §3.1. The current v1.x cadence (v1.0.0 → v1.0.1 → v1.0.2 → v1.0.3 → v1.0.4 → v1.0.5 → v1.0.6 → v1.0.7 → v1.0.9 → v1.0.10 → v1.0.11 → v1.0.12 → v1.0.13 → v1.0.14 → v1.0.15 → v1.0.16 → v1.0.17; v1.0.8 reserved for the evidence-gated two-key topology amendment). Covers both typo-class and substantive-additive amendments; the revision history entry describes the scope. Post-major-bump, **v2.x amendments follow the same third-dot pattern**: v2.0.0 final at Phase 7.F.4 session 102 (initial major); v2.0.1 at Phase 7.F.5 session 103 (additive §18.3.1 library-API registry); future v2.0.2+ for additive amendments to the v2 path.

The cadence rule is informed by the de facto v1.0.x amendment history at `bundle-format-v1.md` revision history (line 8+). Future Year-3 formal adoption MAY refine this rule based on accumulated amendment evidence (e.g., promoting a class of substantive-additive amendments to second-dot cadence). Until then: third-dot for additive; first-dot for breaking; second-dot reserved.

## §7. References

- `docs/spec/bundle-format-v1.md` — the bundle format specification
- `docs/spec/event-v1.schema.json` — the event-v1 JSON Schema (primary event chain)
- `docs/spec/audit-log-event-v1.schema.json` — the audit-log-event-v1 JSON Schema companion (audit-log chain; Phase 7.D session 85 adoption)
- `docs/spec/fixtures/bundle-format-v1/README.md` — the conformance fixture suite
- `docs/reviewer-protocol-calibration.md` — the reviewer-tier framework
- `docs/build-plan.md` — Standards-Track Posture §§1-8 (the load-bearing posture this framework operationalizes)
- `docs/operator-manual-v1_2_4.md` §9 Decisions Made archive (institutional decision history)

## §8. Adoption status

**v0.1 draft adopted at session-author level 2026-05-15** (Phase 6.2.A authoring session per Sub-arc 3 of the session prompt). Formal institutional adoption deferred to Year-3 per operator manual §9 Decisions Ahead pending external-implementer engagement signal + community-readiness evidence + successor-entity-readiness assessment.

Pre-Year-3 amendments to spec MAY proceed under this v0.1 framework with session-author-level adoption discipline. Year-3 formal adoption MAY refine §§1-7 based on accumulated amendment-history evidence.

-----

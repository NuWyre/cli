package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/nuwyre/cli/internal/bundle"
)

// Check9AuditLogMerkle verifies the spec §16 audit-log-export bundle
// type's dual-subtree Merkle composition + chain integrity contract:
//
//   - Conditional gate: skip when bundle_type != "audit-log-export"
//     (customer-export + example-demo + sandbox-preview bundles use
//     single-tree composition per pre-v1.0.10 §8 semantics; Check 9
//     is not applicable).
//   - Pre-condition validation: bundle_subtype REQUIRED + ∈
//     {"customer-scoped","operator-only"}; audit_log_event_count
//     REQUIRED + equals len(audit_log_events.jsonl); merkle_subtrees
//     REQUIRED; audit_log_subtree.json REQUIRED.
//   - §16.5 sentinel UUID gate: operator-only → manifest.organization_id
//     MUST equal all-zero sentinel UUID; customer-scoped → manifest.
//     organization_id MUST NOT equal sentinel.
//   - §16.5 cross-tenant invariant: customer-scoped audit log events
//     with non-null subject.organization_id MUST have subject.
//     organization_id == manifest.organization_id (no cross-tenant
//     leakage through subject reference).
//   - §16.2.2 chain integrity: each audit log event's prev_event_hash
//     links to the previous event's event_hash (or genesis sentinel
//     for the first event); content_hash recomputes from {actor,
//     event_type, subject}; event_hash recomputes from {content_hash,
//     prev_event_hash, sequence_number, timestamp_unix_ns}.
//   - §16.3.2 leaf ordering: audit_log_subtree.proofs[] ordered by
//     audit_log_events[].forensic.sequence_number ascending.
//   - §16.3 dual-subtree composition: daily_root = SHA-256(
//     events_subtree_root_bytes || audit_log_subtree_root_bytes) per
//     v1.0.11 F3 MUST-language (events FIRST; swapped order produces
//     a different daily_root and is a generation defect). The
//     concatenation operates on 32-byte decoded operands per
//     crypto-int H2 byte-encoding closure.
//   - §16.3.1 empty-subtree composition: when audit_log_events.jsonl
//     is empty, audit_log_subtree_root_bytes = 0x00 * 32 (64 zero hex
//     chars).
//   - Manifest cross-references: manifest.merkle_subtrees.events_root
//     equals merkle_proofs.json:root; manifest.merkle_subtrees.
//     audit_log_root equals audit_log_subtree.json:subtree_root.
//   - Per-proof Merkle walk: every audit log event's proof reconstructs
//     to audit_log_subtree.subtree_root via the same §8.2 walker
//     Check 4 uses (raw-byte SHA-256 internal nodes; position dispatch
//     per {left, right} closed vocabulary).
//   - Coverage symmetry: every audit log event has exactly one proof;
//     no orphan proofs; no duplicate proofs.
//
// **Cross-implementation parity** with packages/evidence/src/
// audit-log-export.ts:
//
//   - computeAuditLogContentHash: SHA-256(JCS({actor, event_type,
//     subject})). The Go canonicalJSON helper produces JCS-canonical
//     output via Go's map-key-sorted encoder (mirrors TS canonicalize).
//   - computeAuditLogEventHash: SHA-256(JCS({content_hash,
//     prev_event_hash, sequence_number, timestamp_unix_ns})). Mirrors
//     primary-event event_hash payload shape (spec §6.2 4-field
//     verbatim per v1.0.12 F-SC-5 closure).
//   - computeDualSubtreeDailyRoot: raw-byte concat, NOT hex strings.
//     Operand order is fixed at events FIRST per v1.0.11 §16.3 MUST-
//     language. Swapping the operand order is a generation defect
//     (cross-implementation divergence at SHA-256 input bytes).
//   - buildAuditLogSubtree: §8.1 single-leaf padding rule (a single-
//     event subtree pads with the genesis sentinel as the right
//     sibling); raw-byte internal-node hashing.
//
// **Six tenants framing** (Phase 6.2.C session 70):
//   - T1 (long-term correctness) load-bearing: third-party verifier
//     extension is the structurally correct long-term architecture
//     per Standards-Track Posture §5 multiple-implementations-as-goal.
//   - T2 (quality/reliability): cross-language byte-equivalence with
//     packages/evidence/src/audit-log-export.ts via the 6 KAT golden
//     vectors + conformance fixtures.
//   - T3 (security/privacy): cross-tenant invariant + sentinel UUID
//     discipline preserve customer data isolation through the
//     audit-log subtree's leaf set; chain integrity verification
//     catches tampered audit log events.
//   - T5 (customer trust): audit-log-export bundle's anchor chain of
//     trust is fully reconstructible from the bundle bytes alone
//     (no NuWyre runtime required).
type Check9AuditLogMerkle struct{}

func (Check9AuditLogMerkle) ID() int      { return 9 }
func (Check9AuditLogMerkle) Name() string { return "audit-log Merkle" }
func (Check9AuditLogMerkle) Slug() string { return "audit-log-merkle" }

// sentinelUUIDAllZero is the all-zero canonical UUID used per spec
// §16.5 to identify operator-only audit log chains. Mirrors
// packages/evidence/src/audit-log-export.ts OPERATOR_ONLY_SENTINEL_UUID.
const sentinelUUIDAllZero = "00000000-0000-0000-0000-000000000000"

// genesisSentinelHash is the 64-char lowercase hex representation of
// the 32-byte all-zero hash used as the chain-genesis prev_event_hash
// per spec §6.2 + §16.2.2 (mirrors evidence GENESIS_SENTINEL_HASH).
const genesisSentinelHash = "0000000000000000000000000000000000000000000000000000000000000000"

// numberMaxSafeInteger is JS Number.MAX_SAFE_INTEGER (2^53 - 1).
// Phase 6.2.C session 70 reviewer-pass closure (code-rev SEQNUM-JSNUM-
// BOUNDARY + crypto-int F2 TRIPLE-corroborated HIGH): TS reference impl
// rejects sequence_number > MAX_SAFE_INTEGER at audit-log-export.ts:326-
// 329 per v1.0.12 F-SC-11 closure. The Go side accepts int64 up to
// 2^63-1 — a non-conformant writer emitting [2^53, 2^63-1] would produce
// bundles the Go verifier accepts but the TS verifier rejects, breaking
// cross-impl byte-equivalence (T2). Bound the verifier surface to the
// MORE RESTRICTIVE TS range so cross-language conformance holds.
const numberMaxSafeInteger int64 = 1<<53 - 1

// auditLogActorTypeAllowed enumerates the closed vocabulary for
// audit_log_events.actor.type. Mirrors the TS emit-helper at
// packages/evidence/src/audit-log-export-emit.ts:174 ACTOR_TYPES set
// verbatim. Cross-implementation byte-equivalence (T2 load-bearing
// contract) requires the Go verifier vocabulary to match the TS writer
// vocabulary exactly — a TS-emitted bundle with actor.type="admin"
// (canonical operator path; also used by all 6 KAT golden vectors at
// packages/evidence/tests/audit-log-export.test.ts) must verify under
// Go Check 9 unmodified.
//
// **Phase 6.2.C-D session 73 CRITICAL deploy-blocker fix**: at session
// 70 the F-SC6-GAP "closure" inline-during-reduced-pass invented Go
// vocabularies ({user, api_key, system, cron_job, operator}) that did
// NOT match the TS emit helper ({user, admin, system, cron}). Every
// TS-generated audit-log-export bundle would have FAILED Go Check 9
// at the actor.type validation. The crypto-integrity-reviewer triage
// at session 73 caught the divergence. Both vocabulary maps now match
// TS emit-helper sets verbatim.
var auditLogActorTypeAllowed = map[string]bool{
	"user":   true,
	"admin":  true,
	"system": true,
	"cron":   true,
}

// auditLogSubjectTypeAllowed enumerates the closed vocabulary for
// audit_log_events.subject.type. Mirrors the TS emit-helper at
// packages/evidence/src/audit-log-export-emit.ts:175-184 SUBJECT_TYPES
// set verbatim. Kebab-case ("api-key", "policy-pack", "admin-action",
// "cross-tenant") per TS — NOT snake_case ("api_key", "policy_pack")
// which the session-70 inline closure incorrectly chose.
var auditLogSubjectTypeAllowed = map[string]bool{
	"customer":     true,
	"user":         true,
	"api-key":      true,
	"policy-pack":  true,
	"admin-action": true,
	"cross-tenant": true,
	"system":       true,
	"cron":         true,
}

// canonicalLowercaseUUID reports whether s matches the canonical
// lowercase RFC 4122 UUID form: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
// where each x is `[0-9a-f]`. Phase 6.2.C session 70 reviewer-pass
// closure (code-rev F-SC2-GAP): TS reference at audit-log-export.ts:
// 197-201 validates lowercase canonical at primitive boundary per
// v1.0.12 F-SC-2 closure. The Go verifier MUST enforce the same
// posture so a mixed-case organization_id can't slip through with
// a self-consistent (but cross-impl-divergent) content_hash.
func canonicalLowercaseUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, ch := range s {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			switch {
			case ch >= '0' && ch <= '9':
			case ch >= 'a' && ch <= 'f':
			default:
				return false
			}
		}
	}
	return true
}

func (c Check9AuditLogMerkle) Run(b *bundle.Bundle, _ CheckOptions) CheckResult {
	const id = 9
	const checkName = "audit-log Merkle"
	const slug = "audit-log-merkle"

	// (1) Conditional gate: skip on non-audit-log-export bundles.
	if b.Manifest.BundleType != "audit-log-export" {
		return Skipped(id, checkName, slug,
			fmt.Sprintf("bundle_type=%q is not audit-log-export; dual-subtree composition not applicable", b.Manifest.BundleType))
	}

	var errs []error
	var warnings []error

	// (2) Pre-condition validation: required fields present.
	if b.Manifest.BundleSubtype == "" {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			"bundle_subtype is REQUIRED when bundle_type=\"audit-log-export\"",
			SpecRefManifestFields, "manifest.bundle_subtype REQUIRED for audit-log-export per spec §4.1 + §16.5"))
	} else if b.Manifest.BundleSubtype != "customer-scoped" && b.Manifest.BundleSubtype != "operator-only" {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("bundle_subtype=%q is not in closed vocabulary {\"customer-scoped\",\"operator-only\"}", b.Manifest.BundleSubtype),
			SpecRefManifestFields, "manifest.bundle_subtype closed vocabulary per spec §16.5"))
	}
	if b.Manifest.AuditLogEventCount == nil {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			"audit_log_event_count is REQUIRED when bundle_type=\"audit-log-export\"",
			SpecRefManifestFields, "manifest.audit_log_event_count REQUIRED for audit-log-export per spec §4.1 v1.0.11 F2"))
	} else if *b.Manifest.AuditLogEventCount != len(b.AuditLogEvents) {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("audit_log_event_count=%d does not equal audit_log_events.jsonl line count=%d",
				*b.Manifest.AuditLogEventCount, len(b.AuditLogEvents)),
			SpecRefManifestFields, "manifest.audit_log_event_count MUST equal lines in audit_log_events.jsonl"))
	}
	if b.Manifest.MerkleSubtrees == nil {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			"merkle_subtrees is REQUIRED when bundle_type=\"audit-log-export\"",
			SpecRefManifestFields, "manifest.merkle_subtrees REQUIRED for audit-log-export per spec §16.3"))
	}
	if b.AuditLogSubtree == nil {
		errs = append(errs, Errorf(id, checkName, "audit_log_subtree.json",
			"audit_log_subtree.json is REQUIRED when bundle_type=\"audit-log-export\" (even when audit log subtree is empty per §16.3.1)",
			SpecRefManifestFields, "audit_log_subtree.json REQUIRED for audit-log-export per spec §16.3"))
	}

	// Phase 6.4 session 76 BACKLOG 1.39 closure: per-defect-class
	// collection vs early-return. Pre-fix, this early-return at
	// "len(errs) > 0" suppressed all downstream findings (cross-
	// references, chain integrity, Merkle walks) when ANY pre-condition
	// validation failed. Operator localization speed required multiple
	// verify runs to see the full defect surface.
	//
	// Post-fix: skip-flag dispatch. Downstream sections that depend on
	// specific pre-conditions skip individually rather than the whole
	// check returning early. Sections that DON'T need the missing
	// precondition (e.g., sentinel-UUID gate doesn't need
	// audit_log_subtree.json) run regardless and surface their own
	// defects. The aggregate errs list reports the complete defect
	// surface in a single verify run.
	//
	// Skip flags (computed once; consumed by individual sections):
	// - skipMerkleSubtreesDependent: sections (4) cross-refs + (5)
	//   dual-subtree composition deref Manifest.MerkleSubtrees fields.
	// - skipAuditLogSubtreeDependent: sections (4b) audit_log_root cross-
	//   ref + (7) per-proof walk + (8) coverage symmetry + (9)
	//   empty-subtree §16.3.1 deref AuditLogSubtree.SubtreeRoot/Proofs.
	// AuditLogEventCount pre-condition validation at section (2) uses
	// `if X == nil` guards directly — no skip-flag needed for it; no
	// downstream section derefs AuditLogEventCount.
	skipMerkleSubtreesDependent := b.Manifest.MerkleSubtrees == nil
	skipAuditLogSubtreeDependent := b.AuditLogSubtree == nil

	// (3) §16.5 sentinel UUID gate + F-SC-2 lowercase canonical
	//     validation. Phase 6.2.C session 70 reviewer-pass closure
	//     (code-rev F-SC2-GAP HIGH; crypto-int F4/F5 MEDIUM): validate
	//     manifest.organization_id is canonical lowercase RFC 4122
	//     UUID at the verifier surface (TS-side enforces at primitive
	//     boundary per v1.0.12 F-SC-2 closure; verifier-side mirror
	//     prevents mixed-case slipping through with self-consistent
	//     but cross-impl-divergent content_hash).
	orgID := b.Manifest.OrganizationID
	if !canonicalLowercaseUUID(orgID) {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("organization_id=%q is not canonical lowercase RFC 4122 UUID (v1.0.12 F-SC-2 closure: cross-impl byte-equivalence requires lowercase canonical form)",
				orgID),
			SpecRefManifestFields, "manifest.organization_id MUST be canonical lowercase RFC 4122 UUID per spec §4.1 + v1.0.12 F-SC-2 closure"))
	}
	switch b.Manifest.BundleSubtype {
	case "operator-only":
		if orgID != sentinelUUIDAllZero {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				fmt.Sprintf("bundle_subtype=\"operator-only\" requires manifest.organization_id=%q (all-zero sentinel UUID); got %q",
					sentinelUUIDAllZero, orgID),
				SpecRefManifestFields, "operator-only audit-log-export bundles set organization_id to all-zero sentinel UUID per spec §16.5"))
		}
	case "customer-scoped":
		if orgID == sentinelUUIDAllZero {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				"bundle_subtype=\"customer-scoped\" forbids manifest.organization_id=all-zero sentinel UUID",
				SpecRefManifestFields, "customer-scoped audit-log-export bundles MUST NOT use the operator sentinel UUID per spec §16.5"))
		}
	}

	// (4) Manifest cross-references: events_root + audit_log_root.
	// Phase 6.4 BACKLOG 1.39: skip-flag dispatch instead of early-return.
	if !skipMerkleSubtreesDependent {
		if b.Manifest.MerkleSubtrees.EventsRoot != b.MerkleProofs.Root {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				fmt.Sprintf("merkle_subtrees.events_root=%s does not equal merkle_proofs.json:root=%s",
					truncate(b.Manifest.MerkleSubtrees.EventsRoot, 16), truncate(b.MerkleProofs.Root, 16)),
				SpecRefMerkleProofs, "manifest.merkle_subtrees.events_root equals merkle_proofs.json:root (the primary-event single-tree subtree root)"))
		}
		if !skipAuditLogSubtreeDependent &&
			b.Manifest.MerkleSubtrees.AuditLogRoot != b.AuditLogSubtree.SubtreeRoot {
			errs = append(errs, Errorf(id, checkName, "audit_log_subtree.json",
				fmt.Sprintf("manifest.merkle_subtrees.audit_log_root=%s does not equal audit_log_subtree.json:subtree_root=%s",
					truncate(b.Manifest.MerkleSubtrees.AuditLogRoot, 16), truncate(b.AuditLogSubtree.SubtreeRoot, 16)),
				SpecRefMerkleProofs, "manifest.merkle_subtrees.audit_log_root equals audit_log_subtree.json:subtree_root"))
		}
	}

	// (5) §16.3 dual-subtree composition: daily_root = SHA-256(
	//     events_subtree_root_bytes || audit_log_subtree_root_bytes).
	//     Events FIRST per v1.0.11 F3 MUST-language. Swapping order
	//     produces a different daily_root and is a generation defect.
	// Phase 6.4 BACKLOG 1.39: skip if MerkleSubtrees pre-condition absent.
	if !skipMerkleSubtreesDependent {
		composed, err := computeDualSubtreeComposition(
			b.Manifest.MerkleSubtrees.EventsRoot,
			b.Manifest.MerkleSubtrees.AuditLogRoot,
		)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				fmt.Sprintf("dual-subtree composition: %v", err),
				SpecRefManifestFields, "spec §16.3 dual-subtree composition requires 64-char lowercase hex subtree roots"))
		} else if composed != b.Manifest.DailyRoot {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				fmt.Sprintf("dual-subtree composition SHA-256(events_root_bytes || audit_log_root_bytes)=%s does not equal manifest.daily_root=%s",
					truncate(composed, 16), truncate(b.Manifest.DailyRoot, 16)),
				SpecRefManifestFields, "spec §16.3 daily_root = SHA-256(events_subtree_root_bytes || audit_log_subtree_root_bytes) per v1.0.11 F3 events-FIRST MUST-language"))
		}
	}

	// (6) §16.2.2 chain integrity + §16.3.2 leaf ordering + §16.5
	//     cross-tenant invariant. Per-event walk over AuditLogEvents in
	//     the order they appear in audit_log_events.jsonl. Spec
	//     §16.3.2 requires sequence_number ASCENDING; we verify
	//     monotonic increase as part of the chain walk (a non-monotonic
	//     sequence flags BOTH a chain break AND a §16.3.2 ordering
	//     violation).
	//
	// Phase 7.E session 118 TRIPLE-CORROBORATED HIGH INLINE CLOSURE
	// (sec-aud H1 + crypto-int H1; n=24+ recurring-defect-class
	// defensive-helper-bypass FIRED FOR THE FOURTH CONSECUTIVE
	// SESSION — 115 Ed25519/ML-DSA self-test, 116 events/audit_log_events
	// hard-delete, 117 INSERT-policy auth.uid pinning, 118 chain-walk
	// MaxChainEvents bound). Check 3's MaxChainEvents bound applies
	// to primary events; this symmetric MaxAuditLogEvents bound
	// applies to the audit-log-export bundle's audit_log_events.jsonl
	// chain. A malicious audit-log-export bundle with phantom-event
	// padding would otherwise bypass the H3 defense by switching
	// bundle_type. Same 10M value for symmetry; same phantom-event-
	// padding rationale.
	if int64(len(b.AuditLogEvents)) > MaxAuditLogEvents {
		errs = append(errs, Errorf(id, checkName, "audit_log_events.jsonl",
			fmt.Sprintf("audit-log event count %d exceeds MaxAuditLogEvents %d; refusing to walk (zip-bomb / phantom-event-padding defense; symmetric with Check 3 MaxChainEvents per session 118 sec-aud H1 + crypto-int H1 TRIPLE-CORROBORATED inline closure)",
				len(b.AuditLogEvents), MaxAuditLogEvents),
			SpecRefManifestFields, "per-bundle audit-log event count is bounded for predictable verifier latency"))
		return Result(id, checkName, slug, errs, warnings)
	}

	prevEventHash := genesisSentinelHash
	var prevSequenceNumber int64 = -1
	for i, ev := range b.AuditLogEvents {
		loc := fmt.Sprintf("audit_log_events.jsonl line %d (sequence_number=%d)", i+1, ev.Forensic.SequenceNumber)

		// SEQNUM-JSNUM-BOUNDARY closure (Phase 6.2.C session 70 reviewer-
		// pass TRIPLE-corroborated code-rev MEDIUM + crypto-int F2 HIGH):
		// bound sequence_number at JS Number.MAX_SAFE_INTEGER per v1.0.12
		// F-SC-11 cross-impl conformance. TS reference rejects > 2^53-1
		// at emit; verifier-side rejection preserves the cross-impl byte-
		// equivalence guarantee.
		if ev.Forensic.SequenceNumber < 0 {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("sequence_number=%d is negative (spec §16.2 v1.0.12 F-SC-11: range [0, 2^53-1])",
					ev.Forensic.SequenceNumber),
				SpecRefManifestFields, "spec §16.2 v1.0.12 F-SC-11: sequence_number range [0, 2^53-1] for cross-language safe-integer compatibility"))
		} else if ev.Forensic.SequenceNumber > numberMaxSafeInteger {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("sequence_number=%d exceeds JS Number.MAX_SAFE_INTEGER=%d (spec §16.2 v1.0.12 F-SC-11)",
					ev.Forensic.SequenceNumber, numberMaxSafeInteger),
				SpecRefManifestFields, "spec §16.2 v1.0.12 F-SC-11: cross-language conformance requires sequence_number ≤ JS Number.MAX_SAFE_INTEGER (2^53-1)"))
		}

		// §16.3.2 leaf ordering: sequence_number ascending. The first
		// event has no predecessor to compare; subsequent events MUST
		// have strictly greater sequence_number than the previous.
		if i > 0 && ev.Forensic.SequenceNumber <= prevSequenceNumber {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("sequence_number=%d is not strictly greater than previous=%d (audit log subtree leaves MUST be ordered by sequence_number ascending per spec §16.3.2)",
					ev.Forensic.SequenceNumber, prevSequenceNumber),
				SpecRefManifestFields, "spec §16.3.2 audit_log_events.jsonl ordered by forensic.sequence_number ascending"))
		}
		prevSequenceNumber = ev.Forensic.SequenceNumber

		// F-SC-6 closed-vocabulary validation (Phase 6.2.C session 70
		// reviewer-pass closure code-rev F-SC6-GAP HIGH): actor.type +
		// subject.type per spec §16.2 v1.0.11 F-SC-6. Recurring-defect-
		// class-at-parallel-substrate sub-pattern firing at n=7+ this
		// session — TS-side enforces via Postgres CHECK + emit-time
		// validation; Go verifier-side mirror enforces same posture.
		if !auditLogActorTypeAllowed[ev.Actor.Type] {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("actor.type=%q is not in closed vocabulary {user, admin, system, cron} per spec §16.2 + v1.0.11 F-SC-6 (matches TS emit-helper ACTOR_TYPES set)",
					ev.Actor.Type),
				SpecRefManifestFields, "spec §16.2 + v1.0.11 F-SC-6: actor.type closed vocabulary"))
		}
		if !auditLogSubjectTypeAllowed[ev.Subject.Type] {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("subject.type=%q is not in closed vocabulary {customer, user, api-key, policy-pack, admin-action, cross-tenant, system, cron} per spec §16.2 + v1.0.11 F-SC-6 (matches TS emit-helper SUBJECT_TYPES set; kebab-case)",
					ev.Subject.Type),
				SpecRefManifestFields, "spec §16.2 + v1.0.11 F-SC-6: subject.type closed vocabulary"))
		}
		// subject.organization_id casing validation (F-SC-2 mirror).
		// Customer-scoped non-null + customer-scoped null + operator-only
		// (where subject.organization_id MAY be customer-UUID OR null per
		// §16.5) all converge on the lowercase canonical UUID requirement
		// when non-null.
		if ev.Subject.OrganizationID != nil && !canonicalLowercaseUUID(*ev.Subject.OrganizationID) {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("subject.organization_id=%q is not canonical lowercase RFC 4122 UUID (v1.0.12 F-SC-2)",
					*ev.Subject.OrganizationID),
				SpecRefManifestFields, "spec §16.2 v1.0.12 F-SC-2: subject.organization_id MUST be canonical lowercase RFC 4122 UUID (when non-null)"))
		}

		// §16.2.2 chain link: prev_event_hash MUST equal previous event's
		// event_hash (or genesis sentinel for the first event).
		if ev.Forensic.PrevEventHash != prevEventHash {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("forensic.prev_event_hash=%s does not equal expected predecessor=%s (chain link broken)",
					truncate(ev.Forensic.PrevEventHash, 16), truncate(prevEventHash, 16)),
				SpecRefHashChain, "spec §16.2.2 audit log chain: prev_event_hash links to previous event's event_hash (or genesis sentinel for first event)"))
		}

		// §16.5 cross-tenant invariant: customer-scoped audit log events
		// with non-null subject.organization_id MUST equal manifest.
		// organization_id. operator-only events are scoped via the
		// chain-isolation invariant; subject.organization_id MAY be null
		// (subject is not customer-bound) OR a real-customer UUID (the
		// operator action's customer reference).
		if b.Manifest.BundleSubtype == "customer-scoped" && ev.Subject.OrganizationID != nil {
			if *ev.Subject.OrganizationID != b.Manifest.OrganizationID {
				errs = append(errs, Errorf(id, checkName, loc,
					fmt.Sprintf("subject.organization_id=%q does not equal manifest.organization_id=%q (cross-tenant boundary violation)",
						*ev.Subject.OrganizationID, b.Manifest.OrganizationID),
					SpecRefManifestFields, "spec §16.5 customer-scoped audit log events: subject.organization_id (when non-null) MUST equal manifest.organization_id"))
			}
		}

		// §16.2.1 content_hash recompute. SHA-256(JCS({actor,
		// event_type, subject})) per packages/evidence/src/audit-log-
		// export.ts computeAuditLogContentHash.
		recomputedContentHash, err := computeAuditLogContentHashGo(ev.Actor, ev.EventType, ev.Subject)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("content_hash recompute: %v", err),
				SpecRefHashChain, "spec §16.2.1 audit log content_hash = SHA-256(JCS({actor, event_type, subject}))"))
		} else if recomputedContentHash != ev.ContentHash {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("recomputed content_hash=%s does not equal stored content_hash=%s",
					truncate(recomputedContentHash, 16), truncate(ev.ContentHash, 16)),
				SpecRefHashChain, "spec §16.2.1 audit log content_hash mismatch"))
		}

		// §16.2.2 event_hash recompute. SHA-256(JCS({content_hash,
		// prev_event_hash, sequence_number, timestamp_unix_ns})) — same
		// 4-field payload as primary-event §6.2 per v1.0.12 F-SC-5.
		//
		// Phase 6.2.C session 70 reviewer-pass closure (crypto-int F6
		// MEDIUM): use the RECOMPUTED content_hash (when recompute
		// succeeded) rather than the stored ev.ContentHash. This binds
		// the chain link to the actual content bytes — a content
		// tamper that survives only via a fabricated event_hash now
		// surfaces as event_hash mismatch even if the stored content_
		// hash is internally consistent with the fabricated event_hash.
		contentHashForChain := ev.ContentHash
		if recomputedContentHash != "" {
			contentHashForChain = recomputedContentHash
		}
		recomputedEventHash, err := computeEventHashGo(
			contentHashForChain,
			ev.Forensic.PrevEventHash,
			ev.Forensic.SequenceNumber,
			ev.Forensic.TimestampUnixNs,
		)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("event_hash recompute: %v", err),
				SpecRefHashChain, "spec §16.2.2 audit log event_hash = SHA-256(JCS({content_hash, prev_event_hash, sequence_number, timestamp_unix_ns}))"))
		} else if recomputedEventHash != ev.Forensic.EventHash {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("recomputed event_hash=%s does not equal stored event_hash=%s",
					truncate(recomputedEventHash, 16), truncate(ev.Forensic.EventHash, 16)),
				SpecRefHashChain, "spec §16.2.2 audit log event_hash mismatch"))
		}

		prevEventHash = ev.Forensic.EventHash
	}

	// (7) Per-proof Merkle walk against audit_log_subtree.subtree_root.
	//     Build event-id index for cross-reference symmetry check.
	// Phase 6.4 BACKLOG 1.39: duplicate-event_id detection runs
	// regardless (doesn't depend on AuditLogSubtree); proof-walk +
	// symmetry checks gated on skipAuditLogSubtreeDependent.
	eventIdx := make(map[string]int, len(b.AuditLogEvents))
	for i, ev := range b.AuditLogEvents {
		if _, dup := eventIdx[ev.EventID]; dup {
			errs = append(errs, Errorf(id, checkName,
				fmt.Sprintf("audit_log_events.jsonl event_id=%s", shortID(ev.EventID)),
				"duplicate event_id in audit_log_events.jsonl",
				SpecRefManifestFields, "spec §16.2 audit log event_id is unique within a chain"))
		}
		eventIdx[ev.EventID] = i
	}

	if skipAuditLogSubtreeDependent {
		// Skip per-proof walk + coverage symmetry + empty-subtree §16.3.1
		// check; the audit_log_subtree.json pre-condition error at section
		// (2) already surfaces. Audit-log-events chain integrity (section
		// 6) DID run unconditionally above — duplicate-event_id detection
		// + content_hash/event_hash recompute + sequence_number ordering
		// + cross-tenant invariant all surfaced their own defects.
		return Result(id, checkName, slug, errs, warnings)
	}

	proofIdx := make(map[string]bool, len(b.AuditLogSubtree.Proofs))
	for i, p := range b.AuditLogSubtree.Proofs {
		loc := fmt.Sprintf("audit_log_subtree.json:proofs[%d] event_id=%s", i, shortID(p.EventID))

		if proofIdx[p.EventID] {
			errs = append(errs, Errorf(id, checkName, loc,
				"duplicate proof for this event_id",
				SpecRefMerkleProofs, "spec §16.3 audit log subtree: one proof per event"))
		}
		proofIdx[p.EventID] = true

		evIdx, ok := eventIdx[p.EventID]
		if !ok {
			errs = append(errs, Errorf(id, checkName, loc,
				"proof event_id has no corresponding entry in audit_log_events.jsonl (orphan proof)",
				SpecRefMerkleProofs, "spec §16.3 audit log subtree: every proof references an event in audit_log_events.jsonl"))
			continue
		}

		// proof.leaf MUST equal the event's forensic.event_hash.
		expectedLeaf := b.AuditLogEvents[evIdx].Forensic.EventHash
		if p.Leaf != expectedLeaf {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("proof.leaf=%s does not equal forensic.event_hash=%s",
					truncate(p.Leaf, 16), truncate(expectedLeaf, 16)),
				SpecRefMerkleProofs, "spec §16.3 audit log subtree: proof.leaf equals event's forensic.event_hash"))
		}

		// proof.root MUST equal audit_log_subtree.subtree_root.
		if p.Root != b.AuditLogSubtree.SubtreeRoot {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("proof.root=%s does not equal audit_log_subtree.subtree_root=%s",
					truncate(p.Root, 16), truncate(b.AuditLogSubtree.SubtreeRoot, 16)),
				SpecRefMerkleProofs, "spec §16.3 audit log subtree: every proof's root equals subtree_root"))
		}

		// Walk the proof: reconstruct subtree_root from leaf + path
		// using the same §8.2 algorithm Check 4 uses. Adapter:
		// AuditLogSubtreeProof.Path uses MerkleProofStep (same shape
		// as MerkleProofEntry.Path), so we re-use walkMerkleProof by
		// constructing a synthetic MerkleProofEntry.
		synth := bundle.MerkleProofEntry{
			EventID: p.EventID,
			Leaf:    p.Leaf,
			Path:    p.Path,
			Root:    p.Root,
		}
		walked, werr := walkMerkleProof(synth)
		if werr != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("Merkle walk: %v", werr),
				SpecRefMerkleProof, "spec §8.2 walker applies symmetrically to audit log subtree per §16.3"))
		} else if walked != b.AuditLogSubtree.SubtreeRoot {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("walked Merkle root=%s does not equal audit_log_subtree.subtree_root=%s",
					truncate(walked, 16), truncate(b.AuditLogSubtree.SubtreeRoot, 16)),
				SpecRefMerkleProof, "spec §16.3 audit log subtree: reconstructed root from leaf+path equals subtree_root"))
		}
	}

	// (8) Coverage symmetry: every audit log event has exactly one proof.
	missing := make([]string, 0)
	for evID := range eventIdx {
		if !proofIdx[evID] {
			missing = append(missing, evID)
		}
	}
	sort.Strings(missing)
	for _, evID := range missing {
		errs = append(errs, Errorf(id, checkName,
			fmt.Sprintf("audit_log_events.jsonl event_id=%s", shortID(evID)),
			"no Merkle proof present for this audit log event (unproven event)",
			SpecRefMerkleProofs, "spec §16.3 audit log subtree: every audit log event has a corresponding proof"))
	}

	// (9) §16.3.1 empty-subtree composition validation. When 0 audit log
	//     events, the subtree root MUST be the all-zero genesis sentinel
	//     hex (64 zero chars). Caught indirectly by the dual-subtree
	//     composition check above (the manifest.audit_log_root would
	//     have to be the sentinel for SHA-256 input to match
	//     manifest.daily_root); explicit check here catches malformed
	//     audit_log_subtree.json with non-empty proofs[] under
	//     empty-events.
	if len(b.AuditLogEvents) == 0 && b.AuditLogSubtree.SubtreeRoot != genesisSentinelHash {
		errs = append(errs, Errorf(id, checkName, "audit_log_subtree.json",
			fmt.Sprintf("audit_log_events.jsonl is empty but subtree_root=%s (expected all-zero sentinel %s per spec §16.3.1)",
				truncate(b.AuditLogSubtree.SubtreeRoot, 16), truncate(genesisSentinelHash, 16)),
			SpecRefMerkleProofs, "spec §16.3.1 empty-subtree composition: audit_log_subtree_root = 0x00 * 32 when audit_log_events.jsonl is empty"))
	}
	if len(b.AuditLogEvents) == 0 && len(b.AuditLogSubtree.Proofs) > 0 {
		errs = append(errs, Errorf(id, checkName, "audit_log_subtree.json",
			fmt.Sprintf("audit_log_events.jsonl is empty but audit_log_subtree.proofs[] has %d entries", len(b.AuditLogSubtree.Proofs)),
			SpecRefMerkleProofs, "spec §16.3.1 empty-subtree composition: audit_log_subtree.proofs[] is empty when audit_log_events.jsonl is empty"))
	}

	return Result(id, checkName, slug, errs, warnings)
}

// computeDualSubtreeComposition computes the dual-subtree daily_root
// per spec §16.3: SHA-256(events_subtree_root_bytes ||
// audit_log_subtree_root_bytes). Events FIRST per v1.0.11 F3 MUST-
// language (swapping the operand order is a generation defect — the
// resulting daily_root is different and verifiers MUST NOT accept it).
//
// Operands are 64-char lowercase hex strings; the function decodes
// each to 32 raw bytes BEFORE concatenation per crypto-int H2 byte-
// encoding closure (the SHA-256 input is 64 raw bytes, NOT 128 hex
// characters; this is the load-bearing cross-implementation invariant).
//
// Mirrors packages/evidence/src/audit-log-export.ts
// computeDualSubtreeDailyRoot.
func computeDualSubtreeComposition(eventsRootHex, auditLogRootHex string) (string, error) {
	if !isLowercaseHex64(eventsRootHex) {
		return "", fmt.Errorf("events_subtree_root is not 64-char lowercase hex: %q", truncate(eventsRootHex, 16))
	}
	if !isLowercaseHex64(auditLogRootHex) {
		return "", fmt.Errorf("audit_log_subtree_root is not 64-char lowercase hex: %q", truncate(auditLogRootHex, 16))
	}
	eventsBytes, err := hex.DecodeString(eventsRootHex)
	if err != nil {
		return "", fmt.Errorf("events_subtree_root hex decode: %w", err)
	}
	auditLogBytes, err := hex.DecodeString(auditLogRootHex)
	if err != nil {
		return "", fmt.Errorf("audit_log_subtree_root hex decode: %w", err)
	}
	combined := make([]byte, 0, len(eventsBytes)+len(auditLogBytes))
	combined = append(combined, eventsBytes...)    // events FIRST per spec §16.3
	combined = append(combined, auditLogBytes...)
	sum := sha256.Sum256(combined)
	return hex.EncodeToString(sum[:]), nil
}

// computeAuditLogContentHashGo computes the SHA-256 hex of the
// canonical JSON of {actor, event_type, subject} per spec §16.2.1.
//
// Cross-implementation parity with packages/evidence/src/audit-log-
// export.ts computeAuditLogContentHash:
//
//   - JCS canonicalization via canonicalJSON helper (map-key sorted).
//   - subject.organization_id is nullable: nil pointer → JSON null;
//     non-nil → string. This matches TS AuditLogSubject.organization_id
//     null-vs-string discipline.
//   - actor + subject are flat objects with closed-vocabulary type
//     fields; no nested structures.
//
// **F-SC-2 closure**: organization_id (when non-null) is the subject's
// organization UUID; the writer side validates lowercase canonical
// RFC 4122 UUID at emission. The verifier passes through to canonical
// JSON without re-validation (the cross-tenant invariant check above
// in Run() handles the customer-scoped value check).
func computeAuditLogContentHashGo(actor bundle.AuditLogActor, eventType string, subject bundle.AuditLogSubject) (string, error) {
	subjectMap := map[string]interface{}{
		"id":   subject.ID,
		"type": subject.Type,
	}
	// nullable organization_id: emit JSON null when nil pointer; emit
	// string when non-nil. Mirrors TS canonicalize null-vs-string
	// distinction per §16.5 cross-tenant invariant + AuditLogContentPayload
	// shape.
	if subject.OrganizationID == nil {
		subjectMap["organization_id"] = nil
	} else {
		subjectMap["organization_id"] = *subject.OrganizationID
	}

	payload := map[string]interface{}{
		"actor": map[string]interface{}{
			"id":   actor.ID,
			"type": actor.Type,
		},
		"event_type": eventType,
		"subject":    subjectMap,
	}
	canon, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

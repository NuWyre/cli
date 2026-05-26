package bundle

import (
	"crypto/ed25519"
	"encoding/json"
)

// Bundle is the parsed in-memory representation of a NuWyre evidence
// bundle ZIP. Every field mirrors a spec section in
// /docs/spec/bundle-format-v1.md. Fields the spec marks "required"
// MUST be non-zero post-Load(); fields the spec marks "conditional"
// or "example-only" MAY be zero.
type Bundle struct {
	// Path is the operator-visible source label the bundle was loaded
	// from — a filesystem path under Load() or "(bytes)" / a caller-
	// supplied filename under LoadFromBytes(). Used in error messages
	// so the operator can localize a malformed bundle. NOT used by
	// checks for re-opening the zip — use RawZip for that.
	Path string

	// RawZip is the raw zip bytes the bundle was loaded from. Always
	// populated post-Load() / LoadFromBytes(); enables checks (notably
	// Check2Artifacts, which re-iterates the zip to detect extra-files
	// + verify per-entry SHA-256) to operate on the original bytes
	// without re-opening the filesystem path. This is the load-bearing
	// design choice that lets the WASM verifier produce identical
	// Check2Artifacts results to the native CLI in a browser environment
	// where no filesystem path exists.
	//
	// Memory cost: equal to the zip file size (typically <500 KB for
	// example-demo bundles, <10 MB for production customer exports).
	// Acceptable trade-off for cross-implementation conformance (T2)
	// vs. WASM/browser compatibility (T3+T5+T6).
	RawZip []byte

	// Manifest is the parsed manifest.json (spec §4).
	Manifest ManifestJSON

	// ManifestRaw is the raw bytes of manifest.json — what was on
	// disk, byte-for-byte. Used by Phase 4 verification check 1
	// (Ed25519 signature verifies over the canonicalized manifest
	// bytes, so the verifier needs the bytes as-stored).
	ManifestRaw []byte

	// Signature is the parsed signature.sig (spec §5).
	Signature SignatureJSON

	// SignatureRaw is the raw bytes of signature.sig.
	SignatureRaw []byte

	// CoverPDF is the raw cover.pdf bytes (spec §3 required).
	CoverPDF []byte

	// VerifyMD is the raw verify.md contents (spec §3 required).
	VerifyMD string

	// Events is the parsed events.jsonl line-by-line (spec §6).
	// Each entry preserves the canonical JSON object.
	Events []EventJSONL

	// EventsRaw is the raw events.jsonl bytes — what was on disk,
	// byte-for-byte. Phase 4 Session 2 check 3 (chain reconstruction +
	// per-event ingestion_signature reverification) MUST split
	// EventsRaw on \n and use the per-line raw bytes (NOT struct
	// re-canonicalization) for signature verification: spec §1 +
	// §14 mandate forward-compat tolerance, so a writer-emitted
	// extension field would NOT round-trip through the EventJSONL
	// struct, and recanonicalizing from the struct would drop the
	// extension field and break signature equality. Re-splitting
	// EventsRaw on \n preserves byte-level fidelity.
	EventsRaw []byte

	// Evaluations is the parsed evaluations.jsonl line-by-line
	// (spec §7). Per spec §7.3, row_hash is computed as SHA-256 of
	// canonicalize(row minus row_hash). Phase 4 Session 2-3 MAY add
	// a per-row recomputation backstop (spec §7.2 row_hash row's
	// "Recommended Phase 4 verifier behavior") to localize tampering
	// when check 2's file SHA-256 mismatches; the backstop is not a
	// normative check today.
	Evaluations []EvaluationJSONL

	// EvaluationsRaw mirrors EventsRaw for evaluations.jsonl.
	// Same forward-compat reasoning: any future per-row signature
	// or row_hash reverification check MUST split EvaluationsRaw on
	// \n rather than recanonicalize from the EvaluationJSONL struct.
	EvaluationsRaw []byte

	// MerkleProofs is the parsed merkle_proofs.json (spec §8).
	MerkleProofs MerkleProofsJSON

	// DailyRoots is the parsed daily_roots.json (spec §9).
	DailyRoots DailyRootsJSON

	// OTSReceipts maps utc_day (yyyy-mm-dd) to raw .ots bytes
	// (spec §10).
	OTSReceipts map[string][]byte

	// RFC3161Receipts maps utc_day → tsa_name → {.tsr, .chain.pem}
	// pairs (spec §11).
	RFC3161Receipts map[string]map[string]RFC3161Pair

	// GithubAnchors maps utc_day to parsed
	// github_anchors/<date>.json (spec §12).
	GithubAnchors map[string]GithubAnchorJSON

	// AudioFiles maps content-addressed filename
	// (sha256.ext) → raw audio bytes. Conditional per spec §13;
	// nil when no events have audio_ref.
	AudioFiles map[string][]byte

	// AuditLogEvents is the parsed audit_log_events.jsonl line-by-line
	// (spec §16.2 v1.0.10+ audit-log-export bundle type). Conditional;
	// nil when bundle_type != "audit-log-export". Phase 6.2.C session
	// 70 Check 9 audit-log-merkle reconstructs the audit-log Merkle
	// subtree from these entries.
	AuditLogEvents []AuditLogEventJSONL

	// AuditLogEventsRaw is the raw audit_log_events.jsonl bytes —
	// what was on disk, byte-for-byte. Mirrors EventsRaw discipline:
	// Phase 4 Session 2 check 3's forward-compat tolerance applies
	// here too. Any future per-row signature reverification check
	// MUST split AuditLogEventsRaw on \n rather than recanonicalize
	// from the AuditLogEventJSONL struct.
	AuditLogEventsRaw []byte

	// AuditLogSubtree is the parsed audit_log_subtree.json
	// (spec §16.3 v1.0.10+). REQUIRED for audit-log-export bundles
	// even when the subtree is empty (§16.3.1 empty-subtree
	// composition rule); nil when bundle_type != "audit-log-export".
	AuditLogSubtree *AuditLogSubtreeJSON

	// ScenarioIndex is the parsed scenario_index.json. Example-only
	// per spec §3; nil for customer-export bundles.
	ScenarioIndex *ScenarioIndexJSON

	// EphemeralPubkeyByID is the verifier-internal map populated by
	// Check 8 (spec §6.5.6) under ephemeral-sessions topology. Maps
	// `signing.ephemeral_sessions[i].session_id` to the recomputed
	// 32-byte Ed25519 public key. Check 3's topology-aware branch
	// reads from this map to route per-event signature verification
	// under ephemeral-sessions topology.
	//
	// **Lifecycle**: nil pre-Check-8; populated to a non-nil non-empty
	// map iff Check 8 returns Pass; reset to nil on Check 8 Fail or
	// Skipped (single-key topology). Read-only contract for Check 3
	// and downstream consumers.
	//
	// Pre-Phase 6 Item 2 closure 2026-05-15 (v1.0.9 amendment).
	EphemeralPubkeyByID map[string]ed25519.PublicKey
}

// RFC3161Pair groups one TSA's .tsr + .chain.pem from a single day.
// Spec §11 mandates that .tsr and .chain.pem MUST appear together;
// half-pairs are a generation bug the loader rejects.
type RFC3161Pair struct {
	TSR      []byte
	ChainPEM []byte
}

// =============================================================================
// manifest.json (spec §4)
// =============================================================================

// ManifestJSON mirrors the spec §4 manifest schema. Required fields
// per spec §4.1 are non-pointer types; conditional fields use
// pointers / json:"omitempty" so the loader can detect absence.
type ManifestJSON struct {
	SchemaVersion   int    `json:"schema_version"`
	BundleFormat    string `json:"bundle_format"`
	BundleID        string `json:"bundle_id"`
	BundleType      string `json:"bundle_type"`
	// BundleSubtype is conditional per spec §4.1 + §16.5 (v1.0.10):
	// REQUIRED when BundleType == "audit-log-export" (closed
	// vocabulary {"customer-scoped", "operator-only"}); FORBIDDEN
	// otherwise. Empty string when absent — Check 9 dispatch validates
	// presence + value against bundle_type at run time.
	BundleSubtype   string `json:"bundle_subtype,omitempty"`
	GeneratedAt     string `json:"generated_at"`
	OrganizationID  string `json:"organization_id"`
	AgentID         string `json:"agent_id"`
	AgentAttestID   string `json:"agent_attestation_id"`

	// DemoDayUTC is required for single-day bundles only; spec §4.1
	// says future v1.x will define a different field set for
	// multi-day. Pointer so absence is distinguishable.
	DemoDayUTC *string `json:"demo_day_utc,omitempty"`

	// PeriodStart / PeriodEnd are present on multi-day bundles
	// (Phase 3 V1 customer-export shape per
	// generate-bundle.ts). Pointers so absence is distinguishable.
	PeriodStart *string `json:"period_start,omitempty"`
	PeriodEnd   *string `json:"period_end,omitempty"`

	EventCount       int `json:"event_count"`
	EvaluationCount  int `json:"evaluation_count"`
	FlaggedCount     int `json:"flagged_count"`
	CleanCount       int `json:"clean_count"`
	EvaluationSource string `json:"evaluation_source"`

	// AuditLogEventCount is conditional per spec §4.1 + §16.8 (v1.0.11
	// amendment F2 closure): REQUIRED when BundleType == "audit-log-
	// export". MUST equal len(AuditLogEvents). Pointer so absence is
	// distinguishable from explicit zero (an empty operator-only chain
	// is a legitimate state where audit_log_event_count == 0).
	AuditLogEventCount *int `json:"audit_log_event_count,omitempty"`

	DailyRoot string `json:"daily_root"`

	// MerkleSubtrees is conditional per spec §16.3 (v1.0.10):
	// REQUIRED when BundleType == "audit-log-export"; the events_root
	// + audit_log_root operands are the subtrees that compose into
	// daily_root via SHA-256(events_subtree_root_bytes ||
	// audit_log_subtree_root_bytes). FORBIDDEN otherwise (forward-
	// compat tolerance §1 — pre-v1.0.10 customer-export + example-
	// demo + sandbox-preview bundles emit the field as absent and
	// verifiers treat absence as single-tree composition). Pointer
	// so absence is distinguishable.
	MerkleSubtrees *ManifestMerkleSubtrees `json:"merkle_subtrees,omitempty"`

	Signing      ManifestSigning      `json:"signing"`
	AnchorStatus ManifestAnchorStatus `json:"anchor_status"`
	Anchors      ManifestAnchors      `json:"anchors"`
	Artifacts    []ManifestArtifact   `json:"artifacts"`

	// AudioRecords is conditional per spec §4.1; required when any
	// event has audio_ref.
	AudioRecords []ManifestAudioRecord `json:"audio_records,omitempty"`

	PackSubscriptions []ManifestPackSubscription `json:"pack_subscriptions"`
	Binding           ManifestBinding            `json:"binding"`
}

// ManifestSigning is the spec §5 signing metadata block embedded in
// manifest.json. signature.sig also carries this; verifiers
// cross-check.
//
// **v1.0.9 amendment fields (Pre-Phase 6 Item 2 closure 2026-05-15)**:
// `topology` and `ephemeral_sessions` are OPTIONAL fields added to
// support sandbox-only session-scoped ephemeral signing per spec §6.5.
// Legacy bundles + customer-export bundles omit both fields entirely;
// sandbox-preview bundles MAY emit them under the v1.0.9 topology.
type ManifestSigning struct {
	// v1 single-signature fields per spec §5. At v2 (bundle_format ==
	// "nuwyre-bundle/v2") these are absent (zero-valued in Go); the
	// Signatures array below carries the per-algorithm entries instead.
	// Phase 7.F.3 (2026-05-21): Algorithm/KeyFingerprintB64/KeyPurpose
	// remain non-pointer for v1 back-compat — the dispatch fires off
	// BundleFormat at Check 1, not off field-presence.
	Algorithm         string `json:"algorithm,omitempty"`
	KeyFingerprintB64 string `json:"key_fingerprint_spki_b64,omitempty"`
	KeyPurpose        string `json:"key_purpose,omitempty"`

	// SchemaVersion is the v2 signing-block schema marker. Present at
	// v2 (== 1); absent at v1. Phase 7.F.3 v2.0.0-rc1 addition.
	SchemaVersion int `json:"schema_version,omitempty"`

	// Signatures is the v2 dual-signature array per spec §§18.1-18.2.
	// REQUIRED with cardinality EXACTLY 2 at v2 bundles
	// (signatures[0] = Ed25519, signatures[1] = ML-DSA-65).
	// FORBIDDEN at v1 bundles. Phase 7.F.3 v2.0.0-rc1 addition.
	Signatures []ManifestSigningEntry `json:"signatures,omitempty"`

	// Topology is "single-key" (default; legacy + customer-export +
	// example-demo + pre-v1.0.9 sandbox) or "ephemeral-sessions"
	// (v1.0.9 sandbox-preview only). Empty string when absent —
	// defaults to single-key per spec §5.
	Topology string `json:"topology,omitempty"`

	// EphemeralSessions is the v1.0.9 per-session metadata array.
	// REQUIRED non-empty when Topology == "ephemeral-sessions";
	// FORBIDDEN otherwise. v1.0.9 sandbox-preview bundles carry
	// exactly one entry; v2+ may generalize.
	EphemeralSessions []EphemeralSessionMeta `json:"ephemeral_sessions,omitempty"`
}

// ManifestSigningEntry is a single algorithm row in the v2 signatures[]
// array per spec §18.1. v2 bundles emit exactly TWO entries:
// signatures[0] = Ed25519 + signatures[1] = ML-DSA-65 per spec §18.8
// positional-ordering invariant. Phase 7.F.3 v2.0.0-rc1 addition.
type ManifestSigningEntry struct {
	// Algorithm is "ed25519" or "ml-dsa-65" per spec §18.4 closed
	// vocabulary; signatures[0].algorithm MUST be "ed25519" and
	// signatures[1].algorithm MUST be "ml-dsa-65".
	Algorithm string `json:"algorithm"`

	// KeyFingerprintB64 is the canonical SPKI DER base64-encoded.
	// Ed25519: 44 bytes raw DER → 60 chars base64 with == padding
	// (RFC 5280). ML-DSA-65: 1974 bytes raw DER → 2632 chars base64
	// with NO padding per spec §18.4 (1974 mod 3 == 0).
	KeyFingerprintB64 string `json:"key_fingerprint_spki_b64"`

	// KeyID is the writer's identifier for the signing key. Opaque
	// at spec §18.1 layer; apps/api convention is
	// "issuer-{prod,dev}-v2-{algorithm}". Used for cross-environment-
	// slot defense at Check 1 step 2 per spec §18.6.
	KeyID string `json:"key_id"`

	// KeyPurpose is the spec-pinned literal per writer authority
	// (Phase 7.F.2-B crypto-integrity C2 + spec-conformance H1
	// closure 2026-05-21). For Ed25519: "Ed25519 manifest signature;
	// v2.0.0-rc1+ dual-sig topology". For ML-DSA-65: "ML-DSA-65
	// manifest signature; v2.0.0-rc1+ dual-sig topology".
	KeyPurpose string `json:"key_purpose"`
}

// EphemeralSessionMeta is one entry in spec §5 v1.0.9 amendment
// manifest.signing.ephemeral_sessions[]. Per spec §6.5, the verifier
// (Check 8) consumes these fields to reconstruct the ephemeral SPKI
// from the canonical seed + KMS attestation and cross-check it
// against the manifest's claimed SPKI.
type EphemeralSessionMeta struct {
	SchemaVersion         int    `json:"schema_version"`
	SessionID             string `json:"session_id"`
	StartedAtNs           string `json:"started_at_ns"`
	SessionSeedBytesB64   string `json:"session_seed_bytes_b64"`
	KmsAttestationB64     string `json:"kms_attestation_b64"`
	EphemeralSpkiB64      string `json:"ephemeral_spki_b64"`
}

// ManifestAnchorStatus enumerates the per-leg anchor states per
// spec §4.2. Phase 4 Session B Item 5 reconciliation: github_status
// uses spec-canonical 4-state enum.
type ManifestAnchorStatus struct {
	OTSStatus     string `json:"ots_status"`
	RFC3161Status string `json:"rfc3161_status"`
	GithubStatus  string `json:"github_status"`
}

// ManifestAnchors is the per-leg detailed anchor metadata per
// spec §§9-11.
type ManifestAnchors struct {
	OpenTimestamps ManifestOTSAnchor       `json:"opentimestamps"`
	RFC3161        []ManifestRFC3161Anchor `json:"rfc3161"`
	Github         json.RawMessage         `json:"github"`
}

// ManifestOTSAnchor is spec §9. submitted_at is required;
// receipt_path is required when ots_status != "not_attempted".
type ManifestOTSAnchor struct {
	ReceiptPath string `json:"receipt_path"`
	Status      string `json:"status"`
	SubmittedAt string `json:"submitted_at"`
}

// ManifestRFC3161Anchor is one TSA's entry in spec §11's
// anchors.rfc3161 array. receipt_path / chain_path are bundle-
// relative paths with the flat layout
// rfc3161_receipts/<utc_day>__<tsa_name>.{tsr,chain.pem}. (Phase 4
// Session A's per-org scoping applies to the github-anchor REPO
// directory layout — daily_roots/<organization_id>/<date>/... — not
// to the bundle's internal file paths, which remain flat per spec
// §11. A V1 bundle carries one organization's data; per-org
// subdirectories inside the bundle would be redundant.)
type ManifestRFC3161Anchor struct {
	TSAName       string `json:"tsa_name"`
	ReceiptPath   string `json:"receipt_path"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	ChainPath     string `json:"chain_path"`
	ChainSHA256   string `json:"chain_sha256"`
	SubmittedAt   string `json:"submitted_at"`
	TSATime       string `json:"tsa_time"`
}

// ManifestArtifact is one entry in spec §4 artifacts[]. Every file
// in the bundle except manifest.json + signature.sig MUST appear
// here with byte size and SHA-256.
type ManifestArtifact struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// ManifestAudioRecord is one entry in spec §4 audio_records[].
// Required when any event has audio_ref.
type ManifestAudioRecord struct {
	SHA256      string `json:"sha256"`
	StoragePath string `json:"storage_path"`
	Bytes       int64  `json:"bytes"`
	DurationMs  int    `json:"duration_ms"`
	MIMEType    string `json:"mime_type"`
}

// ManifestPackSubscription is one entry in spec §4
// pack_subscriptions[]. Empty array when no packs were subscribed.
type ManifestPackSubscription struct {
	PackID      string `json:"pack_id"`
	PackVersion string `json:"pack_version"`
	BodyHash    string `json:"body_hash"`
}

// ManifestBinding is the methodology document binding per spec §4
// binding object.
type ManifestBinding struct {
	MethodologyDoc          string `json:"methodology_doc"`
	MethodologySection      string `json:"methodology_section"`
	ValidationScenariosDir  string `json:"validation_scenarios_dir"`
}

// =============================================================================
// signature.sig (spec §5)
// =============================================================================

// SignatureJSON mirrors the spec §5 signature schema (v1) AND the
// spec §18.2 multi-signature container (v2). The dispatch fires off
// the parent manifest.bundle_format at Check 1:
//   - v1: top-level Algorithm/KeyFingerprintB64/SignatureB64 carry the
//     single Ed25519 signature; Signatures array is absent.
//   - v2: Signatures array carries cardinality-2 entries (Ed25519 + ML-DSA-65);
//     top-level Algorithm/KeyFingerprintB64/SignatureB64 are absent.
//
// SchemaVersion + SignedArtifact are present in both v1 and v2.
type SignatureJSON struct {
	SchemaVersion  int    `json:"schema_version"`
	SignedArtifact string `json:"signed_artifact"`

	// v1 single-signature fields (omitempty so they're absent in v2 emissions).
	Algorithm         string `json:"algorithm,omitempty"`
	KeyFingerprintB64 string `json:"key_fingerprint_spki_b64,omitempty"`
	SignatureB64      string `json:"signature_b64,omitempty"`

	// Signatures is the v2 dual-signature array per spec §§18.1-18.2.
	// REQUIRED with cardinality EXACTLY 2 at v2 bundles. FORBIDDEN at
	// v1 bundles. Phase 7.F.3 v2.0.0-rc1 addition.
	Signatures []SignatureEntry `json:"signatures,omitempty"`
}

// SignatureEntry is a single algorithm row in the v2 signature.sig
// signatures[] array per spec §18.2. Phase 7.F.3 v2.0.0-rc1 addition.
type SignatureEntry struct {
	// Algorithm is "ed25519" or "ml-dsa-65" per spec §18.4. Positional
	// invariant: signatures[0]=ed25519; signatures[1]=ml-dsa-65.
	Algorithm string `json:"algorithm"`

	// KeyFingerprintB64 cross-checks against
	// manifest.signing.signatures[i].key_fingerprint_spki_b64 at
	// Check 1 step 2 per spec §18.7.
	KeyFingerprintB64 string `json:"key_fingerprint_spki_b64"`

	// KeyID cross-checks against manifest.signing.signatures[i].key_id
	// at Check 1 step 2 per spec §18.7.
	KeyID string `json:"key_id"`

	// SignatureB64 is the raw signature base64-encoded.
	// Ed25519: 64 bytes raw → 88 chars base64 with == padding.
	// ML-DSA-65: 3309 bytes raw → 4412 chars base64 with NO padding
	// (3309 mod 3 == 0) per spec §18.4 + crypto-integrity L1 closure.
	SignatureB64 string `json:"signature_b64"`
}

// =============================================================================
// events.jsonl (spec §6) — one JSON object per line
// =============================================================================

// EventJSONL mirrors the spec §6.1 per-line shape. Phase 4 Session 2
// check 3 walks these in order, recomputing content_hash + event_hash
// from the parsed fields.
type EventJSONL struct {
	SchemaVersion       int                  `json:"schema_version"`
	EventID             string               `json:"event_id"`
	AgentAttestationID  string               `json:"agent_attestation_id"`
	Identity            EventIdentity        `json:"identity"`
	Content             EventContent         `json:"content"`
	Forensic            EventForensic        `json:"forensic"`
	ComplianceMetadata  EventComplianceMeta  `json:"compliance_metadata"`
	Provenance          EventProvenance      `json:"provenance"`
}

type EventIdentity struct {
	OrganizationID string  `json:"organization_id"`
	AgentID        string  `json:"agent_id"`
	SessionID      string  `json:"session_id"`
	ModelID        string  `json:"model_id"`
	ModelVersion   string  `json:"model_version"`
	DeploymentID   *string `json:"deployment_id"`
}

type EventContent struct {
	Role             string          `json:"role"`
	Content          *string         `json:"content"`
	ContentHash      string          `json:"content_hash"`
	ToolCalls        json.RawMessage `json:"tool_calls"`
	PromptHash       *string         `json:"prompt_hash"`
	SystemPromptHash *string         `json:"system_prompt_hash"`
	AudioRef         *EventAudioRef  `json:"audio_ref,omitempty"`
}

type EventAudioRef struct {
	Hash        string `json:"hash"`
	StoragePath string `json:"storage_path"`
	MIMEType    string `json:"mime_type"`
	DurationMs  int    `json:"duration_ms"`
	// SampleRate and Channels are *int (not int) because the TS schema
	// permits null per packages/schema/src/event-v1.ts AudioRefSchema
	// (sample_rate / channels: `z.number().int().positive().nullable()`).
	// The current writer always emits explicit ints (never null), but
	// using a pointer here preserves the null-vs-zero distinction so
	// Phase 4 Session 2 check 3's content_hash recomputation produces
	// canonical JSON with `null` (matching TS canonicalize) rather than
	// `0` (which would diverge silently). M2 from commit-4 reviewer pass.
	SampleRate *int `json:"sample_rate"`
	Channels   *int `json:"channels"`
}

type EventForensic struct {
	TimestampISO       string `json:"timestamp_iso"`
	TimestampUnixNs    string `json:"timestamp_unix_ns"`
	// SequenceNumber is int64 — forensic counters can grow large,
	// and 32-bit `int` would top at ~2.1B. Per-org global chain
	// (organization_chain_state, Phase 3) issues monotonically
	// increasing sequence numbers; production scale could exceed
	// 32-bit in a multi-year chain.
	SequenceNumber     int64  `json:"sequence_number"`
	PrevEventHash      string `json:"prev_event_hash"`
	EventHash          string `json:"event_hash"`
	IngestionSignature string `json:"ingestion_signature"`
}

type EventComplianceMeta struct {
	Jurisdiction         string   `json:"jurisdiction"`
	RetentionClass       string   `json:"retention_class"`
	LegalHold            bool     `json:"legal_hold"`
	ConsentState         string   `json:"consent_state"`
	ClassificationLabels []string `json:"classification_labels"`
	RedactionApplied     bool     `json:"redaction_applied"`
	RedactionMethod      string   `json:"redaction_method"`
	PIIDetected          []string `json:"pii_detected"`
	PHIDetected          []string `json:"phi_detected"`
}

type EventProvenance struct {
	SourceAdapter      string `json:"source_adapter"`
	SourceVersion      string `json:"source_version"`
	IngestionTimestamp string `json:"ingestion_timestamp"`
}

// =============================================================================
// evaluations.jsonl (spec §7) — one JSON object per line
// =============================================================================

// EvaluationJSONL mirrors spec §7.1. Required fields (always present):
//   - content_hash: 64-char lowercase hex; equals the referenced
//     event's content.content_hash (cross-reference per spec §7.4)
//   - event_id: UUID; matches one row in events.jsonl
//   - rule_id: the policy-pack rule that produced the verdict
//   - pack_id + pack_body_hash: pin the exact pack version evaluated
//     against (pack_body_hash MUST equal manifest.pack_subscriptions[]
//     .body_hash for the matching pack_id)
//   - verdict: "flagged" | "clean" | "uncertain" (per spec §7.2)
//   - severity: "info" | "low" | "medium" | "high" | "critical"
//   - reasoning: human-readable rationale
//   - evaluator_runtime_version: e.g., "1.0.0-canned" for canned
//     evaluator, "<model>:<version>" for live evaluator
//   - row_hash: 64-char lowercase hex SHA-256 of canonicalize(row
//     minus row_hash) per spec §7.3
//
// Conditional field:
//   - derived_from_scenario_id: present when manifest.evaluation_source
//     == "validation-canned"; absent for "live-evaluator" (per spec §7.4)
type EvaluationJSONL struct {
	ContentHash             string  `json:"content_hash"`
	EventID                 string  `json:"event_id"`
	RuleID                  string  `json:"rule_id"`
	PackID                  string  `json:"pack_id"`
	PackBodyHash            string  `json:"pack_body_hash"`
	Verdict                 string  `json:"verdict"`
	Severity                string  `json:"severity"`
	Reasoning               string  `json:"reasoning"`
	EvaluatorRuntimeVersion string  `json:"evaluator_runtime_version"`
	DerivedFromScenarioID   *string `json:"derived_from_scenario_id,omitempty"`
	RowHash                 string  `json:"row_hash"`
}

// =============================================================================
// merkle_proofs.json (spec §8) + daily_roots.json (spec §9)
// =============================================================================

// MerkleProofsJSON mirrors spec §8. Top-level fields are { root,
// proofs[] } — root is required + must equal manifest.daily_root +
// daily_roots.json:roots[<date>].root + every proof's per-entry root.
//
// SchemaVersion is captured for parity with DailyRootsJSON even though
// spec §8 doesn't currently mandate it; the writer
// (packages/evidence/src/generate-bundle.ts) emits schema_version=1.
// Pinning it here means a future v1.x bump on this file alone is
// surfaced to the verifier rather than silently ignored.
type MerkleProofsJSON struct {
	SchemaVersion int                `json:"schema_version"`
	Root          string             `json:"root"`
	Proofs        []MerkleProofEntry `json:"proofs"`
}

// MerkleProofEntry is one event's proof of membership per spec §8.
// Phase 4 Session 2 check 4 walks each path step-by-step against root.
//
// Production generate-bundle.ts (packages/evidence) optionally emits
// utc_day + leaf_index extension fields beyond the spec; this V1
// type captures only the spec-canonical fields. Permissive JSON
// parsing tolerates the extension fields silently — they're
// available in the raw bytes if a future verifier needs them.
type MerkleProofEntry struct {
	EventID string            `json:"event_id"`
	Leaf    string            `json:"leaf"`
	Path    []MerkleProofStep `json:"path"`
	Root    string            `json:"root"`
}

// MerkleProofStep matches the @nuwyre/schema MerkleProofStep shape:
// position is the side the SIBLING sits on relative to the current
// node, so verifyProof knows which side to combine on.
type MerkleProofStep struct {
	Sibling  string `json:"sibling"`
	Position string `json:"position"` // "left" | "right"
}

// DailyRootsJSON mirrors spec §9. Each root entry corresponds to one
// UTC day in the bundle's range.
type DailyRootsJSON struct {
	SchemaVersion int             `json:"schema_version"`
	Roots         []DailyRootEntry `json:"roots"`
}

// DailyRootEntry is one day's root in daily_roots.json.
type DailyRootEntry struct {
	Date            string `json:"date"`
	Root            string `json:"root"`
	LeafCount       int    `json:"leaf_count"`
	PaddedLeafCount int    `json:"padded_leaf_count"`
}

// =============================================================================
// github_anchors/<date>.json (spec §12)
// =============================================================================

// GithubAnchorJSON mirrors spec §12.1. Phase 4 Session B Item 4
// added commit_sha_format; Item 5 reconciled mirror_status to
// canonical 4-state enum.
type GithubAnchorJSON struct {
	SchemaVersion          int     `json:"schema_version"`
	Date                   string  `json:"date"`
	Repo                   string  `json:"repo"`
	CommitShaFormat        string  `json:"commit_sha_format"`
	CommitSha              *string `json:"commit_sha"`
	SignedBySSHFingerprint string  `json:"signed_by_ssh_key_fingerprint,omitempty"`
	Path                   *string `json:"path"`
	AnchoredAt             *string `json:"anchored_at"`
	MirrorStatus           string  `json:"mirror_status"`
	Note                   string  `json:"note,omitempty"`
}

// =============================================================================
// scenario_index.json (spec §3 example-only)
// =============================================================================

// ScenarioIndexJSON mirrors the example-bundle scenario_index format.
// Customer-export bundles don't include this file.
type ScenarioIndexJSON struct {
	SchemaVersion int                  `json:"schema_version"`
	BindingDoc    string               `json:"binding_methodology_section"`
	Note          string               `json:"note"`
	Scenarios     []ScenarioIndexEntry `json:"scenarios"`
}

type ScenarioIndexEntry struct {
	ScenarioID          string                     `json:"scenario_id"`
	ScenarioVersion     string                     `json:"scenario_version"`
	Regime              string                     `json:"regime"`
	Title               string                     `json:"title"`
	SessionID           *string                    `json:"session_id"`
	EventIDs            []string                   `json:"event_ids"`
	ExpectedPrimaryFlag ScenarioExpectedPrimaryFlag `json:"expected_primary_flag"`
}

// ScenarioExpectedPrimaryFlag is the canned-evaluator's expected
// verdict for the scenario's primary event. The example bundle's
// canned evaluator produces a deterministic primary verdict from this
// pre-recorded shape; production bundles do not include
// scenario_index.json so this type is example-only.
type ScenarioExpectedPrimaryFlag struct {
	RuleID                       string   `json:"rule_id"`
	Verdict                      string   `json:"verdict"`
	Severity                     string   `json:"severity"`
	ReasoningMustReference       []string `json:"reasoning_must_reference,omitempty"`
	ReasoningShouldNotReference  []string `json:"reasoning_should_not_reference,omitempty"`
}

// =============================================================================
// audit_log_events.jsonl + audit_log_subtree.json (spec §16, v1.0.10+)
// Phase 6.2.C session 70 audit-log-export bundle type support.
// =============================================================================

// ManifestMerkleSubtrees is the spec §16.3 manifest field that carries
// the two subtree roots that compose into the dual-subtree daily_root
// for audit-log-export bundles. Per spec §16.3 v1.0.11 F3 MUST-language:
// daily_root = SHA-256(events_subtree_root_bytes ||
// audit_log_subtree_root_bytes) — events FIRST. Each root is a 64-char
// lowercase hex string; verifiers decode to 32 raw bytes per operand
// before concatenation (crypto-int H2 byte-encoding closure).
type ManifestMerkleSubtrees struct {
	// EventsRoot is the Merkle root of the primary event chain for
	// the day (computed identically to v1.0.7 single-tree semantics
	// per §8). MUST equal merkle_proofs.json:root. When events.jsonl
	// is empty, value is 64 zero hex chars per §16.3.1 empty-subtree
	// composition rule.
	EventsRoot string `json:"events_root"`
	// AuditLogRoot is the Merkle root of the audit log event chain
	// for the day (computed per §8 semantics over audit_log_events.
	// jsonl ordered by sequence_number ascending per §16.3.2).
	// MUST equal audit_log_subtree.json:subtree_root. When
	// audit_log_events.jsonl is empty, value is 64 zero hex chars.
	AuditLogRoot string `json:"audit_log_root"`
}

// AuditLogEventJSONL mirrors the spec §16.2 per-line shape (v1.0.10+).
// Audit log events form an independent chain per (organization_id,
// bundle_subtype) per §16.2.2 chain isolation rule. Phase 6.2.C Check
// 9 walks these in sequence_number ascending order, recomputing
// content_hash + event_hash from the parsed fields.
//
// Cross-package boundary: this mirrors packages/evidence/src/audit-
// log-export.ts:AuditLogEvent (TS reference impl); the Go field tags
// match the canonical JSON keys emitted by audit-log-export-emit.ts.
type AuditLogEventJSONL struct {
	SchemaVersion int                  `json:"schema_version"`
	EventID       string               `json:"event_id"`
	EventType     string               `json:"event_type"`
	Actor         AuditLogActor        `json:"actor"`
	Subject       AuditLogSubject      `json:"subject"`
	ContentHash   string               `json:"content_hash"`
	Forensic      AuditLogForensic     `json:"forensic"`
}

// AuditLogActor is the spec §16.2 actor sub-record. Closed vocabulary
// at v1.0.11 §16.2 (per F-SC-6 amendment): type ∈ {"user", "api_key",
// "system", "cron_job", "operator"}. id is the actor identifier (UUID
// for user/api_key, string slug for system/cron_job/operator).
type AuditLogActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// AuditLogSubject is the spec §16.2 subject sub-record. Closed
// vocabulary at v1.0.11 §16.2 (per F-SC-6): type ∈ {"customer",
// "policy_pack", "evidence_export", "audit_log_export", "sandbox_
// session", "api_key", "user", "integration", "system"}. organization_id
// is REQUIRED for customer-scoped audit log events (cross-tenant
// invariant per §16.5); nullable for operator-only audit log events
// where subject is not customer-bound.
type AuditLogSubject struct {
	Type           string  `json:"type"`
	ID             string  `json:"id"`
	OrganizationID *string `json:"organization_id"`
}

// AuditLogForensic is the spec §16.2 forensic sub-record. Mirror of
// EventForensic for primary events; per-field semantics differ
// (sequence_number is per-chain monotonic; prev_event_hash links the
// audit-log chain not the primary-event chain). sequence_number is
// int64 — spec §16.2 v1.0.12 F-SC-11 pins range [0, 2^63-1] for
// cross-language Go i64 + Rust u64 + JS Number safety.
type AuditLogForensic struct {
	TimestampISO        string `json:"timestamp_iso"`
	TimestampUnixNs     string `json:"timestamp_unix_ns"`
	SequenceNumber      int64  `json:"sequence_number"`
	PrevEventHash       string `json:"prev_event_hash"`
	EventHash           string `json:"event_hash"`
	IngestionSignature  string `json:"ingestion_signature"`
}

// AuditLogSubtreeJSON mirrors the spec §16.3 audit_log_subtree.json
// shape. Carries the subtree_root + per-leaf Merkle proof paths. The
// proof step shape ({position, sibling}) matches the v1.0.7 §8 walker
// per v1.0.11 F1 closure (reconciled to existing MerkleProofStep
// shape — same fields, same semantics, just a different subtree).
type AuditLogSubtreeJSON struct {
	SchemaVersion int                     `json:"schema_version"`
	SubtreeRoot   string                  `json:"subtree_root"`
	Proofs        []AuditLogSubtreeProof  `json:"proofs"`
}

// AuditLogSubtreeProof is one audit log event's proof of membership
// in the audit-log subtree. Phase 6.2.C Check 9 walks each path
// step-by-step against subtree_root per §8 verification algorithm.
type AuditLogSubtreeProof struct {
	EventID string            `json:"event_id"`
	Leaf    string            `json:"leaf"`
	Path    []MerkleProofStep `json:"path"`
	Root    string            `json:"root"`
}

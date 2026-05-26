package checks

// Spec-section reference constants. Centralized here so a future
// /docs/spec/bundle-format-v1.md amendment that renumbers sections
// (as the v1.0.1 amendment did when inserting §7 evaluations.jsonl)
// touches one Go file rather than every check's error-message call
// site.
//
// Convention: SpecRef<Topic> = "<§N.M>", matching the spec markdown
// heading. Major-only when the rule lives in the section's top-level
// text; major + sub when a specific subsection contains the rule.
//
// When updating, also update apps/cli/internal/bundle/load.go,
// load_dirs.go, types.go, and load_test.go which reference spec
// sections directly.

const (
	// §1 Overview
	SpecRefOverview = "§1"
	// §1 + §15.1 — bundle_format pin "nuwyre-bundle/v1"
	SpecRefBundleFormatPin = "§1"

	// §3 directory layout (which files are required, conditional,
	// example-only)
	SpecRefDirectoryLayout = "§3"

	// §4 + §4.1 — manifest.json field discipline (required vs
	// conditional, count invariants)
	SpecRefManifestSchema = "§4"
	SpecRefManifestFields = "§4.1"

	// §5 — signature.sig structure + Ed25519 algorithm + key
	// dispatch by bundle_type
	SpecRefSignature = "§5"

	// §6 events.jsonl per-line shape
	SpecRefEventsLine = "§6.1"
	// §6.2 hash chain semantics (single global per-org chain;
	// genesis sentinel)
	SpecRefHashChain = "§6.2"
	// §6.3 per-event ingestion_signature
	SpecRefEventSignature = "§6.3"
	// §6.4 audio_ref binding inside events.content
	SpecRefAudioRef = "§6.4"

	// §7 evaluations.jsonl (added in v1.0.1 amendment)
	SpecRefEvaluations = "§7"
	// §7.1 per-line shape
	SpecRefEvaluationsLine = "§7.1"
	// §7.2 field semantics + verdict/severity enums
	SpecRefEvaluationsFields = "§7.2"
	// §7.3 row_hash computation
	SpecRefRowHash = "§7.3"
	// §7.4 cross-references (event_id, content_hash, pack_body_hash)
	SpecRefEvaluationsCrossRef = "§7.4"

	// §8 merkle_proofs.json (was §7 pre-v1.0.1)
	SpecRefMerkleProofs = "§8"
	// §8.1 tree construction (leaves, padding, hashing)
	SpecRefMerkleTree = "§8.1"
	// §8.2 per-event proof verification
	SpecRefMerkleProof = "§8.2"

	// §9 daily_roots.json
	SpecRefDailyRoots = "§9"

	// §10 OpenTimestamps receipts
	SpecRefOTS = "§10"
	// §10.1 lifecycle (pending vs confirmed)
	SpecRefOTSLifecycle = "§10.1"
	// §10.2 verification path
	SpecRefOTSVerify = "§10.2"

	// §11 RFC 3161 receipts
	SpecRefRFC3161 = "§11"
	// §11.1 three TSAs attempted, two required (2-of-3)
	SpecRefRFC3161Threshold = "§11.1"
	// §11.2 embedded .chain.pem
	SpecRefRFC3161Chain = "§11.2"
	// §11.3 verification path
	SpecRefRFC3161Verify = "§11.3"

	// §12 GitHub anchor refs
	SpecRefGitHubAnchor = "§12"
	// §12.1 github_anchors/<UTC_DAY>.json schema
	SpecRefGitHubAnchorSchema = "§12.1"
	// §12.4 verification path
	SpecRefGitHubAnchorVerify = "§12.4"

	// §13 audio files
	SpecRefAudio = "§13"
	// §13.1 path discipline (audio/<sha256>.<ext>)
	SpecRefAudioPath = "§13.1"

	// §14 verification procedure (the seven checks + aggregate
	// semantics)
	SpecRefVerification = "§14"

	// §15 versioning + revision history
	SpecRefVersioning = "§15"

	// §18 dual-signature topology (v2.0.0-rc1) — Ed25519 + ML-DSA-65.
	// Phase 7.F.3 addition.
	SpecRefDualSignature = "§18"
	// §18.1 manifest.signing.signatures[] schema
	SpecRefDualSignatureManifest = "§18.1"
	// §18.2 signature.sig.signatures[] schema
	SpecRefDualSignatureSig = "§18.2"
	// §18.4 algorithm closed vocabulary + key/signature sizes
	SpecRefDualSignatureAlgo = "§18.4"
	// §18.6 cross-environment-slot coherence
	SpecRefDualSignatureSlot = "§18.6"
	// §18.7 verifier dispatch + step-ordering
	SpecRefDualSignatureVerify = "§18.7"
	// §18.8 positional-ordering invariant
	SpecRefDualSignatureOrdering = "§18.8"
	// §18.10 per-algorithm verdict surface (AlgorithmVerdicts)
	SpecRefDualSignatureVerdicts = "§18.10"
)

// Package bundle parses NuWyre evidence bundles per
// /docs/spec/bundle-format-v1.md.
//
// Phase 4 Session 1 lands type definitions + Load(); subsequent
// sessions wire the seven verification checks (Sessions 2-3) and the
// orchestrator that runs them (Session 4).
//
// **No shared code with packages/evidence (TS).** This Go
// implementation is independent per the build plan's
// "cross-language conformance via spec + fixtures" posture. The
// contract is /docs/spec/bundle-format-v1.md and the (Phase 4
// Session 4) /spec/fixtures/bundle-format-v1/ suite.
package bundle

// BundleFormatV1 is the spec-pinned bundle format string for v1
// bundles. Loader accepts both v1 + v2 (Phase 7.F.3 v2.0.0-rc1).
const BundleFormatV1 = "nuwyre-bundle/v1"

// BundleFormatV2 is the spec-pinned bundle format string for v2.0.0-rc1
// dual-signature bundles per spec §§18.1-18.10. Phase 7.F.3 addition.
const BundleFormatV2 = "nuwyre-bundle/v2"

// SchemaVersion is the spec-pinned manifest schema version for v1
// bundles. v2 bundles carry SchemaVersionV2.
const SchemaVersion = 1

// SchemaVersionV2 is the spec-pinned manifest schema version for v2
// bundles per spec §18.1. Phase 7.F.3 addition.
const SchemaVersionV2 = 2

// GenesisPrevHash is the spec §6.2 sentinel value for the first event
// in a per-org chain — sequence_number == 0 implies prev_event_hash
// MUST equal this 64-character zero string. Phase 4 Session 2 check 3
// (chain reconstruction) anchors at this sentinel.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

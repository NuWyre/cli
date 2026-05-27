// Package checks implements the seven verification checks documented
// in /docs/spec/bundle-format-v1.md §14. Phase 4 Sessions 2-3
// populate this package; Session 1 leaves it empty.
//
// The seven checks (per build plan v3.1.11 §Phase 4 Step 4):
//
//  1. Manifest signature (Ed25519 over manifest.json verifies
//     against pinned issuer key selected by bundle_type).
//  2. Artifact integrity (every file in manifest.artifacts hashes
//     to declared SHA-256, including audio).
//  3. Hash chain reconstruction (events.jsonl in order; recompute
//     content_hash + event_hash from prev_hash chain; confirm
//     signatures).
//  4. Merkle proof verification (each event's proof in
//     merkle_proofs.json verifies against the relevant per-org
//     daily root).
//  5. OpenTimestamps Bitcoin anchor (each daily_root's .ots
//     receipt verifies against the public Bitcoin chain; pending
//     state passes with --allow-pending-ots).
//  6. RFC 3161 timestamp anchor (each .tsr verifies against its
//     embedded .chain.pem; ≥2 of 3 distinct TSAs required per day).
//  7. GitHub anchor cross-check (commit_sha format-dispatched per
//     bundle's commit_sha_format; root.json contents at
//     daily-roots/<organization_id>/<date>/<bundle_type>/ match the
//     bundle's claims; SSH signature verifies against pinned issuer
//     SSH key).
package checks

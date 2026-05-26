package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/nuwyre/cli/internal/bundle"
)

// Check4Merkle verifies the spec §8 + §9 Merkle proof contract:
//
//   - Top-level root cross-check: manifest.daily_root == merkle_proofs.root.
//   - Per-day cross-check: every daily_roots.roots[] entry's root agrees
//     with manifest.daily_root (for V1 single-day bundles all entries
//     map to the same root; multi-day bundles will need per-date
//     proof grouping in a future revision).
//   - Per-proof verification: walk merkle path step-by-step per spec
//     §8.2 algorithm; resulting hash MUST equal proof.root AND
//     merkle_proofs.root.
//   - Per-proof leaf cross-check: proof.leaf MUST equal the matching
//     event's forensic.event_hash.
//   - Coverage symmetry: every event in events.jsonl has exactly one
//     proof (no unproven events; no orphan proofs; no duplicate
//     proofs for the same event).
//
// Check 4 is INDEPENDENT of check 3 — it does NOT assume check 3
// passed. If a bundle has tampered event_hash values that would also
// fail check 3, check 4 still catches the leaf-vs-event-hash mismatch
// directly. Each check contributes independently to the aggregate
// verdict.
//
// **Cross-implementation parity** with packages/schema/src/merkle.ts:
//
//   - hashPair(leftHex, rightHex) = hex(SHA-256(decode(left) || decode(right))).
//     Decoded raw bytes concatenated, then re-hex-encoded — matches TS
//     hashPair at packages/schema/src/merkle.ts:142-147.
//   - position semantics: "left" = sibling sits LEFT of current →
//     hash(sibling || current). "right" = sibling sits RIGHT →
//     hash(current || sibling). Mirrors TS verifyProof at
//     packages/schema/src/merkle.ts:122-135.
//   - Hex strings are 64-char lowercase per spec; the implementation
//     uses byte-equal comparison (case-sensitive). Tampered uppercase
//     hex would fail comparison.
//
// **TS-side oddity for V1.** TS verify-bundle.ts's check 4 does NOT
// validate proof contents — it only asserts that the set of proof
// leaves equals the set of event_hashes (verify-bundle.ts:539-560),
// trusting the writer's tree construction. The Go verifier here is
// stricter: every proof is walked and its computed root is verified.
// This is a deliberate divergence — the Go verifier is the
// load-bearing third-party tool; checking proof correctness is its
// job, not just leaf-set agreement.
type Check4Merkle struct{}

func (Check4Merkle) ID() int      { return 4 }
func (Check4Merkle) Name() string { return "Merkle proof" }
func (Check4Merkle) Slug() string { return "merkle-proof" }

func (c Check4Merkle) Run(b *bundle.Bundle, _ CheckOptions) CheckResult {
	const id = 4
	const checkName = "Merkle proof"
	const slug = "merkle-proof"

	var errs []error
	var warnings []error

	// 1. Top-level root cross-check.
	//
	// Phase 7.D session 88 — BACKLOG 1.48 A.1.3 closure: for audit-log-
	// export bundles (spec §16), merkle_proofs.root carries the
	// PRIMARY-EVENT subtree root (events_subtree_root) which composes
	// with audit_log_subtree_root to form manifest.daily_root via the
	// dual-subtree composition at spec §16.3 + §16.4. The expected
	// equality is therefore:
	//
	//   audit-log-export:  merkle_proofs.root === manifest.merkle_subtrees.events_root
	//   customer-export + sandbox-preview + example-demo:
	//                      merkle_proofs.root === manifest.daily_root
	//
	// The daily_root verification for audit-log-export bundles
	// (composed dual-subtree root cross-check) is Check 9's
	// responsibility (apps/cli/internal/checks/check9_audit_log_merkle.go).
	if b.MerkleProofs.Root == "" {
		errs = append(errs, Errorf(id, checkName, "merkle_proofs.json",
			"root is empty",
			SpecRefMerkleProofs, "merkle_proofs.root is the daily Merkle root for the bundle's window"))
		return Result(id, checkName, slug, errs, warnings)
	}
	expectedTopLevelRoot := b.Manifest.DailyRoot
	expectedTopLevelLabel := "manifest.daily_root"
	if b.Manifest.BundleType == "audit-log-export" {
		// Audit-log-export dispatch: cross-check against
		// manifest.merkle_subtrees.events_root per spec §16.3 dual-
		// subtree composition. The merkle_subtrees field is REQUIRED
		// for audit-log-export bundles per spec §16.3 + Go-side
		// ManifestMerkleSubtrees struct (pointer; nil when bundle_type
		// != audit-log-export).
		if b.Manifest.MerkleSubtrees == nil {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				"bundle_type=audit-log-export but manifest.merkle_subtrees is absent; spec §16.3 requires merkle_subtrees.{events_root, audit_log_root} for audit-log-export bundles",
				SpecRefMerkleProofs, "audit-log-export bundles MUST include manifest.merkle_subtrees per spec §16.3 dual-subtree composition"))
			return Result(id, checkName, slug, errs, warnings)
		}
		expectedTopLevelRoot = b.Manifest.MerkleSubtrees.EventsRoot
		expectedTopLevelLabel = "manifest.merkle_subtrees.events_root"
	}
	if expectedTopLevelRoot != b.MerkleProofs.Root {
		errs = append(errs, Errorf(id, checkName, "merkle_proofs.json",
			fmt.Sprintf("merkle_proofs.root=%s does not equal %s=%s",
				truncate(b.MerkleProofs.Root, 16), expectedTopLevelLabel, truncate(expectedTopLevelRoot, 16)),
			SpecRefMerkleProofs, fmt.Sprintf("merkle_proofs.root equals %s", expectedTopLevelLabel)))
		// Continue: per-proof verification is still informative even
		// when the top-level root cross-check fails.
	}

	// 2. Per-day cross-check (daily_roots vs manifest).
	if len(b.DailyRoots.Roots) == 0 {
		errs = append(errs, Errorf(id, checkName, "daily_roots.json",
			"no roots[] entries",
			SpecRefDailyRoots, "daily_roots.json carries at least one per-day root"))
	} else {
		// V1 single-day bundles: exactly one entry expected. Multi-day
		// bundles (future v1.x or v2) would need date-keyed proof
		// dispatch; flag with a warning if multi-day so the operator
		// knows the verifier doesn't yet partition proofs by date.
		//
		// **M3 from commit-5 reviewer pass**: in a real multi-day
		// bundle, each per-date proof would walk to a per-date root,
		// none of which would equal manifest.daily_root (which is per
		// spec §4 a single-day field). The current implementation
		// would emit the Warn AND many false-positive walked-root
		// failures. Multi-day support requires per-date proof grouping
		// + per-date root dispatch — defer to a future revision when
		// multi-day bundles actually exist. Until then the Warn is
		// honest about the limitation without preempting the noise
		// that would result from running on a multi-day bundle.
		if len(b.DailyRoots.Roots) > 1 {
			warnings = append(warnings, Warnf(id, checkName, "daily_roots.json",
				fmt.Sprintf("multi-day bundle (%d roots) — V1 verifier validates all proofs against manifest.daily_root without date partitioning; multi-day proof dispatch is a future revision",
					len(b.DailyRoots.Roots)),
				SpecRefDailyRoots, "single-day V1 bundles have exactly one daily_roots.roots[] entry"))
		}
		for i, dr := range b.DailyRoots.Roots {
			if dr.Root != b.Manifest.DailyRoot {
				errs = append(errs, Errorf(id, checkName, "daily_roots.json",
					fmt.Sprintf("roots[%d].date=%s root=%s does not equal manifest.daily_root=%s",
						i, dr.Date, truncate(dr.Root, 16), truncate(b.Manifest.DailyRoot, 16)),
					SpecRefDailyRoots, "every daily_roots.roots[].root agrees with manifest.daily_root for V1 single-day bundles"))
			}
		}
	}

	// 3. Build event_id → event_hash map for leaf cross-checks +
	// coverage symmetry.
	eventIdx := make(map[string]string, len(b.Events))
	for _, ev := range b.Events {
		if existing, dup := eventIdx[ev.EventID]; dup {
			// Defensive: duplicate event_id in events.jsonl (loader
			// doesn't currently reject this; spec §6 mandates UUID
			// uniqueness implicitly). Surface alongside Merkle errors
			// so the operator sees the integrity break holistically.
			errs = append(errs, Errorf(id, checkName, "events.jsonl",
				fmt.Sprintf("duplicate event_id %s (first event_hash=%s, second=%s)",
					ev.EventID, truncate(existing, 16), truncate(ev.Forensic.EventHash, 16)),
				SpecRefEventsLine, "event_id is unique within events.jsonl"))
			continue
		}
		eventIdx[ev.EventID] = ev.Forensic.EventHash
	}

	// 4. Per-proof verification (sorted by event_id for deterministic
	// error sequence).
	proofIdx := make(map[string]bool, len(b.MerkleProofs.Proofs))
	sortedProofs := make([]bundle.MerkleProofEntry, len(b.MerkleProofs.Proofs))
	copy(sortedProofs, b.MerkleProofs.Proofs)
	sort.SliceStable(sortedProofs, func(i, j int) bool {
		return sortedProofs[i].EventID < sortedProofs[j].EventID
	})

	for _, p := range sortedProofs {
		loc := fmt.Sprintf("merkle_proofs.json proof event_id=%s", shortID(p.EventID))

		// Duplicate-proof detection.
		if proofIdx[p.EventID] {
			errs = append(errs, Errorf(id, checkName, loc,
				"duplicate proof for the same event_id",
				SpecRefMerkleProofs, "each event has exactly one proof"))
			continue
		}
		proofIdx[p.EventID] = true

		// Orphan-proof detection: proof references an event_id not in
		// events.jsonl.
		eventHash, ok := eventIdx[p.EventID]
		if !ok {
			errs = append(errs, Errorf(id, checkName, loc,
				"proof references an event_id not present in events.jsonl (orphan proof)",
				SpecRefMerkleProofs, "every proof's event_id matches an event in events.jsonl"))
			continue
		}

		// Leaf cross-check: proof.leaf MUST equal the event's
		// forensic.event_hash.
		if p.Leaf != eventHash {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("proof.leaf=%s does not equal event.forensic.event_hash=%s",
					truncate(p.Leaf, 16), truncate(eventHash, 16)),
				SpecRefMerkleProof, "proof.leaf equals the event's event_hash (per spec §8.2 algorithm input)"))
			// Continue to walk the proof anyway — a wrong leaf might
			// still pass the path walk if the path was crafted for it,
			// but the leaf-vs-event mismatch is the load-bearing fail.
		}

		// Walk the proof path.
		computedRoot, err := walkMerkleProof(p)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("proof walk failed: %v", err),
				SpecRefMerkleProof, "proof path uses {position: left|right, sibling: 64-char lowercase hex}"))
			continue
		}

		// Per-proof: computed root MUST equal proof.root.
		if computedRoot != p.Root {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("walked root=%s does not equal proof.root=%s",
					truncate(computedRoot, 16), truncate(p.Root, 16)),
				SpecRefMerkleProof, "walking the proof path from leaf produces proof.root"))
			continue
		}

		// Per-proof: proof.root MUST equal merkle_proofs.root.
		if p.Root != b.MerkleProofs.Root {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("proof.root=%s does not equal merkle_proofs.root=%s",
					truncate(p.Root, 16), truncate(b.MerkleProofs.Root, 16)),
				SpecRefMerkleProof, "every proof's root equals the top-level merkle_proofs.root"))
		}
	}

	// 5. Coverage symmetry: every event in events.jsonl has a proof.
	// Iterate sorted event ids for deterministic error sequence.
	missing := make([]string, 0)
	for evID := range eventIdx {
		if !proofIdx[evID] {
			missing = append(missing, evID)
		}
	}
	sort.Strings(missing)
	for _, evID := range missing {
		errs = append(errs, Errorf(id, checkName,
			fmt.Sprintf("events.jsonl event_id=%s", shortID(evID)),
			"no Merkle proof present for this event (unproven event)",
			SpecRefMerkleProofs, "every event in events.jsonl has a corresponding proof in merkle_proofs.proofs[]"))
	}

	return Result(id, checkName, slug, errs, warnings)
}

// walkMerkleProof walks a single Merkle proof from its declared leaf
// up to the (computed) root, applying the spec §8.2 algorithm:
//
//	current = leaf
//	for step in path:
//	    if step.position == "left":
//	        current = sha256(decode(step.sibling) || decode(current))
//	    else:  # "right"
//	        current = sha256(decode(current) || decode(step.sibling))
//	    current = hex_lowercase(current)
//
// Returns the final 64-char lowercase hex string. Each step's sibling
// MUST be 64-char hex (validated implicitly by hex.DecodeString); the
// position field MUST be exactly "left" or "right".
//
// Mirrors packages/schema/src/merkle.ts:122-135 verifyProof — same
// algorithm, same hashPair semantics. Cross-implementation parity is
// the load-bearing claim that Go and TS produce identical roots from
// identical leaf+path inputs.
func walkMerkleProof(p bundle.MerkleProofEntry) (string, error) {
	if p.Leaf == "" {
		return "", fmt.Errorf("leaf is empty")
	}
	// M1 fix from commit-5 reviewer pass: validate leaf format on the
	// degenerate empty-path case too. Without this guard, a single-leaf
	// tree with a malformed leaf would return junk as "the root" and
	// rely solely on downstream cross-checks to catch the divergence.
	if !isLowercaseHex64(p.Leaf) {
		return "", fmt.Errorf("leaf is not 64-char lowercase hex")
	}
	current := p.Leaf
	for i, step := range p.Path {
		switch step.Position {
		case "left":
			next, err := hashMerklePair(step.Sibling, current)
			if err != nil {
				return "", fmt.Errorf("step %d: %w", i, err)
			}
			current = next
		case "right":
			next, err := hashMerklePair(current, step.Sibling)
			if err != nil {
				return "", fmt.Errorf("step %d: %w", i, err)
			}
			current = next
		default:
			return "", fmt.Errorf("step %d: invalid position %q (expected \"left\" or \"right\")", i, step.Position)
		}
	}
	return current, nil
}

// hashMerklePair computes SHA-256(decode(leftHex) || decode(rightHex))
// and returns the result as 64-char lowercase hex. Mirrors
// packages/schema/src/merkle.ts:142-147 hashPair.
//
// **H1 fix from commit-5 reviewer pass.** Both inputs MUST be 64-char
// LOWERCASE hex per spec §8 + TS reference regex
// `/^[0-9a-f]{64}$/.test(...)` at packages/schema/src/merkle.ts:128.
// Go's hex.DecodeString accepts both uppercase and lowercase silently,
// so without this guard, an uppercase sibling/leaf/root would compute
// the same decoded bytes and pass the walk — silently accepting a
// bundle that the TS verifier would reject as malformed. The guard
// closes the cross-implementation divergence.
func hashMerklePair(leftHex, rightHex string) (string, error) {
	if !isLowercaseHex64(leftHex) {
		return "", fmt.Errorf("left is not 64-char lowercase hex")
	}
	if !isLowercaseHex64(rightHex) {
		return "", fmt.Errorf("right is not 64-char lowercase hex")
	}
	left, err := hex.DecodeString(leftHex)
	if err != nil {
		return "", fmt.Errorf("left hex decode: %w", err)
	}
	right, err := hex.DecodeString(rightHex)
	if err != nil {
		return "", fmt.Errorf("right hex decode: %w", err)
	}
	combined := make([]byte, 0, len(left)+len(right))
	combined = append(combined, left...)
	combined = append(combined, right...)
	sum := sha256.Sum256(combined)
	return hex.EncodeToString(sum[:]), nil
}

// isLowercaseHex64 reports whether s is exactly 64 characters of
// lowercase hex digits (`0-9`, `a-f`). Mirrors the TS regex
// `/^[0-9a-f]{64}$/` used at packages/schema/src/merkle.ts:128 +
// :56 to validate sibling / leaf / root inputs.
//
// Independent of bundle.isLowercaseHex (load_dirs.go) — that helper
// validates audio path stems and lives in the bundle package. Same
// semantic; intentionally duplicated here to keep the checks package
// independent of bundle-package internals.
func isLowercaseHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}

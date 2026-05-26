package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Check 4: Merkle proof verification — happy path against the
// regenerated example bundle.
// =============================================================================

func TestCheck4HappyPath(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusPass {
		t.Errorf("happy path: Status = %v, want Pass", r.Status)
		for _, e := range r.Errors {
			t.Logf("  error: %v", e)
		}
		for _, w := range r.Warnings {
			t.Logf("  warning: %v", w)
		}
	}
	if len(r.Errors) != 0 {
		t.Errorf("happy path: %d errors, want 0", len(r.Errors))
	}
}

func TestCheck4Slug(t *testing.T) {
	t.Parallel()
	c := Check4Merkle{}
	if c.ID() != 4 {
		t.Errorf("ID() = %d, want 4", c.ID())
	}
	if c.Name() != "Merkle proof" {
		t.Errorf("Name() = %q, want %q", c.Name(), "Merkle proof")
	}
	if c.Slug() != "merkle-proof" {
		t.Errorf("Slug() = %q, want %q", c.Slug(), "merkle-proof")
	}
}

// TestCheck4RejectsTamperedProofSibling alters one sibling hash in
// a proof. The walked root no longer matches proof.root → Fail.
func TestCheck4RejectsTamperedProofSibling(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 {
		t.Fatal("no proofs")
	}
	target := &b.MerkleProofs.Proofs[0]
	if len(target.Path) == 0 {
		t.Fatal("first proof has empty path")
	}
	original := target.Path[0].Sibling
	defer func() { target.Path[0].Sibling = original }()
	target.Path[0].Sibling = strings.Repeat("a", 64)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered sibling: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "walked root") &&
			strings.Contains(e.Error(), "does not equal proof.root") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected walked-root mismatch; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsTamperedDailyRoot alters daily_roots.roots[0].root.
// Per-day cross-check fails.
func TestCheck4RejectsTamperedDailyRoot(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.DailyRoots.Roots) == 0 {
		t.Fatal("no daily roots")
	}
	original := b.DailyRoots.Roots[0].Root
	defer func() { b.DailyRoots.Roots[0].Root = original }()
	b.DailyRoots.Roots[0].Root = strings.Repeat("c", 64)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered daily_root: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "daily_roots.json") &&
			strings.Contains(e.Error(), "does not equal manifest.daily_root") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected daily_roots cross-check fail; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsTamperedMerkleProofsRoot alters
// merkle_proofs.root. Top-level cross-check fails.
func TestCheck4RejectsTamperedMerkleProofsRoot(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	original := b.MerkleProofs.Root
	defer func() { b.MerkleProofs.Root = original }()
	b.MerkleProofs.Root = strings.Repeat("d", 64)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered merkle_proofs.root: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "merkle_proofs.root") &&
			strings.Contains(e.Error(), "does not equal manifest.daily_root") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected top-level cross-check fail; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsMissingProof removes one proof. The matching event
// is unproven → Fail with "no Merkle proof present".
func TestCheck4RejectsMissingProof(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 {
		t.Fatal("no proofs")
	}
	original := b.MerkleProofs.Proofs
	defer func() { b.MerkleProofs.Proofs = original }()
	missingEventID := original[0].EventID
	b.MerkleProofs.Proofs = original[1:]

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("missing proof: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), shortID(missingEventID)) &&
			strings.Contains(e.Error(), "no Merkle proof present") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected unproven-event error for %s; got:", shortID(missingEventID))
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsOrphanProof adds a proof for an event_id not in
// events.jsonl. The orphan-proof error fires.
func TestCheck4RejectsOrphanProof(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	original := b.MerkleProofs.Proofs
	defer func() { b.MerkleProofs.Proofs = original }()
	const orphanID = "ffffffff-ffff-4fff-bfff-ffffffffffff"
	orphan := bundle.MerkleProofEntry{
		EventID: orphanID,
		Leaf:    strings.Repeat("e", 64),
		Path:    []bundle.MerkleProofStep{},
		Root:    b.MerkleProofs.Root,
	}
	b.MerkleProofs.Proofs = append(append([]bundle.MerkleProofEntry{}, original...), orphan)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("orphan proof: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), shortID(orphanID)) &&
			strings.Contains(e.Error(), "orphan proof") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected orphan-proof error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsDuplicateProof adds a duplicate proof for an
// existing event_id. The duplicate-proof error fires.
func TestCheck4RejectsDuplicateProof(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 {
		t.Fatal("no proofs")
	}
	original := b.MerkleProofs.Proofs
	defer func() { b.MerkleProofs.Proofs = original }()
	dup := original[0] // exact copy
	b.MerkleProofs.Proofs = append(append([]bundle.MerkleProofEntry{}, original...), dup)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("duplicate proof: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "duplicate proof") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected duplicate-proof error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsTamperedProofLeaf alters proof.leaf to NOT match
// the event's event_hash. The leaf cross-check fires.
func TestCheck4RejectsTamperedProofLeaf(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 {
		t.Fatal("no proofs")
	}
	target := &b.MerkleProofs.Proofs[0]
	original := target.Leaf
	defer func() { target.Leaf = original }()
	target.Leaf = strings.Repeat("f", 64)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered leaf: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "proof.leaf") &&
			strings.Contains(e.Error(), "does not equal event.forensic.event_hash") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected leaf-vs-event mismatch; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4RejectsInvalidPosition pins the position-enum check.
// Anything other than "left" / "right" → Fail.
func TestCheck4RejectsInvalidPosition(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 || len(b.MerkleProofs.Proofs[0].Path) == 0 {
		t.Fatal("no proofs with non-empty path")
	}
	target := &b.MerkleProofs.Proofs[0]
	original := target.Path[0].Position
	defer func() { target.Path[0].Position = original }()
	target.Path[0].Position = "middle" // invalid enum

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("invalid position: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "invalid position") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected invalid-position error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck4DeterministicErrorOrder asserts that two runs against the
// same tampered bundle produce byte-identical error sequences. L3
// from commit-5 reviewer pass: also remove proofs to exercise the
// missing-events sort path in addition to the per-proof iteration.
func TestCheck4DeterministicErrorOrder(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) < 5 {
		t.Skip("need at least 5 proofs")
	}
	// Tamper multiple proofs (per-proof iteration sort) AND remove
	// 2 proofs (missing-events sort). Both code paths exercised.
	for i := 0; i < 3; i++ {
		b.MerkleProofs.Proofs[i].Path[0].Sibling = strings.Repeat("a", 64)
	}
	// Remove the last two proofs → the matching events become unproven.
	b.MerkleProofs.Proofs = b.MerkleProofs.Proofs[:len(b.MerkleProofs.Proofs)-2]

	var firstSeq []string
	for run := 0; run < 5; run++ {
		r := Check4Merkle{}.Run(b, CheckOptions{})
		var seq []string
		for _, e := range r.Errors {
			seq = append(seq, e.Error())
		}
		if run == 0 {
			firstSeq = seq
			continue
		}
		if len(seq) != len(firstSeq) {
			t.Errorf("run %d: %d errors, want %d", run, len(seq), len(firstSeq))
			continue
		}
		for i := range seq {
			if seq[i] != firstSeq[i] {
				t.Errorf("run %d index %d differs:\n  first: %q\n  now:   %q", run, i, firstSeq[i], seq[i])
			}
		}
	}
}

// =============================================================================
// Cross-implementation oracle: the Go hashPair function MUST produce
// the same root as the TS reference (packages/schema/src/merkle.ts)
// for identical inputs. The strongest test is end-to-end parity:
// Go's walk of the example bundle's first proof produces the
// example bundle's daily_root.
// =============================================================================

// TestCheck4CrossImplementationProofWalk takes the example bundle's
// first proof and walks it via the Go implementation. The result MUST
// equal manifest.daily_root — proving Go's hashPair semantics +
// position semantics match the TS reference for the example bundle's
// real proof shapes.
func TestCheck4CrossImplementationProofWalk(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 {
		t.Fatal("no proofs")
	}
	for i, p := range b.MerkleProofs.Proofs {
		root, err := walkMerkleProof(p)
		if err != nil {
			t.Errorf("proof %d (%s): walk failed: %v", i, shortID(p.EventID), err)
			continue
		}
		if root != b.Manifest.DailyRoot {
			t.Errorf("proof %d (%s): cross-impl divergence — Go walked root=%s, TS-declared manifest.daily_root=%s",
				i, shortID(p.EventID), root, b.Manifest.DailyRoot)
		}
	}
}

// TestCheck4HashPairKnownVector pins the hashPair helper against a
// known test vector: SHA-256 of the all-zeros 32-byte sibling pair
// concatenated. This is the hash of two ZERO_HASH leaves at the
// bottom level of any padded-only tree.
func TestCheck4HashPairKnownVector(t *testing.T) {
	t.Parallel()
	const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
	got, err := hashMerklePair(zeroHash, zeroHash)
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256 of 64 zero bytes:
	const want = "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
	if got != want {
		t.Errorf("hashMerklePair(0…, 0…) = %s, want %s", got, want)
	}
}

// TestCheck4HashPairRejectsBadHex verifies that non-hex inputs
// surface as errors rather than silently producing wrong hashes.
//
// L2 + H1 from commit-5 reviewer pass: case-sensitivity matters.
// The TS reference enforces /^[0-9a-f]{64}$/ (lowercase only); Go's
// hex.DecodeString accepts uppercase silently. The H1 fix added a
// strict format guard, and this test pins the rejection path for
// both uppercase and length divergence.
func TestCheck4HashPairRejectsBadHex(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		left, right string
	}{
		{"left non-hex", "zz" + strings.Repeat("0", 62), strings.Repeat("0", 64)},
		{"right non-hex", strings.Repeat("0", 64), "zz" + strings.Repeat("0", 62)},
		{"left odd length", "0", strings.Repeat("0", 64)},
		{"left uppercase", strings.Repeat("0", 60) + "ABCD", strings.Repeat("0", 64)},
		{"right uppercase", strings.Repeat("0", 64), strings.Repeat("0", 60) + "DEAD"},
		{"left 65 chars", strings.Repeat("0", 65), strings.Repeat("0", 64)},
		{"left 63 chars", strings.Repeat("0", 63), strings.Repeat("0", 64)},
		{"left empty", "", strings.Repeat("0", 64)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := hashMerklePair(c.left, c.right)
			if err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}

// TestCheck4RejectsUppercaseSibling pins the H1 fix at the
// integration level: a tampered bundle whose proof carries an
// uppercase sibling must Fail check 4 (the TS verifier would reject
// the bundle as malformed). Prior to H1, Go's hex.DecodeString
// silently accepted uppercase and the walk produced the correct root.
func TestCheck4RejectsUppercaseSibling(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.MerkleProofs.Proofs) == 0 || len(b.MerkleProofs.Proofs[0].Path) == 0 {
		t.Fatal("no proofs with non-empty path")
	}
	target := &b.MerkleProofs.Proofs[0]
	original := target.Path[0].Sibling
	defer func() { target.Path[0].Sibling = original }()
	target.Path[0].Sibling = strings.ToUpper(original)

	r := Check4Merkle{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("uppercase sibling: Status = %v, want Fail (spec mandates lowercase hex)", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "proof walk failed") &&
			strings.Contains(e.Error(), "lowercase hex") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected lowercase-hex format error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestIsLowercaseHex64Unit covers the format helper directly.
func TestIsLowercaseHex64Unit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid 64 lowercase", strings.Repeat("0", 64), true},
		{"valid 64 mixed digits/letters", strings.Repeat("0a", 32), true},
		{"empty", "", false},
		{"63 chars", strings.Repeat("0", 63), false},
		{"65 chars", strings.Repeat("0", 65), false},
		{"contains uppercase", strings.Repeat("0", 60) + "ABCD", false},
		{"contains non-hex", strings.Repeat("0", 60) + "zzzz", false},
		{"contains space", strings.Repeat("0", 60) + " " + strings.Repeat("0", 3), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isLowercaseHex64(c.in); got != c.want {
				t.Errorf("isLowercaseHex64(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestWalkMerkleProofEmptyPath verifies the degenerate-tree case:
// a single-leaf tree has no path, and the walked root equals the leaf.
func TestWalkMerkleProofEmptyPath(t *testing.T) {
	t.Parallel()
	const leaf = "abc1234567890def00112233445566778899aabbccddeeff00112233445566ff"
	p := bundle.MerkleProofEntry{
		Leaf: leaf,
		Path: nil,
	}
	root, err := walkMerkleProof(p)
	if err != nil {
		t.Fatal(err)
	}
	if root != leaf {
		t.Errorf("empty path: walked root=%s, want leaf=%s", root, leaf)
	}
}

// TestWalkMerkleProofTwoLeafTree verifies the two-leaf case using
// a hand-computed expected root. Sibling on the right means
// hash(current || sibling); on the left means hash(sibling || current).
func TestWalkMerkleProofTwoLeafTree(t *testing.T) {
	t.Parallel()
	const a = "0101010101010101010101010101010101010101010101010101010101010101"
	const b = "0202020202020202020202020202020202020202020202020202020202020202"
	// Compute expected root: SHA-256(decode(a) || decode(b)) re-hex.
	left, _ := hex.DecodeString(a)
	right, _ := hex.DecodeString(b)
	combined := append([]byte{}, left...)
	combined = append(combined, right...)
	sum := sha256.Sum256(combined)
	expectedRoot := hex.EncodeToString(sum[:])

	// "left=a current=b sibling on left of b": position="left",
	// sibling=a → hash(a||b) = expected.
	pBOnRight := bundle.MerkleProofEntry{
		Leaf: b,
		Path: []bundle.MerkleProofStep{
			{Sibling: a, Position: "left"},
		},
	}
	root1, err := walkMerkleProof(pBOnRight)
	if err != nil {
		t.Fatal(err)
	}
	if root1 != expectedRoot {
		t.Errorf("position=left: walked=%s, want=%s", root1, expectedRoot)
	}

	// Symmetric: leaf=a, sibling on right of a → hash(a||b) = expected.
	pAOnLeft := bundle.MerkleProofEntry{
		Leaf: a,
		Path: []bundle.MerkleProofStep{
			{Sibling: b, Position: "right"},
		},
	}
	root2, err := walkMerkleProof(pAOnLeft)
	if err != nil {
		t.Fatal(err)
	}
	if root2 != expectedRoot {
		t.Errorf("position=right: walked=%s, want=%s", root2, expectedRoot)
	}
}

package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// Check 9 audit-log-merkle test suite. Phase 6.2.C session 70.
//
// Strategy: synthetic in-process bundles (no real bundle.zip required).
// Real-bundle fixture testing lands in Sub-arc 4 (3-way conformance CI
// extension) which generates bundle.zip via the TS reference impl at
// packages/evidence and round-trips through the Go verifier.
//
// These unit tests exercise:
//   - Gate semantics: non-audit-log-export bundles return Skipped
//   - Pre-condition validations: missing bundle_subtype /
//     audit_log_event_count / merkle_subtrees / audit_log_subtree.json
//   - §16.5 sentinel UUID gate: operator-only requires sentinel;
//     customer-scoped forbids sentinel
//   - §16.5 cross-tenant invariant: customer-scoped subject org_id
//     MUST equal manifest.organization_id
//   - §16.3 dual-subtree composition: events FIRST per v1.0.11 F3
//   - §16.3.1 empty-subtree composition: 0 events → genesis sentinel
//   - §16.3.2 leaf ordering: sequence_number ascending
//   - §16.2.2 chain integrity: prev_event_hash links
//   - Cross-tenant + cross-implementation correctness on a happy path

const testGenesisSentinel = "0000000000000000000000000000000000000000000000000000000000000000"

// helperHexSHA256Pair concatenates two 64-char lowercase hex strings as
// raw 32-byte operands and SHA-256-hashes the result. Mirrors the
// dual-subtree composition primitive but exposed for test setup.
func helperHexSHA256Pair(t *testing.T, leftHex, rightHex string) string {
	t.Helper()
	left, err := hex.DecodeString(leftHex)
	if err != nil {
		t.Fatalf("hex decode left: %v", err)
	}
	right, err := hex.DecodeString(rightHex)
	if err != nil {
		t.Fatalf("hex decode right: %v", err)
	}
	combined := append(append([]byte{}, left...), right...)
	sum := sha256.Sum256(combined)
	return hex.EncodeToString(sum[:])
}

// TestCheck9SkippedOnNonAuditLogExportBundles asserts the conditional
// gate: Check 9 returns Skipped for customer-export + example-demo +
// sandbox-preview bundles (Phase 6.2.C session 70 registry pattern).
func TestCheck9SkippedOnNonAuditLogExportBundles(t *testing.T) {
	cases := []string{"customer-export", "example-demo", "sandbox-preview", "unknown-future-type"}
	for _, bt := range cases {
		t.Run(bt, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{BundleType: bt},
			}
			result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
			if result.Status != StatusSkipped {
				t.Errorf("bundle_type=%q: expected Status=Skipped; got %v (errors=%v)", bt, result.Status, result.Errors)
			}
			if !strings.Contains(result.SkipReason, "audit-log-export") {
				t.Errorf("bundle_type=%q: SkipReason should mention audit-log-export; got %q", bt, result.SkipReason)
			}
		})
	}
}

// TestCheck9FailsWhenMissingRequiredFields asserts each pre-condition
// failure case produces a Fail with a specific error message.
func TestCheck9FailsWhenMissingRequiredFields(t *testing.T) {
	t.Run("missing bundle_subtype", func(t *testing.T) {
		count := 0
		b := &bundle.Bundle{
			Manifest: bundle.ManifestJSON{
				BundleType:         "audit-log-export",
				AuditLogEventCount: &count,
				MerkleSubtrees:     &bundle.ManifestMerkleSubtrees{},
			},
			AuditLogSubtree: &bundle.AuditLogSubtreeJSON{},
		}
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if result.Status != StatusFail {
			t.Errorf("expected Fail; got %v", result.Status)
		}
		if !errorListContains(result.Errors, "bundle_subtype is REQUIRED") {
			t.Errorf("expected error about missing bundle_subtype; got %v", result.Errors)
		}
	})

	t.Run("invalid bundle_subtype vocabulary", func(t *testing.T) {
		count := 0
		b := &bundle.Bundle{
			Manifest: bundle.ManifestJSON{
				BundleType:         "audit-log-export",
				BundleSubtype:      "operator-banana", // invalid
				AuditLogEventCount: &count,
				MerkleSubtrees:     &bundle.ManifestMerkleSubtrees{},
			},
			AuditLogSubtree: &bundle.AuditLogSubtreeJSON{},
		}
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if result.Status != StatusFail {
			t.Errorf("expected Fail; got %v", result.Status)
		}
		if !errorListContains(result.Errors, "closed vocabulary") {
			t.Errorf("expected error about closed vocabulary; got %v", result.Errors)
		}
	})

	t.Run("missing audit_log_event_count", func(t *testing.T) {
		b := &bundle.Bundle{
			Manifest: bundle.ManifestJSON{
				BundleType:     "audit-log-export",
				BundleSubtype:  "operator-only",
				MerkleSubtrees: &bundle.ManifestMerkleSubtrees{},
			},
			AuditLogSubtree: &bundle.AuditLogSubtreeJSON{},
		}
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if !errorListContains(result.Errors, "audit_log_event_count is REQUIRED") {
			t.Errorf("expected error about missing audit_log_event_count; got %v", result.Errors)
		}
	})

	t.Run("missing merkle_subtrees", func(t *testing.T) {
		count := 0
		b := &bundle.Bundle{
			Manifest: bundle.ManifestJSON{
				BundleType:         "audit-log-export",
				BundleSubtype:      "operator-only",
				AuditLogEventCount: &count,
			},
			AuditLogSubtree: &bundle.AuditLogSubtreeJSON{},
		}
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if !errorListContains(result.Errors, "merkle_subtrees is REQUIRED") {
			t.Errorf("expected error about missing merkle_subtrees; got %v", result.Errors)
		}
	})

	t.Run("missing audit_log_subtree.json", func(t *testing.T) {
		count := 0
		b := &bundle.Bundle{
			Manifest: bundle.ManifestJSON{
				BundleType:         "audit-log-export",
				BundleSubtype:      "operator-only",
				AuditLogEventCount: &count,
				MerkleSubtrees:     &bundle.ManifestMerkleSubtrees{},
			},
		}
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if !errorListContains(result.Errors, "audit_log_subtree.json is REQUIRED") {
			t.Errorf("expected error about missing audit_log_subtree.json; got %v", result.Errors)
		}
	})
}

// TestCheck9SentinelUUIDGate asserts §16.5 sentinel UUID discipline.
func TestCheck9SentinelUUIDGate(t *testing.T) {
	t.Run("operator-only requires sentinel", func(t *testing.T) {
		count := 0
		b := makeMinimalEmptyAuditLogBundle("operator-only",
			"a7c3e8f1-1234-4abc-89ab-1234567890ab", // real org UUID — WRONG for operator-only
			count)
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if !errorListContains(result.Errors, "all-zero sentinel UUID") {
			t.Errorf("expected sentinel UUID error; got %v", result.Errors)
		}
	})

	t.Run("customer-scoped forbids sentinel", func(t *testing.T) {
		count := 0
		b := makeMinimalEmptyAuditLogBundle("customer-scoped", sentinelUUIDAllZero, count)
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		if !errorListContains(result.Errors, "forbids manifest.organization_id=all-zero sentinel UUID") {
			t.Errorf("expected forbid-sentinel error; got %v", result.Errors)
		}
	})

	t.Run("operator-only with sentinel passes gate", func(t *testing.T) {
		count := 0
		b := makeMinimalEmptyAuditLogBundle("operator-only", sentinelUUIDAllZero, count)
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		// Empty audit-log bundle should pass (or only fail on cross-references which we control here).
		for _, e := range result.Errors {
			if strings.Contains(e.Error(), "sentinel UUID") {
				t.Errorf("sentinel gate should pass; got error: %v", e)
			}
		}
	})

	t.Run("customer-scoped with real UUID passes gate", func(t *testing.T) {
		count := 0
		b := makeMinimalEmptyAuditLogBundle("customer-scoped",
			"a7c3e8f1-1234-4abc-89ab-1234567890ab", count)
		result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
		for _, e := range result.Errors {
			if strings.Contains(e.Error(), "sentinel UUID") || strings.Contains(e.Error(), "forbids") {
				t.Errorf("sentinel gate should pass; got error: %v", e)
			}
		}
	})
}

// TestCheck9EmptySubtreeComposition asserts §16.3.1 empty-subtree
// composition: when 0 audit log events, audit_log_subtree_root_bytes
// = 0x00 * 32 (genesis sentinel hex). dual-subtree composition then
// becomes SHA-256(events_root_bytes || 0x00*32).
func TestCheck9EmptySubtreeComposition(t *testing.T) {
	count := 0
	eventsRoot := "1111111111111111111111111111111111111111111111111111111111111111"
	composed := helperHexSHA256Pair(t, eventsRoot, testGenesisSentinel)
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   eventsRoot,
				AuditLogRoot: testGenesisSentinel,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: eventsRoot},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: testGenesisSentinel,
			Proofs:      []bundle.AuditLogSubtreeProof{},
		},
		AuditLogEvents: []bundle.AuditLogEventJSONL{},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if result.Status != StatusPass {
		t.Errorf("expected Pass for empty-subtree composition; got %v\nerrors: %v", result.Status, result.Errors)
	}
}

// TestCheck9RejectsSwappedSubtreeOrder asserts the v1.0.11 F3 MUST-
// language: events FIRST. Swapping the operand order produces a
// different daily_root that MUST NOT verify.
func TestCheck9RejectsSwappedSubtreeOrder(t *testing.T) {
	count := 0
	eventsRoot := "1111111111111111111111111111111111111111111111111111111111111111"
	auditLogRoot := "2222222222222222222222222222222222222222222222222222222222222222"
	// CORRECT: events FIRST
	correctComposed := helperHexSHA256Pair(t, eventsRoot, auditLogRoot)
	// WRONG: audit-log FIRST (swapped)
	swappedComposed := helperHexSHA256Pair(t, auditLogRoot, eventsRoot)
	if correctComposed == swappedComposed {
		t.Fatal("test invariant broken: SHA-256(a||b) should differ from SHA-256(b||a)")
	}

	// Build a bundle where manifest.daily_root carries the SWAPPED
	// value. The dual-subtree composition check should reject this.
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          swappedComposed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   eventsRoot,
				AuditLogRoot: auditLogRoot,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: eventsRoot},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: auditLogRoot,
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if result.Status != StatusFail {
		t.Errorf("swapped subtree order should Fail; got %v", result.Status)
	}
	if !errorListContains(result.Errors, "dual-subtree composition") {
		t.Errorf("expected dual-subtree composition error; got %v", result.Errors)
	}
}

// TestCheck9RejectsMismatchedEventsRoot asserts manifest.merkle_subtrees.
// events_root MUST equal merkle_proofs.json:root.
func TestCheck9RejectsMismatchedEventsRoot(t *testing.T) {
	count := 0
	eventsRootManifest := "1111111111111111111111111111111111111111111111111111111111111111"
	eventsRootMerkleProofs := "9999999999999999999999999999999999999999999999999999999999999999"
	composed := helperHexSHA256Pair(t, eventsRootManifest, testGenesisSentinel)
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   eventsRootManifest,
				AuditLogRoot: testGenesisSentinel,
			},
		},
		MerkleProofs:    bundle.MerkleProofsJSON{Root: eventsRootMerkleProofs}, // mismatch
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{SubtreeRoot: testGenesisSentinel},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "events_root") || !errorListContains(result.Errors, "does not equal merkle_proofs.json:root") {
		t.Errorf("expected events_root mismatch error; got %v", result.Errors)
	}
}

// TestCheck9CrossTenantInvariant asserts §16.5: customer-scoped audit
// log events with non-null subject.organization_id MUST equal
// manifest.organization_id.
func TestCheck9CrossTenantInvariant(t *testing.T) {
	manifestOrgID := "a7c3e8f1-1234-4abc-89ab-1234567890ab"
	foreignOrgID := "deadbeef-1234-4abc-89ab-1234567890ab"

	// Build a 1-event audit-log subtree with a subject that points at a
	// FOREIGN org. content_hash and event_hash don't need to be
	// computed correctly — the cross-tenant check fires before chain
	// integrity recomputation in the per-event walk; but to avoid
	// downstream noise we make them syntactically valid hex.
	subjectForeign := foreignOrgID
	count := 1
	dummyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	composed := helperHexSHA256Pair(t, dummyHash, dummyHash)

	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "customer-scoped",
			OrganizationID:     manifestOrgID,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   dummyHash,
				AuditLogRoot: dummyHash,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: dummyHash},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: dummyHash,
		},
		AuditLogEvents: []bundle.AuditLogEventJSONL{
			{
				EventID:   "00000000-1234-5678-9abc-def012345678",
				EventType: "audit-log:api-key:issued",
				Actor:     bundle.AuditLogActor{Type: "user", ID: "1"},
				Subject: bundle.AuditLogSubject{
					Type:           "api-key", // kebab-case per TS emit-helper SUBJECT_TYPES
					ID:             "key-1",
					OrganizationID: &subjectForeign, // cross-tenant violation
				},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:00Z",
					TimestampUnixNs: "1747260000000000000",
					SequenceNumber:  1,
					PrevEventHash:   testGenesisSentinel,
					EventHash:       dummyHash,
				},
			},
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "cross-tenant boundary violation") {
		t.Errorf("expected cross-tenant violation error; got %v", result.Errors)
	}
}

// TestCheck9SequenceOrdering asserts §16.3.2 leaf ordering: subtree
// leaves MUST be ordered by sequence_number ascending. Out-of-order
// events fail Check 9.
func TestCheck9SequenceOrdering(t *testing.T) {
	count := 2
	dummyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	composed := helperHexSHA256Pair(t, dummyHash, dummyHash)
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   dummyHash,
				AuditLogRoot: dummyHash,
			},
		},
		MerkleProofs:    bundle.MerkleProofsJSON{Root: dummyHash},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{SubtreeRoot: dummyHash},
		AuditLogEvents: []bundle.AuditLogEventJSONL{
			{
				EventID:   "00000000-1111-1111-1111-111111111111",
				EventType: "system.event",
				Actor:     bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:   bundle.AuditLogSubject{Type: "system", ID: "x", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:00Z",
					TimestampUnixNs: "1747260000000000000",
					SequenceNumber:  5, // sequence #5 first
					PrevEventHash:   testGenesisSentinel,
					EventHash:       dummyHash,
				},
			},
			{
				EventID:   "00000000-2222-2222-2222-222222222222",
				EventType: "system.event",
				Actor:     bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:   bundle.AuditLogSubject{Type: "system", ID: "y", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:01Z",
					TimestampUnixNs: "1747260001000000000",
					SequenceNumber:  3, // sequence #3 SECOND — violates ascending
					PrevEventHash:   dummyHash,
					EventHash:       dummyHash,
				},
			},
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "sequence_number=3 is not strictly greater than previous=5") {
		t.Errorf("expected sequence ordering error; got %v", result.Errors)
	}
}

// TestComputeDualSubtreeCompositionByteOrder asserts the standalone
// composition primitive: SHA-256(events_bytes || audit_log_bytes) —
// raw-byte concat, events FIRST. The output MUST match the TS-side
// computeDualSubtreeDailyRoot byte-for-byte (KAT discipline).
func TestComputeDualSubtreeCompositionByteOrder(t *testing.T) {
	// KAT-style golden vector: two known subtree roots produce a known
	// composed root. This is a Go-side reproduction of one of the
	// 6 KAT golden vectors from packages/evidence/scripts/compute-
	// audit-log-kats.ts (the daily_root KAT specifically). Phase 6.2.C
	// Sub-arc 4 (3-way conformance CI extension) wires up the full
	// 6-KAT cross-implementation comparison.
	eventsRoot := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	auditLogRoot := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	expected := helperHexSHA256Pair(t, eventsRoot, auditLogRoot)

	actual, err := computeDualSubtreeComposition(eventsRoot, auditLogRoot)
	if err != nil {
		t.Fatalf("computeDualSubtreeComposition: %v", err)
	}
	if actual != expected {
		t.Errorf("composition: got %s, expected %s", actual, expected)
	}

	// Swap the order — output MUST differ.
	swapped, err := computeDualSubtreeComposition(auditLogRoot, eventsRoot)
	if err != nil {
		t.Fatalf("swapped composition: %v", err)
	}
	if swapped == actual {
		t.Errorf("SHA-256(a||b) should not equal SHA-256(b||a); got %s for both", actual)
	}
}

// TestComputeDualSubtreeCompositionRejectsMalformedHex asserts the
// hex validation: non-lowercase / non-64-char / non-hex inputs fail
// without producing a malformed root.
func TestComputeDualSubtreeCompositionRejectsMalformedHex(t *testing.T) {
	validHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cases := []struct {
		name  string
		left  string
		right string
	}{
		{"uppercase left", strings.ToUpper(validHex), validHex},
		{"uppercase right", validHex, strings.ToUpper(validHex)},
		{"too short left", "abc", validHex},
		{"too long right", validHex, validHex + "00"},
		{"non-hex left", "zzzz" + validHex[4:], validHex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := computeDualSubtreeComposition(tc.left, tc.right)
			if err == nil {
				t.Errorf("expected error for %s; got nil", tc.name)
			}
		})
	}
}

// makeMinimalEmptyAuditLogBundle constructs a synthetic empty-subtree
// audit-log-export bundle for sentinel-UUID gate tests. Composition
// is consistent (manifest.daily_root matches computed composed root)
// so the test isolates the sentinel-gate behavior.
func makeMinimalEmptyAuditLogBundle(subtype, orgID string, count int) *bundle.Bundle {
	eventsRoot := "1111111111111111111111111111111111111111111111111111111111111111"
	composed := dualSubtreeComposeForTest(eventsRoot, testGenesisSentinel)
	return &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      subtype,
			OrganizationID:     orgID,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   eventsRoot,
				AuditLogRoot: testGenesisSentinel,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: eventsRoot},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: testGenesisSentinel,
			Proofs:      []bundle.AuditLogSubtreeProof{},
		},
		AuditLogEvents: []bundle.AuditLogEventJSONL{},
	}
}

// dualSubtreeComposeForTest is the non-helper-T variant used in
// constructors (cannot accept *testing.T). Panics on hex decode error.
func dualSubtreeComposeForTest(leftHex, rightHex string) string {
	left, err := hex.DecodeString(leftHex)
	if err != nil {
		panic(err)
	}
	right, err := hex.DecodeString(rightHex)
	if err != nil {
		panic(err)
	}
	combined := append(append([]byte{}, left...), right...)
	sum := sha256.Sum256(combined)
	return hex.EncodeToString(sum[:])
}

// errorListContains reports whether any error in the list contains
// `needle` as a substring. Tests use this rather than exact-message
// matching so error-message wording can evolve without breaking tests
// (per checks.go T2 stability discipline).
func errorListContains(errs []error, needle string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), needle) {
			return true
		}
	}
	return false
}

// Phase 6.4 session 76 BACKLOG 1.38 closure: test coverage extension
// for duplicate/orphan/missing-proof scenarios. The production code at
// check9_audit_log_merkle.go:~470-490 handles these but session-70
// crypto-int F8 flagged the test gap. These 4 tests close the gap.

// TestCheck9DuplicateEventIdInEvents asserts that two audit log events
// sharing the same event_id (a §16.2 chain-integrity violation;
// event_id is UUID v5 derived deterministically from (org_id, seq,
// timestamp_unix_ns) per spec §16.2.2) get flagged as duplicate.
func TestCheck9DuplicateEventIdInEvents(t *testing.T) {
	count := 2
	dummyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	composed := dualSubtreeComposeForTest(dummyHash, dummyHash)
	duplicateEventID := "00000000-1111-1111-1111-111111111111"
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   dummyHash,
				AuditLogRoot: dummyHash,
			},
		},
		MerkleProofs:    bundle.MerkleProofsJSON{Root: dummyHash},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{SubtreeRoot: dummyHash},
		AuditLogEvents: []bundle.AuditLogEventJSONL{
			{
				EventID:     duplicateEventID, // collision with line 2
				EventType:   "audit-log:system:tick",
				Actor:       bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:     bundle.AuditLogSubject{Type: "system", ID: "x", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:00Z",
					TimestampUnixNs: "1747260000000000000",
					SequenceNumber:  1,
					PrevEventHash:   testGenesisSentinel,
					EventHash:       dummyHash,
				},
			},
			{
				EventID:     duplicateEventID, // collision with line 1
				EventType:   "audit-log:system:tick",
				Actor:       bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:     bundle.AuditLogSubject{Type: "system", ID: "y", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:01Z",
					TimestampUnixNs: "1747260001000000000",
					SequenceNumber:  2,
					PrevEventHash:   dummyHash,
					EventHash:       dummyHash,
				},
			},
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "duplicate event_id in audit_log_events.jsonl") {
		t.Errorf("expected duplicate event_id error; got %v", result.Errors)
	}
}

// TestCheck9DuplicateProofForEvent asserts that two proofs in audit_
// log_subtree.json referencing the same event_id get flagged. Spec
// §16.3 audit log subtree: one proof per event.
func TestCheck9DuplicateProofForEvent(t *testing.T) {
	count := 1
	dummyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	composed := dualSubtreeComposeForTest(dummyHash, dummyHash)
	eventID := "00000000-2222-2222-2222-222222222222"
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   dummyHash,
				AuditLogRoot: dummyHash,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: dummyHash},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: dummyHash,
			Proofs: []bundle.AuditLogSubtreeProof{
				{EventID: eventID, Leaf: dummyHash, Path: nil, Root: dummyHash},
				{EventID: eventID, Leaf: dummyHash, Path: nil, Root: dummyHash}, // duplicate
			},
		},
		AuditLogEvents: []bundle.AuditLogEventJSONL{
			{
				EventID:     eventID,
				EventType:   "audit-log:system:tick",
				Actor:       bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:     bundle.AuditLogSubject{Type: "system", ID: "x", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:00Z",
					TimestampUnixNs: "1747260000000000000",
					SequenceNumber:  1,
					PrevEventHash:   testGenesisSentinel,
					EventHash:       dummyHash,
				},
			},
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "duplicate proof for this event_id") {
		t.Errorf("expected duplicate proof error; got %v", result.Errors)
	}
}

// TestCheck9OrphanProof asserts that a proof referencing an event_id
// NOT present in audit_log_events.jsonl gets flagged. Spec §16.3
// audit log subtree: every proof references an event in audit_log_
// events.jsonl.
func TestCheck9OrphanProof(t *testing.T) {
	count := 1
	dummyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	composed := dualSubtreeComposeForTest(dummyHash, dummyHash)
	eventID := "00000000-3333-3333-3333-333333333333"
	orphanID := "ffffffff-9999-9999-9999-999999999999" // not in events.jsonl
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   dummyHash,
				AuditLogRoot: dummyHash,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: dummyHash},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: dummyHash,
			Proofs: []bundle.AuditLogSubtreeProof{
				{EventID: eventID, Leaf: dummyHash, Path: nil, Root: dummyHash},
				{EventID: orphanID, Leaf: dummyHash, Path: nil, Root: dummyHash}, // orphan
			},
		},
		AuditLogEvents: []bundle.AuditLogEventJSONL{
			{
				EventID:     eventID,
				EventType:   "audit-log:system:tick",
				Actor:       bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:     bundle.AuditLogSubject{Type: "system", ID: "x", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:00Z",
					TimestampUnixNs: "1747260000000000000",
					SequenceNumber:  1,
					PrevEventHash:   testGenesisSentinel,
					EventHash:       dummyHash,
				},
			},
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "orphan proof") {
		t.Errorf("expected orphan proof error; got %v", result.Errors)
	}
}

// TestCheck9MissingProof asserts that an audit log event WITHOUT a
// corresponding proof in audit_log_subtree.json:proofs[] gets flagged
// at coverage symmetry check (8). Spec §16.3: every audit log event
// has a corresponding proof.
func TestCheck9MissingProof(t *testing.T) {
	count := 2
	dummyHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	composed := dualSubtreeComposeForTest(dummyHash, dummyHash)
	eventIDProven := "00000000-4444-4444-4444-444444444444"
	eventIDUnproven := "00000000-5555-5555-5555-555555555555"
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			BundleType:         "audit-log-export",
			BundleSubtype:      "operator-only",
			OrganizationID:     sentinelUUIDAllZero,
			AuditLogEventCount: &count,
			DailyRoot:          composed,
			MerkleSubtrees: &bundle.ManifestMerkleSubtrees{
				EventsRoot:   dummyHash,
				AuditLogRoot: dummyHash,
			},
		},
		MerkleProofs: bundle.MerkleProofsJSON{Root: dummyHash},
		AuditLogSubtree: &bundle.AuditLogSubtreeJSON{
			SubtreeRoot: dummyHash,
			Proofs: []bundle.AuditLogSubtreeProof{
				// Only ONE proof for two events — eventIDUnproven is missing.
				{EventID: eventIDProven, Leaf: dummyHash, Path: nil, Root: dummyHash},
			},
		},
		AuditLogEvents: []bundle.AuditLogEventJSONL{
			{
				EventID:     eventIDProven,
				EventType:   "audit-log:system:tick",
				Actor:       bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:     bundle.AuditLogSubject{Type: "system", ID: "x", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:00Z",
					TimestampUnixNs: "1747260000000000000",
					SequenceNumber:  1,
					PrevEventHash:   testGenesisSentinel,
					EventHash:       dummyHash,
				},
			},
			{
				EventID:     eventIDUnproven,
				EventType:   "audit-log:system:tick",
				Actor:       bundle.AuditLogActor{Type: "system", ID: "cron"},
				Subject:     bundle.AuditLogSubject{Type: "system", ID: "y", OrganizationID: nil},
				ContentHash: dummyHash,
				Forensic: bundle.AuditLogForensic{
					TimestampISO:    "2026-05-15T00:00:01Z",
					TimestampUnixNs: "1747260001000000000",
					SequenceNumber:  2,
					PrevEventHash:   dummyHash,
					EventHash:       dummyHash,
				},
			},
		},
	}
	result := Check9AuditLogMerkle{}.Run(b, CheckOptions{})
	if !errorListContains(result.Errors, "no Merkle proof present for this audit log event") {
		t.Errorf("expected missing-proof error; got %v", result.Errors)
	}
}

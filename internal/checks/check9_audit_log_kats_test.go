package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// Phase 6.4 session 76 BACKLOG 1.36 closure: KAT golden vector
// consumer tests. The vectors are pinned at
// `testdata/audit_log_kats_v1.json`; this file asserts the Go-side
// primitives produce byte-identical hex outputs to the TS source-of-
// truth at `packages/evidence/tests/audit-log-export.test.ts:564-650`.
//
// **Standards-Track Posture** (tenants T1+T2+T5): a third-party
// implementer reading the spec alone MUST be able to produce a
// conformant implementation whose KAT outputs match these hex strings
// byte-for-byte. Drift between TS and Go would be a SHIPPED CONFORMANCE
// DEFECT — investigate the root cause; do NOT snapshot-update.

type katFile struct {
	SpecVersionPinnedAt string `json:"spec_version_pinned_at"`
	Vectors             struct {
		KAT2 struct {
			Description string `json:"description"`
			Input       struct {
				Actor     bundle.AuditLogActor   `json:"actor"`
				EventType string                 `json:"event_type"`
				Subject   bundle.AuditLogSubject `json:"subject"`
			} `json:"input"`
			ExpectedContentHashHex string `json:"expected_content_hash_hex"`
		} `json:"KAT-2"`
		KAT3 struct {
			Description string `json:"description"`
			Input       struct {
				PrevEventHash   string `json:"prev_event_hash"`
				ContentHash     string `json:"content_hash"`
				SequenceNumber  int64  `json:"sequence_number"`
				TimestampUnixNs string `json:"timestamp_unix_ns"`
			} `json:"input"`
			ExpectedEventHashHex string `json:"expected_event_hash_hex"`
		} `json:"KAT-3"`
		KAT5 struct {
			Description string `json:"description"`
			Input       struct {
				EventsSubtreeRoot   string `json:"events_subtree_root"`
				AuditLogSubtreeRoot string `json:"audit_log_subtree_root"`
			} `json:"input"`
			ExpectedDailyRootHex string `json:"expected_daily_root_hex"`
		} `json:"KAT-5"`
	} `json:"vectors"`
}

func loadAuditLogKATs(t *testing.T) katFile {
	t.Helper()
	path := filepath.Join("testdata", "audit_log_kats_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read KAT file: %v", err)
	}
	var k katFile
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("unmarshal KAT file: %v", err)
	}
	return k
}

// TestAuditLogKAT2ContentHash asserts computeAuditLogContentHashGo
// matches the TS golden vector for (admin actor, api-key:rotated,
// api-key subject with org). This is the cross-language byte-
// equivalence anchor for spec §16.2.1.
func TestAuditLogKAT2ContentHash(t *testing.T) {
	k := loadAuditLogKATs(t)
	in := k.Vectors.KAT2.Input
	got, err := computeAuditLogContentHashGo(in.Actor, in.EventType, in.Subject)
	if err != nil {
		t.Fatalf("computeAuditLogContentHashGo: %v", err)
	}
	if got != k.Vectors.KAT2.ExpectedContentHashHex {
		t.Errorf("KAT-2 content_hash mismatch:\n  got:  %s\n  want: %s\n(TS source-of-truth at packages/evidence/tests/audit-log-export.test.ts KAT-2; if this drifts, investigate the byte-encoding root cause — DO NOT snapshot-update)",
			got, k.Vectors.KAT2.ExpectedContentHashHex)
	}
}

// TestAuditLogKAT3EventHash asserts computeEventHashGo matches the TS
// golden vector for (genesis prev_event_hash, KAT-2 content_hash, seq=
// 0, KAT_TS_NS). This is the cross-language byte-equivalence anchor
// for spec §16.2.2 chain integrity.
//
// Note: computeEventHashGo is shared between primary events and audit-
// log events per spec §16.2.2 (audit-log event_hash uses the verbatim
// §6.2 4-field composition — F-SC-5 closure). The KAT therefore also
// validates §6.2 byte-encoding.
func TestAuditLogKAT3EventHash(t *testing.T) {
	k := loadAuditLogKATs(t)
	in := k.Vectors.KAT3.Input
	got, err := computeEventHashGo(in.ContentHash, in.PrevEventHash, in.SequenceNumber, in.TimestampUnixNs)
	if err != nil {
		t.Fatalf("computeEventHashGo: %v", err)
	}
	if got != k.Vectors.KAT3.ExpectedEventHashHex {
		t.Errorf("KAT-3 event_hash mismatch:\n  got:  %s\n  want: %s\n(TS source-of-truth at packages/evidence/tests/audit-log-export.test.ts KAT-3; if this drifts, investigate the §6.2 byte-encoding root cause — DO NOT snapshot-update)",
			got, k.Vectors.KAT3.ExpectedEventHashHex)
	}
}

// TestAuditLogKAT5DualSubtreeDailyRoot asserts
// computeDualSubtreeComposition matches the TS golden vector for
// events_root=ffff… + audit_log_root=KAT-4 subtree. This is the
// cross-language byte-equivalence anchor for spec §8.2 dual-subtree
// composition (events FIRST + raw-byte concatenation NOT hex).
func TestAuditLogKAT5DualSubtreeDailyRoot(t *testing.T) {
	k := loadAuditLogKATs(t)
	in := k.Vectors.KAT5.Input
	got, err := computeDualSubtreeComposition(in.EventsSubtreeRoot, in.AuditLogSubtreeRoot)
	if err != nil {
		t.Fatalf("computeDualSubtreeComposition: %v", err)
	}
	if got != k.Vectors.KAT5.ExpectedDailyRootHex {
		t.Errorf("KAT-5 daily_root mismatch:\n  got:  %s\n  want: %s\n(TS source-of-truth at packages/evidence/tests/audit-log-export.test.ts KAT-5; if this drifts, investigate the §8.2 byte-order or hex-vs-bytes root cause — DO NOT snapshot-update)",
			got, k.Vectors.KAT5.ExpectedDailyRootHex)
	}
}

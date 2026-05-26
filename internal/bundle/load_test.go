package bundle

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exampleBundlePath returns the absolute path to the regenerated
// example bundle that ships in the repo. Tests use this as the
// canonical fixture; subsequent Session 4 work will harvest tampered
// fixtures alongside it.
func exampleBundlePath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Layout-agnostic: walk up looking for the example bundle at either its
	// monorepo home (apps/marketing/public/examples/) or the standalone
	// verifier repo's testdata/. Skip (not fail) if absent, so the published
	// repo can choose whether to ship the bundle without breaking this smoke.
	candidates := []string{
		filepath.Join("apps", "marketing", "public", "examples", "nuwyre_export_cypress-derm_2026-04-22.zip"),
		filepath.Join("testdata", "example-bundle.zip"),
	}
	dir := wd
	for {
		for _, rel := range candidates {
			cand := filepath.Join(dir, rel)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("example bundle not found walking up from %s (looked for %v); ship it at testdata/example-bundle.zip to run the load smoke", wd, candidates)
		}
		dir = parent
	}
}

// TestLoadExampleBundle is the consolidated D4 smoke for Phase 4
// Session 1. It walks every Bundle field that should be populated by
// loading the regenerated example bundle in one pass and asserts all
// the build-plan-cited invariants together. Individual field-by-field
// tests (TestLoadParses*) cover the same surface piecemeal; this test
// catches whole-bundle integration issues that single-field tests
// would miss (e.g., a parser that silently nil-stomps a sibling
// field).
func TestLoadExampleBundle(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// --- Manifest + signature ---
	if bundle.Manifest.BundleFormat != BundleFormatV1 {
		t.Errorf("bundle_format = %q, want %q", bundle.Manifest.BundleFormat, BundleFormatV1)
	}
	if bundle.Manifest.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", bundle.Manifest.SchemaVersion, SchemaVersion)
	}
	if bundle.Manifest.BundleType != "example-demo" {
		t.Errorf("bundle_type = %q, want example-demo", bundle.Manifest.BundleType)
	}
	if bundle.Manifest.DailyRoot == "" {
		t.Error("manifest.daily_root empty")
	}
	if len(bundle.ManifestRaw) == 0 {
		t.Error("ManifestRaw empty")
	}
	if bundle.Signature.Algorithm != "ed25519" {
		t.Errorf("signature.algorithm = %q, want ed25519", bundle.Signature.Algorithm)
	}
	if bundle.Signature.SignatureB64 == "" {
		t.Error("signature.signature_b64 empty")
	}

	// --- Events + evaluations + raw bytes ---
	if len(bundle.Events) != 37 {
		t.Errorf("len(Events) = %d, want 37", len(bundle.Events))
	}
	if len(bundle.EventsRaw) == 0 {
		t.Error("EventsRaw empty (Session 2 check 3 needs raw bytes)")
	}
	if len(bundle.Evaluations) != 11 {
		t.Errorf("len(Evaluations) = %d, want 11", len(bundle.Evaluations))
	}
	if len(bundle.EvaluationsRaw) == 0 {
		t.Error("EvaluationsRaw empty")
	}

	// --- Merkle proofs + daily_roots ---
	if bundle.MerkleProofs.Root == "" {
		t.Error("merkle_proofs.root empty")
	}
	if len(bundle.MerkleProofs.Proofs) != 37 {
		t.Errorf("len(merkle_proofs.proofs) = %d, want 37", len(bundle.MerkleProofs.Proofs))
	}
	if bundle.MerkleProofs.Root != bundle.Manifest.DailyRoot {
		t.Errorf("merkle_proofs.root (%s) != manifest.daily_root (%s)",
			bundle.MerkleProofs.Root, bundle.Manifest.DailyRoot)
	}
	if len(bundle.DailyRoots.Roots) == 0 {
		t.Error("daily_roots.roots empty")
	}

	// --- Anchors ---
	if len(bundle.OTSReceipts) != 1 {
		t.Errorf("len(OTSReceipts) = %d, want 1", len(bundle.OTSReceipts))
	}
	if len(bundle.RFC3161Receipts) != 1 {
		t.Errorf("len(RFC3161Receipts) = %d (days), want 1", len(bundle.RFC3161Receipts))
	}
	if dayMap, ok := bundle.RFC3161Receipts["2026-04-22"]; !ok || len(dayMap) != 3 {
		t.Errorf("RFC3161Receipts[2026-04-22] missing or wrong TSA count: %v", dayMap)
	}
	if len(bundle.GithubAnchors) != 1 {
		t.Errorf("len(GithubAnchors) = %d, want 1", len(bundle.GithubAnchors))
	}

	// --- Audio + scenario index ---
	if len(bundle.AudioFiles) != 1 {
		t.Errorf("len(AudioFiles) = %d, want 1", len(bundle.AudioFiles))
	}
	if bundle.ScenarioIndex == nil {
		t.Error("ScenarioIndex nil (example-demo bundles ship scenario_index.json)")
	} else if len(bundle.ScenarioIndex.Scenarios) == 0 {
		t.Error("scenario_index.scenarios empty")
	}

	// --- Required artifacts ---
	if len(bundle.CoverPDF) == 0 {
		t.Error("CoverPDF empty (spec §3 required)")
	}
	if bundle.VerifyMD == "" {
		t.Error("VerifyMD empty (spec §3 required)")
	}

	// --- Path round-trip ---
	if bundle.Path == "" {
		t.Error("bundle.Path not preserved")
	}
}

func TestLoadOpensExampleBundle(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Path == "" {
		t.Error("bundle.Path empty")
	}
}

func TestLoadParsesManifest(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Spec §1 + §4.1 — bundle_format MUST equal "nuwyre-bundle/v1"
	if bundle.Manifest.BundleFormat != BundleFormatV1 {
		t.Errorf("manifest.bundle_format = %q, want %q", bundle.Manifest.BundleFormat, BundleFormatV1)
	}
	if bundle.Manifest.SchemaVersion != SchemaVersion {
		t.Errorf("manifest.schema_version = %d, want %d", bundle.Manifest.SchemaVersion, SchemaVersion)
	}

	// example-demo bundle — the regeneration produced a Cypress
	// Dermatology demo bundle.
	if bundle.Manifest.BundleType != "example-demo" {
		t.Errorf("manifest.bundle_type = %q, want example-demo", bundle.Manifest.BundleType)
	}
	if bundle.Manifest.OrganizationID == "" {
		t.Error("manifest.organization_id empty")
	}
	if bundle.Manifest.AgentID == "" {
		t.Error("manifest.agent_id empty")
	}

	// Counts (per regeneration verdict: 37 events, 11 evaluations).
	if bundle.Manifest.EventCount != 37 {
		t.Errorf("manifest.event_count = %d, want 37", bundle.Manifest.EventCount)
	}
	if bundle.Manifest.EvaluationCount != 11 {
		t.Errorf("manifest.evaluation_count = %d, want 11", bundle.Manifest.EvaluationCount)
	}

	// Phase 4 prereq Session B Item 5 reconciliation: github_status
	// is canonical 4-state ("anchor-pending" for V1 example).
	if bundle.Manifest.AnchorStatus.GithubStatus != "anchor-pending" {
		t.Errorf("anchor_status.github_status = %q, want anchor-pending (Phase 4 prereq Session B)",
			bundle.Manifest.AnchorStatus.GithubStatus)
	}

	// rfc3161 array: 3 TSAs verified per regeneration verdict.
	if len(bundle.Manifest.Anchors.RFC3161) != 3 {
		t.Errorf("anchors.rfc3161 length = %d, want 3 (freetsa+sectigo+digicert)",
			len(bundle.Manifest.Anchors.RFC3161))
	}

	// signing — Ed25519, dev key fingerprint matches issuer-dev-v1.
	if bundle.Manifest.Signing.Algorithm != "ed25519" {
		t.Errorf("signing.algorithm = %q, want ed25519", bundle.Manifest.Signing.Algorithm)
	}
	if bundle.Manifest.Signing.KeyFingerprintB64 == "" {
		t.Error("signing.key_fingerprint_spki_b64 empty")
	}

	// Raw bytes preserved for Phase 4 check 1 (signature verifies
	// over canonicalized manifest bytes).
	if len(bundle.ManifestRaw) == 0 {
		t.Error("ManifestRaw empty (verifier needs raw bytes)")
	}
}

func TestLoadParsesSignature(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if bundle.Signature.SchemaVersion != 1 {
		t.Errorf("signature.schema_version = %d, want 1", bundle.Signature.SchemaVersion)
	}
	if bundle.Signature.Algorithm != "ed25519" {
		t.Errorf("signature.algorithm = %q, want ed25519", bundle.Signature.Algorithm)
	}
	if bundle.Signature.SignedArtifact != "manifest.json" {
		t.Errorf("signature.signed_artifact = %q, want manifest.json", bundle.Signature.SignedArtifact)
	}
	if bundle.Signature.SignatureB64 == "" {
		t.Error("signature.signature_b64 empty")
	}

	// Cross-check: signature.key_fingerprint_spki_b64 MUST match
	// manifest.signing.key_fingerprint_spki_b64. (Spec §5: the
	// signature wrapper carries the same key identity as manifest's
	// signing block; verifiers MAY treat divergence as a verification
	// failure — Phase 4 Session 2 check 1 enforces.)
	if bundle.Signature.KeyFingerprintB64 != bundle.Manifest.Signing.KeyFingerprintB64 {
		t.Errorf("signature key fingerprint (%q) doesn't match manifest signing fingerprint (%q)",
			bundle.Signature.KeyFingerprintB64, bundle.Manifest.Signing.KeyFingerprintB64)
	}
}

func TestLoadRejectsMalformedZip(t *testing.T) {
	t.Parallel()
	_, err := Load("nonexistent-bundle-path.zip")
	if err == nil {
		t.Error("Load succeeded on nonexistent path; expected error")
	}
}

// TestReadZipFileRejectsZipBomb pins AUDIT-1 Sub-arc 4 (C2/S-C5):
// an entry whose decompressed size would exceed MaxEntryUncompressedBytes
// must be rejected. Builds an in-memory zip with > 64 MiB of all-zero
// payload (deflate-compresses to a tiny header), then asserts readZipFile
// refuses with a "zip-bomb defense" error before allocating the GB-scale
// expansion. Defends both the native CLI process and the WASM /verify
// browser tab from a customer-facing low-friction DoS surface.
func TestReadZipFileRejectsZipBomb(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("bomb.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Write more than the per-entry cap; all-zeros compresses to ~tiny.
	payload := make([]byte, MaxEntryUncompressedBytes+1024)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("expected 1 file, got %d", len(zr.File))
	}
	_, err = readZipFile(zr.File[0])
	if err == nil {
		t.Fatal("readZipFile accepted zip-bomb entry; expected rejection")
	}
	if !strings.Contains(err.Error(), "zip-bomb defense") {
		t.Errorf("expected 'zip-bomb defense' in error, got: %v", err)
	}
}

func TestLoadParsesEventsJSONL(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 37 events per regeneration verdict.
	if len(bundle.Events) != 37 {
		t.Errorf("len(Events) = %d, want 37", len(bundle.Events))
	}
	if len(bundle.EventsRaw) == 0 {
		t.Error("EventsRaw empty (verifier needs raw bytes for spec §6 canonicalization re-check)")
	}
	// First event sanity: schema_version=1, has identity + content
	// + forensic.
	if len(bundle.Events) > 0 {
		ev := bundle.Events[0]
		if ev.SchemaVersion != 1 {
			t.Errorf("Events[0].schema_version = %d, want 1", ev.SchemaVersion)
		}
		if ev.EventID == "" {
			t.Error("Events[0].event_id empty")
		}
		if ev.Identity.OrganizationID == "" {
			t.Error("Events[0].identity.organization_id empty")
		}
		if ev.Forensic.EventHash == "" {
			t.Error("Events[0].forensic.event_hash empty")
		}
		// Genesis sentinel for first event in chain.
		if ev.Forensic.SequenceNumber == 0 && ev.Forensic.PrevEventHash != GenesisPrevHash {
			t.Errorf("first event prev_event_hash = %q, want GenesisPrevHash (spec §6.2 sentinel)",
				ev.Forensic.PrevEventHash)
		}
	}
}

func TestLoadParsesEvaluationsJSONL(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 11 evaluations per regeneration verdict.
	if len(bundle.Evaluations) != 11 {
		t.Errorf("len(Evaluations) = %d, want 11", len(bundle.Evaluations))
	}
	flagged, clean := 0, 0
	for _, e := range bundle.Evaluations {
		switch e.Verdict {
		case "flagged":
			flagged++
		case "clean":
			clean++
		}
		if e.RowHash == "" {
			t.Errorf("evaluation %s: row_hash empty", e.EventID)
		}
	}
	if flagged != 7 {
		t.Errorf("flagged count = %d, want 7", flagged)
	}
	if clean != 4 {
		t.Errorf("clean count = %d, want 4", clean)
	}
}

func TestLoadParsesMerkleProofs(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Top-level root must be present (spec §8).
	if bundle.MerkleProofs.Root == "" {
		t.Error("merkle_proofs.root empty (spec §8 requires top-level root)")
	}
	// One proof per event; 37 events → 37 proofs.
	if len(bundle.MerkleProofs.Proofs) != 37 {
		t.Errorf("len(Proofs) = %d, want 37", len(bundle.MerkleProofs.Proofs))
	}
	// Per spec §8.2: every proof's root MUST equal the top-level
	// root AND manifest.daily_root AND daily_roots.json:roots[<date>].root.
	// Phase 4 Session 2 check 4 enforces; here we just sanity-check
	// the first proof's per-entry root matches the top-level.
	if len(bundle.MerkleProofs.Proofs) > 0 {
		p := bundle.MerkleProofs.Proofs[0]
		if p.Root != bundle.MerkleProofs.Root {
			t.Errorf("proof[0].root (%s) != merkle_proofs.root (%s)",
				p.Root, bundle.MerkleProofs.Root)
		}
		if p.Leaf == "" {
			t.Error("proof[0].leaf empty")
		}
		if len(p.Path) == 0 {
			t.Error("proof[0].path empty (every event in a non-trivial tree has a path)")
		}
		// Path step shapes.
		for _, step := range p.Path {
			if step.Position != "left" && step.Position != "right" {
				t.Errorf("proof[0].path step has invalid position: %q", step.Position)
			}
			if step.Sibling == "" {
				t.Error("proof[0].path step has empty sibling hash")
			}
		}
	}
	// Cross-check: merkle root MUST equal manifest.daily_root.
	if bundle.MerkleProofs.Root != bundle.Manifest.DailyRoot {
		t.Errorf("merkle_proofs.root (%s) != manifest.daily_root (%s)",
			bundle.MerkleProofs.Root, bundle.Manifest.DailyRoot)
	}
}

func TestLoadParsesDailyRoots(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(bundle.DailyRoots.Roots) == 0 {
		t.Error("daily_roots.roots empty")
	}
	for _, dr := range bundle.DailyRoots.Roots {
		if dr.Date == "" {
			t.Error("daily_root entry has empty date")
		}
		if dr.Root == "" {
			t.Error("daily_root entry has empty root")
		}
		if dr.LeafCount <= 0 {
			t.Errorf("daily_root entry has non-positive leaf_count: %d", dr.LeafCount)
		}
		if dr.PaddedLeafCount < dr.LeafCount {
			t.Errorf("padded_leaf_count (%d) < leaf_count (%d) — pad must >= raw",
				dr.PaddedLeafCount, dr.LeafCount)
		}
	}
}

func TestLoadParsesCoverPDFAndVerifyMD(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// cover.pdf — required per spec §3.
	if len(bundle.CoverPDF) == 0 {
		t.Error("CoverPDF empty (spec §3 lists cover.pdf as required)")
	}
	// verify.md — required per spec §3.
	if bundle.VerifyMD == "" {
		t.Error("VerifyMD empty (spec §3 lists verify.md as required)")
	}
	// PDF magic-number sanity.
	if len(bundle.CoverPDF) >= 4 && string(bundle.CoverPDF[:4]) != "%PDF" {
		t.Errorf("cover.pdf doesn't start with %%PDF magic; got %q", bundle.CoverPDF[:4])
	}
}

func TestLoadParsesScenarioIndex(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Example bundle MUST have scenario_index.json (spec §3
	// "example-only" — present iff bundle_type=example-demo).
	if bundle.ScenarioIndex == nil {
		t.Fatal("ScenarioIndex nil (example-demo bundle should have scenario_index.json)")
	}
	if len(bundle.ScenarioIndex.Scenarios) == 0 {
		t.Error("scenario_index.scenarios empty")
	}
}

// TestLoadCrossChecksManifestCounts asserts the spec §4.1 invariant
// that manifest's event_count + evaluation_count + flagged_count +
// clean_count match the actual files. Tampering that desyncs these
// counts is a Phase 4 Session 2 verification concern, but the data
// is loaded NOW so the loader-layer test catches struct-field drift
// (e.g., a typo'd JSON tag dropping flagged evaluations to clean).
func TestLoadCrossChecksManifestCounts(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Manifest.EventCount != len(bundle.Events) {
		t.Errorf("manifest.event_count (%d) != len(Events) (%d) — spec §4.1 invariant",
			bundle.Manifest.EventCount, len(bundle.Events))
	}
	if bundle.Manifest.EvaluationCount != len(bundle.Evaluations) {
		t.Errorf("manifest.evaluation_count (%d) != len(Evaluations) (%d)",
			bundle.Manifest.EvaluationCount, len(bundle.Evaluations))
	}
	flagged, clean := 0, 0
	for _, e := range bundle.Evaluations {
		switch e.Verdict {
		case "flagged":
			flagged++
		case "clean":
			clean++
		}
	}
	if bundle.Manifest.FlaggedCount != flagged {
		t.Errorf("manifest.flagged_count (%d) != observed flagged (%d)",
			bundle.Manifest.FlaggedCount, flagged)
	}
	if bundle.Manifest.CleanCount != clean {
		t.Errorf("manifest.clean_count (%d) != observed clean (%d)",
			bundle.Manifest.CleanCount, clean)
	}
}

// =============================================================================
// parseJSONL direct unit tests — H3/M6 coverage. These exercise the
// JSONL parser's contract without zip overhead.
// =============================================================================

type stubJSONLRow struct {
	A int    `json:"a"`
	B string `json:"b"`
}

func TestParseJSONLEmptyInput(t *testing.T) {
	t.Parallel()
	out, err := parseJSONL[stubJSONLRow](nil, "test")
	if err != nil {
		t.Errorf("empty input: unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty input: len(out) = %d, want 0", len(out))
	}
	// Single LF only — degenerate empty file. Loader treats as empty.
	out, err = parseJSONL[stubJSONLRow]([]byte("\n"), "test")
	if err != nil {
		t.Errorf("single LF: unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("single LF: len(out) = %d, want 0", len(out))
	}
}

func TestParseJSONLSingleRecord(t *testing.T) {
	t.Parallel()
	// With trailing LF (spec-canonical).
	out, err := parseJSONL[stubJSONLRow]([]byte(`{"a":1,"b":"x"}`+"\n"), "test")
	if err != nil {
		t.Fatalf("single record: %v", err)
	}
	if len(out) != 1 || out[0].A != 1 || out[0].B != "x" {
		t.Errorf("single record: got %+v, want [{1 x}]", out)
	}
	// Without trailing LF — non-canonical but the parser tolerates
	// (no spec ambiguity, and loader-layer strictness on this is too
	// strict for forensic tooling).
	out, err = parseJSONL[stubJSONLRow]([]byte(`{"a":1,"b":"x"}`), "test")
	if err != nil {
		t.Fatalf("single record no trailing LF: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("single record no trailing LF: len(out) = %d, want 1", len(out))
	}
}

func TestParseJSONLMultipleRecords(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"a":1,"b":"x"}` + "\n" + `{"a":2,"b":"y"}` + "\n" + `{"a":3,"b":"z"}` + "\n")
	out, err := parseJSONL[stubJSONLRow](raw, "test")
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("multi: len = %d, want 3", len(out))
	}
	if out[2].A != 3 || out[2].B != "z" {
		t.Errorf("multi[2]: %+v, want {3 z}", out[2])
	}
}

func TestParseJSONLCRLFTolerance(t *testing.T) {
	t.Parallel()
	// CRLF throughout (Windows-edited).
	raw := []byte(`{"a":1,"b":"x"}` + "\r\n" + `{"a":2,"b":"y"}` + "\r\n")
	out, err := parseJSONL[stubJSONLRow](raw, "test")
	if err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("CRLF: len = %d, want 2", len(out))
	}
	// Mixed LF and CRLF.
	raw = []byte(`{"a":1,"b":"x"}` + "\n" + `{"a":2,"b":"y"}` + "\r\n")
	out, err = parseJSONL[stubJSONLRow](raw, "test")
	if err != nil {
		t.Fatalf("mixed CRLF: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("mixed CRLF: len = %d, want 2", len(out))
	}
}

func TestParseJSONLRejectsLeadingBlankLine(t *testing.T) {
	t.Parallel()
	raw := []byte("\n" + `{"a":1,"b":"x"}` + "\n")
	_, err := parseJSONL[stubJSONLRow](raw, "events.jsonl")
	if err == nil {
		t.Fatal("leading blank: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("leading blank: error doesn't mention line 1: %v", err)
	}
	if !strings.Contains(err.Error(), "blank line not permitted") {
		t.Errorf("leading blank: error doesn't say 'blank line not permitted': %v", err)
	}
}

func TestParseJSONLRejectsInteriorBlankLine(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"a":1,"b":"x"}` + "\n\n" + `{"a":2,"b":"y"}` + "\n")
	_, err := parseJSONL[stubJSONLRow](raw, "events.jsonl")
	if err == nil {
		t.Fatal("interior blank: expected error, got nil")
	}
	// Physical line 2 is the blank one; user's editor would show
	// it that way.
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("interior blank: error doesn't mention line 2: %v", err)
	}
}

func TestParseJSONLRejectsExtraTrailingBlankLine(t *testing.T) {
	t.Parallel()
	// Two trailing LFs — one is spec-canonical, second is the
	// "extra" the parser must reject.
	raw := []byte(`{"a":1,"b":"x"}` + "\n\n")
	_, err := parseJSONL[stubJSONLRow](raw, "events.jsonl")
	if err == nil {
		t.Fatal("extra trailing blank: expected error, got nil")
	}
}

func TestParseJSONLMalformedLineReportsLineNumber(t *testing.T) {
	t.Parallel()
	// Malformed line is line 1.
	_, err := parseJSONL[stubJSONLRow]([]byte(`{not json}`+"\n"), "events.jsonl")
	if err == nil {
		t.Fatal("malformed line 1: expected error")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("malformed line 1: error doesn't mention 'line 1': %v", err)
	}
	// Malformed line is line 3 of 4 records.
	raw := []byte(`{"a":1,"b":"x"}` + "\n" +
		`{"a":2,"b":"y"}` + "\n" +
		`{not json}` + "\n" +
		`{"a":4,"b":"z"}` + "\n")
	_, err = parseJSONL[stubJSONLRow](raw, "events.jsonl")
	if err == nil {
		t.Fatal("malformed line 3: expected error")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("malformed line 3: error doesn't mention 'line 3': %v", err)
	}
	// Malformed line is the final line with no trailing LF.
	raw = []byte(`{"a":1,"b":"x"}` + "\n" + `{not json}`)
	_, err = parseJSONL[stubJSONLRow](raw, "events.jsonl")
	if err == nil {
		t.Fatal("malformed final line no LF: expected error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("malformed final line: error doesn't mention 'line 2': %v", err)
	}
}

// =============================================================================
// M3: two-pass loader regression test. Spec §2 mandates that
// bundle_format check fires BEFORE any other parse. A v2 bundle with
// a structurally invalid v1-shape events.jsonl must reject on the
// pin check, NOT bubble up an opaque events.jsonl parse error.
// =============================================================================

// =============================================================================
// D3c3: directory-based parser tests (ots_receipts/, rfc3161_receipts/,
// github_anchors/).
// =============================================================================

func TestLoadParsesOTSReceipts(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Example bundle: 1 OTS receipt for 2026-04-22.
	if len(bundle.OTSReceipts) != 1 {
		t.Errorf("len(OTSReceipts) = %d, want 1", len(bundle.OTSReceipts))
	}
	receipt, ok := bundle.OTSReceipts["2026-04-22"]
	if !ok {
		t.Fatal("missing OTS receipt for 2026-04-22")
	}
	if len(receipt) == 0 {
		t.Error("OTS receipt empty bytes")
	}
}

func TestLoadParsesRFC3161Receipts(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Example bundle: 1 day, 3 TSAs (digicert, freetsa, sectigo).
	if len(bundle.RFC3161Receipts) != 1 {
		t.Errorf("len(RFC3161Receipts) = %d (days), want 1", len(bundle.RFC3161Receipts))
	}
	dayMap, ok := bundle.RFC3161Receipts["2026-04-22"]
	if !ok {
		t.Fatal("missing RFC3161 receipts for 2026-04-22")
	}
	if len(dayMap) != 3 {
		t.Errorf("len(dayMap) = %d (TSAs), want 3 (digicert + freetsa + sectigo)", len(dayMap))
	}
	for _, expected := range []string{"digicert", "freetsa", "sectigo"} {
		pair, ok := dayMap[expected]
		if !ok {
			t.Errorf("missing TSA %q", expected)
			continue
		}
		if len(pair.TSR) == 0 {
			t.Errorf("TSA %q .tsr empty", expected)
		}
		if len(pair.ChainPEM) == 0 {
			t.Errorf("TSA %q .chain.pem empty", expected)
		}
	}
}

func TestLoadParsesGithubAnchors(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(bundle.GithubAnchors) != 1 {
		t.Errorf("len(GithubAnchors) = %d, want 1", len(bundle.GithubAnchors))
	}
	anchor, ok := bundle.GithubAnchors["2026-04-22"]
	if !ok {
		t.Fatal("missing github_anchors entry for 2026-04-22")
	}
	if anchor.Date != "2026-04-22" {
		t.Errorf("anchor.Date = %q, want 2026-04-22", anchor.Date)
	}
	if anchor.SchemaVersion != 1 {
		t.Errorf("anchor.schema_version = %d, want 1", anchor.SchemaVersion)
	}
	// commit_sha_format MUST be present per Phase 4 prereq Session B
	// Item 4 (sha1 | sha256 discriminator).
	if anchor.CommitShaFormat != "sha1" && anchor.CommitShaFormat != "sha256" {
		t.Errorf("anchor.commit_sha_format = %q, want sha1 or sha256", anchor.CommitShaFormat)
	}
	// mirror_status MUST be one of the canonical 4-state enum
	// (Session B Item 5 reconciliation).
	switch anchor.MirrorStatus {
	case "not_attempted", "anchor-pending", "anchored", "failed":
	default:
		t.Errorf("anchor.mirror_status = %q, not in canonical 4-state enum", anchor.MirrorStatus)
	}
	// Repo URL must be set.
	if anchor.Repo == "" {
		t.Error("anchor.repo empty")
	}
}

// TestLoadRejectsHalfPairRFC3161 verifies the spec §11 invariant:
// every (utc_day, tsa_name) MUST have BOTH a .tsr and a .chain.pem.
// A half-pair bundle is malformed and Load() must reject it.
func TestLoadRejectsHalfPairRFC3161(t *testing.T) {
	t.Parallel()
	// Build a v1 bundle with a half-pair: .tsr present, .chain.pem
	// missing. Manifest is minimally well-formed (passes the pin
	// check) so dispatch progresses to RFC 3161 parsing.
	zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
		extraEntries: map[string][]byte{
			"rfc3161_receipts/2026-04-22__halfpair.tsr": []byte("dummy-tsr-bytes"),
			// chain.pem omitted on purpose
		},
	})
	tmp := t.TempDir()
	path := filepath.Join(tmp, "halfpair.zip")
	if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected half-pair rejection, got nil")
	}
	if !strings.Contains(err.Error(), "chain.pem") || !strings.Contains(err.Error(), "missing") {
		t.Errorf("error doesn't say 'chain.pem missing': %v", err)
	}
}

// TestLoadRejectsGithubAnchorDateMismatch verifies the per-entry
// cross-check that github_anchors/<utc_day>.json's path-derived day
// matches the JSON's date field. A mismatch is a tampering signal.
func TestLoadRejectsGithubAnchorDateMismatch(t *testing.T) {
	t.Parallel()
	zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
		extraEntries: map[string][]byte{
			"github_anchors/2026-04-22.json": []byte(`{
				"schema_version": 1,
				"date": "2026-04-23",
				"repo": "https://example.invalid",
				"commit_sha_format": "sha1",
				"commit_sha": null,
				"path": null,
				"anchored_at": null,
				"mirror_status": "anchor-pending"
			}`),
		},
	})
	tmp := t.TempDir()
	path := filepath.Join(tmp, "datemismatch.zip")
	if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected date-mismatch rejection, got nil")
	}
	if !strings.Contains(err.Error(), "path date") {
		t.Errorf("error doesn't mention 'path date': %v", err)
	}
}

// TestLoadRejectsMalformedReceiptPaths verifies that path-derived
// utc_day values are validated. Spec §10/11/12 mandate strict
// YYYY-MM-DD prefixes; an attacker-supplied path like
// "ots_receipts/../escape.ots" or "ots_receipts/2026__04__22.ots"
// must NOT slip past keying.
func TestLoadRejectsMalformedReceiptPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		entryPath string
		entryData []byte
		wantErr   string
	}{
		{
			name:      "ots malformed day",
			entryPath: "ots_receipts/2026_04_22.ots",
			entryData: []byte("dummy"),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "ots wrong extension",
			entryPath: "ots_receipts/2026-04-22.bin",
			entryData: []byte("dummy"),
			wantErr:   "must end in .ots",
		},
		{
			name:      "ots calendar-impossible month",
			entryPath: "ots_receipts/2026-13-22.ots",
			entryData: []byte("dummy"),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "ots calendar-impossible day",
			entryPath: "ots_receipts/2026-04-32.ots",
			entryData: []byte("dummy"),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "ots zero-month",
			entryPath: "ots_receipts/2026-00-22.ots",
			entryData: []byte("dummy"),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "ots zero-day",
			entryPath: "ots_receipts/2026-04-00.ots",
			entryData: []byte("dummy"),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "ots nested directory",
			entryPath: "ots_receipts/sub/2026-04-22.ots",
			entryData: []byte("dummy"),
			wantErr:   "malformed ots_receipts path",
		},
		{
			name:      "rfc3161 missing __ separator",
			entryPath: "rfc3161_receipts/2026-04-22.tsr",
			entryData: []byte("dummy"),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "rfc3161 nested directory",
			entryPath: "rfc3161_receipts/sub/2026-04-22__digicert.tsr",
			entryData: []byte("dummy"),
			wantErr:   "malformed rfc3161_receipts path",
		},
		{
			name:      "github_anchors malformed day",
			entryPath: "github_anchors/badday.json",
			entryData: []byte(`{}`),
			wantErr:   "malformed utc_day prefix",
		},
		{
			name:      "github_anchors nested directory",
			entryPath: "github_anchors/sub/2026-04-22.json",
			entryData: []byte(`{}`),
			wantErr:   "malformed github_anchors path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
				extraEntries: map[string][]byte{tc.entryPath: tc.entryData},
			})
			tmp := t.TempDir()
			path := filepath.Join(tmp, "malformed.zip")
			if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
				t.Fatalf("write tmp: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error doesn't contain %q: %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadRejectsDuplicateOTSReceipt asserts that two ots_receipts/
// entries for the same UTC day error out (a write-side bug or
// tampering signal that pre-D3c3 would have silently let last-write
// win).
func TestLoadRejectsDuplicateOTSReceipt(t *testing.T) {
	t.Parallel()
	zipBytes := buildSyntheticBundleAllowingDuplicates(t, []syntheticEntry{
		{Path: "ots_receipts/2026-04-22.ots", Data: []byte("first")},
		{Path: "ots_receipts/2026-04-22.ots", Data: []byte("second")},
	})
	tmp := t.TempDir()
	path := filepath.Join(tmp, "dupots.zip")
	if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected duplicate-OTS rejection, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate ots receipt") {
		t.Errorf("error doesn't mention 'duplicate ots receipt': %v", err)
	}
}

// TestLoadRejectsDuplicateRFC3161 asserts that two .tsr (or two
// .chain.pem) entries for the same (utc_day, tsa_name) error out.
func TestLoadRejectsDuplicateRFC3161(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "tsr", path: "rfc3161_receipts/2026-04-22__digicert.tsr", wantErr: "duplicate .tsr"},
		{name: "chain", path: "rfc3161_receipts/2026-04-22__digicert.chain.pem", wantErr: "duplicate chain.pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zipBytes := buildSyntheticBundleAllowingDuplicates(t, []syntheticEntry{
				{Path: tc.path, Data: []byte("first")},
				{Path: tc.path, Data: []byte("second")},
			})
			tmp := t.TempDir()
			path := filepath.Join(tmp, "dup.zip")
			if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
				t.Fatalf("write tmp: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected duplicate rejection, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error doesn't contain %q: %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadRejectsGithubAnchorEmptyOrNullDate covers the smuggle vector
// where path == "" or path == JSON date == "" would slip past the
// path-vs-JSON mismatch check. Independent calendar-shape validation
// on anchor.Date closes this.
func TestLoadRejectsGithubAnchorEmptyOrNullDate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "empty date",
			body:    `{"schema_version":1,"date":"","repo":"x","commit_sha_format":"sha1","commit_sha":null,"path":null,"anchored_at":null,"mirror_status":"anchor-pending"}`,
			wantErr: "json.date \"\" is not valid YYYY-MM-DD",
		},
		{
			name:    "null date",
			body:    `{"schema_version":1,"date":null,"repo":"x","commit_sha_format":"sha1","commit_sha":null,"path":null,"anchored_at":null,"mirror_status":"anchor-pending"}`,
			wantErr: "json.date \"\" is not valid YYYY-MM-DD",
		},
		{
			name:    "calendar-impossible date in json",
			body:    `{"schema_version":1,"date":"9999-99-99","repo":"x","commit_sha_format":"sha1","commit_sha":null,"path":null,"anchored_at":null,"mirror_status":"anchor-pending"}`,
			wantErr: "json.date \"9999-99-99\" is not valid YYYY-MM-DD",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
				extraEntries: map[string][]byte{
					"github_anchors/2026-04-22.json": []byte(tc.body),
				},
			})
			tmp := t.TempDir()
			path := filepath.Join(tmp, "anchor.zip")
			if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
				t.Fatalf("write tmp: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error doesn't contain %q: %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadRejectsGithubAnchorBadEnums covers Phase 4 prereq Session B
// Item 4 (commit_sha_format ∈ {sha1, sha256}) and Item 5
// (mirror_status ∈ {not_attempted, anchor-pending, anchored, failed})
// loader-layer enforcement.
func TestLoadRejectsGithubAnchorBadEnums(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "bad commit_sha_format",
			body:    `{"schema_version":1,"date":"2026-04-22","repo":"x","commit_sha_format":"sha-1","commit_sha":null,"path":null,"anchored_at":null,"mirror_status":"anchor-pending"}`,
			wantErr: "commit_sha_format = \"sha-1\"",
		},
		{
			name:    "missing commit_sha_format (empty string)",
			body:    `{"schema_version":1,"date":"2026-04-22","repo":"x","commit_sha":null,"path":null,"anchored_at":null,"mirror_status":"anchor-pending"}`,
			wantErr: "commit_sha_format = \"\"",
		},
		{
			name:    "bad mirror_status",
			body:    `{"schema_version":1,"date":"2026-04-22","repo":"x","commit_sha_format":"sha1","commit_sha":null,"path":null,"anchored_at":null,"mirror_status":"pending"}`,
			wantErr: "mirror_status = \"pending\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
				extraEntries: map[string][]byte{
					"github_anchors/2026-04-22.json": []byte(tc.body),
				},
			})
			tmp := t.TempDir()
			path := filepath.Join(tmp, "anchor.zip")
			if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
				t.Fatalf("write tmp: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error doesn't contain %q: %v", tc.wantErr, err)
			}
		})
	}
}

// TestFinalizeBundleHalfPairErrorIsDeterministic asserts the M2 fix:
// a multi-half-pair bundle returns a deterministically-ordered
// errors.Join so forensic output is reproducible across runs.
func TestFinalizeBundleHalfPairErrorIsDeterministic(t *testing.T) {
	t.Parallel()
	zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
		extraEntries: map[string][]byte{
			// Two TSAs missing chain.pem on different days. Map
			// iteration would surface them in random order; the
			// finalizer sorts.
			"rfc3161_receipts/2026-04-22__digicert.tsr": []byte("a"),
			"rfc3161_receipts/2026-04-23__freetsa.tsr":  []byte("b"),
		},
	})
	tmp := t.TempDir()
	path := filepath.Join(tmp, "halfpairs.zip")
	if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	// Run Load() multiple times; the joined error string MUST be
	// byte-identical across runs (proving sort is in effect).
	var first string
	for i := 0; i < 5; i++ {
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected half-pair error")
		}
		if i == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Errorf("half-pair error not deterministic across runs:\n  run0: %q\n  run%d: %q",
				first, i, err.Error())
		}
	}
	// Both findings should appear (errors.Join surfaces all).
	if !strings.Contains(first, "2026-04-22__digicert") {
		t.Errorf("error missing 2026-04-22__digicert finding: %v", first)
	}
	if !strings.Contains(first, "2026-04-23__freetsa") {
		t.Errorf("error missing 2026-04-23__freetsa finding: %v", first)
	}
}

// =============================================================================
// D3c4: audio/ directory parser tests.
// =============================================================================

func TestLoadParsesAudioFiles(t *testing.T) {
	t.Parallel()
	bundle, err := Load(exampleBundlePath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Example bundle ships exactly 1 audio file: 6f34baca...wav.
	if len(bundle.AudioFiles) != 1 {
		t.Errorf("len(AudioFiles) = %d, want 1", len(bundle.AudioFiles))
	}
	const expectedKey = "6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c.wav"
	bytes, ok := bundle.AudioFiles[expectedKey]
	if !ok {
		t.Fatalf("AudioFiles missing expected key %q; got keys: %v",
			expectedKey, mapKeys(bundle.AudioFiles))
	}
	if len(bytes) == 0 {
		t.Error("audio file empty bytes")
	}
	// WAV magic bytes (RIFF header).
	if len(bytes) >= 4 && string(bytes[:4]) != "RIFF" {
		t.Errorf("audio file doesn't start with RIFF magic; got %q", bytes[:4])
	}
}

// TestLoadRejectsMalformedAudioPaths covers spec §13.1 path discipline:
// "audio/<sha256>.<ext>" exactly. Anything else must reject — the
// content-addressing claim depends on filename rigor.
func TestLoadRejectsMalformedAudioPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		entryPath string
		wantErr   string
	}{
		{
			name:      "no extension",
			entryPath: "audio/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c",
			wantErr:   "missing extension",
		},
		{
			name:      "stem too short",
			entryPath: "audio/abc123.wav",
			wantErr:   "must be 64-char lowercase hex",
		},
		{
			name:      "stem too long",
			entryPath: "audio/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c00.wav",
			wantErr:   "must be 64-char lowercase hex",
		},
		{
			name:      "stem uppercase hex",
			entryPath: "audio/6F34BACA370C0E69BB146220C7677B9614800887DD8A4CB52218DBBB032C335C.wav",
			wantErr:   "must be 64-char lowercase hex",
		},
		{
			name:      "stem non-hex chars",
			entryPath: "audio/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335zz.wav",
			wantErr:   "must be 64-char lowercase hex",
		},
		{
			name:      "nested directory",
			entryPath: "audio/sub/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c.wav",
			wantErr:   "malformed audio path",
		},
		{
			name:      "empty extension after dot",
			entryPath: "audio/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c.",
			wantErr:   "empty extension",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zipBytes := buildSyntheticBundle(t, syntheticBundleSpec{
				extraEntries: map[string][]byte{tc.entryPath: []byte("dummy")},
			})
			tmp := t.TempDir()
			path := filepath.Join(tmp, "malformed.zip")
			if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
				t.Fatalf("write tmp: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error doesn't contain %q: %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadRejectsDuplicateAudioFile(t *testing.T) {
	t.Parallel()
	zipBytes := buildSyntheticBundleAllowingDuplicates(t, []syntheticEntry{
		{
			Path: "audio/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c.wav",
			Data: []byte("first"),
		},
		{
			Path: "audio/6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c.wav",
			Data: []byte("second"),
		},
	})
	tmp := t.TempDir()
	path := filepath.Join(tmp, "dup.zip")
	if err := os.WriteFile(path, zipBytes, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected duplicate-audio rejection, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate audio file") {
		t.Errorf("error doesn't mention duplicate: %v", err)
	}
}

// mapKeys is a small helper for diagnostic output in audio tests.
func mapKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// =============================================================================
// Synthetic-bundle test helpers
// =============================================================================

type syntheticEntry struct {
	Path string
	Data []byte
}

// buildSyntheticBundleAllowingDuplicates builds a bundle from an
// ordered list of entries. Unlike the map-based buildSyntheticBundle,
// this preserves duplicates so duplicate-detection tests can probe
// the loader's symmetric checks.
func buildSyntheticBundleAllowingDuplicates(t *testing.T, entries []syntheticEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// bundle_type set per Phase 6.4 SA2 closed-vocabulary validation
	// (BACKLOG 1.40 closure); tests in this file probe path/duplicate/
	// format detection — bundle_type value is incidental but required.
	manifest := `{"schema_version":1,"bundle_format":"nuwyre-bundle/v1","bundle_type":"customer-export"}`
	addEntry(t, zw, "manifest.json", []byte(manifest))
	addEntry(t, zw, "signature.sig", []byte(`{"schema_version":1}`))
	for _, e := range entries {
		addEntry(t, zw, e.Path, e.Data)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// syntheticBundleSpec builds a minimal v1-passing bundle suitable for
// negative-path tests. Manifest is just enough to clear the
// bundle_format + schema_version pin check; signature.sig is valid
// JSON; extraEntries are added verbatim so each test can probe the
// dispatchEntry layer.
type syntheticBundleSpec struct {
	extraEntries map[string][]byte
}

func buildSyntheticBundle(t *testing.T, spec syntheticBundleSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// bundle_type set per Phase 6.4 SA2 closed-vocabulary validation
	// (BACKLOG 1.40 closure); tests in this file probe path/duplicate/
	// format detection — bundle_type value is incidental but required.
	manifest := `{"schema_version":1,"bundle_format":"nuwyre-bundle/v1","bundle_type":"customer-export"}`
	addEntry(t, zw, "manifest.json", []byte(manifest))
	addEntry(t, zw, "signature.sig", []byte(`{"schema_version":1}`))
	for name, data := range spec.extraEntries {
		addEntry(t, zw, name, data)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func addEntry(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create %q: %v", name, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zip write %q: %v", name, err)
	}
}

func TestLoadFailsBundleFormatCheckBeforeOtherParse(t *testing.T) {
	t.Parallel()
	// Build a minimal in-memory zip with: manifest.json declaring
	// bundle_format=v2, signature.sig (valid JSON), AND a malformed
	// events.jsonl that would parse-fail. If the two-pass loader is
	// correct, the v2 rejection fires first; if the loader regresses
	// to single-pass dispatch, the parse error surfaces instead.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifestV2 := `{
		"schema_version": 1,
		"bundle_format": "nuwyre-bundle/v2"
	}`
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("zip create manifest: %v", err)
	}
	if _, err := w.Write([]byte(manifestV2)); err != nil {
		t.Fatalf("zip write manifest: %v", err)
	}
	w, err = zw.Create("signature.sig")
	if err != nil {
		t.Fatalf("zip create sig: %v", err)
	}
	if _, err := w.Write([]byte(`{"schema_version":1}`)); err != nil {
		t.Fatalf("zip write sig: %v", err)
	}
	// Malformed events.jsonl — would fail parseJSONL.
	w, err = zw.Create("events.jsonl")
	if err != nil {
		t.Fatalf("zip create events: %v", err)
	}
	if _, err := w.Write([]byte("{this is not json}\n")); err != nil {
		t.Fatalf("zip write events: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	// Persist + load.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "v2-bundle.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tmp zip: %v", err)
	}

	_, err = Load(path)
	if err == nil {
		t.Fatal("expected v2 rejection error, got nil")
	}
	// MUST mention bundle_format. MUST NOT be the events.jsonl parse
	// error (which would mean the second pass ran before the pin check).
	if !strings.Contains(err.Error(), "bundle_format") {
		t.Errorf("error doesn't mention bundle_format (two-pass invariant violated?): %v", err)
	}
	if strings.Contains(err.Error(), "events.jsonl") {
		t.Errorf("error mentions events.jsonl — second pass ran before bundle_format pin check (spec §2 violation): %v", err)
	}
}

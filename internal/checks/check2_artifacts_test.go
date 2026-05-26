package checks

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// Check 2: artifact integrity — happy path against the regenerated
// example bundle. Every declared artifact present, hashes match,
// no extras, no missing.
// =============================================================================

func TestCheck2HappyPath(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check2Artifacts{}.Run(b, CheckOptions{})
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

// TestCheck2Slug pins the matcher form for `--check artifact-integrity`.
func TestCheck2Slug(t *testing.T) {
	t.Parallel()
	c := Check2Artifacts{}
	if c.ID() != 2 {
		t.Errorf("ID() = %d, want 2", c.ID())
	}
	if c.Name() != "artifact integrity" {
		t.Errorf("Name() = %q, want %q", c.Name(), "artifact integrity")
	}
	if c.Slug() != "artifact-integrity" {
		t.Errorf("Slug() = %q, want %q", c.Slug(), "artifact-integrity")
	}
}

// TestCheck2EveryBundleFileIsDeclared asserts the spec §3 / §4
// invariant: every file in the bundle except manifest.json +
// signature.sig appears in manifest.artifacts. Detects regression
// where an example-bundle generator emits a file but forgets to
// declare it.
func TestCheck2EveryBundleFileIsDeclared(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "extra file = tampering signal") {
			t.Errorf("regenerated example bundle has extra/undeclared file: %v", e)
		}
	}
}

// TestCheck2RejectsTamperedCoverPDFBytes flips one byte of cover.pdf
// in a copy of the example bundle. SHA-256 mismatch → Fail.
//
// We tamper cover.pdf rather than events.jsonl because events.jsonl
// goes through the loader's strict JSONL parser, which would reject
// a single-byte flip with a parse error before check 2 runs. cover.pdf
// is loaded as opaque binary; the loader is happy with any byte
// content. Either tampering should be rejected by check 2 — testing
// the cover.pdf path exercises the same byte-level integrity check
// that events.jsonl tampering would trigger if Load() didn't reject
// it first.
func TestCheck2RejectsTamperedCoverPDFBytes(t *testing.T) {
	t.Parallel()
	tamperedPath := buildTamperedBundle(t, func(name string, data []byte) []byte {
		if name != "cover.pdf" {
			return data
		}
		out := make([]byte, len(data))
		copy(out, data)
		// Flip a byte well past the PDF header (avoid breaking the
		// magic bytes; the loader doesn't validate PDF format but
		// keeping the file recognizable preserves cleaner test
		// semantics).
		if len(out) > 200 {
			out[len(out)-100] ^= 0x01
		}
		return out
	})
	b, err := bundle.Load(tamperedPath)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered cover.pdf: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "cover.pdf") &&
			strings.Contains(e.Error(), "computed sha256") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected cover.pdf SHA-256 mismatch error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck2RejectsTamperedAudioBytes flips one byte of an audio file.
// Both errors should surface: the file SHA-256 no longer matches the
// manifest-declared hash AND the filename stem (still original SHA)
// no longer equals the new computed SHA — content-addressing broken.
func TestCheck2RejectsTamperedAudioBytes(t *testing.T) {
	t.Parallel()
	tamperedPath := buildTamperedBundle(t, func(name string, data []byte) []byte {
		if !strings.HasPrefix(name, "audio/") {
			return data
		}
		out := make([]byte, len(data))
		copy(out, data)
		// Flip a byte well into the file (avoid the WAV header to
		// keep the tamper detection focused on bytes-change, not
		// format change).
		if len(out) > 100 {
			out[len(out)-50] ^= 0x01
		}
		return out
	})
	b, err := bundle.Load(tamperedPath)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered audio: Status = %v, want Fail", r.Status)
	}
	// Both errors expected: manifest-hash mismatch AND content-address
	// broken.
	sawHashMismatch := false
	sawContentAddrBroken := false
	for _, e := range r.Errors {
		msg := e.Error()
		if !strings.Contains(msg, "audio/") {
			continue
		}
		if strings.Contains(msg, "computed sha256") {
			sawHashMismatch = true
		}
		if strings.Contains(msg, "content-addressing broken") {
			sawContentAddrBroken = true
		}
	}
	if !sawHashMismatch {
		t.Error("expected manifest-hash mismatch error for audio file")
	}
	if !sawContentAddrBroken {
		t.Error("expected content-addressing-broken error for audio file")
	}
	if !sawHashMismatch || !sawContentAddrBroken {
		for _, e := range r.Errors {
			t.Logf("  %v", e)
		}
	}
}

// TestCheck2RejectsMissingArtifact removes a declared file from the
// bundle. Check 2 must report missing-artifact for that path.
func TestCheck2RejectsMissingArtifact(t *testing.T) {
	t.Parallel()
	const removeTarget = "verify.md"
	tamperedPath := buildTamperedBundleWithFilter(t,
		passthroughTransform,
		func(name string) bool { return name != removeTarget })
	b, err := bundle.Load(tamperedPath)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("missing artifact: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), removeTarget) &&
			strings.Contains(e.Error(), "missing from the bundle") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected missing-artifact error for %s; got:", removeTarget)
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck2RejectsExtraFile adds an undeclared file to the bundle.
// Check 2 must report extra-file for it.
func TestCheck2RejectsExtraFile(t *testing.T) {
	t.Parallel()
	const extraName = "smuggled-payload.txt"
	tamperedPath := buildTamperedBundleWithExtras(t,
		map[string][]byte{extraName: []byte("attacker-controlled content")})
	b, err := bundle.Load(tamperedPath)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("extra file: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), extraName) &&
			strings.Contains(e.Error(), "extra file = tampering signal") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected extra-file error for %s; got:", extraName)
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck2RejectsBytesCountMismatch tampers a file's bytes WITHOUT
// updating the manifest's bytes count. The bytes-count mismatch
// surfaces alongside the SHA-256 mismatch (both errors expected).
func TestCheck2RejectsBytesCountMismatch(t *testing.T) {
	t.Parallel()
	tamperedPath := buildTamperedBundle(t, func(name string, data []byte) []byte {
		if name != "verify.md" {
			return data
		}
		// Append bytes — both the byte count AND the SHA-256 change.
		return append(append([]byte{}, data...), []byte(" extra payload")...)
	})
	b, err := bundle.Load(tamperedPath)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("bytes mismatch: Status = %v, want Fail", r.Status)
	}
	sawBytes := false
	sawHash := false
	for _, e := range r.Errors {
		msg := e.Error()
		if !strings.Contains(msg, "verify.md") {
			continue
		}
		if strings.Contains(msg, "actual bytes=") {
			sawBytes = true
		}
		if strings.Contains(msg, "computed sha256") {
			sawHash = true
		}
	}
	if !sawBytes {
		t.Error("expected bytes-count mismatch error")
	}
	if !sawHash {
		t.Error("expected SHA-256 mismatch error")
	}
}

// TestCheck2RejectsTamperedManifestArtifactHash modifies one entry's
// declared SHA-256 in the manifest itself. The actual file is
// untouched; the manifest is lying about it. Check 2 catches the
// divergence.
func TestCheck2RejectsTamperedManifestArtifactHash(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Manifest.Artifacts) == 0 {
		t.Fatal("manifest.artifacts empty")
	}
	// Tamper in-memory: rewrite the first artifact's declared SHA-256
	// to something obviously wrong but still 64 hex chars (so we test
	// the hash-comparison path, not a length-validation short-circuit).
	original := b.Manifest.Artifacts[0].SHA256
	defer func() { b.Manifest.Artifacts[0].SHA256 = original }()
	b.Manifest.Artifacts[0].SHA256 = strings.Repeat("a", 64)

	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("tampered manifest artifact hash: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), b.Manifest.Artifacts[0].Path) &&
			strings.Contains(e.Error(), "declared sha256") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected hash-mismatch error for %s; got:", b.Manifest.Artifacts[0].Path)
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck2RejectsManifestDuplicateArtifact tests the manifest-side
// duplicate detection: a manifest that lists the same path twice
// fails check 2 even if the file's bytes match the first declaration.
func TestCheck2RejectsManifestDuplicateArtifact(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if len(b.Manifest.Artifacts) == 0 {
		t.Fatal("manifest.artifacts empty")
	}
	// Append a duplicate of the first artifact entry (different
	// hash to make the duplication visible). In-memory tamper.
	first := b.Manifest.Artifacts[0]
	originalArtifacts := b.Manifest.Artifacts
	defer func() { b.Manifest.Artifacts = originalArtifacts }()
	dup := first
	dup.SHA256 = strings.Repeat("b", 64)
	b.Manifest.Artifacts = append(append([]bundle.ManifestArtifact{}, originalArtifacts...), dup)

	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("duplicate manifest artifact: Status = %v, want Fail", r.Status)
	}
	hit := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error(), "declares the same path twice") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected duplicate-path error; got:")
		for _, e := range r.Errors {
			t.Errorf("  %v", e)
		}
	}
}

// TestCheck2EmptyRawZipFailsLoudly defends against a future loader
// regression where Bundle.RawZip isn't preserved. Check 2 cannot run
// without re-iterating the zip bytes; an empty RawZip must surface
// as Fail with a clear error rather than silently succeed.
//
// (Renamed from TestCheck2EmptyBundlePathFailsLoudly during Phase 5.5
// Session 5.5.1B C5: check 2 now re-iterates from Bundle.RawZip
// instead of re-opening Bundle.Path on the filesystem. This lets the
// WASM verifier produce identical results in a browser environment.)
func TestCheck2EmptyRawZipFailsLoudly(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.RawZip = nil
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("empty RawZip: Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Error(), "bundle.RawZip empty") {
		t.Errorf("expected bundle.RawZip empty error; got: %v", r.Errors)
	}
}

// TestCheck2DeterministicErrorOrder asserts that two runs against the
// same tampered bundle produce byte-identical error sequences. A
// reviewer / regulator capturing CLI output into a written report
// needs reproducible diagnostics across runs (Go map iteration would
// otherwise scramble order).
func TestCheck2DeterministicErrorOrder(t *testing.T) {
	t.Parallel()
	// Create a tampered bundle with multiple extras, which exercises
	// the sort path inside check 2's extra-file detection.
	tamperedPath := buildTamperedBundleWithExtras(t, map[string][]byte{
		"zzz_smuggled_z.txt": []byte("z"),
		"aaa_smuggled_a.txt": []byte("a"),
		"mmm_smuggled_m.txt": []byte("m"),
	})
	b, err := bundle.Load(tamperedPath)
	if err != nil {
		t.Fatalf("Load tampered: %v", err)
	}
	var firstSeq []string
	for run := 0; run < 5; run++ {
		r := Check2Artifacts{}.Run(b, CheckOptions{})
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
				t.Errorf("run %d index %d:\n  first: %q\n  now:   %q", run, i, firstSeq[i], seq[i])
			}
		}
	}
}

// TestCheck2RejectsMalformedRawZip checks the bytes-parse error surface:
// a bundle whose RawZip is corrupted (truncated or non-zip bytes)
// surfaces as Fail with a parse error, not a panic.
//
// (Replaces TestCheck2RejectsMissingZipFile during Phase 5.5 Session
// 5.5.1B C5: check 2 now re-iterates from Bundle.RawZip rather than
// re-opening Bundle.Path, so the "missing zip file" case can no longer
// arise — the failure mode becomes "the RawZip bytes don't parse as a
// valid zip archive" instead.)
func TestCheck2RejectsMalformedRawZip(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	b.RawZip = []byte("not a zip archive — corrupted bytes")
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("malformed RawZip: Status = %v, want Fail", r.Status)
	}
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Error(), "re-open zip from bytes failed") {
		t.Errorf("expected re-open-from-bytes error; got: %v", r.Errors)
	}
}

// TestVerifyAudioContentAddressUnit covers the audio content-address
// helper directly: stem matches → nil; stem mismatches → error;
// missing extension → error.
func TestVerifyAudioContentAddressUnit(t *testing.T) {
	t.Parallel()
	const realHash = "6f34baca370c0e69bb146220c7677b9614800887dd8a4cb52218dbbb032c335c"
	cases := []struct {
		name      string
		path      string
		computed  string
		wantError bool
	}{
		{"match", "audio/" + realHash + ".wav", realHash, false},
		{"stem mismatch", "audio/abc123.wav", realHash, true},
		{"uppercase stem fails (lowercase invariant)",
			"audio/" + strings.ToUpper(realHash) + ".wav", realHash, true},
		{"missing extension", "audio/" + realHash, realHash, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyAudioContentAddress(tc.path, tc.computed)
			if (err != nil) != tc.wantError {
				t.Errorf("path=%q computed=%q: err=%v, wantError=%v",
					tc.path, tc.computed, err, tc.wantError)
			}
		})
	}
}

// =============================================================================
// Tampered-bundle test helpers
// =============================================================================

// passthroughTransform is the no-op transform used when callers want
// to filter entries (or add extras) without modifying any bytes.
func passthroughTransform(_ string, data []byte) []byte { return data }

// buildTamperedBundle reads the example bundle and writes a copy with
// each entry's bytes optionally transformed. Returns the path to the
// tampered copy under t.TempDir(). The transform receives (name,
// originalBytes); returning the original bytes leaves the entry
// unchanged. nil return is treated as the empty byte slice (which
// would still create a zero-byte zip entry — to remove an entry,
// use buildTamperedBundleWithFilter).
func buildTamperedBundle(t *testing.T, transform func(name string, data []byte) []byte) string {
	t.Helper()
	return buildTamperedBundleWithFilter(t, transform, func(string) bool { return true })
}

// buildTamperedBundleWithFilter is like buildTamperedBundle but also
// accepts a filter that controls which entries to preserve. Entries
// for which keep returns false are dropped from the tampered copy.
func buildTamperedBundleWithFilter(
	t *testing.T,
	transform func(name string, data []byte) []byte,
	keep func(name string) bool,
) string {
	t.Helper()
	src := exampleBundleAbs(t)
	r, err := zip.OpenReader(src)
	if err != nil {
		t.Fatalf("open source bundle: %v", err)
	}
	defer r.Close()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !keep(f.Name) {
			continue
		}
		raw, err := readFileFromZip(f)
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		out := transform(f.Name, raw)
		if out == nil {
			out = []byte{}
		}
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatalf("zip create %s: %v", f.Name, err)
		}
		if _, err := w.Write(out); err != nil {
			t.Fatalf("zip write %s: %v", f.Name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "tampered.zip")
	if err := os.WriteFile(dst, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	return dst
}

// buildTamperedBundleWithExtras copies the example bundle and adds
// extras as additional entries (no manifest update — that's the
// point: the manifest doesn't declare them and check 2 catches them
// as extras).
func buildTamperedBundleWithExtras(t *testing.T, extras map[string][]byte) string {
	t.Helper()
	src := exampleBundleAbs(t)
	r, err := zip.OpenReader(src)
	if err != nil {
		t.Fatalf("open source bundle: %v", err)
	}
	defer r.Close()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		raw, err := readFileFromZip(f)
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatalf("zip create %s: %v", f.Name, err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatalf("zip write %s: %v", f.Name, err)
		}
	}
	for name, data := range extras {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create extra %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write extra %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "with-extras.zip")
	if err := os.WriteFile(dst, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	return dst
}

func readFileFromZip(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// exampleBundleAbs returns the absolute path to the example bundle
// (the loadExampleBundle helper hides this behind a relative path
// that's not exposed; the tampered-bundle helpers need the path
// directly).
func exampleBundleAbs(t *testing.T) string {
	t.Helper()
	// Layout-agnostic (monorepo path or standalone testdata/); skips if absent.
	return findArtifact(t, exampleBundleCandidates...)
}

// =============================================================================
// Sanity unit: SHA-256 of an empty byte slice equals the canonical
// constant. Defends against a future helper regression where the
// hash function is silently swapped.
// =============================================================================

func TestSHA256EmptyByteSliceIsCanonical(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256(nil)
	got := hex.EncodeToString(sum[:])
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("SHA-256 of empty bytes = %q, want %q", got, want)
	}
}

// =============================================================================
// Sanity unit: the JSON encoder used by the tampered-bundle helpers
// produces stable output for ManifestArtifact (ensures our test
// assertion about hash-mismatch errors isn't subtly affected by the
// encoder reordering keys).
// =============================================================================

// =============================================================================
// Phase 7.E session 118 H2 closure — zip-bomb defense
// =============================================================================

// TestCheck2RejectsBytesMismatchOnDeclaredOversize (renamed from
// TestCheck2RejectsZipEntryExceedingMaxArtifactBytes per code-rev M3
// inline closure — the original test exercised the byte-count
// cross-check path, NOT the H2 declared-size precheck path). Pins
// the bytes mismatch error reporting. The pure H2 LimitReader cap
// behavior is exercised at TestReadZipEntryBoundedRejectsOversized
// + TestReadZipEntryBoundedAcceptsAtCap.
func TestCheck2RejectsBytesMismatchOnDeclaredOversize(t *testing.T) {
	t.Parallel()
	var manifestObj bundle.ManifestJSON
	manifestObj.SchemaVersion = 1
	manifestObj.GeneratedAt = "2026-05-23T00:00:00Z"
	manifestObj.BundleType = "customer-export"
	manifestObj.EventCount = 0
	// Use MaxArtifactBytesMetadata+1 as the declared bytes — test
	// hits the byte-count cross-check (declared bytes != actual=1).
	manifestObj.Artifacts = []bundle.ManifestArtifact{
		{Path: "huge.bin", Bytes: MaxArtifactBytesMetadata + 1, SHA256: strings.Repeat("a", 64)},
	}
	manifestJSON, err := json.Marshal(manifestObj)
	if err != nil {
		t.Fatalf("manifest marshal: %v", err)
	}
	// Build a zip with a synthetic huge.bin entry — we don't need
	// to actually emit MaxArtifactBytes+1 bytes; we need the zip
	// header's UncompressedSize64 to claim it. The simplest path is
	// to write a 1-byte entry then patch UncompressedSize64 on the
	// FileHeader before WriteHeader.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	mh, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("manifest zip create: %v", err)
	}
	if _, err := mh.Write(manifestJSON); err != nil {
		t.Fatalf("manifest zip write: %v", err)
	}
	// Synthetic huge.bin with UncompressedSize64 LIE: declare
	// > MaxArtifactBytes in the header. archive/zip's NewWriter API
	// computes UncompressedSize64 from actual bytes written, so we
	// can't lie via the standard interface. Instead, write 1 byte —
	// the test will exercise the readZipEntryBounded path directly
	// via a separate sub-test below; for this case we trip the
	// total-budget check by making the manifest declare bytes
	// larger than the cap (precheck-via-manifest-declared bytes).
	hh, err := zw.Create("huge.bin")
	if err != nil {
		t.Fatalf("huge zip create: %v", err)
	}
	if _, err := hh.Write([]byte("x")); err != nil {
		t.Fatalf("huge zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	b := &bundle.Bundle{
		Manifest: manifestObj,
		RawZip:   zipBuf.Bytes(),
	}
	r := Check2Artifacts{}.Run(b, CheckOptions{})
	if r.Status != StatusFail {
		t.Errorf("oversize artifact: Status = %v, want Fail", r.Status)
	}
	// Expect at least one error citing the bytes mismatch (declared
	// >MaxArtifactBytes but actual=1). The declared-size precheck
	// fires off UncompressedSize64 which equals actual=1 here (the
	// zip writer can't lie via stdlib API), so this test exercises
	// the byte-count cross-check rather than the H2 cap. The pure
	// H2 cap test follows in the unit-test below.
	if len(r.Errors) == 0 {
		t.Errorf("expected at least one error; got none")
	}
}

// TestReadZipEntryBoundedRejectsOversized constructs a zip entry whose
// decompressed size exceeds MaxArtifactBytes and confirms
// readZipEntryBounded returns the H2 zip-bomb error. Uses a small
// cap (1024 bytes) for test speed; the production constant
// MaxArtifactBytes (512 MiB) would require minutes of allocation
// for an equivalent test.
func TestReadZipEntryBoundedRejectsOversized(t *testing.T) {
	t.Parallel()
	const testCap int64 = 1024
	// Build a zip with one entry containing testCap+10 bytes of 'x'.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	hh, err := zw.Create("data.bin")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := hh.Write(bytes.Repeat([]byte("x"), int(testCap)+10)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("zip has %d files, want 1", len(zr.File))
	}
	_, err = readZipEntryBounded(zr.File[0], testCap)
	if err == nil {
		t.Errorf("readZipEntryBounded: want error for testCap=%d entry size %d, got nil", testCap, testCap+10)
	}
	if err != nil && !strings.Contains(err.Error(), "zip-bomb defense") {
		t.Errorf("expected zip-bomb defense error; got %v", err)
	}
}

// TestReadZipEntryBoundedAcceptsAtCap verifies the LimitReader +
// length-check pattern correctly admits an entry of exactly testCap
// bytes (boundary condition between "ok" and "rejected").
func TestReadZipEntryBoundedAcceptsAtCap(t *testing.T) {
	t.Parallel()
	const testCap int64 = 1024
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	hh, err := zw.Create("data.bin")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := hh.Write(bytes.Repeat([]byte("x"), int(testCap))); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	raw, err := readZipEntryBounded(zr.File[0], testCap)
	if err != nil {
		t.Errorf("readZipEntryBounded: want success at exact cap, got %v", err)
	}
	if int64(len(raw)) != testCap {
		t.Errorf("readZipEntryBounded: got %d bytes, want %d", len(raw), testCap)
	}
}

func TestManifestArtifactRoundTripsAsExpected(t *testing.T) {
	t.Parallel()
	art := bundle.ManifestArtifact{
		Path:   "events.jsonl",
		Bytes:  100,
		SHA256: strings.Repeat("a", 64),
	}
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back bundle.ManifestArtifact
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Path != art.Path || back.SHA256 != art.SHA256 || back.Bytes != art.Bytes {
		t.Errorf("round-trip drift: got %+v, want %+v", back, art)
	}
}

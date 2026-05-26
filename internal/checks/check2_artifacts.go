package checks

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nuwyre/cli/internal/bundle"
)

// Phase 7.E session 118 H2 closure — zip-bomb defense bounds.
//
// **Threat**: a malicious bundle can contain a zip entry whose
// CompressedSize64 is tiny but UncompressedSize64 is gigabytes (the
// canonical zip bomb: a few-KB zip that decompresses to TBs via DEFLATE
// repetition). Pre-closure, Check2Artifacts called io.ReadAll(rc)
// per entry without a size cap; reading a 10TB-decompressed entry would
// OOM the verifier process. Even a well-behaved attacker who declares
// `bytes` in the manifest correctly could still OOM the verifier on the
// first read since the size-check happens AFTER ReadAll completes.
//
// **Defense (layered with bundle.Load() loader caps)**:
//   1. **PER-ENTRY CAP, per-class**:
//      - Audio entries (path prefix "audio/"): bounded by
//        bundle.MaxAudioUncompressedBytes (1 GiB). v1 voice-AI bundles
//        can legitimately have hour-long recordings approaching this.
//      - All other entries: bounded by bundle.MaxEntryUncompressedBytes
//        (64 MiB). Metadata entries (manifest.json, events.jsonl,
//        evaluations.jsonl, merkle_proofs.json, daily_roots.json) are
//        well under this in any real bundle.
//      Symmetric with the loader's enforcement so a legitimate bundle
//      that passed bundle.Load() will pass Check 2 readZipEntryBounded.
//   2. **TOTAL-DECOMPRESSED CAP**: track running sum of decompressed
//      bytes across all entries; refuse to continue past
//      MaxTotalDecompressedBytes. Bounds peak memory pressure during
//      a single verify pass.
//   3. **DECLARED-SIZE PRECHECK**: refuse to attempt read if
//      zip.File.UncompressedSize64 already exceeds the per-entry cap.
//      Avoids spending CPU on DEFLATE before failing.
//
// **Tier B sec-aud H-2 + crypto-int H-2 DOUBLE-CORROBORATED INLINE
// CLOSURE**: prior version used a single MaxArtifactBytes=512 MiB
// cap which was LOWER than the loader's MaxAudioUncompressedBytes=1 GiB
// — a legitimate ~700 MiB audio entry would pass bundle.Load() then
// fail Check 2 with a misleading "zip-bomb defense" error. False-
// positives in fail-CLOSED defenses corrupt operator trust (operators
// learn to --skip-check 2, weakening real-tampering coverage). Per-
// class caps that match the loader fix this.
const (
	// MaxArtifactBytesMetadata caps non-audio entries. Mirrors
	// bundle.MaxEntryUncompressedBytes (64 MiB) so a bundle that
	// passed loader's caps will pass this check.
	MaxArtifactBytesMetadata int64 = 64 * 1024 * 1024

	// MaxArtifactBytesAudio caps audio entries (path prefix "audio/").
	// Mirrors bundle.MaxAudioUncompressedBytes (1 GiB).
	MaxArtifactBytesAudio int64 = 1024 * 1024 * 1024

	// MaxTotalDecompressedBytes caps total decompressed bytes summed
	// across all entries read in one Check2Artifacts.Run. 2 GiB
	// bounds peak memory pressure during a single verify pass.
	MaxTotalDecompressedBytes int64 = 2 * 1024 * 1024 * 1024
)

// maxBytesForArtifact returns the per-entry decompressed-size cap
// based on the artifact's path. Audio entries (path prefix "audio/")
// get the higher cap; everything else gets the metadata cap.
// Phase 7.E session 118 H-2 inline closure.
func maxBytesForArtifact(path string) int64 {
	if strings.HasPrefix(path, "audio/") {
		return MaxArtifactBytesAudio
	}
	return MaxArtifactBytesMetadata
}

// Check2Artifacts verifies the spec §3 + §4 + §13 artifact-integrity
// contract:
//
//   - Every entry in manifest.artifacts[] is present in the zip and its
//     bytes hash to the declared SHA-256.
//   - Bytes count cross-check: manifest.artifacts[].bytes equals the
//     file's actual byte length.
//   - Audio files specifically (path prefix "audio/"): the path stem
//     MUST equal the file's computed SHA-256 (content-addressed per
//     spec §13.1). A double-broken audio file (filename wrong AND
//     manifest hash wrong) surfaces both errors so the operator sees
//     the full divergence.
//   - Extra-file detection: every file in the zip except manifest.json
//     and signature.sig MUST be declared in manifest.artifacts (a
//     tampered bundle that smuggles in an extra file is rejected, not
//     silently ignored).
//   - Missing-file detection: a path declared in manifest.artifacts
//     that isn't in the zip is rejected.
//   - Manifest-side duplicate detection: manifest.artifacts MUST NOT
//     declare the same path twice.
//
// **Bytes-as-loaded posture.** The check re-opens the bundle's zip and
// hashes raw bytes per entry, NOT the loader's typed representation.
// The loader's dispatchEntry silently drops unrecognized entries
// (load.go:208 forward-compat fallback) — re-iterating the zip
// independently is how check 2 catches extra-file tampering without
// trusting the loader to surface it.
//
// **TOCTOU caveat.** Between bundle.Load() and Check2Artifacts.Run,
// the on-disk zip could be swapped. The CLI's verify subcommand
// invokes Load() then runs all checks immediately, minimizing the
// window. A future hardening could checksum the zip's outer bytes at
// Load() time and recheck here; v1 doesn't, on the basis that the
// verifier runs against a stable artifact rather than a live writer.
//
// **Determinism.** Errors are sorted: first by per-artifact iteration
// order (declared in manifest), then extras alphabetically. A
// reviewer / regulator capturing the CLI output into a written report
// gets byte-identical diagnostics across runs.
type Check2Artifacts struct{}

func (Check2Artifacts) ID() int      { return 2 }
func (Check2Artifacts) Name() string { return "artifact integrity" }
func (Check2Artifacts) Slug() string { return "artifact-integrity" }

func (c Check2Artifacts) Run(b *bundle.Bundle, _ CheckOptions) CheckResult {
	const id = 2
	const checkName = "artifact integrity"
	const slug = "artifact-integrity"

	var errs []error
	var warnings []error

	// Phase 5.5 Session 5.5.1B C5: re-iterate from Bundle.RawZip (the
	// in-memory bytes captured at Load/LoadFromBytes time) rather than
	// re-opening b.Path on the filesystem. This lets the WASM verifier
	// (running in a browser with no filesystem) produce identical
	// Check2Artifacts results to the native CLI. Bundle.RawZip is
	// guaranteed populated by both Load() and LoadFromBytes().
	if len(b.RawZip) == 0 {
		errs = append(errs, Errorf(id, checkName, "",
			"bundle.RawZip empty; cannot re-iterate zip for byte-level integrity check",
			SpecRefDirectoryLayout, "the bundle is loaded with raw zip bytes available"))
		return Result(id, checkName, slug, errs, warnings)
	}

	r, err := zip.NewReader(bytes.NewReader(b.RawZip), int64(len(b.RawZip)))
	if err != nil {
		errs = append(errs, Errorf(id, checkName, b.Path,
			fmt.Sprintf("re-open zip from bytes failed: %v", err),
			SpecRefDirectoryLayout, "the bundle's zip is readable"))
		return Result(id, checkName, slug, errs, warnings)
	}

	// Build a map of zip entry name → *zip.File. Reject duplicate
	// names: a zip CAN contain two entries with the same name; the
	// loader's first-pass dispatch handles only the first occurrence.
	// Surfacing duplicate-name as a check 2 error catches a tampering
	// vector where an attacker double-stuffs an entry hoping the
	// loader takes one and the verifier hashes the other.
	zipFiles := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if _, dup := zipFiles[f.Name]; dup {
			errs = append(errs, Errorf(id, checkName, f.Name,
				"duplicate zip entry (zip contains two entries with the same name)",
				SpecRefDirectoryLayout, "each bundle path appears exactly once in the zip"))
			continue
		}
		zipFiles[f.Name] = f
	}

	// Build the set of declared paths and detect manifest-side
	// duplicates (manifest.artifacts shouldn't list the same path
	// twice — would cause downstream tools to double-count).
	declaredPaths := make(map[string]bundle.ManifestArtifact, len(b.Manifest.Artifacts))
	for _, art := range b.Manifest.Artifacts {
		if existing, dup := declaredPaths[art.Path]; dup {
			errs = append(errs, Errorf(id, checkName, art.Path,
				fmt.Sprintf("manifest.artifacts declares the same path twice (first sha256=%s, second sha256=%s)",
					truncate(existing.SHA256, 16), truncate(art.SHA256, 16)),
				SpecRefManifestSchema, "manifest.artifacts paths are unique"))
			continue
		}
		declaredPaths[art.Path] = art
	}

	// Verify every declared artifact: present, hash matches, bytes
	// matches. Iterate in manifest-declared order so the error
	// sequence is stable.
	//
	// Phase 7.E session 118 H2 closure: track total decompressed bytes
	// across entries and refuse to continue past MaxTotalDecompressedBytes.
	// Index-based loop so the budget-exceeded "remaining unverified"
	// summary at break time can slice the residual artifacts (crypto-int
	// M-1 inline closure: operator-actionable list rather than implicit
	// truncation).
	var totalDecompressed int64
	var budgetExceededAt = -1
	for i := range b.Manifest.Artifacts {
		art := b.Manifest.Artifacts[i]
		zf, ok := zipFiles[art.Path]
		if !ok {
			errs = append(errs, Errorf(id, checkName, art.Path,
				"manifest.artifacts declares this path but it is missing from the bundle",
				SpecRefDirectoryLayout, "every manifest-declared file is present in the bundle"))
			continue
		}
		// Phase 7.E session 118 H2: declared-size precheck. The zip
		// header's UncompressedSize64 field is attacker-influenced (zip
		// is unauthenticated until Check 1+2 succeed) but checking it
		// before DEFLATE saves CPU on the obvious malicious cases.
		cap := maxBytesForArtifact(art.Path)
		if zf.UncompressedSize64 > uint64(cap) {
			errs = append(errs, Errorf(id, checkName, art.Path,
				fmt.Sprintf("zip header declares uncompressed size %d bytes > per-entry cap %d (verifier policy cap mirroring bundle loader; not a tampering signal — operators with legitimately larger artifacts should consult docs)",
					zf.UncompressedSize64, cap),
				SpecRefDirectoryLayout, "per-entry decompressed size is bounded"))
			continue
		}
		raw, err := readZipEntryBounded(zf, cap)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, art.Path,
				fmt.Sprintf("read failed: %v", err),
				SpecRefDirectoryLayout, "every manifest-declared file is readable"))
			continue
		}
		// Phase 7.E session 118 H2: total decompressed budget check.
		totalDecompressed += int64(len(raw))
		if totalDecompressed > MaxTotalDecompressedBytes {
			errs = append(errs, Errorf(id, checkName, art.Path,
				fmt.Sprintf("cumulative decompressed bytes %d > MaxTotalDecompressedBytes %d at this artifact; aborting (zip-bomb defense; total budget exceeded)",
					totalDecompressed, MaxTotalDecompressedBytes),
				SpecRefDirectoryLayout, "total decompressed bytes across all entries is bounded"))
			budgetExceededAt = i
			// Break the per-artifact loop — continuing would only burn
			// more memory; downstream errors would be noise.
			break
		}
		// Bytes count cross-check (cheap; surfaces mismatches with a
		// nicer error than the SHA-256 line alone). Mismatch implies
		// SHA-256 mismatch, but we report both for clarity.
		if int64(len(raw)) != art.Bytes {
			errs = append(errs, Errorf(id, checkName, art.Path,
				fmt.Sprintf("declared bytes=%d but actual bytes=%d", art.Bytes, len(raw)),
				SpecRefManifestFields, "manifest.artifacts[].bytes equals the file's byte length"))
		}
		// SHA-256 cross-check. Spec mandates lowercase hex; we
		// compute lowercase and compare byte-for-byte. A manifest
		// declaring uppercase hex (non-spec) fails this comparison
		// and is reported as a hash mismatch.
		sum := sha256.Sum256(raw)
		actualHex := hex.EncodeToString(sum[:])
		if actualHex != art.SHA256 {
			errs = append(errs, Errorf(id, checkName, art.Path,
				fmt.Sprintf("declared sha256=%s but computed sha256=%s",
					truncate(art.SHA256, 16),
					truncate(actualHex, 16)),
				SpecRefManifestSchema, "manifest.artifacts[].sha256 matches the file's bytes"))
		}
		// Audio-specific content-addressed check: filename stem MUST
		// equal the file's SHA-256 (spec §13.1). Reported alongside
		// the manifest-hash check on purpose — a doubly-broken audio
		// file (filename wrong AND manifest declaration wrong) shows
		// both errors so the operator sees the full divergence.
		if strings.HasPrefix(art.Path, "audio/") {
			if err := verifyAudioContentAddress(art.Path, actualHex); err != nil {
				errs = append(errs, Errorf(id, checkName, art.Path,
					err.Error(),
					SpecRefAudioPath, "audio filename stem equals the file's SHA-256 (content-addressed)"))
			}
		}
	}

	// Phase 7.E session 118 crypto-int M-1 INLINE CLOSURE: when the
	// total-decompressed budget tripped, surface an explicit list of
	// remaining-unverified artifacts so the operator cannot misread
	// the truncated verification as "N specific failures + a budget
	// note" rather than "verification ABORTED; (M-N) artifacts NOT
	// verified".
	if budgetExceededAt >= 0 {
		remaining := b.Manifest.Artifacts[budgetExceededAt+1:]
		if len(remaining) > 0 {
			var unverifiedPaths []string
			for _, a := range remaining {
				unverifiedPaths = append(unverifiedPaths, a.Path)
			}
			errs = append(errs, Errorf(id, checkName, "",
				fmt.Sprintf("verification ABORTED at total-budget cap; %d manifest-declared artifacts were NOT verified (paths: %s)",
					len(remaining), strings.Join(unverifiedPaths, ", ")),
				SpecRefDirectoryLayout, "every manifest-declared file is verified"))
		}
	}

	// Extra-file detection: every file in the zip except the
	// signing-system files manifest.json + signature.sig MUST be
	// declared in manifest.artifacts. Iterate in sorted order so the
	// error sequence is stable across runs.
	var extraNames []string
	for name := range zipFiles {
		if name == "manifest.json" || name == "signature.sig" {
			continue
		}
		if _, declared := declaredPaths[name]; !declared {
			extraNames = append(extraNames, name)
		}
	}
	sort.Strings(extraNames)
	for _, extra := range extraNames {
		errs = append(errs, Errorf(id, checkName, extra,
			"this file is present in the bundle but not declared in manifest.artifacts (extra file = tampering signal)",
			SpecRefManifestSchema, "every bundle file except manifest.json and signature.sig is declared in manifest.artifacts"))
	}

	return Result(id, checkName, slug, errs, warnings)
}

// readZipEntryBounded reads up to maxBytes from a zip entry. Returns
// an error if the entry's decompressed size would exceed the limit.
// Phase 7.E session 118 H2 closure (zip-bomb defense): bounds the
// io.ReadAll wrapper used in Check2Artifacts to prevent OOM on a
// malicious bundle with a small compressed → enormous decompressed
// entry (the canonical zip bomb).
//
// Uses io.LimitReader + a post-read length check: if the entry stops
// AT maxBytes, the next byte (which io.LimitReader would not yield)
// would indicate the entry was actually larger. We detect this by
// requesting maxBytes+1 from LimitReader and rejecting if we got
// exactly maxBytes+1 (entry continues past the cap).
func readZipEntryBounded(f *zip.File, maxBytes int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// LimitReader allows maxBytes+1 so we can detect overflow vs
	// "exactly maxBytes" (legitimate edge case).
	limited := io.LimitReader(rc, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("zip entry exceeds MaxArtifactBytes %d (zip-bomb defense)", maxBytes)
	}
	return raw, nil
}

// verifyAudioContentAddress checks that the audio file's path stem
// equals its computed SHA-256 (case-sensitive lowercase per spec
// §13.1). Returns nil on match, an error describing the divergence
// on mismatch.
//
// The loader's load_dirs.go:loadAudioFile already enforces lowercase-
// hex stem at Load() time, so a malformed audio path would fail
// Load() before this check runs. This function is the second layer:
// the path-stem-equals-SHA256 invariant is the load-bearing
// content-addressing claim, and this check verifies it explicitly
// per spec §13.2 ("the load-bearing check is `audio_ref.hash` ==
// file SHA-256 == path stem").
//
// **Coupling note for future contributors (M1 from commit-3 reviewer
// pass).** The `strings.Index(rest, ".")` first-dot parse is correct
// only because loadAudioFile rejects multi-dot stems at Load() time
// (its `len(stem) != 64 || !isLowercaseHex(stem)` check would reject
// e.g., "<wrong>.<good_hash>.wav"). A future "verify without loading"
// mode that bypasses Load() would silently weaken this check — anyone
// considering that refactor MUST move the stem-shape validation here
// or keep loadAudioFile in the path.
func verifyAudioContentAddress(path, computedHex string) error {
	rest := strings.TrimPrefix(path, "audio/")
	dotIdx := strings.Index(rest, ".")
	if dotIdx < 0 {
		return fmt.Errorf("audio path %q missing extension; spec §13.1 requires audio/<sha256>.<ext>", path)
	}
	stem := rest[:dotIdx]
	if stem != computedHex {
		return fmt.Errorf("audio filename stem %s does not equal computed sha256 %s (content-addressing broken)",
			truncate(stem, 16), truncate(computedHex, 16))
	}
	return nil
}

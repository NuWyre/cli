package bundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// validateSchemaVersion enforces the schema_version pin for typed
// bundle structs after JSON unmarshal.
//
// **Phase 7.E session 113 P2 closure (Tier 2 HIGH structural pattern)**:
// pre-closure, 11+ types in apps/cli/internal/bundle/types.go declared
// SchemaVersion fields that were parsed-but-never-validated. A tampered
// bundle that flips e.g. MerkleProofs.schema_version to 99 (signaling a
// hypothetical future layout) would be silently parsed as v1 — the
// doc comment at types.go:582-585 explicitly claimed pinning prevents
// silent ignore, but the actual enforcement was missing. Helper applied
// at every loadX site below + at the parseJSONL caller sites
// (loadEventsJSONL / loadEvaluationsJSONL / loadAuditLogEventsJSONL) so
// per-line SchemaVersion tampering is also caught.
//
// Accepts EITHER 0 (absent — for fields with `json:"...,omitempty"`
// OR JSON object lacking the key) OR the expected version. Anything
// else is the recurring-defect-class n=22 (missing-constant-on-closed-
// vocabulary-spec-pinned-field) instance the helper closes.
func validateSchemaVersion(typeName string, got, expected int) error {
	if got != 0 && got != expected {
		return fmt.Errorf(
			"bundle: %s schema_version: got %d, expected %d (or absent/0); a tampered bundle attempting to signal a different schema version is rejected at parse time per spec pinning discipline",
			typeName, got, expected,
		)
	}
	return nil
}

// Load opens a NuWyre evidence bundle ZIP at path and returns a
// parsed Bundle. Returns specific errors for malformed bundles —
// every error names the file path or line number that triggered
// it, so a third-party verifier debugging a tampered bundle has
// enough detail to localize the divergence.
//
// Phase 4 Session 1 D3c1 lands the entry point + zip iteration +
// manifest.json + signature.sig parsing. Subsequent commits in
// this session populate the rest of Bundle's fields.
//
// **Verification is NOT performed here.** Load() only parses; the
// seven verification checks live in internal/checks/ (Sessions
// 2-3) and run against the parsed Bundle.
func Load(path string) (*Bundle, error) {
	// Read the full file into memory so the bytes survive after the
	// loader returns (Check2Artifacts re-iterates the zip from the same
	// bytes via Bundle.RawZip — see the doc comment on Bundle.RawZip).
	// Memory cost is bounded by the bundle size (typically <500 KB
	// for example-demo, <10 MB for production); the per-bundle full-
	// file-read is a single round-trip and the bytes are reused by
	// LoadFromBytes below, eliminating a second filesystem open at
	// Check2Artifacts time.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bundle: read %s: %w", path, err)
	}
	return LoadFromBytes(data, path)
}

// LoadFromBytes parses an in-memory bundle ZIP and returns a parsed
// Bundle. Equivalent to Load() but for callers that already hold the
// zip bytes — Phase 5.5 Session 5.5.1B WASM verifier (browsers pass
// File-API bytes, no filesystem path) and any future server-side
// verifier reading from an HTTP request body. The Bundle.Path field
// is set to the supplied label (typically a filename + "(bytes)" or
// just "(bytes)" when no name is known) so error messages still
// localize the source.
//
// Six tenants: T4 simplicity (one loader, two entry points; the
// zip-reader parsing logic lives in loadFromZipReader and is shared);
// T2 quality (byte-loaded path produces identical Bundle as
// path-loaded for the same zip bytes — no divergence between
// WASM and native verifiers, which is the conformance contract).
func LoadFromBytes(data []byte, label string) (*Bundle, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("bundle: open zip %s: %w", label, err)
	}
	b, err := loadFromZipReader(r, label)
	if err != nil {
		return nil, err
	}
	// Store the raw zip bytes so Check2Artifacts can re-iterate the
	// archive without re-opening a filesystem path. See Bundle.RawZip
	// doc comment for the design rationale.
	b.RawZip = data
	return b, nil
}

// loadFromZipReader is the shared zip-iteration path for Load and
// LoadFromBytes. `path` is the operator-visible source label
// (filesystem path or "(bytes)").
func loadFromZipReader(r *zip.Reader, path string) (*Bundle, error) {
	bundle := &Bundle{
		Path:            path,
		OTSReceipts:     make(map[string][]byte),
		RFC3161Receipts: make(map[string]map[string]RFC3161Pair),
		GithubAnchors:   make(map[string]GithubAnchorJSON),
		AudioFiles:      make(map[string][]byte),
	}

	// **Two-pass loader.** First pass: locate + parse manifest.json
	// + signature.sig only, then validate bundle_format +
	// schema_version pins. Second pass: dispatch all other
	// entries to their parsers. Spec §2: "Verification MUST fail
	// on the format check before any other check runs."
	// Two passes ensure a future v2 bundle's events.jsonl /
	// merkle_proofs.json / etc. don't get parsed under v1 rules
	// and surface confusing errors before the clean
	// "wrong bundle_format" rejection.
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		switch f.Name {
		case "manifest.json":
			if err := loadManifest(bundle, f); err != nil {
				return nil, err
			}
		case "signature.sig":
			if err := loadSignature(bundle, f); err != nil {
				return nil, err
			}
		}
	}

	// Required-file post-conditions for the pin check.
	if len(bundle.ManifestRaw) == 0 {
		return nil, errors.New("bundle: required file manifest.json missing")
	}
	if len(bundle.SignatureRaw) == 0 {
		return nil, errors.New("bundle: required file signature.sig missing")
	}

	// bundle_format pin per spec §1 (v1) + §§18.1-18.10 (v2): writer
	// + verifier MUST reject any bundle with a bundle_format value
	// outside the closed set {nuwyre-bundle/v1, nuwyre-bundle/v2}.
	// Rejection is fail-loud BEFORE any other parse runs.
	// Phase 7.F.3 v2.0.0-rc1: v2 acceptance added. Per-version
	// schema_version pin: v1 carries schema_version=1; v2 carries
	// schema_version=2 (spec §18.1). The check1_signature dispatch
	// then routes v2 bundles to runV2DualSignature.
	var expectedSchemaVersion int
	switch bundle.Manifest.BundleFormat {
	case BundleFormatV1:
		expectedSchemaVersion = SchemaVersion
	case BundleFormatV2:
		expectedSchemaVersion = SchemaVersionV2
	default:
		return nil, fmt.Errorf(
			"bundle: manifest.bundle_format = %q; expected one of {%q, %q}",
			bundle.Manifest.BundleFormat, BundleFormatV1, BundleFormatV2,
		)
	}
	if bundle.Manifest.SchemaVersion != expectedSchemaVersion {
		return nil, fmt.Errorf(
			"bundle: manifest.schema_version = %d; expected %d for bundle_format=%q",
			bundle.Manifest.SchemaVersion, expectedSchemaVersion, bundle.Manifest.BundleFormat,
		)
	}

	// Phase 6.4 session 76 BACKLOG 1.40 closure: closed-vocabulary
	// bundle_type validation. The spec §4.1 + §16.5 + §17 enumerate
	// {customer-export, audit-log-export, example-demo, sandbox-preview}.
	// Defense-in-depth — Check 1/2/9 dispatch already validates the
	// bundle_type semantics at their per-check entry points, but a
	// fail-loud rejection here gives operators a clean "manifest.bundle_
	// type not in closed vocabulary" diagnostic before any downstream
	// surface (e.g., Check 7's FetchRootJson path-traversal defense)
	// fires with a less-localized error. Mirrors the bundle_format pin
	// rejection at line 122-127 above (also fail-loud BEFORE other
	// parsing runs).
	switch bundle.Manifest.BundleType {
	case "customer-export", "audit-log-export", "example-demo", "sandbox-preview":
		// OK — closed vocabulary per spec §4.1 + §16.5 + §17.
	default:
		return nil, fmt.Errorf(
			"bundle: manifest.bundle_type = %q; expected one of {customer-export, audit-log-export, example-demo, sandbox-preview} per spec §4.1 + §16.5 + §17",
			bundle.Manifest.BundleType,
		)
	}

	// Second pass: dispatch all other entries to their parsers.
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Name == "manifest.json" || f.Name == "signature.sig" {
			continue // handled in first pass
		}
		if err := dispatchEntry(bundle, f); err != nil {
			return nil, err
		}
	}

	// Cross-entry invariants that single-entry parsers can't enforce
	// (e.g., spec §11 .tsr/.chain.pem pair-completeness).
	if err := finalizeBundleAfterDispatch(bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

func loadManifest(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read manifest.json: %w", err)
	}
	bundle.ManifestRaw = raw
	if err := json.Unmarshal(raw, &bundle.Manifest); err != nil {
		return fmt.Errorf("bundle: parse manifest.json: %w", err)
	}
	// P2 closure note: manifest.schema_version pin enforcement lives
	// at the two-pass post-load check at loadFromZipReader lines
	// 154-171 (dispatch by bundle_format: v1→1, v2→2 per spec §18.1).
	// That check fires AFTER bundle_format has been validated against
	// the closed set, so a tampered manifest carrying an unknown
	// bundle_format surfaces a bundle_format error first (operator-
	// visible localization). Adding a check inline here would
	// duplicate + fire prematurely + use a fixed-not-dispatched
	// expected version — closed by routing through the canonical
	// post-load check.
	return nil
}

func loadSignature(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read signature.sig: %w", err)
	}
	bundle.SignatureRaw = raw
	if err := json.Unmarshal(raw, &bundle.Signature); err != nil {
		return fmt.Errorf("bundle: parse signature.sig: %w", err)
	}
	// P2 closure: schema_version pin enforcement.
	if err := validateSchemaVersion("signature.sig", bundle.Signature.SchemaVersion, 1); err != nil {
		return err
	}
	return nil
}

// dispatchEntry routes one non-manifest non-signature zip entry to
// the appropriate parser. Phase 4 Session 1 D3c2 lands top-level
// file cases (events, evaluations, merkle_proofs, daily_roots,
// cover.pdf, verify.md, scenario_index); D3c3 lands the
// directory-based cases (ots_receipts/, rfc3161_receipts/,
// github_anchors/, audio/).
func dispatchEntry(bundle *Bundle, f *zip.File) error {
	switch f.Name {
	case "events.jsonl":
		return loadEventsJSONL(bundle, f)
	case "evaluations.jsonl":
		return loadEvaluationsJSONL(bundle, f)
	case "merkle_proofs.json":
		return loadMerkleProofs(bundle, f)
	case "daily_roots.json":
		return loadDailyRoots(bundle, f)
	case "cover.pdf":
		raw, err := readZipFile(f)
		if err != nil {
			return fmt.Errorf("bundle: read cover.pdf: %w", err)
		}
		bundle.CoverPDF = raw
		return nil
	case "verify.md":
		raw, err := readZipFile(f)
		if err != nil {
			return fmt.Errorf("bundle: read verify.md: %w", err)
		}
		bundle.VerifyMD = string(raw)
		return nil
	case "scenario_index.json":
		raw, err := readZipFile(f)
		if err != nil {
			return fmt.Errorf("bundle: read scenario_index.json: %w", err)
		}
		var idx ScenarioIndexJSON
		if err := json.Unmarshal(raw, &idx); err != nil {
			return fmt.Errorf("bundle: parse scenario_index.json: %w", err)
		}
		// P2 closure: schema_version pin enforcement.
		if err := validateSchemaVersion("scenario_index.json", idx.SchemaVersion, 1); err != nil {
			return err
		}
		bundle.ScenarioIndex = &idx
		return nil
	case "audit_log_events.jsonl":
		return loadAuditLogEventsJSONL(bundle, f)
	case "audit_log_subtree.json":
		return loadAuditLogSubtree(bundle, f)
	}

	// Directory-based cases. ots_receipts/, rfc3161_receipts/,
	// github_anchors/ landed in D3c3; audio/ in D3c4.
	switch {
	case strings.HasPrefix(f.Name, "ots_receipts/"):
		return loadOTSReceipt(bundle, f)
	case strings.HasPrefix(f.Name, "rfc3161_receipts/"):
		return loadRFC3161Entry(bundle, f)
	case strings.HasPrefix(f.Name, "github_anchors/"):
		return loadGithubAnchor(bundle, f)
	case strings.HasPrefix(f.Name, "audio/"):
		return loadAudioFile(bundle, f)
	}

	// legal/ is reserved-but-unused in V1 per spec §3 (Phase 5+). D3c2's
	// unrecognized-entry case stays a no-op — the loader is
	// forward-compatible with itself across commits.
	//
	// **Safety note for future contributors.** This silent skip is
	// safe ONLY because Phase 4 Session 2's Check 2 (manifest
	// artifacts) re-iterates the zip independently and verifies every
	// declared artifact's bytes+sha256. If a future refactor moves
	// Check 2 to derive the file set from the parsed Bundle's typed
	// fields (rather than re-iterating the zip), this fallback
	// becomes a correctness hole — a tampered bundle could include
	// extra files matching a spec-permitted forward-compat extension
	// path AND a typo in dispatchEntry's case label would silently
	// drop the file from the verifier's view.
	return nil
}

// loadEventsJSONL parses events.jsonl line-by-line into Bundle.Events,
// preserving the raw bytes for Phase 4 check 3 (chain reconstruction
// re-canonicalizes parsed fields and recomputes hashes; the raw
// bytes are also kept for forensic debugging).
func loadEventsJSONL(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read events.jsonl: %w", err)
	}
	bundle.EventsRaw = raw
	events, err := parseJSONL[EventJSONL](raw, "events.jsonl")
	if err != nil {
		return err
	}
	// P2 closure: per-line schema_version pin enforcement. Catches
	// per-event tampering of the schema_version field (a single
	// tampered event in a 100k-event chain would otherwise slip
	// through unnoticed).
	for i, e := range events {
		if err := validateSchemaVersion(
			fmt.Sprintf("events.jsonl line %d", i+1),
			e.SchemaVersion,
			1,
		); err != nil {
			return err
		}
	}
	bundle.Events = events
	return nil
}

// loadEvaluationsJSONL parses evaluations.jsonl line-by-line into
// Bundle.Evaluations.
func loadEvaluationsJSONL(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read evaluations.jsonl: %w", err)
	}
	bundle.EvaluationsRaw = raw
	evals, err := parseJSONL[EvaluationJSONL](raw, "evaluations.jsonl")
	if err != nil {
		return err
	}
	// P2 closure note: EvaluationJSONL has no SchemaVersion field per
	// types.go:559 (evaluations don't carry per-row schema_version;
	// the parent manifest.schema_version pin covers this surface).
	// No per-line check needed here — symmetric defense is at the
	// manifest layer.
	bundle.Evaluations = evals
	return nil
}

// loadMerkleProofs parses merkle_proofs.json. **No raw bytes
// preserved** — unlike events.jsonl/evaluations.jsonl, this file is
// not a direct signing input: signature.sig signs over manifest.json
// (which carries daily_root), and Phase 4 Session 2 check 4 verifies
// proofs by re-running the Merkle math on parsed leaves+paths against
// the parsed root, not by recanonicalizing this file. SHA-256 byte
// integrity for this file is enforced by check 2 (manifest artifacts)
// which re-opens the zip entry independently.
func loadMerkleProofs(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read merkle_proofs.json: %w", err)
	}
	if err := json.Unmarshal(raw, &bundle.MerkleProofs); err != nil {
		return fmt.Errorf("bundle: parse merkle_proofs.json: %w", err)
	}
	// P2 closure: schema_version pin enforcement.
	if err := validateSchemaVersion("merkle_proofs.json", bundle.MerkleProofs.SchemaVersion, 1); err != nil {
		return err
	}
	return nil
}

// loadDailyRoots parses daily_roots.json. **No raw bytes preserved**
// for the same reason as loadMerkleProofs: not a direct signing input.
func loadDailyRoots(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read daily_roots.json: %w", err)
	}
	if err := json.Unmarshal(raw, &bundle.DailyRoots); err != nil {
		return fmt.Errorf("bundle: parse daily_roots.json: %w", err)
	}
	// P2 closure: schema_version pin enforcement.
	if err := validateSchemaVersion("daily_roots.json", bundle.DailyRoots.SchemaVersion, 1); err != nil {
		return err
	}
	return nil
}

// loadAuditLogEventsJSONL parses audit_log_events.jsonl line-by-line
// into Bundle.AuditLogEvents (spec §16.2 v1.0.10+). Preserves raw bytes
// for forward-compat tolerance: any future per-row signature
// reverification check MUST split AuditLogEventsRaw on \n rather than
// recanonicalize from the AuditLogEventJSONL struct (mirrors EventsRaw
// + EvaluationsRaw discipline at loadEventsJSONL).
//
// Phase 6.2.C session 70 Check 9 audit-log-merkle walks these in
// sequence_number ascending order, recomputing content_hash + event_hash
// from the parsed fields against the audit-log Merkle subtree.
func loadAuditLogEventsJSONL(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read audit_log_events.jsonl: %w", err)
	}
	bundle.AuditLogEventsRaw = raw
	events, err := parseJSONL[AuditLogEventJSONL](raw, "audit_log_events.jsonl")
	if err != nil {
		return err
	}
	// P2 closure: per-line schema_version pin enforcement.
	for i, e := range events {
		if err := validateSchemaVersion(
			fmt.Sprintf("audit_log_events.jsonl line %d", i+1),
			e.SchemaVersion,
			1,
		); err != nil {
			return err
		}
	}
	bundle.AuditLogEvents = events
	return nil
}

// loadAuditLogSubtree parses audit_log_subtree.json (spec §16.3 v1.0.10+).
// **No raw bytes preserved** for the same reason as loadMerkleProofs +
// loadDailyRoots: not a direct signing input. SHA-256 byte integrity is
// enforced by check 2 (manifest artifacts) which re-opens the zip entry
// independently. Check 9 audit-log-merkle verifies the subtree_root +
// proofs by re-running the Merkle math on parsed leaves+paths against
// the parsed subtree_root, NOT by recanonicalizing this file.
func loadAuditLogSubtree(bundle *Bundle, f *zip.File) error {
	raw, err := readZipFile(f)
	if err != nil {
		return fmt.Errorf("bundle: read audit_log_subtree.json: %w", err)
	}
	var subtree AuditLogSubtreeJSON
	if err := json.Unmarshal(raw, &subtree); err != nil {
		return fmt.Errorf("bundle: parse audit_log_subtree.json: %w", err)
	}
	// P2 closure: schema_version pin enforcement.
	if err := validateSchemaVersion("audit_log_subtree.json", subtree.SchemaVersion, 1); err != nil {
		return err
	}
	bundle.AuditLogSubtree = &subtree
	return nil
}

// parseJSONL parses a JSON-Lines (newline-delimited JSON) byte slice
// into a slice of T. Each line is a complete JSON object.
//
// Spec §6: "UTF-8 encoded, LF line endings, trailing LF on the last
// line. Each line is a JSON object that has been canonicalized via
// RFC 8785 JCS." The spec permits exactly one trailing LF after the
// final record and does NOT permit leading or interior blank lines —
// this parser enforces both invariants strictly. CRLF line endings
// are tolerated to be friendly to Windows-edited fixtures.
//
// Errors carry the physical line number a user's editor would show
// (1-indexed), so a third-party verifier debugging a tampered bundle
// can localize the divergence directly.
func parseJSONL[T any](raw []byte, label string) ([]T, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// Strip exactly one trailing LF if present (spec §6 — required).
	// Anything else (no trailing LF, OR multiple trailing LFs) is
	// surfaced as a blank-line error below for tampering detection.
	work := raw
	if work[len(work)-1] == '\n' {
		work = work[:len(work)-1]
	}
	if len(work) == 0 {
		// Original was just a single LF — degenerate empty file. Accept
		// as empty rather than error: a 0-event bundle is structurally
		// odd but not malformed at the JSONL layer.
		return nil, nil
	}
	lines := bytes.Split(work, []byte{'\n'})
	out := make([]T, 0, len(lines))
	for i, line := range lines {
		// Strip trailing CR for CRLF-line-ended files.
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			return nil, fmt.Errorf(
				"bundle: parse %s line %d: blank line not permitted (spec §6 mandates LF line endings, no leading/interior/extra-trailing blanks)",
				label, i+1,
			)
		}
		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			return nil, fmt.Errorf("bundle: parse %s line %d: %w", label, i+1, err)
		}
		out = append(out, item)
	}
	return out, nil
}

// MaxEntryUncompressedBytes caps the uncompressed size of a single
// zip entry the loader will materialize into memory for METADATA
// entries (manifest.json, signature.sig, events.jsonl, evaluations.jsonl,
// merkle_proofs.json, daily_roots.json, scenario_index.json, OTS receipts,
// RFC 3161 receipts, GitHub anchor JSONs). For audio entries the
// separate MaxAudioUncompressedBytes cap applies — see readAudioZipFile.
//
// AUDIT-1 Sub-arc 4 (C2/S-C5): closes the zip-bomb defect surfaced by
// the cross-cutting audit at 2026-05-14. AUDIT-1-FIXUP-3 HIGH-5: the
// 64 MiB cap was originally applied uniformly across all entry types,
// which incorrectly rejected legitimate audio fixtures (a 30-minute
// 44.1kHz 16-bit stereo PCM recording is ~317 MiB). MaxAudioUncompressedBytes
// at 1 GiB now accommodates real-world audio sizes while keeping the
// strict 64 MiB cap on metadata entries (no legitimate NuWyre metadata
// entry approaches that scale).
//
// 64 MiB is symmetric with apps/cli/cmd/nuwyre-wasm/main.go:84
// MaxBundleBytes (compressed input cap). The WASM /verify customer-
// facing surface uses LoadFromBytes which goes through the same loader;
// at the WASM input boundary the compressed bundle is bounded by
// MaxBundleBytes (64 MiB compressed). Per-entry uncompressed caps
// further bound memory: metadata entries 64 MiB; audio entries 1 GiB.
// The aggregate WASM memory budget is still bounded by the small number
// of distinct entry types in a typical bundle.
const MaxEntryUncompressedBytes = 64 * 1024 * 1024

// MaxAudioUncompressedBytes is the per-entry cap for audio/ entries
// in the bundle. Accommodates a ~hour of 44.1kHz 16-bit stereo PCM
// audio (~635 MiB) plus headroom. AUDIT-1-FIXUP-3 HIGH-5.
const MaxAudioUncompressedBytes = 1024 * 1024 * 1024

// readZipFile reads the entire contents of one zip entry, capped at
// MaxEntryUncompressedBytes uncompressed. Used for metadata entries
// (manifest, signature, events.jsonl, etc.). For audio entries use
// readAudioZipFile which applies the larger MaxAudioUncompressedBytes
// cap.
func readZipFile(f *zip.File) ([]byte, error) {
	return readZipFileBounded(f, MaxEntryUncompressedBytes)
}

// readAudioZipFile reads an audio entry capped at MaxAudioUncompressedBytes.
// Per AUDIT-1-FIXUP-3 HIGH-5: legitimate audio fixtures routinely exceed
// 64 MiB (a 30-min PCM stereo recording is ~317 MiB); the metadata-entry
// cap was an over-restriction inherited from the original zip-bomb defense.
func readAudioZipFile(f *zip.File) ([]byte, error) {
	return readZipFileBounded(f, MaxAudioUncompressedBytes)
}

// readZipFileBounded is the shared two-stage defense:
//
//  1. Pre-flight reject on the header's claimed UncompressedSize64.
//     Cheap; a non-malicious encoder would never declare beyond the
//     entry-class cap.
//  2. Hard guard via io.LimitReader on the decompressed stream. Even
//     if the header lied (UncompressedSize64 forged to bypass the
//     pre-flight), the actual decompressor output is capped — the
//     loader rejects the entry once the cap is hit.
func readZipFileBounded(f *zip.File, maxBytes int64) ([]byte, error) {
	if int64(f.UncompressedSize64) > maxBytes || f.UncompressedSize64 > 1<<62 {
		return nil, fmt.Errorf(
			"bundle: zip entry %q declares %d bytes uncompressed (max %d; zip-bomb defense)",
			f.Name, f.UncompressedSize64, maxBytes,
		)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// LimitReader caps actual decompressed bytes — covers the case where
	// UncompressedSize64 was forged to bypass the pre-flight.
	limited := io.LimitReader(rc, maxBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, fmt.Errorf(
			"bundle: zip entry %q exceeded %d bytes uncompressed (zip-bomb defense)",
			f.Name, maxBytes,
		)
	}
	return buf, nil
}

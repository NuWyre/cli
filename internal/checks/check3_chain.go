package checks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/nuwyre/cli/internal/bundle"
	"github.com/nuwyre/cli/internal/keys"
)

// MaxChainEvents bounds the per-bundle chain-walk iteration count in
// Check3Chain. Phase 7.E session 118 H3 closure (sequence_number
// upper bound): a malicious bundle with phantom-event padding could
// force a huge chain-walk even if Check 2's MaxTotalDecompressedBytes
// caps the JSONL size. 10 million events is well above the largest
// customer bundle observed to date (~50K events) and bounds verifier
// latency at <100ms even on slow hardware. Operators with legitimately
// larger bundles should split into multiple bundles or use a future
// streaming-verify mode.
//
// **Layering note** (crypto-int L-3 inline closure): Check 2's
// MaxTotalDecompressedBytes (2 GiB) caps total JSONL bytes which at
// ~500 bytes/event = ~4M events — well under MaxChainEvents. So this
// bound is the second-line defense if Check 2 is bypassed (e.g., a
// future streaming-verify mode that skips re-iterating the zip).
const MaxChainEvents int64 = 10_000_000

// MaxAuditLogEvents bounds the per-bundle chain-walk iteration count
// in Check9AuditLogMerkle. Symmetric with MaxChainEvents — same value,
// same rationale, same phantom-event-padding defense. Closes the
// recurring-defect-class n=24+ defensive-helper-bypass that fired
// across sessions 115/116/117/118 — defense applied to primary substrate,
// symmetric audit-log substrate missed.
const MaxAuditLogEvents int64 = 10_000_000

// Check3Chain verifies the spec §6 hash-chain reconstruction contract
// per spec §6.2 (per-organization chain semantics) + §6.3 (decoded-hex
// event_hash byte signatures):
//
//   - Sort all events by sequence_number across the bundle (no grouping
//     by session_id; session_id is a column tag preserved on each
//     event but does NOT participate in chain construction).
//   - Walk the chain in sequence order:
//   - Sequence is gap-free monotonic starting at 0; a gap is the
//     canonical signal of whole-event deletion or reordering.
//   - For each event, recompute content_hash from the canonical
//     content payload and confirm it equals the row's declared
//     content_hash.
//   - For sequence 0 (genesis), prev_event_hash MUST equal
//     GENESIS_PREV_HASH; for every subsequent event,
//     prev_event_hash MUST equal the prior event's event_hash
//     regardless of session boundary.
//   - Recompute event_hash from {content_hash, prev_event_hash,
//     sequence_number, timestamp_unix_ns} and confirm it equals
//     the row's declared event_hash.
//   - Verify ingestion_signature: Ed25519 over the decoded-hex
//     bytes of event_hash, against the issuer key dispatched by
//     the same logic as Check 1.
//
// Path A.1 reconciliation (2026-05-10) closes the divergence the
// Phase 4 Session 2 implementation surfaced. Pre-amendment, this
// check grouped events by session_id and walked per-session — matching
// the example bundle (compose-events.ts pre-amendment emitted
// per-session) but failing on production-canonical bundles
// (per-organization chain via organization_chain_state). Post-amendment
// (commits 660a53a schema, 2f6620d compose-events.ts, 0244707
// verify-bundle.ts, this commit), all consumers enforce per-organization
// chain semantics and the cross-implementation oracle property is
// meaningful.
//
// Independence from Check 1: Check 3 dispatches the issuer key by the
// same bundle_type → key logic as Check 1, but does NOT honor the
// AllowDevKey policy gate. Check 1 is the policy authority; Check 3
// is the cryptographic authority. If a bundle dispatches to the dev
// key and AllowDevKey=false, Check 1 surfaces the policy fail; Check
// 3 still verifies the cryptographic chain (succeeds in happy path).
// Both checks contribute independently to the aggregate verdict.
//
// **Placeholder prod key**: if dispatch lands on issuer-prod-v1 with
// the placeholder fingerprint, Check 3 cannot verify per-event
// signatures (no real public key) and short-circuits with Fail. Same
// posture as Check 1's placeholder branch.
//
// **Cross-implementation oracle parity** with the TS verifier at
// packages/example-bundle/scripts/verify-bundle.ts: same sort order
// (sequence_number ASC), same gap-free monotonic check, same genesis
// detection (sequence 0 → expect GENESIS_PREV_HASH; non-zero → expect
// prior event_hash), same break-on-first-error walk discipline. Both
// verifiers MUST produce equivalent PASS/FAIL verdicts on identical
// bundles.
type Check3Chain struct{}

// **Phase 5+ verifier tightening bookmark** (Phase 5.5 Session 5.5.1B
// reviewer-batch finding: crypto-int M5 — methodology-vs-implementation
// drift on file-line ordering): the current V1 check 3 walks per-
// organization chains via prev_event_hash links but does NOT enforce
// that events appear in sequence_number order within events.jsonl. A
// swap of two same-session adjacent events does NOT trigger check 3 —
// the chain links still resolve, just discovered in a different file
// order. The `swapped-event` conformance fixture pins this V1 baseline
// as-is. Phase 5+ tightening: enforce file-line monotonicity per
// methodology §02-integrity-model.md "events ordered by sequence_number
// within each session" — assert that lines[i+1].sequence_number > lines[i].sequence_number
// for any two adjacent same-session events. When tightening lands:
// regenerate the swapped-event fixture's results.json with check 3 = fail.
// Preservation surface 1 of 3 (code FIXME); surface 2 = ops log entry
// at Session 5.5.1B closure; surface 3 = README PROVISIONAL banner.
func (Check3Chain) ID() int      { return 3 }
func (Check3Chain) Name() string { return "hash chain" }
func (Check3Chain) Slug() string { return "hash-chain" }

func (c Check3Chain) Run(b *bundle.Bundle, _ CheckOptions) CheckResult {
	const id = 3
	const checkName = "hash chain"
	const slug = "hash-chain"

	var errs []error
	var warnings []error

	if len(b.Events) == 0 {
		// Phase 7.D session 88 — BACKLOG 1.48 A.1.2 closure: empty
		// events.jsonl is structurally valid for audit-log-export
		// bundles per spec §16.5 (operator-only subtype + customer-
		// scoped subtype with no primary events that day) + §16.3.1
		// (empty-subtree daily_root composition: events_subtree_root_
		// bytes = 32 zero bytes per the empty-subtree canonical
		// sentinel). The audit-log chain integrity is verified at
		// Check 9 (audit-log-merkle) which walks audit_log_events.jsonl
		// + the audit_log_subtree.json proofs. Check 3 (primary event
		// chain) has nothing to verify and SKIPs.
		//
		// For all other bundle_types (customer-export, example-demo,
		// sandbox-preview, fail-secure default), empty events.jsonl
		// remains a fatal structural anomaly per the original M1 from
		// D4 reviewer pass rationale (mirrors verify-bundle.ts:371-373
		// cross-implementation oracle parity).
		if b.Manifest.BundleType == "audit-log-export" {
			return Skipped(id, checkName, slug,
				"audit-log-export bundle with empty events.jsonl; audit-log chain integrity verified at Check 9 per spec §16.2.2 + §16.3.1 empty-subtree composition")
		}
		// M1 from D4 reviewer pass: an empty events.jsonl is a
		// structural anomaly worth failing loudly. Spec §4.1 requires
		// manifest.event_count == lines in events.jsonl; a 0-event
		// bundle either has manifest.event_count == 0 (no chain to
		// verify) or manifest.event_count > 0 (count mismatch).
		// Either way, "Pass on 0 events" is a confusing affordance
		// for the operator. Mirrors verify-bundle.ts:371-373 (TS
		// returns fail on empty events.jsonl) — closes the
		// cross-implementation oracle parity gap the reviewer
		// surfaced.
		errs = append(errs, Errorf(id, checkName, "events.jsonl",
			"events.jsonl is empty; no chain to verify",
			SpecRefHashChain, "events.jsonl carries at least one event for the bundle's window"))
		return Result(id, checkName, slug, errs, warnings)
	}

	// Dispatch issuer key by the same logic as Check 1 (independent
	// of AllowDevKey — see type doc).
	generatedAt, ok := parseGeneratedAt(b.Manifest.GeneratedAt)
	if !ok {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("generated_at = %q is not valid RFC 3339; cannot dispatch issuer key for ingestion_signature verification", b.Manifest.GeneratedAt),
			SpecRefManifestFields, "generated_at is RFC 3339 / ISO-8601 UTC"))
		return Result(id, checkName, slug, errs, warnings)
	}
	pinned, err := keys.KeyForBundle(b.Manifest.BundleType, generatedAt)
	if err != nil {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("no pinned issuer key for bundle_type=%q at generated_at=%q (%v)",
				b.Manifest.BundleType, b.Manifest.GeneratedAt, err),
			SpecRefSignature, "verifier expects a pinned key for the bundle's bundle_type"))
		return Result(id, checkName, slug, errs, warnings)
	}

	if pinned.SPKIFingerprintB64 == keys.PlaceholderProdFingerprint {
		errs = append(errs, Errorf(id, checkName, "",
			fmt.Sprintf("cannot verify per-event ingestion_signature: this binary's pinned %s key is a placeholder (Phase 5 deploy-bootstrap pending)", pinned.KeyID),
			SpecRefSignature, "production binaries embed the real prod-key SPKI"))
		return Result(id, checkName, slug, errs, warnings)
	}

	// Topology-aware per-event signature key selection per spec §6.3
	// + §6.5.6 (v1.0.9 amendment). Under single-key topology (legacy +
	// customer-export + example-demo) the pub is the pinned issuer key.
	// Under ephemeral-sessions topology (sandbox-preview at v1.0.9) the
	// pub is the recomputed ephemeral SPKI populated by Check 8 in
	// b.EphemeralPubkeyByID. v1.0.9 sandbox-preview cardinality is
	// exactly one ephemeral session per bundle, so all events route
	// through the single entry; the map lookup is trivial.
	//
	// Unknown-topology gate per spec §5 v1.0.9 (crypto-integrity-reviewer
	// H3, 2026-05-15): any topology value outside the closed
	// {"" (absent), "single-key", "ephemeral-sessions"} vocabulary is
	// a v2+ extension a v1.0.9 verifier cannot handle. Refuse rather
	// than silently fall through to single-key dispatch — Check 8
	// already does this; Check 3 mirrors for defense-in-depth.
	topology := b.Manifest.Signing.Topology
	if topology != "" && topology != "single-key" && topology != "ephemeral-sessions" {
		errs = append(errs, Errorf(id, checkName, "manifest.json",
			fmt.Sprintf("signing.topology=%q is not in the v1.0.9 closed vocabulary {single-key, ephemeral-sessions}; refusing to route per-event signatures", topology),
			SpecRefSignature,
			"signing.topology closed-vocabulary discipline per spec §5 v1.0.9 amendment"))
		return Result(id, checkName, slug, errs, warnings)
	}
	var pub ed25519.PublicKey
	if topology == "ephemeral-sessions" {
		// Check 8 MUST have run before us. If it didn't (or it failed),
		// b.EphemeralPubkeyByID is nil. Refuse to fall back to single-
		// key dispatch — that would silently misverify ephemeral
		// signatures against the dev key. Surface as Fail so the
		// operator localizes the upstream Check 8 failure.
		if len(b.EphemeralPubkeyByID) == 0 {
			errs = append(errs, Errorf(id, checkName, "manifest.json",
				"topology=ephemeral-sessions but bundle.EphemeralPubkeyByID is empty (Check 8 must run successfully before Check 3 under ephemeral-sessions topology)",
				SpecRefSignature,
				"per-event signature verification routes through the Check 8-populated ephemeral SPKI map per spec §6.5.6"))
			return Result(id, checkName, slug, errs, warnings)
		}
		// v1.0.9 sandbox-preview: pick the single entry. (Future v2
		// multi-session impl would look up by event.identity.session_id;
		// for v1.0.9 the spec mandates exactly one ephemeral session
		// per bundle so any event_id routes to the same SPKI.)
		for _, ephemeralPubKey := range b.EphemeralPubkeyByID {
			pub = ephemeralPubKey
			break
		}
	} else {
		// Single-key topology (or topology field absent): use the
		// pinned issuer key for per-event signature verification.
		var err error
		pub, err = parseEd25519SPKI(pinned.SPKIFingerprintB64)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, "",
				fmt.Sprintf("internal: pinned %s SPKI parse failed: %v", pinned.KeyID, err),
				SpecRefSignature, "pinned issuer key is Ed25519"))
			return Result(id, checkName, slug, errs, warnings)
		}
	}

	// Per-organization chain semantics (Path A.1, 2026-05-10 + spec
	// §6.2). Sort all events by sequence_number across the bundle.
	// session_id is preserved as a column tag for forensic localization
	// but does NOT participate in chain reconstruction. The chain is
	// gap-free monotonically increasing starting at sequence 0;
	// prev_event_hash references span session boundaries.
	sortedEvents := make([]bundle.EventJSONL, len(b.Events))
	copy(sortedEvents, b.Events)
	sort.SliceStable(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].Forensic.SequenceNumber < sortedEvents[j].Forensic.SequenceNumber
	})

	// Phase 7.E session 118 H3 closure (upper bound) — code-rev L-1
	// ordering inline: cap check is O(1) `len`, must run BEFORE the
	// O(n) negative-seq scan so a 1B-event tampered bundle aborts
	// after the cheap check rather than burning iterations.
	// MaxChainEvents documented at package-level constant above.
	if int64(len(sortedEvents)) > MaxChainEvents {
		errs = append(errs, Errorf(id, checkName, "events.jsonl",
			fmt.Sprintf("event count %d exceeds MaxChainEvents %d; refusing to walk (zip-bomb / phantom-event-padding defense; per-invocation chain-walk budget bounded for predictable verifier latency)",
				len(sortedEvents), MaxChainEvents),
			SpecRefHashChain, "per-bundle event count is bounded for predictable verifier latency"))
		return Result(id, checkName, slug, errs, warnings)
	}

	// Phase 7.E session 118 H3 closure (sequence_number bound):
	// reject events with negative SequenceNumber. JSON admits any
	// int64 including negatives; the chain-walk's monotonic check
	// catches mismatches against expectedSequence=0 on the first
	// iteration, but a negative SequenceNumber slipping through any
	// future refactor (or non-chain-walk consumer) could compute
	// nonsensical statistics. Defense-in-depth: surface negative
	// values as structured CHECK violations.
	//
	// crypto-int L-1 inline closure: accumulate ALL negative-seq
	// errors before returning, mirroring the rest of Check 3's
	// error-accumulation pattern. Prior version returned on first
	// negative-seq event, which meant a 100-event bundle with all
	// negative seqs surfaced only the first; the operator had to
	// patch + re-run 100 times to see them all.
	negSeqFound := false
	for _, ev := range sortedEvents {
		if ev.Forensic.SequenceNumber < 0 {
			errs = append(errs, Errorf(id, checkName, fmt.Sprintf("events.jsonl line ?, sequence_number=%d", ev.Forensic.SequenceNumber),
				fmt.Sprintf("sequence_number %d is negative; spec §6.2 requires non-negative monotonic chain starting at 0", ev.Forensic.SequenceNumber),
				SpecRefHashChain, "events.jsonl carries a gap-free per-(organization_id, sequence_number) chain starting at sequence 0; all values are non-negative"))
			negSeqFound = true
		}
	}
	if negSeqFound {
		return Result(id, checkName, slug, errs, warnings)
	}

	expectedSequence := int64(0)
	prevHash := bundle.GenesisPrevHash

	for _, ev := range sortedEvents {
		seq := ev.Forensic.SequenceNumber
		loc := fmt.Sprintf("events.jsonl seq=%d session=%s", seq, shortID(ev.Identity.SessionID))

		// 1. Gap-free monotonic check. seq must equal expectedSequence
		// — gap (e.g., expected 5 got 7), wrong-genesis (sequence
		// starts at 1), repeated sequence (caught as second event's
		// `seq != expectedSequence + 1` after first increments
		// expectedSequence). Mirrors verify-bundle.ts gap-detection.
		if seq != expectedSequence {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("sequence gap — expected %d, got %d (whole-event deletion or reordering)",
					expectedSequence, seq),
				SpecRefHashChain, "events.jsonl carries a gap-free per-(organization_id, sequence_number) chain starting at sequence 0"))
			break // chain semantics broken from here
		}

		// 2. content_hash recompute + compare.
		recomputedContentHash, err := computeContentHashGo(ev.Content)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("content_hash canonicalization failed: %v", err),
				SpecRefHashChain, "content payload canonicalizes to RFC 8785 JCS"))
			break
		}
		if recomputedContentHash != ev.Content.ContentHash {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("content_hash mismatch: recomputed=%s declared=%s",
					truncate(recomputedContentHash, 16), truncate(ev.Content.ContentHash, 16)),
				SpecRefHashChain, "content_hash equals SHA-256 of canonical content payload"))
			break
		}

		// 3. prev_event_hash chain check. Genesis (seq 0) expects
		// GENESIS_PREV_HASH; every subsequent event expects the
		// prior event's event_hash regardless of session membership.
		if ev.Forensic.PrevEventHash != prevHash {
			var expectation string
			if seq == 0 {
				expectation = "GENESIS_PREV_HASH"
			} else {
				expectation = fmt.Sprintf("prior event's event_hash %s", truncate(prevHash, 16))
			}
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("prev_event_hash mismatch — expected %s, got %s",
					expectation, truncate(ev.Forensic.PrevEventHash, 16)),
				SpecRefHashChain, "every event's prev_event_hash equals the prior event's event_hash within the same organization's chain (GENESIS_PREV_HASH for sequence 0); chain spans session boundaries"))
			break
		}

		// 4. event_hash recompute + compare.
		recomputedEventHash, err := computeEventHashGo(
			ev.Content.ContentHash,
			ev.Forensic.PrevEventHash,
			ev.Forensic.SequenceNumber,
			ev.Forensic.TimestampUnixNs,
		)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("event_hash canonicalization failed: %v", err),
				SpecRefHashChain, "event payload canonicalizes to RFC 8785 JCS"))
			break
		}
		if recomputedEventHash != ev.Forensic.EventHash {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("event_hash mismatch: recomputed=%s declared=%s",
					truncate(recomputedEventHash, 16), truncate(ev.Forensic.EventHash, 16)),
				SpecRefHashChain, "event_hash equals SHA-256 of canonical {content_hash, prev_event_hash, sequence_number, timestamp_unix_ns}"))
			break
		}

		// 5. ingestion_signature: Ed25519 over decoded-hex event_hash bytes.
		eventHashBytes, err := hex.DecodeString(ev.Forensic.EventHash)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("event_hash hex-decode failed: %v", err),
				SpecRefEventSignature, "event_hash is 64-char lowercase hex"))
			break
		}
		sig, err := base64.StdEncoding.DecodeString(ev.Forensic.IngestionSignature)
		if err != nil {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("ingestion_signature base64-decode failed: %v", err),
				SpecRefEventSignature, "ingestion_signature is base64-encoded Ed25519 signature"))
			break
		}
		if len(sig) != ed25519.SignatureSize {
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("ingestion_signature decoded to %d bytes, expected %d", len(sig), ed25519.SignatureSize),
				SpecRefEventSignature, "Ed25519 signatures are 64 bytes"))
			break
		}
		if !ed25519.Verify(pub, eventHashBytes, sig) {
			// Topology-aware error message per spec §6.3 + §6.5.6.
			var keyLabel, ruleText string
			if topology == "ephemeral-sessions" {
				keyLabel = "ephemeral session key"
				ruleText = "ingestion_signature verifies over event_hash bytes under the bundle's ephemeral session SPKI per spec §6.5.6"
			} else {
				keyLabel = fmt.Sprintf("pinned %s key", pinned.KeyID)
				ruleText = "ingestion_signature verifies over event_hash bytes under the pinned issuer key"
			}
			errs = append(errs, Errorf(id, checkName, loc,
				fmt.Sprintf("ingestion_signature Ed25519 verification failed against %s", keyLabel),
				SpecRefEventSignature, ruleText))
			break
		}

		prevHash = ev.Forensic.EventHash
		expectedSequence = seq + 1
	}

	return Result(id, checkName, slug, errs, warnings)
}

// shortID returns the first 8 chars of an ID for log-friendly display.
// Mirrors the TS verifier's shortId helper at
// packages/example-bundle/scripts/verify-bundle.ts.
func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// parseEd25519SPKI decodes a base64 SPKI DER and returns the Ed25519
// public key. Mirrors the SPKI handling in Check1Signature.Run; kept
// as a private helper here so each check is self-contained without
// reaching into another check's internals.
func parseEd25519SPKI(spkiB64 string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("PKIX parse: %w", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not ed25519.PublicKey", pubAny)
	}
	return pub, nil
}

// =============================================================================
// Canonical JSON + content/event hash helpers
// =============================================================================

// canonicalJSON returns the RFC 8785 JCS canonical encoding of v.
// Implementation: hand v to a json.Encoder with HTML-escape disabled,
// then post-process to restore raw UTF-8 for U+2028/U+2029 (which
// Go's json.Encoder always escapes regardless of SetEscapeHTML — a
// load-bearing divergence from the TS reference at
// packages/schema/src/canonical.ts).
//
// Go's json package since 1.12 sorts map keys alphabetically (matches
// JCS UTF-16 ordering for ASCII-only keys, which is what the v1
// hashing payloads use per spec §6.1; for code points ≤ U+FFFF, UTF-8
// byte order and UTF-16 code unit order produce the same string
// ordering — they only diverge on supplementary code points beyond
// U+FFFF, which our payload keys never contain).
//
// **Caveats vs strict RFC 8785 JCS:**
//
//   - String escapes for control chars match (\b\f\n\r\t plus \u00XX
//     for unprintable; raw UTF-8 for printable non-ASCII).
//   - U+2028 and U+2029 are post-processed to raw UTF-8 (M1 fix from
//     commit-4 reviewer pass: Go's json.Encoder escapes these as
//     /  even with SetEscapeHTML(false); JCS emits raw
//     bytes). The post-process is a literal byte substitution and is
//     safe because the only way ` ` appears in encoder output is
//     as the encoded form of U+2028 — actual literal backslash-u-2028
//     in input would be encoded as `\\u2028` (escaped backslash).
//   - Non-finite floats are rejected by json.Marshal (matches JCS).
//   - Numbers: integers emit without decimal point; floats use
//     shortest-roundtrip per ECMA-262 §7.1.12 (Go's strconv default
//     for float64). Matches JS Number.toString.
//
// This canonicalizer is sufficient for the v1 hashing payloads
// (content_hash, event_hash); it is NOT a general-purpose JCS
// library. The cross-implementation oracle tests
// TestCheck3CrossImplementationContentHash + ...EventHash assert
// byte-identical SHA-256 output for the example bundle's events
// against the TS reference implementation's canonical bytes.
func canonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	out := buf.Bytes()
	// json.Encoder.Encode appends a newline; strip it for byte-exact
	// hashing input parity with TS's canonicalize() (which returns a
	// string with no trailing newline).
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	// M1 fix: restore raw UTF-8 for U+2028 / U+2029. Go's json
	// package escapes these as 6-ASCII-byte sequences even with
	// SetEscapeHTML(false); JCS emits raw 3-byte UTF-8.
	out = restoreJCSLineSeparators(out)
	return out, nil
}

// jcsU2028Escape and jcsU2029Escape are the 6-ASCII-byte escape
// sequences Go's json.Encoder always emits for U+2028 and U+2029.
// JCS emits raw 3-byte UTF-8 instead.
var (
	jcsU2028Escape = []byte{'\\', 'u', '2', '0', '2', '8'}
	jcsU2029Escape = []byte{'\\', 'u', '2', '0', '2', '9'}
	jcsU2028Raw    = []byte{0xe2, 0x80, 0xa8}
	jcsU2029Raw    = []byte{0xe2, 0x80, 0xa9}
)

// restoreJCSLineSeparators replaces Go-encoded U+2028 / U+2029 escape
// sequences with raw UTF-8 bytes per RFC 8785.
//
// **Backslash-parity correctness.** A naive bytes.ReplaceAll for the
// 6-byte literal " " would also match the trailing 6 bytes of
// "\\u2028" (Go's encoding of an input string containing literal
// backslash + "u2028"), silently corrupting that input into raw
// U+2028. The scanner below walks left-to-right and only treats
// " " / " " as an encoder escape when preceded by an EVEN
// number of consecutive backslashes (0 = the bare encoder escape;
// 2/4/... = the input contains escaped-backslash pairs followed by
// the encoder escape, still safe to replace). An ODD count means the
// immediately-preceding backslash escapes the "u2028"-as-bare-ASCII
// case — leave it alone.
//
// Discovered by TestRestoreJCSLineSeparatorsLeavesEscapedBackslashAlone
// in commit-4 reviewer's M1-fix follow-up.
func restoreJCSLineSeparators(out []byte) []byte {
	if !bytes.Contains(out, jcsU2028Escape) && !bytes.Contains(out, jcsU2029Escape) {
		return out
	}
	result := make([]byte, 0, len(out))
	i := 0
	for i < len(out) {
		// Try to match   or   at position i.
		if i+5 < len(out) && out[i] == '\\' && out[i+1] == 'u' &&
			out[i+2] == '2' && out[i+3] == '0' && out[i+4] == '2' &&
			(out[i+5] == '8' || out[i+5] == '9') {
			// Count consecutive backslashes immediately before i.
			bs := 0
			for j := i - 1; j >= 0 && out[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				// Bare encoder escape — replace with raw UTF-8.
				if out[i+5] == '8' {
					result = append(result, jcsU2028Raw...)
				} else {
					result = append(result, jcsU2029Raw...)
				}
				i += 6
				continue
			}
			// Odd backslash count → preceding "\\" escapes a literal
			// backslash, and "u2028"/"u2029" is bare ASCII. Leave alone.
		}
		result = append(result, out[i])
		i++
	}
	return result
}

// computeContentHashGo computes the SHA-256 hex of the canonical JSON
// of the content fields per spec §6.1 and packages/schema/src/hashing.ts
// computeContentHash. Payload includes role, content, tool_calls,
// prompt_hash, system_prompt_hash, and audio_ref (when non-nil — TS
// omits the key entirely when nil/undefined per the writer's
// `...(audioRefForThisEvent ? { audio_ref: ... } : {})` spread).
func computeContentHashGo(c bundle.EventContent) (string, error) {
	payload := map[string]interface{}{
		"role":               c.Role,
		"content":            ptrToAny(c.Content),
		"prompt_hash":        ptrToAny(c.PromptHash),
		"system_prompt_hash": ptrToAny(c.SystemPromptHash),
	}
	// tool_calls: round-trip through interface{} so any nested
	// objects also canonicalize via Go's map-key sorting. Empty in
	// the example bundle, but the loader captures whatever bytes
	// were on disk via json.RawMessage.
	//
	// AUDIT-4 C-H3 closure: explicit null-vs-absent disambiguation
	// at the canonical-input boundary. The TS writer canonicalize
	// always emits tool_calls (Zod default `[]` when adapter omits;
	// explicit `[...]` when adapter provides). The Go verifier MUST
	// emit the same bytes:
	//   - absent (len=0): per spec §6.1, the writer always emits
	//     the field; absence indicates a malformed bundle. Synthesize
	//     `[]` for backwards compat with example bundles + emit a
	//     warning; future writers should never produce this state.
	//   - explicit null ("null" bytes): unmarshal yields nil → emit
	//     JSON null. Forward-compat with any future spec rev that
	//     uses null to indicate "schema-not-applicable".
	//   - explicit `[]` or `[...]`: unmarshal yields slice → emit
	//     canonical sorted bytes.
	// Per-instance behavior verified by Go json.RawMessage semantics:
	// `json.Unmarshal` of `null` field populates RawMessage with the
	// literal "null" bytes (length 4); ABSENT fields leave RawMessage
	// at zero-value (length 0). The length check disambiguates.
	var toolCalls interface{}
	if len(c.ToolCalls) == 0 {
		// Absent — synthesize `[]` for backwards-compat. Future writers
		// MUST emit the field per spec §6.1 invariant; pre-emptive
		// fail-loud here would break example bundles, so accept absence
		// with the synthesized canonical value.
		toolCalls = []interface{}{}
	} else {
		// Explicit value (including "null"). Unmarshal preserves the
		// distinction: "null" bytes → nil interface{} → canonical emits
		// JSON null; "[]" → empty slice → canonical emits "[]"; "[...]"
		// → slice → canonical emits sorted.
		if err := json.Unmarshal(c.ToolCalls, &toolCalls); err != nil {
			return "", fmt.Errorf("tool_calls unmarshal: %w", err)
		}
	}
	payload["tool_calls"] = toolCalls

	if c.AudioRef != nil {
		payload["audio_ref"] = audioRefPayload(*c.AudioRef)
	}

	canon, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// audioRefPayload mirrors the TS AudioRefHashInput payload (sorted
// key order is achieved at canonicalize time via map-key sort, not
// here). Channels and sample_rate are *int — when nil they emit as
// JSON null in the canonical bytes (matching TS canonicalize), when
// non-nil they emit as integers. The current writer always emits
// explicit ints, but using *int preserves the null-vs-zero
// distinction for forward-compat (M2 from commit-4 reviewer pass).
func audioRefPayload(ar bundle.EventAudioRef) map[string]interface{} {
	return map[string]interface{}{
		"channels":     intPtrToAny(ar.Channels),
		"duration_ms":  ar.DurationMs,
		"hash":         ar.Hash,
		"mime_type":    ar.MIMEType,
		"sample_rate":  intPtrToAny(ar.SampleRate),
		"storage_path": ar.StoragePath,
	}
}

// computeEventHashGo computes the SHA-256 hex of the canonical JSON
// of {content_hash, prev_event_hash, sequence_number, timestamp_unix_ns}
// per spec §6.2 and packages/schema/src/hashing.ts computeEventHash.
//
// Note: timestamp_unix_ns is a string (NOT a number) — JS numbers
// can't represent ns precision. The Go forensic struct uses string
// too. The canonical JSON quotes it as a string per JCS string-vs-
// number distinction.
func computeEventHashGo(contentHash, prevEventHash string, sequenceNumber int64, timestampUnixNs string) (string, error) {
	payload := map[string]interface{}{
		"content_hash":      contentHash,
		"prev_event_hash":   prevEventHash,
		"sequence_number":   sequenceNumber,
		"timestamp_unix_ns": timestampUnixNs,
	}
	canon, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// ptrToAny returns an interface{} wrapping the dereferenced string,
// or nil when p is nil. Used to put nullable string fields into the
// canonical map: nil → JSON null; non-nil → JSON string. Matches the
// TS canonicalize behavior (null is kept as the literal "null" in
// the output).
//
// Used for content + prompt_hash + system_prompt_hash. M3 fix from
// commit-4 reviewer pass replaced the prior stringDeref-coerces-to-""
// path: silent nil→"" coercion would have diverged from TS's nil→null
// canonical output on bundles whose writer ever emits null content.
// Today the writer always emits non-null strings; this hardening
// preserves cross-impl parity for forward-compat.
func ptrToAny(p *string) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

// intPtrToAny is the *int variant of ptrToAny — nil pointer → JSON
// null; non-nil → integer. M2 from commit-4 reviewer pass: the
// TS AudioRefHashInput schema permits null sample_rate / channels;
// using *int + nil-aware payload preserves cross-impl parity for
// forward-compat with writers that emit null.
func intPtrToAny(p *int) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

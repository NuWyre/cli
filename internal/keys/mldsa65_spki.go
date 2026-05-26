package keys

// MlDsa65SPKIPrefix is the canonical 22-byte SPKI DER prefix
// preceding the raw 1952-byte ML-DSA-65 public key bytes per spec
// §18.4 + RFC 5280 SubjectPublicKeyInfo construction. Phase 7.F.3
// 2026-05-22 (consolidated closure: spec-conformance H3 + crypto-
// integrity H1 + code-reviewer H2/L3 + security-auditor H1).
//
// Writer-side authority: packages/evidence/src/ml-dsa-65.ts:90
// (SPKI_PREFIX_BYTES). Both sides MUST emit/expect byte-identical
// prefix construction; recurring-defect-class memory n=18+ (writer-
// side authority on closed-vocabulary spec-pinned fields).
//
// Construction (per spec §18.4 + draft-ietf-lamps-dilithium-certificates):
//   - outer SEQUENCE: tag 0x30 + long-form length 0x82 0x07 0xB2 (1970 content)
//   - AlgorithmIdentifier SEQUENCE: tag 0x30 + short-form length 0x0B (11 content)
//   - OID: tag 0x06 + length 0x09 (9 content)
//   - OID content (9 bytes): id-ml-dsa-65 = 2.16.840.1.101.3.4.3.18
//     encoded as 0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x03 0x12
//   - BIT STRING: tag 0x03 + long-form length 0x82 0x07 0xA1 (1953 content)
//   - unused-bits octet: 0x00
//
// Total: 4 + 2 + 2 + 9 + 4 + 1 = 22 bytes. Followed by 1952 raw public
// key bytes. SPKI total: 22 + 1952 = 1974 bytes.
var MlDsa65SPKIPrefix = []byte{
	0x30, 0x82, 0x07, 0xb2, // outer SEQUENCE: tag 0x30 + long-form length (1970 content)
	0x30, 0x0b, // AlgorithmIdentifier SEQUENCE
	0x06, 0x09, // OID header
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, // id-ml-dsa-65 OID content
	0x03, 0x82, 0x07, 0xa1, // BIT STRING header (1953 content)
	0x00, // unused-bits octet
}

// MlDsa65SPKISize is the canonical total SPKI DER byte count per
// spec §18.4. Strict equality posture: parseMlDsa65SPKI rejects any
// other length.
const MlDsa65SPKISize = 1974

// MlDsa65PublicKeySize is the raw public key byte count per FIPS 204
// §4 Table 1 (matches cloudflare/circl mldsa65.PublicKeySize).
const MlDsa65PublicKeySize = 1952

// MlDsa65SPKIPrefixSize is the byte count of the prefix preceding the
// raw public key bytes. Derived constant for readability.
const MlDsa65SPKIPrefixSize = MlDsa65SPKISize - MlDsa65PublicKeySize // 22

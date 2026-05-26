// Package tsa implements RFC 3161 timestamp token verification for
// the Phase 4 verification CLI. Phase 4 Session 3 populates this
// package; Session 1 leaves it empty.
//
// Per build plan v3.1.11 §Phase 4 Step 4 check 6: each .tsr in the
// bundle is paired with its .chain.pem (full PEM-encoded chain
// captured at stamping time). Verification chains the token's
// signing certificate up through its embedded chain to a
// publicly-known root CA — system trust store first, falling back
// to pinned roots in internal/keys/. ≥2 of 3 distinct TSAs MUST
// produce verifying {token, chain} pairs per daily root.
package tsa

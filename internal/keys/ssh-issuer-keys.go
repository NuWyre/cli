package keys

import (
	"errors"
	"time"
)

// SSHIssuerKey describes one pinned SSH signing key for git anchor
// commit verification. Parallel to IssuerKey (which pins manifest
// signing keys); the conceptual distinction is that an issuer
// identity has TWO operational key materials at the V1 grain:
//
//   - Manifest signing key (Ed25519 / DER SPKI; pinned in
//     PinnedIssuerKeys via SPKIFingerprintB64) — used by the
//     example-bundle generator + Phase 5 KMS production signer.
//   - SSH commit signing key (Ed25519 in OpenSSH wire format;
//     pinned here via AuthorizedKeyFormat) — used by the operator's
//     git client when committing to the anchor repo.
//
// These are distinct keys per V1's operational reality (verified
// empirically against actual NuWyre/anchors signed commits during
// the SSH-signature-verification audit). Keeping them in parallel
// pinned-key sets keeps each surface's verification logic focused
// on its own key material without the conceptual contortions of
// shoehorning two keys into one struct.
//
// Per Tenant 1 (long-term value): V1 binaries pin the V1 SSH key;
// rotation in Phase 5 (or beyond) accumulates entries here without
// dropping previous ones, so older anchored commits continue to
// verify against the key active at their commit time.
type SSHIssuerKey struct {
	// KeyID is the stable identifier (e.g., "issuer-ssh-prod-v1",
	// "issuer-ssh-dev-v1"). Distinct from IssuerKey.KeyID to avoid
	// confusion at debug + log surfaces.
	KeyID string

	// KeyRole selects the verifier path: "prod" for customer-export
	// bundles' anchor commits; "dev" for example-demo bundles.
	// Reuses the existing KeyRole enum (no new dispatch primitive
	// needed).
	KeyRole KeyRole

	// EffectiveAfter / EffectiveBefore — same semantics as
	// IssuerKey. Allow rotation accumulation without breaking
	// pre-rotation commit verification.
	EffectiveAfter  time.Time
	EffectiveBefore time.Time

	// AuthorizedKeyFormat is the OpenSSH authorized_keys-format
	// string for the public key (e.g., "ssh-ed25519 AAAA...").
	// Parsed via ssh.ParseAuthorizedKey at verification time. The
	// format is stable across OpenSSH versions; any value the
	// generating ssh-keygen / git-config-emitted material would
	// produce on output.
	//
	// **Pin discipline.** The literal string is the cross-language
	// canonical representation of the SSH key — a future Python or
	// Rust implementation pins the same literal. Future readers
	// can validate the pinned value against the actual NuWyre/
	// anchors commit signature by base64-decoding the SSHSIG blob's
	// public-key field and reformatting to authorized_keys form.
	AuthorizedKeyFormat string

	// Description for forensic + operator output. Stable across the
	// V1 binary lifetime.
	Description string
}

// PlaceholderProdSSHAuthorizedKey is the V1 placeholder for the
// production SSH signing key's authorized_keys form. Production
// deploy-bootstrap (Phase 5) replaces this with the real KMS-backed
// SSH key's authorized_keys form before V1 binaries can verify
// customer-export anchored bundles.
//
// Two-layer fail-secure (matches PlaceholderProdFingerprint pattern
// in issuer-keys.go):
//   - The string is intentionally non-base64 (contains underscores)
//     so any real SSH key blob comparison against it fails immediately.
//   - Any downstream attempt to parse it as ssh.ParseAuthorizedKey
//     fails too (the keyword "PROD_SSH_KEY..." isn't a recognized
//     SSH key type).
const PlaceholderProdSSHAuthorizedKey = "PROD_SSH_KEY_PENDING_PHASE_5_DEPLOY_BOOTSTRAP"

// PinnedSSHIssuerKeys is the compile-time embedded set of pinned
// SSH commit-signing keys. Phase 4 verification dispatch (analogous
// to PinnedIssuerKeys but for SSH commit signatures):
//
//   - bundle_type="customer-export" → match against issuer-ssh-prod-v1
//   - bundle_type="example-demo"    → match against issuer-ssh-dev-v1
//   - any other / missing            → fail-secure: customer-export
//     path; placeholder mismatches
//     anything real, so tampered
//     bundles that omit bundle_type
//     fail loudly
//
// V1 dev value: the SSH key actually used to sign NuWyre/anchors
// commits at the time of pinning. Extracted from the v3.1.9 first-
// commit `1a1635b3...` and the 2026-04-22 anchor commit
// `ade149b2...` (both signed by the same key). Verified: the
// ssh-ed25519 raw public key bytes match across both commits.
//
// To re-derive this value: fetch any signed commit from
// https://github.com/NuWyre/anchors via the GitHub API
// (`commit.verification.signature`), base64-decode the armored
// "BEGIN SSH SIGNATURE" block, parse the SSHSIG protocol payload
// (per the OpenSSH PROTOCOL.sshsig spec), extract the embedded
// public key field, and re-format to OpenSSH authorized_keys form.
// The test
// `internal/checks/ssh_signature_test.go:TestExtractedKeyMatchesPinned`
// pins this re-derivation as a regression check.
var PinnedSSHIssuerKeys = []SSHIssuerKey{
	{
		KeyID:               "issuer-ssh-prod-v1",
		KeyRole:             KeyRoleProd,
		EffectiveAfter:      time.Time{},
		EffectiveBefore:     time.Time{},
		AuthorizedKeyFormat: PlaceholderProdSSHAuthorizedKey,
		Description:         "Production SSH signing key for customer-export bundles' anchor repo commits. PLACEHOLDER — Phase 5 deploy-bootstrap replaces with the real KMS-backed SSH key's authorized_keys form. V1 binaries reject all customer-export anchored bundles by design (no real SSH key matches the placeholder).",
	},
	{
		KeyID:           "issuer-ssh-dev-v1",
		KeyRole:         KeyRoleDev,
		EffectiveAfter:  time.Time{},
		EffectiveBefore: time.Time{},
		// Extracted from the SSHSIG signature on NuWyre/anchors
		// commit f56183a02e228655ba5f8c4493dbc07d99b41dd5 (the
		// .gitattributes commit) AND commit
		// 5af4596ece859d5697af732f3f1818a27d73e44c (the 2026-04-22 daily
		// root anchor). Both commits are signed by the dedicated "NuWyre
		// Anchors Bot" ssh-ed25519 key (fingerprint
		// SHA256:EHGMx5SmPUSseyhyV0ffLrMukBlqO69d9M5KIKpb/kA), migrated
		// 2026-05-26 off the founder's personal SSH key so the evidence
		// chain is a role identity, not one individual (see
		// docs/initiatives/public-verifier-repo.md). Both commits' SSHSIG
		// blobs embed the same public key; the extracted bytes base64-encode
		// to the authorized_keys-format value pinned below.
		//
		// Pinning workflow:
		//  1. gh api repos/NuWyre/anchors/commits/<sha>
		//  2. Decode armored signature ("BEGIN SSH SIGNATURE" block)
		//  3. Parse SSHSIG protocol payload (OpenSSH PROTOCOL.sshsig)
		//  4. Extract public key field bytes
		//  5. Base64-encode bytes → AuthorizedKeyFormat below
		AuthorizedKeyFormat: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdRBv9ADOLWZH7z3S1v0v3wufS6SFj6V9KqJ6778mFk",
		Description:         "Development SSH signing key for git anchor commits to NuWyre/anchors — the dedicated NuWyre Anchors Bot key (a role identity, not a personal key). Distinct from issuer-dev-v1 (which signs example-demo bundle MANIFESTS); this SSH key signs git COMMITS in the anchor repo. CLI surfaces the signer fingerprint per anchored verification for forensic transparency.",
	},
}

// ErrNoSSHIssuerKey is returned by SSHKeyForBundle when no pinned
// SSH key matches the bundle's bundle_type and generated_at.
var ErrNoSSHIssuerKey = errors.New("no pinned SSH issuer key matches the bundle's bundle_type and generated_at")

// SSHKeyForBundle returns the pinned SSH issuer key matching the
// bundle's bundle_type + generated_at. Dispatch:
//
//   - bundle_type="customer-export" → KeyRoleProd (placeholder in V1)
//   - bundle_type="example-demo"    → KeyRoleDev
//   - any other / missing            → KeyRoleProd (fail-secure
//     default; tampered bundles
//     that omit bundle_type fail
//     at the verification layer
//     because the placeholder
//     pinned-prod SSH key fails
//     any real-bundle comparison)
//
// **AllowDevKey gating is the CALLER's responsibility, not this
// function's.** Per security-auditor H1 (dedicated SSH session
// commit 1 review): unlike check 1's manifest signature path
// which gates on opts.AllowDevKey before resolving the pinned key,
// this function does NOT enforce the gate. The caller (check 7's
// anchored cross-check, currently stubbed) MUST verify
// `opts.AllowDevKey == true` before invoking this function with
// bundleType="example-demo", OR return early without dispatching
// to SSH verification. Failing to gate would produce an SSH
// verification path that silently bypasses --allow-dev-key — a
// cross-check policy split with check 1 that defense-in-depth
// posture is built to prevent.
//
// (The gate isn't enforced here because the caller already has
// the AllowDevKey context from CheckOptions and can produce a
// clearer error message + dispatch decision than a fail-secure
// "no key" return from this function would.)
func SSHKeyForBundle(bundleType string, generatedAt time.Time) (*SSHIssuerKey, error) {
	return sshKeyForBundleIn(PinnedSSHIssuerKeys, bundleType, generatedAt)
}

// sshKeyForBundleIn is the testable variant of SSHKeyForBundle that
// accepts a custom keys slice rather than the package's
// PinnedSSHIssuerKeys global. Used by ssh-issuer-keys_test.go.
func sshKeyForBundleIn(keys []SSHIssuerKey, bundleType string, generatedAt time.Time) (*SSHIssuerKey, error) {
	role := KeyRoleProd
	if bundleType == "example-demo" {
		role = KeyRoleDev
	}
	for i := range keys {
		k := &keys[i]
		if k.KeyRole != role {
			continue
		}
		if !k.EffectiveAfter.IsZero() && generatedAt.Before(k.EffectiveAfter) {
			continue
		}
		// Crypto-integrity reviewer H1 (dedicated SSH session
		// commit 1 review): use !generatedAt.Before semantics
		// matching keyForBundleIn in keys.go (half-open
		// [After, Before) interval). Previously used .After()
		// which produced inclusive-upper-bound divergence at the
		// rotation-boundary instant. Latent V1 (both pinned SSH
		// keys have zero EffectiveBefore) but a defect that would
		// surface the first time a rotation happens — caught
		// while paired manifest + SSH dispatch was easy to align.
		if !k.EffectiveBefore.IsZero() && !generatedAt.Before(k.EffectiveBefore) {
			continue
		}
		return k, nil
	}
	return nil, ErrNoSSHIssuerKey
}

package keys

import (
	"testing"
	"time"
)

// =============================================================================
// PinnedSSHIssuerKeys + SSHKeyForBundle dispatch tests
// =============================================================================

func TestPinnedSSHIssuerKeysShape(t *testing.T) {
	t.Parallel()
	if len(PinnedSSHIssuerKeys) < 2 {
		t.Fatalf("PinnedSSHIssuerKeys has %d entries; want at least 2 (prod placeholder + dev)", len(PinnedSSHIssuerKeys))
	}

	// Every entry has a stable KeyID + KeyRole.
	for _, k := range PinnedSSHIssuerKeys {
		if k.KeyID == "" {
			t.Errorf("entry has empty KeyID: %+v", k)
		}
		if k.KeyRole == "" {
			t.Errorf("entry %q has empty KeyRole", k.KeyID)
		}
		if k.AuthorizedKeyFormat == "" {
			t.Errorf("entry %q has empty AuthorizedKeyFormat", k.KeyID)
		}
	}
}

func TestPinnedSSHIssuerKeysProdPlaceholder(t *testing.T) {
	t.Parallel()
	prod, err := SSHKeyForBundle("customer-export", time.Now().UTC())
	if err != nil {
		t.Fatalf("SSHKeyForBundle(customer-export): %v", err)
	}
	if prod.KeyRole != KeyRoleProd {
		t.Errorf("KeyRole = %v, want %v", prod.KeyRole, KeyRoleProd)
	}
	// V1 binary ships placeholder for prod; Phase 5 deploy-bootstrap
	// replaces with real KMS-backed SSH key.
	if prod.AuthorizedKeyFormat != PlaceholderProdSSHAuthorizedKey {
		t.Errorf("V1 prod entry should be the placeholder until Phase 5 deploy-bootstrap; got %q", prod.AuthorizedKeyFormat)
	}
}

func TestPinnedSSHIssuerKeysDevReal(t *testing.T) {
	t.Parallel()
	dev, err := SSHKeyForBundle("example-demo", time.Now().UTC())
	if err != nil {
		t.Fatalf("SSHKeyForBundle(example-demo): %v", err)
	}
	if dev.KeyRole != KeyRoleDev {
		t.Errorf("KeyRole = %v, want %v", dev.KeyRole, KeyRoleDev)
	}
	if dev.AuthorizedKeyFormat == PlaceholderProdSSHAuthorizedKey {
		t.Errorf("dev entry should NOT be the prod placeholder")
	}
	if dev.AuthorizedKeyFormat == "" {
		t.Errorf("dev AuthorizedKeyFormat is empty")
	}
}

// TestSSHKeyForBundleFailSecureDefault pins the fail-secure
// dispatch: bundle_type missing or unrecognized maps to KeyRoleProd
// (the placeholder). Tampered bundles that omit bundle_type fail at
// the verification layer because the placeholder doesn't parse +
// doesn't match any real signer key.
func TestSSHKeyForBundleFailSecureDefault(t *testing.T) {
	t.Parallel()
	cases := []string{"", "unknown", "customer-export", "garbage-type"}
	for _, bt := range cases {
		t.Run(bt, func(t *testing.T) {
			k, err := SSHKeyForBundle(bt, time.Now().UTC())
			if err != nil {
				t.Fatalf("SSHKeyForBundle(%q): %v", bt, err)
			}
			if k.KeyRole != KeyRoleProd {
				t.Errorf("bundle_type=%q dispatched to %v, want KeyRoleProd (fail-secure default)", bt, k.KeyRole)
			}
		})
	}
}

// TestSSHKeyForBundleEffectivePeriod pins the rotation-respect
// behavior: a key with EffectiveBefore in the past is not selected
// for a bundle generated after that time.
func TestSSHKeyForBundleEffectivePeriod(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	pastKey := SSHIssuerKey{
		KeyID:               "rotated-out-dev",
		KeyRole:             KeyRoleDev,
		EffectiveAfter:      now.Add(-2 * 24 * time.Hour),
		EffectiveBefore:     now.Add(-1 * 24 * time.Hour),
		AuthorizedKeyFormat: "ssh-ed25519 AAAAplaceholder1",
	}
	currentKey := SSHIssuerKey{
		KeyID:               "current-dev",
		KeyRole:             KeyRoleDev,
		EffectiveAfter:      time.Time{}, // active from issuance
		EffectiveBefore:     time.Time{}, // active indefinitely
		AuthorizedKeyFormat: "ssh-ed25519 AAAAplaceholder2",
	}
	keys := []SSHIssuerKey{pastKey, currentKey}

	// A bundle generated NOW should match the current key, not the
	// rotated-out one.
	k, err := sshKeyForBundleIn(keys, "example-demo", now)
	if err != nil {
		t.Fatalf("sshKeyForBundleIn: %v", err)
	}
	if k.KeyID != "current-dev" {
		t.Errorf("matched %q, want current-dev (past key should be skipped)", k.KeyID)
	}
}

func TestSSHKeyForBundleNoMatchReturnsErr(t *testing.T) {
	t.Parallel()
	// Empty keys slice → no match → ErrNoSSHIssuerKey
	_, err := sshKeyForBundleIn(nil, "example-demo", time.Now())
	if err != ErrNoSSHIssuerKey {
		t.Errorf("err = %v, want ErrNoSSHIssuerKey", err)
	}
}

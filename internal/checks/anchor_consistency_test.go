package checks

import (
	"strings"
	"testing"

	"github.com/nuwyre/cli/internal/bundle"
)

// =============================================================================
// validateOTSConsistency
// =============================================================================

func TestValidateOTSConsistencyPassesOnAgreement(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{OTSStatus: "pending"},
			Anchors: bundle.ManifestAnchors{
				OpenTimestamps: bundle.ManifestOTSAnchor{
					Status: "submitted-pending-bitcoin-confirmation",
				},
			},
		},
	}
	if err := validateOTSConsistency(b); err != nil {
		t.Errorf("agreement case errored: %v", err)
	}
}

func TestValidateOTSConsistencyFailsOnEmptySummary(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{OTSStatus: ""},
			Anchors: bundle.ManifestAnchors{
				OpenTimestamps: bundle.ManifestOTSAnchor{Status: ""},
			},
		},
	}
	err := validateOTSConsistency(b)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-fields error; got %v", err)
	}
}

func TestValidateOTSConsistencyFailsOnUnknownSummary(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{OTSStatus: "fnord"},
			Anchors: bundle.ManifestAnchors{
				OpenTimestamps: bundle.ManifestOTSAnchor{Status: "submitted"},
			},
		},
	}
	err := validateOTSConsistency(b)
	if err == nil || !strings.Contains(err.Error(), "fnord") {
		t.Errorf("expected unrecognized-status error; got %v", err)
	}
}

func TestValidateOTSConsistencyFailsOnEmptyDetailWithSummary(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{OTSStatus: "pending"},
			Anchors: bundle.ManifestAnchors{
				OpenTimestamps: bundle.ManifestOTSAnchor{Status: ""},
			},
		},
	}
	err := validateOTSConsistency(b)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-detail error; got %v", err)
	}
}

// =============================================================================
// validateRFC3161Consistency
// =============================================================================

func TestValidateRFC3161ConsistencyVerifiedRequiresAtLeast2TSAs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		summary string
		tsas    []bundle.ManifestRFC3161Anchor
		wantErr bool
	}{
		{
			name:    "verified with 3 TSAs",
			summary: "verified",
			tsas: []bundle.ManifestRFC3161Anchor{
				{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
				{TSAName: "sectigo", ReceiptPath: "x", ChainPath: "y"},
				{TSAName: "digicert", ReceiptPath: "x", ChainPath: "y"},
			},
			wantErr: false,
		},
		{
			name:    "verified with 2 TSAs",
			summary: "verified",
			tsas: []bundle.ManifestRFC3161Anchor{
				{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
				{TSAName: "sectigo", ReceiptPath: "x", ChainPath: "y"},
			},
			wantErr: false,
		},
		{
			name:    "verified with 1 TSA — false claim",
			summary: "verified",
			tsas: []bundle.ManifestRFC3161Anchor{
				{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
			},
			wantErr: true,
		},
		{
			name:    "verified with 0 TSAs — false claim",
			summary: "verified",
			tsas:    nil,
			wantErr: true,
		},
		{
			name:    "partial with exactly 1 TSA",
			summary: "partial",
			tsas: []bundle.ManifestRFC3161Anchor{
				{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
			},
			wantErr: false,
		},
		{
			name:    "partial with 2 TSAs — should be verified",
			summary: "partial",
			tsas: []bundle.ManifestRFC3161Anchor{
				{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
				{TSAName: "sectigo", ReceiptPath: "x", ChainPath: "y"},
			},
			wantErr: true,
		},
		{
			name:    "not_attempted with 0 TSAs",
			summary: "not_attempted",
			tsas:    nil,
			wantErr: false,
		},
		{
			name:    "not_attempted with TSAs present — bug",
			summary: "not_attempted",
			tsas: []bundle.ManifestRFC3161Anchor{
				{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{RFC3161Status: c.summary},
					Anchors:      bundle.ManifestAnchors{RFC3161: c.tsas},
				},
			}
			err := validateRFC3161Consistency(b)
			if (err != nil) != c.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, c.wantErr)
			}
		})
	}
}

func TestValidateRFC3161ConsistencyDetectsDuplicateTSANames(t *testing.T) {
	t.Parallel()
	// Duplicate tsa_name would falsely satisfy the 2-of-3 threshold
	// — the canonical structural-tampering vector this test guards
	// against.
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{RFC3161Status: "verified"},
			Anchors: bundle.ManifestAnchors{
				RFC3161: []bundle.ManifestRFC3161Anchor{
					{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
					{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"}, // duplicate
				},
			},
		},
	}
	err := validateRFC3161Consistency(b)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate-tsa_name error; got %v", err)
	}
}

func TestValidateRFC3161ConsistencyRequiresReceiptAndChainPaths(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{RFC3161Status: "verified"},
			Anchors: bundle.ManifestAnchors{
				RFC3161: []bundle.ManifestRFC3161Anchor{
					{TSAName: "freetsa", ReceiptPath: "x", ChainPath: "y"},
					{TSAName: "sectigo", ReceiptPath: "", ChainPath: "y"}, // missing receipt
				},
			},
		},
	}
	err := validateRFC3161Consistency(b)
	if err == nil || !strings.Contains(err.Error(), "receipt_path") {
		t.Errorf("expected receipt_path missing error; got %v", err)
	}
}

// =============================================================================
// validateGitHubConsistency
// =============================================================================

func TestValidateGitHubConsistencyAcceptsAnchorPending(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{GithubStatus: "anchor-pending"},
		},
		GithubAnchors: map[string]bundle.GithubAnchorJSON{
			"2026-04-22": {Date: "2026-04-22", MirrorStatus: "anchor-pending"},
		},
	}
	if err := validateGitHubConsistency(b); err != nil {
		t.Errorf("anchor-pending agreement case errored: %v", err)
	}
}

func TestValidateGitHubConsistencyRejectsUnknownSummary(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{GithubStatus: "frozen"},
		},
	}
	err := validateGitHubConsistency(b)
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Errorf("expected unrecognized-status error; got %v", err)
	}
}

func TestValidateGitHubConsistencyRejectsPerDayDisagreement(t *testing.T) {
	t.Parallel()
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{GithubStatus: "anchor-pending"},
		},
		GithubAnchors: map[string]bundle.GithubAnchorJSON{
			"2026-04-22": {Date: "2026-04-22", MirrorStatus: "anchored"}, // disagrees with summary
		},
	}
	err := validateGitHubConsistency(b)
	if err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Errorf("expected disagreement error; got %v", err)
	}
}

func TestValidateGitHubConsistencyAgainstExampleBundle(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if err := validateGitHubConsistency(b); err != nil {
		t.Errorf("regenerated example bundle has GitHub consistency error: %v", err)
	}
}

func TestValidateOTSConsistencyAgainstExampleBundle(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if err := validateOTSConsistency(b); err != nil {
		t.Errorf("regenerated example bundle has OTS consistency error: %v", err)
	}
}

func TestValidateRFC3161ConsistencyAgainstExampleBundle(t *testing.T) {
	t.Parallel()
	b := loadExampleBundle(t)
	if err := validateRFC3161Consistency(b); err != nil {
		t.Errorf("regenerated example bundle has RFC 3161 consistency error: %v", err)
	}
}

// =============================================================================
// Per-leg enum allowlist (Crypto C1 + Sec L11 from D1 reviewer pass)
// =============================================================================

func TestValidateOTSConsistencyRejectsCrossLegValues(t *testing.T) {
	t.Parallel()
	// Per spec §4.2, ots_status ∈ {pending, confirmed, failed}.
	// "anchored" / "verified" / "anchor-pending" are valid in OTHER
	// legs but MUST be rejected here.
	cases := []string{"anchored", "verified", "anchor-pending", "partial", "not_attempted"}
	for _, badStatus := range cases {
		t.Run(badStatus, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{OTSStatus: badStatus},
					Anchors: bundle.ManifestAnchors{
						OpenTimestamps: bundle.ManifestOTSAnchor{Status: "submitted"},
					},
				},
			}
			err := validateOTSConsistency(b)
			if err == nil || !strings.Contains(err.Error(), "OTS status") {
				t.Errorf("ots_status=%q should be rejected as cross-leg value; got %v", badStatus, err)
			}
		})
	}
}

func TestValidateRFC3161ConsistencyRejectsCrossLegValues(t *testing.T) {
	t.Parallel()
	cases := []string{"anchored", "anchor-pending", "pending", "confirmed"}
	for _, badStatus := range cases {
		t.Run(badStatus, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{RFC3161Status: badStatus},
				},
			}
			err := validateRFC3161Consistency(b)
			if err == nil || !strings.Contains(err.Error(), "RFC 3161 status") {
				t.Errorf("rfc3161_status=%q should be rejected as cross-leg value; got %v", badStatus, err)
			}
		})
	}
}

func TestValidateGitHubConsistencyRejectsCrossLegValues(t *testing.T) {
	t.Parallel()
	cases := []string{"verified", "partial", "pending", "confirmed"}
	for _, badStatus := range cases {
		t.Run(badStatus, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{GithubStatus: badStatus},
				},
			}
			err := validateGitHubConsistency(b)
			if err == nil || !strings.Contains(err.Error(), "GitHub status") {
				t.Errorf("github_status=%q should be rejected as cross-leg value; got %v", badStatus, err)
			}
		})
	}
}

// =============================================================================
// OTS consistency matrix (Crypto H5 from D1 reviewer pass)
// =============================================================================

func TestValidateOTSConsistencyMatrixEnforced(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		summary string
		detail  string
		wantErr bool
	}{
		{"pending + submitted-pending", "pending", "submitted-pending-bitcoin-confirmation", false},
		{"pending + still-pending", "pending", "still-pending", false},
		{"pending + confirmed-by-bitcoin", "pending", "confirmed-by-bitcoin-block-NNN", true},
		{"pending + failed-submission", "pending", "submission-failed", true},
		{"confirmed + confirmed-bitcoin-attestation", "confirmed", "confirmed-bitcoin-attestation", false},
		{"confirmed + bitcoin-attested", "confirmed", "bitcoin-attested-at-block-NNN", false},
		{"confirmed + still-pending", "confirmed", "still-pending", true},
		{"confirmed + submission-failed", "confirmed", "submission-failed", true},
		{"failed + submission-failed", "failed", "submission-failed", false},
		{"failed + calendar-rejected-failed", "failed", "calendar-rejected-failed-explicitly", false},
		{"failed + still-pending", "failed", "still-pending", true},
		{"failed + confirmed", "failed", "confirmed-attested", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{OTSStatus: c.summary},
					Anchors: bundle.ManifestAnchors{
						OpenTimestamps: bundle.ManifestOTSAnchor{Status: c.detail},
					},
				},
			}
			err := validateOTSConsistency(b)
			if (err != nil) != c.wantErr {
				t.Errorf("summary=%q detail=%q: err=%v, wantErr=%v", c.summary, c.detail, err, c.wantErr)
			}
		})
	}
}

// =============================================================================
// GitHub empty-anchors guard (Crypto M1 from D1 reviewer pass)
// =============================================================================

func TestValidateGitHubConsistencyRequiresEntriesForNonNotAttempted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		summary string
		wantErr bool
	}{
		{"not_attempted", false}, // legitimate zero-entries case
		{"anchor-pending", true}, // claims state but no per-day file
		{"anchored", true},
		{"failed", true},
	}
	for _, c := range cases {
		t.Run(c.summary, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{GithubStatus: c.summary},
				},
				// No GithubAnchors.
			}
			err := validateGitHubConsistency(b)
			if (err != nil) != c.wantErr {
				t.Errorf("summary=%q with empty GithubAnchors: err=%v, wantErr=%v", c.summary, err, c.wantErr)
			}
		})
	}
}

// =============================================================================
// RFC 3161 tsa_name canonicalization (Sec H4 + L5 from D1 reviewer pass)
// =============================================================================

func TestValidateRFC3161ConsistencyRejectsNonCanonicalTSANames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		tsaName string
		wantMsg string
	}{
		{"leading whitespace", " freetsa", "whitespace"},
		{"trailing whitespace", "freetsa ", "whitespace"},
		{"surrounding whitespace", "  freetsa  ", "whitespace"},
		{"uppercase", "FreeTSA", "lowercase"},
		{"mixed case", "FreeTsa", "lowercase"},
		{"all uppercase", "FREETSA", "lowercase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: bundle.ManifestJSON{
					AnchorStatus: bundle.ManifestAnchorStatus{RFC3161Status: "partial"},
					Anchors: bundle.ManifestAnchors{
						RFC3161: []bundle.ManifestRFC3161Anchor{
							{TSAName: c.tsaName, ReceiptPath: "x", ChainPath: "y"},
						},
					},
				},
			}
			err := validateRFC3161Consistency(b)
			if err == nil {
				t.Errorf("tsa_name=%q should be rejected; got nil err", c.tsaName)
			}
			if err != nil && !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("tsa_name=%q: error doesn't mention %q: %v", c.tsaName, c.wantMsg, err)
			}
		})
	}
}

func TestValidateRFC3161ConsistencyDetectsDuplicateAfterNormalization(t *testing.T) {
	t.Parallel()
	// Sec H4 from D1 reviewer pass: dup detection MUST be
	// case-insensitive + whitespace-normalized so a tampered manifest
	// can't claim "3 TSAs" via spelling tricks. After D1's
	// canonical-form rejection, these specific dup-trick attempts
	// fail at the format-validation step (uppercase/whitespace
	// rejected before dup check). This test pins the canonical-form
	// rejection prevents the dup attack.
	b := &bundle.Bundle{
		Manifest: bundle.ManifestJSON{
			AnchorStatus: bundle.ManifestAnchorStatus{RFC3161Status: "verified"},
			Anchors: bundle.ManifestAnchors{
				RFC3161: []bundle.ManifestRFC3161Anchor{
					{TSAName: "freetsa", ReceiptPath: "a", ChainPath: "b"},
					{TSAName: "FreeTSA", ReceiptPath: "c", ChainPath: "d"}, // would be dup after lowercase
				},
			},
		},
	}
	err := validateRFC3161Consistency(b)
	if err == nil {
		t.Fatal("FreeTSA + freetsa should be rejected (case difference); got nil")
	}
	// With canonical-form rejection in place, the second entry's
	// "FreeTSA" trips the lowercase requirement BEFORE the dup
	// check runs. Either the lowercase error or the dup error is
	// acceptable — both prevent the structural-tampering vector.
	if !strings.Contains(err.Error(), "lowercase") && !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error doesn't mention lowercase or duplicate: %v", err)
	}
}

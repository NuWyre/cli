package keys

import (
	_ "embed"
	"time"
)

// Pinned TSA root certificates per build plan v3.1.11 §Phase 4 Step 2.
// Each cert was extracted from a real chain.pem captured by NuWyre's
// TSA-stamping pipeline during the 2026-05-09 example bundle
// regeneration. Provenance + SHA-256 fingerprints documented in
// internal/keys/roots/NOTICES.md.
//
// Trust-anchor model: the verifier's system trust store is consulted
// first; these pinned roots are fallbacks for cases where a TSA's
// root isn't in the user's system store (Phase 4 Session 3
// implements the dispatch).

//go:embed roots/freetsa-root.pem
var freetsaRootPEM []byte

//go:embed roots/digicert-trusted-root-g4.pem
var digicertTrustedRootG4PEM []byte

//go:embed roots/sectigo-public-time-stamping-root-r46.pem
var sectigoPublicTimeStampingRootR46PEM []byte

// PinnedTSARoots is the compile-time embedded set. The slice is
// initialized via init() so the embedded byte slices are available
// at package load.
var PinnedTSARoots []TSARoot

func init() {
	PinnedTSARoots = []TSARoot{
		{
			RootName:    "freetsa-root",
			Description: "FreeTSA Root CA — self-signed root for FreeTSA's free RFC 3161 timestamping service",
			// EffectiveAfter / EffectiveBefore match the embedded
			// cert's NotBefore / NotAfter exactly. A drift between
			// pinned dates and cert dates would cause Session 3's
			// verifier to reject timestamps in the gap window. Run
			// `openssl x509 -in roots/freetsa-root.pem -noout
			// -dates` to confirm post-edit.
			EffectiveAfter:  time.Date(2016, 3, 13, 1, 52, 13, 0, time.UTC),
			EffectiveBefore: time.Date(2041, 3, 7, 1, 52, 13, 0, time.UTC),
			PEMBytes:        freetsaRootPEM,
		},
		{
			RootName:    "digicert-trusted-root-g4",
			Description: "DigiCert Trusted Root G4 (cross-signed by DigiCert Assured ID Root CA) — root for DigiCert's RFC 3161 TSA chains",
			EffectiveAfter:  time.Date(2022, 8, 1, 0, 0, 0, 0, time.UTC),
			EffectiveBefore: time.Date(2031, 11, 9, 23, 59, 59, 0, time.UTC),
			PEMBytes:        digicertTrustedRootG4PEM,
		},
		{
			RootName:    "sectigo-public-time-stamping-root-r46",
			Description: "Sectigo Public Time Stamping Root R46 (issued by USERTrust RSA) — chain anchor for Sectigo's RFC 3161 TSA",
			EffectiveAfter:  time.Date(2021, 3, 22, 0, 0, 0, 0, time.UTC),
			EffectiveBefore: time.Date(2038, 1, 18, 23, 59, 59, 0, time.UTC),
			PEMBytes:        sectigoPublicTimeStampingRootR46PEM,
		},
	}
}

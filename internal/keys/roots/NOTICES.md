# Pinned TSA root certificates

Each PEM in this directory is a Time Stamping Authority (TSA) root
certificate that NuWyre's verification CLI pins as a trust anchor
for RFC 3161 chain validation (Phase 4 verification check 6).

## Provenance

The three pinned certs were **extracted from chain.pem files captured
at real TSA-stamping time** during the 2026-05-09 example bundle
regeneration session. NuWyre's TSA-stamping pipeline submits the
daily Merkle root to each TSA, receives the timestamp token and the
issuing-cert chain, and embeds both in the bundle. The chain.pem
contents are exactly what the TSA presented at that moment — same
trust anchors any third-party verifier would chain to.

Extracted from:

- `apps/marketing/public/examples/nuwyre_export_cypress-derm_2026-04-22.zip`
  - `rfc3161_receipts/2026-04-22__freetsa.chain.pem`
  - `rfc3161_receipts/2026-04-22__digicert.chain.pem`
  - `rfc3161_receipts/2026-04-22__sectigo.chain.pem`

Per the build plan v3.1.11 §Phase 4 Step 2 framing: "the pinned set
exists as a fallback for cases where the user's system trust store
doesn't include a particular TSA root; chain validation always tries
the system store first."

## Pinned roots + SHA-256 fingerprints

### freetsa-root.pem

`O=Free TSA, OU=Root CA, CN=www.freetsa.org`

- Self-signed: yes (the actual root)
- SHA-256: `A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC`
- Source: `2026-04-22__freetsa.chain.pem` (chain position 2)
- Independent verification: matches the FreeTSA Root CA fingerprint
  published at https://freetsa.org/index_en.php

### digicert-trusted-root-g4.pem

`C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Trusted Root G4`

- Self-signed: no (cross-signed by `DigiCert Assured ID Root CA`)
- SHA-256: `33:84:6B:54:5A:49:C9:BE:49:03:C6:0E:01:71:3C:1B:D4:E4:EF:31:EA:65:CD:95:D6:9E:62:79:4F:30:B9:41`
- Source: `2026-04-22__digicert.chain.pem` (chain position 3)
- Trust-anchor framing: this is the cross-signed version DigiCert
  presents in TSA chains; the self-signed `Trusted Root G4` (issued
  via Mozilla NSS root store) has a different SHA-256. Both share
  the same Subject Public Key, so chain validation against either
  produces identical cryptographic verdicts. Pinning the chain-
  presented cross-signed version matches what NuWyre's bundles
  actually carry.

### sectigo-public-time-stamping-root-r46.pem

`C=GB, O=Sectigo Limited, CN=Sectigo Public Time Stamping Root R46`

- Self-signed: no (issued by `USERTrust RSA Certification Authority`)
- SHA-256: `B5:3A:C1:5C:C1:AF:B6:E2:AC:06:82:8F:55:5B:B3:BF:5B:AD:8B:2B:AC:17:33:CE:4C:B7:AA:FE:72:93:56:DE`
- Validity (per cert): NotBefore 2021-03-22T00:00:00Z; NotAfter 2038-01-18T23:59:59Z
- Source: `2026-04-22__sectigo.chain.pem` (chain position 3)
- Trust-anchor framing: Sectigo's TSA chain ends at this Root R46
  cert in the bundled chain.pem; chain extension to USERTrust RSA
  (the actual self-signed root) requires the verifier's system trust
  store. Pinning the chain-presented Root R46 means the verifier
  validates without external chain extension; system trust store is
  consulted as a fallback.

## Phase 4 Session 3 — RFC 3161 verification

`internal/tsa/` (populated in Session 3) implements chain validation:

1. Try the verifier's system trust store first
2. If the chain doesn't extend to a system-trusted root, fall back
   to the pinned roots in this directory
3. Verify the timestamp token's signing cert + the embedded chain
   chains up to one of these anchors (system OR pinned)

≥2 of 3 distinct TSAs must produce verifying `{token, chain}` pairs
per daily root for check 6 to pass.

## Updates

When TSAs rotate roots, the chain.pem captured in subsequent bundles
will reflect the new chain. The extraction process here regenerates:
unzip a recent example bundle, run the openssl crl2pkcs7 + awk
pipeline documented in the operations log to extract the fresh root,
update the PEM file + this NOTICES.md fingerprint table, regenerate
the binary. The pinned TSA root set is a versioned artifact; CLI
releases publish the set of pinned roots in `nuwyre keys` output.

# NuWyre verification CLI (`nuwyre`)

Open-source, independent verifier for [NuWyre](https://nuwyre.com) evidence
bundles. A single static Go binary — no runtime dependencies, no network calls
to NuWyre. It verifies any NuWyre evidence bundle against the published spec and
the conformance fixture suite in this repository.

The same Go source compiles to the WebAssembly verifier that runs in the browser
at **[nuwyre.com/verify](https://nuwyre.com/verify)** — the in-browser checks and
this CLI are the same code path.

## What it checks

`nuwyre verify ./bundle.zip` runs the bundle through the spec's verification
pipeline and prints a per-check verdict:

1. **Manifest signature** — Ed25519 (and, for v2 bundles, ML-DSA-65) over the
   canonical manifest, against a pinned issuer key.
2. **Artifact integrity** — every artifact's SHA-256 matches the manifest.
3. **Hash chain** — each event's chain hash recomputes from its canonical bytes.
4. **Merkle proof** — every event's proof reconstructs the daily root.
5. **OpenTimestamps** — the daily root is anchored to Bitcoin (or calendar
   attestations, for receipts still awaiting block confirmation).
6. **RFC 3161** — ≥2-of-3 timestamp-authority tokens validate against pinned
   certificate chains.
7. **GitHub anchor** — the daily root was published to the public append-only
   anchors repository.

Audit-log-export bundles add checks 8–9 (ephemeral-session + audit-log Merkle).
The normative contract is [`docs/spec/bundle-format-v1.md`](docs/spec/bundle-format-v1.md)
and the event schema [`docs/spec/event-v1.schema.json`](docs/spec/event-v1.schema.json).

## Install

```bash
go install github.com/nuwyre/cli/cmd/nuwyre@latest
```

Or build from source (Go 1.22+):

```bash
make build      # → bin/nuwyre   (or: go build -o bin/nuwyre ./cmd/nuwyre)
```

## Use

```bash
nuwyre verify ./nuwyre_export_example.zip
```

Flags:

- `--json` — machine-readable per-check results (for CI integration).
- `--offline` — skip the network anchor checks (5–7) for air-gapped review.
- `--version`, `--help`.

Exit code `0` means every check passed (or was skipped under `--offline`);
non-zero means a check failed. Bundle bytes are never sent anywhere.

## Verify the verifier (tamper-evidence)

You don't have to trust a binary handed to you. The verifier's behavior is
pinned by a public conformance suite — 27 fixtures (14 v1 + 13 v2
dual-signature) under
[`docs/spec/fixtures/bundle-format-v1/`](docs/spec/fixtures/bundle-format-v1/),
one valid bundle plus tampered variants per category, each with byte-exact
expected results. Rebuild from source and run the suite; identical verdicts
confirm the build you hold behaves exactly as specified:

```bash
go test ./internal/checks/ -run TestConformanceFixtures   # 27 fixtures
go test ./...                                              # full suite
```

Cross-language byte-equivalence with the TypeScript reference writer is pinned at
the primitive layer by the KAT vectors at
`internal/checks/testdata/v2_dual_sig_kats_v1.json`.

## WebAssembly build

`make wasm` compiles the same source to `web/nuwyre.wasm` plus the matching
`web/wasm_exec.js` loader (the module the browser verifier loads), using
`GOOS=js GOARCH=wasm` with `-trimpath`.

## Layout

```
.
├── cmd/nuwyre/        # CLI entrypoint
├── cmd/nuwyre-wasm/   # WebAssembly entrypoint
├── internal/          # bundle parsing, the checks, output, embedded keys, RFC 3161
├── docs/spec/         # bundle-format spec, event schema, conformance fixtures
├── testdata/          # example bundle (load smoke)
├── Makefile           # build / wasm / test
└── go.mod             # module github.com/nuwyre/cli — no external workspace deps
```

The module is self-contained: it shares no code package with NuWyre's
TypeScript reference implementation. The contract between the two is the spec +
the conformance fixtures; both conform, neither imports the other.

## License

Apache-2.0. See [LICENSE](LICENSE).

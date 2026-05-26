package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Bitcoin client abstraction for check 5 (OpenTimestamps anchor
// verification). Two implementations:
//
//   - EsploraClient — default; HTTPS to public Esplora-protocol
//     endpoints (blockstream.info, mempool.space) with failover.
//     No authentication required; suitable for the public-bundle
//     verification use case where the verifier runs anywhere.
//   - BitcoinRPCClient — invoked when --bitcoin-rpc-url is set.
//     Talks to a user-provided bitcoind via JSON-RPC. The user
//     accepts whatever security posture their RPC endpoint exposes
//     (HTTPS-or-localhost-HTTP enforcement applies here too).
//
// **Both clients are cryptographic-input sources.** The OTS
// receipt's claimed Bitcoin attestation references a block by hash
// or height; the verifier fetches that block and confirms its merkle
// root matches the receipt's claimed value. If an attacker can
// influence the verifier's view of Bitcoin (MITM the block fetch,
// poison a public Esplora endpoint), they can forge OTS verification
// results. The HTTPS-only enforcement on Esplora defaults is the
// primary defense; localhost-bitcoind is trusted by user choice;
// MITM-against-blockstream-AND-mempool requires nation-state
// adversary on the verifier's network path, which is acceptable
// residual risk per the threat model (a compromised verifier
// network is outside the bundle integrity claim's scope).

// BitcoinClient is the interface check 5 uses to verify OTS
// Bitcoin attestations. The OTS verification library may use this
// directly, or may bring its own client; the abstraction exists so
// --bitcoin-rpc-url can override the default endpoint regardless
// of which library does the actual lookup.
//
// **Scope** (Crypto M2 from D1 reviewer pass): The current interface
// covers block-by-hash + block-by-height lookup, which is sufficient
// for OTS receipt verification (the receipt's terminal hash IS a
// block's merkle root; the verifier needs the merkle root + height
// to confirm the block is in the chain at the claimed height). Out
// of scope for V1:
//
//   - PrevHash chain validation: the verifier doesn't maintain its
//     own Bitcoin chain; it trusts the public Esplora endpoints'
//     "this block is at height N" claim. A nation-state adversary
//     who could MITM both blockstream.info AND mempool.space could
//     forge that claim — accepted residual risk per threat model.
//   - GetChainTip / depth-of-confirmation: V1 doesn't enforce a
//     minimum confirmation depth. An OTS attestation in any block
//     in the chain is accepted; reorganization within the last
//     few blocks is theoretically possible but the attacker would
//     need to forge a valid OTS upgrade in the alternate chain.
//
// Both are tracked for Phase 5+ when the verifier may want to enforce
// stronger Bitcoin-chain assumptions.
type BitcoinClient interface {
	// GetBlockHeader fetches the header for the block with the
	// given hash. Returns the header (including merkle root) on
	// success, or an error. Network-level failures wrap a
	// TransientError; definitive failures (404 not found,
	// malformed response) wrap a DefiniteError.
	GetBlockHeader(ctx context.Context, blockHash string) (*BlockHeader, error)

	// GetBlockHeightByHash returns the block height for the
	// given block hash. Some OTS attestations reference blocks
	// by hash; some (older) reference by height + merkle path.
	// The verifier needs both lookup directions.
	GetBlockHeightByHash(ctx context.Context, blockHash string) (int64, error)

	// EndpointDescription returns a log-safe identifier for the
	// underlying endpoint (no credentials, no API keys). Used in
	// CheckResult error/warning messages so the operator knows
	// which Bitcoin source the verifier consulted.
	EndpointDescription() string
}

// BlockHeader is the minimal Bitcoin block header surface check 5
// requires. Includes the merkle root (for cross-checking against
// the OTS receipt's claimed attestation hash) and the block
// timestamp (for plausibility check vs the daily root's
// computed_at time).
type BlockHeader struct {
	// Height is the block height (genesis = 0).
	Height int64
	// Hash is the block's own hash (64-char lowercase hex).
	Hash string
	// MerkleRoot is the block's merkle root (64-char lowercase
	// hex). The OTS receipt's terminal hash MUST equal this.
	MerkleRoot string
	// Timestamp is the block's nTime field (Unix seconds). MUST
	// be later than the daily root's computed_at — a block that
	// predates the root being anchored cannot have legitimately
	// witnessed it.
	Timestamp int64
}

// NewBitcoinClient returns the default BitcoinClient for the
// verifier. If rpcURL is empty, returns an EsploraClient configured
// with the production failover list (blockstream.info primary,
// mempool.space fallback). If rpcURL is non-empty, returns a
// BitcoinRPCClient targeting the user-supplied endpoint (JSON-RPC).
//
// httpClient is the pre-configured network client (per network.go);
// callers pass NewDefaultHTTPClient(version) in production paths.
func NewBitcoinClient(rpcURL string, httpClient *HTTPClient) (BitcoinClient, error) {
	if rpcURL == "" {
		return NewEsploraClient(httpClient), nil
	}
	// Sec M6 from D1 reviewer pass: until BitcoinRPCClient lands
	// fully (Session 4 polish), short-circuit at the factory with
	// a friendly NotImplemented error BEFORE requireHTTPS leaks
	// any URL parsing detail. This keeps the operator-facing
	// error message focused on the actual cause ("not implemented;
	// use the default") rather than a layered scheme-rejection
	// followed by NotImplemented.
	return nil, errors.New("--bitcoin-rpc-url is not yet implemented in Phase 4 Session 3 (Esplora default covers V1 verification needs); omit --bitcoin-rpc-url to use the default")
}

// =============================================================================
// EsploraClient
// =============================================================================

// EsploraClient queries public Esplora-protocol endpoints
// (blockstream.info + mempool.space) with HTTPS-only enforcement
// and failover. No authentication required; both endpoints are
// public services maintained by Bitcoin infrastructure providers.
//
// Failover discipline: try primary first, fall through to fallback
// on TransientError only. DefiniteError (404 not found block) is
// returned immediately — if blockstream says "block X doesn't exist,"
// asking mempool.space won't change the answer (both index the same
// public Bitcoin chain).
type EsploraClient struct {
	HTTPClient *HTTPClient
	// Endpoints are tried in order. First success wins.
	Endpoints []string
}

// NewEsploraClient returns an EsploraClient with the production
// failover list.
func NewEsploraClient(httpClient *HTTPClient) *EsploraClient {
	return &EsploraClient{
		HTTPClient: httpClient,
		Endpoints: []string{
			"https://blockstream.info/api",
			"https://mempool.space/api",
		},
	}
}

func (c *EsploraClient) EndpointDescription() string {
	scrubbed := make([]string, 0, len(c.Endpoints))
	for _, e := range c.Endpoints {
		scrubbed = append(scrubbed, scrubURL(e))
	}
	return "Esplora (" + strings.Join(scrubbed, " / ") + ")"
}

// GetBlockHeader fetches block header info from the first endpoint
// that responds successfully.
func (c *EsploraClient) GetBlockHeader(ctx context.Context, blockHash string) (*BlockHeader, error) {
	if !isLowercaseHex64(blockHash) {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("block hash %q is not 64-char lowercase hex", blockHash),
		}
	}
	// Crypto M3 from D1 reviewer pass: accumulate per-endpoint
	// transient errors so the operator sees "all endpoints exhausted"
	// rather than just the LAST endpoint's error. errors.Join wraps
	// the slice; IsTransient still returns true (any one TransientError
	// in the chain triggers the As).
	var endpointErrs []error
	for _, base := range c.Endpoints {
		url := base + "/block/" + blockHash
		body, err := c.HTTPClient.Fetch(ctx, url)
		if err != nil {
			if !IsTransient(err) {
				return nil, err
			}
			endpointErrs = append(endpointErrs, err)
			continue
		}
		var raw struct {
			ID         string `json:"id"`
			Height     int64  `json:"height"`
			MerkleRoot string `json:"merkle_root"`
			Timestamp  int64  `json:"timestamp"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, &DefiniteError{
				URL: scrubURL(url),
				Err: fmt.Errorf("Esplora block-info JSON parse: %w", err),
			}
		}
		if !isLowercaseHex64(raw.ID) || !isLowercaseHex64(raw.MerkleRoot) {
			return nil, &DefiniteError{
				URL: scrubURL(url),
				Err: fmt.Errorf("Esplora returned malformed block id/merkle_root (id=%s, merkle_root=%s)",
					truncate(raw.ID, 16), truncate(raw.MerkleRoot, 16)),
			}
		}
		if raw.ID != blockHash {
			return nil, &DefiniteError{
				URL: scrubURL(url),
				Err: fmt.Errorf("Esplora returned block %s, expected %s",
					truncate(raw.ID, 16), truncate(blockHash, 16)),
			}
		}
		return &BlockHeader{
			Height:     raw.Height,
			Hash:       raw.ID,
			MerkleRoot: raw.MerkleRoot,
			Timestamp:  raw.Timestamp,
		}, nil
	}
	// All endpoints exhausted with transient errors. Join into a
	// single error so the operator sees the full picture.
	if len(endpointErrs) > 0 {
		return nil, &TransientError{
			URL:      c.EndpointDescription(),
			Err:      errors.Join(endpointErrs...),
			Attempts: len(endpointErrs),
		}
	}
	return nil, &TransientError{
		URL:      c.EndpointDescription(),
		Err:      errors.New("no Esplora endpoints configured"),
		Attempts: 0,
	}
}

// GetBlockHeightByHash fetches just the height field; the underlying
// Esplora /block/<hash> response includes the height inline so this
// is a single round-trip via GetBlockHeader.
func (c *EsploraClient) GetBlockHeightByHash(ctx context.Context, blockHash string) (int64, error) {
	hdr, err := c.GetBlockHeader(ctx, blockHash)
	if err != nil {
		return 0, err
	}
	return hdr.Height, nil
}

// =============================================================================
// BitcoinRPCClient (deferred to Session 4+)
// =============================================================================
//
// `nuwyre verify --bitcoin-rpc-url <url>` would point the verifier
// at a user-run bitcoind via JSON-RPC. The factory NewBitcoinClient
// short-circuits with a NotImplemented error when --bitcoin-rpc-url
// is non-empty (Sec M6 from D1 reviewer pass: short-circuit at
// factory avoids layered scheme-rejection followed by NotImplemented
// when the user passes a malformed URL). Implementation lands in
// Session 4 polish pass with its own reviewer attention; the public
// Esplora client covers V1 verification needs.

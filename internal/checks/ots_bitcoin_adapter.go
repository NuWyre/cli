package checks

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// otsBitcoinAdapter implements the nbd-wtf/opentimestamps `Bitcoin`
// interface (`GetBlockHash(height) → *chainhash.Hash` and
// `GetBlockHeader(hash) → *wire.BlockHeader`) by wrapping our D1
// HTTPClient + the Esplora protocol.
//
// **Why an adapter** (not the library's NewEsploraClient): the
// library's bare Esplora client uses raw http.Get with no HTTPS
// enforcement, no retries, no User-Agent, no response-size cap, and
// no credential-scrubbed error messages. All those are D1's load-
// bearing security primitives. The adapter preserves them — every
// network round-trip the library makes during Sequence.Verify goes
// through HTTPClient's retry-classified, scheme-validated, scrubbed
// pipeline.
//
// **Failover** between blockstream.info and mempool.space mirrors
// EsploraClient (D1's bitcoin.go): try primary first, fall through
// to fallback on TransientError only. DefiniteError (404 not found,
// malformed response) returns immediately — asking mempool.space
// won't change blockstream's "block doesn't exist" answer.
//
// **State capture** (LastHeader): the library's
// `Sequence.Verify(bitcoin, digest)` call internally invokes
// GetBlockHash + GetBlockHeader to retrieve the Bitcoin block whose
// merkle root the receipt claims. After Verify succeeds, the adapter
// has the BlockHeader cached — check 5 reads adapter.LastHeader to
// run additional plausibility checks (e.g., block timestamp ≥ OTS
// submission time minus skew tolerance) without re-fetching.
type otsBitcoinAdapter struct {
	httpClient *HTTPClient
	endpoints  []string
	ctx        context.Context

	// LastHeader is the BlockHeader returned by the most recent
	// successful GetBlockHeader call. Populated for check 5's
	// post-Verify plausibility checks. Zero-valued if no successful
	// header fetch has happened yet.
	LastHeader *wire.BlockHeader
}

// newOTSBitcoinAdapter constructs an adapter with the production
// failover endpoint list.
func newOTSBitcoinAdapter(httpClient *HTTPClient, ctx context.Context) *otsBitcoinAdapter {
	return &otsBitcoinAdapter{
		httpClient: httpClient,
		endpoints: []string{
			"https://blockstream.info/api",
			"https://mempool.space/api",
		},
		ctx: ctx,
	}
}

// GetBlockHash returns the block hash at the given height. Esplora
// path: GET /block-height/<N> returns the block hash hex (NOT
// reversed; we reverse below to match chainhash.Hash byte order
// per the library's existing convention).
func (a *otsBitcoinAdapter) GetBlockHash(height int64) (*chainhash.Hash, error) {
	if height < 0 {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("block height %d is negative; OTS attestation references invalid block", height),
		}
	}
	path := "/block-height/" + strconv.FormatInt(height, 10)
	body, err := a.fetchWithFailover(path)
	if err != nil {
		return nil, err
	}
	hashHex := strings.TrimSpace(string(body))
	if !isLowercaseHex64(hashHex) {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("Esplora block-height/%d returned non-hex64: %q", height, truncate(hashHex, 80)),
		}
	}
	rawHash, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("Esplora block-height/%d hex decode: %w", height, err),
		}
	}
	if len(rawHash) != chainhash.HashSize {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("Esplora block-height/%d returned %d bytes, expected %d",
				height, len(rawHash), chainhash.HashSize),
		}
	}
	// Bitcoin internal byte order is reversed from the human-readable
	// hex form; chainhash.Hash uses internal order. The library's
	// existing Esplora client reverses; we mirror.
	slices.Reverse(rawHash)
	var chash chainhash.Hash
	copy(chash[:], rawHash)
	return &chash, nil
}

// GetBlockHeader fetches the block header for the given hash.
// Esplora path: GET /block/<hash>/header returns the raw header
// hex (80-byte serialized header).
//
// Side effect: on success, populates a.LastHeader so check 5 can
// read post-Verify plausibility metadata (timestamp, etc.).
func (a *otsBitcoinAdapter) GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error) {
	if hash == nil {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("nil block hash"),
		}
	}
	path := "/block/" + hash.String() + "/header"
	body, err := a.fetchWithFailover(path)
	if err != nil {
		return nil, err
	}
	headerHex := strings.TrimSpace(string(body))
	rawHeader, err := hex.DecodeString(headerHex)
	if err != nil {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("Esplora block-header hex decode for %s: %w",
				truncate(hash.String(), 16), err),
		}
	}
	header := &wire.BlockHeader{}
	if err := header.BtcDecode(bytes.NewReader(rawHeader), 0, 0); err != nil {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("Esplora block-header decode for %s: %w",
				truncate(hash.String(), 16), err),
		}
	}
	// H1 from D2 reviewer pass: cross-check the returned header's
	// hash against the requested hash. A malicious or buggy
	// endpoint that returns a header for a different block (with
	// the same merkle root, by collision attack — computationally
	// infeasible today; or by swap, e.g., to influence the block
	// timestamp plausibility check downstream) is caught here.
	// Mirrors EsploraClient.GetBlockHeader's id-equality discipline
	// in bitcoin.go.
	gotHash := header.BlockHash()
	if !gotHash.IsEqual(hash) {
		return nil, &DefiniteError{
			URL: "(esplora)",
			Err: fmt.Errorf("Esplora returned header for block %s, expected %s",
				truncate(gotHash.String(), 16), truncate(hash.String(), 16)),
		}
	}
	a.LastHeader = header
	return header, nil
}

// fetchWithFailover walks the endpoints list, returning the first
// successful response. Transient errors fall through to the next
// endpoint; definitive errors return immediately. After all endpoints
// exhausted, returns a single TransientError annotating the failure
// with the endpoint count.
func (a *otsBitcoinAdapter) fetchWithFailover(path string) ([]byte, error) {
	var lastErr error
	for _, base := range a.endpoints {
		body, err := a.httpClient.Fetch(a.ctx, base+path)
		if err == nil {
			return body, nil
		}
		if !IsTransient(err) {
			return nil, err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no Esplora endpoints configured")
	}
	return nil, &TransientError{
		URL:      "Esplora (" + strings.Join(a.endpoints, " / ") + ")",
		Err:      lastErr,
		Attempts: len(a.endpoints),
	}
}

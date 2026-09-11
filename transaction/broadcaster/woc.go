package broadcaster

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	woc "github.com/mrz1836/go-whatsonchain"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

type WOCNetwork string

var (
	WOCMainnet WOCNetwork = "main"
	WOCTestnet WOCNetwork = "test"
)

// WhatsOnChain broadcasts transactions through the WhatsOnChain API. It delegates
// its HTTP call to github.com/mrz1836/go-whatsonchain, which centralizes URL
// building, API-key handling, and response parsing. A custom util.HTTPClient can
// be supplied via Client (it satisfies go-whatsonchain's HTTPInterface); when nil
// it defaults to http.DefaultClient.
//
// API key resolution: when ApiKey is empty, go-whatsonchain falls back to the
// WHATS_ON_CHAIN_API_KEY environment variable if it is set. Set ApiKey explicitly
// to control the credential; leave both unset for unauthenticated requests.
type WhatsOnChain struct {
	Network WOCNetwork
	ApiKey  string
	Client  util.HTTPClient
}

func (b *WhatsOnChain) Broadcast(t *transaction.Transaction) (
	*transaction.BroadcastSuccess,
	*transaction.BroadcastFailure,
) {
	return b.BroadcastCtx(context.Background(), t)
}

func (b *WhatsOnChain) BroadcastCtx(ctx context.Context, t *transaction.Transaction) (
	*transaction.BroadcastSuccess,
	*transaction.BroadcastFailure,
) {
	if t == nil {
		return nil, &transaction.BroadcastFailure{
			Code:        strconv.Itoa(http.StatusInternalServerError),
			Description: "nil transaction",
		}
	}

	// Resolve the client into a local variable rather than assigning to b.Client,
	// so a broadcaster shared across goroutines with a nil Client does not race on
	// the field. http.DefaultClient reuses a shared, connection-pooled transport.
	client := b.Client
	if client == nil {
		client = http.DefaultClient
	}

	clientOpts := []woc.ClientOption{
		woc.WithNetwork(woc.NetworkType(b.Network)),
		woc.WithHTTPClient(client),
	}
	if b.ApiKey != "" {
		clientOpts = append(clientOpts, woc.WithAPIKey(b.ApiKey))
	}

	wocClient, err := woc.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        strconv.Itoa(http.StatusInternalServerError),
			Description: err.Error(),
		}
	}

	if _, err = wocClient.BroadcastTx(ctx, t.Hex()); err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        strconv.Itoa(http.StatusInternalServerError),
			Description: err.Error(),
		}
	}

	// go-whatsonchain's BroadcastTx treats HTTP 404 as a non-error, so a rejected
	// broadcast can return without an error. Reject any non-200 status as a failure
	// rather than reporting a false success.
	if last := wocClient.LastRequest(); last != nil && last.StatusCode != http.StatusOK {
		return nil, &transaction.BroadcastFailure{
			Code:        strconv.Itoa(last.StatusCode),
			Description: fmt.Sprintf("broadcast rejected: HTTP %d", last.StatusCode),
		}
	}

	return &transaction.BroadcastSuccess{
		Txid: t.TxID().String(),
	}, nil
}

package broadcaster

import (
	"context"
	"net/http"

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
			Code:        "500",
			Description: "nil transaction",
		}
	}

	if b.Client == nil {
		b.Client = http.DefaultClient
	}

	clientOpts := []woc.ClientOption{
		woc.WithNetwork(woc.NetworkType(b.Network)),
		woc.WithHTTPClient(b.Client),
	}
	if b.ApiKey != "" {
		clientOpts = append(clientOpts, woc.WithAPIKey(b.ApiKey))
	}

	client, err := woc.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	if _, err = client.BroadcastTx(ctx, t.Hex()); err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	return &transaction.BroadcastSuccess{
		Txid: t.TxID().String(),
	}, nil
}

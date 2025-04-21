package broadcaster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

type WOCNetwork string

var (
	WOCMainnet WOCNetwork = "main"
	WOCTestnet WOCNetwork = "test"
)

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

	bodyMap := map[string]any{
		"txhex": t.Hex(),
	}
	if body, err := json.Marshal(bodyMap); err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	} else {
		url := fmt.Sprintf("https://api.whatsonchain.com/v1/bsv/%s/tx/raw", b.Network)
		req, err := http.NewRequestWithContext(
			ctx,
			"POST",
			url,
			bytes.NewBuffer(body),
		)
		if err != nil {
			return nil, &transaction.BroadcastFailure{
				Code:        "500",
				Description: err.Error(),
			}
		}
		req.Header.Set("Content-Type", "application/json")
		if b.ApiKey != "" {
			req.Header.Set("Authorization", "Bearer "+b.ApiKey)
		}

		if resp, err := b.Client.Do(req); err != nil {
			return nil, &transaction.BroadcastFailure{
				Code:        "500",
				Description: err.Error(),
			}
		} else {
			defer resp.Body.Close() //nolint:errcheck // standard http client pattern
			if resp.StatusCode != 200 {
				if body, err := io.ReadAll(resp.Body); err != nil {
					return nil, &transaction.BroadcastFailure{
						Code:        fmt.Sprintf("%d", resp.StatusCode),
						Description: "unknown error",
					}
				} else {
					return nil, &transaction.BroadcastFailure{
						Code:        fmt.Sprintf("%d", resp.StatusCode),
						Description: string(body),
					}
				}
			} else {
				return &transaction.BroadcastSuccess{
					Txid: t.TxID().String(),
				}, nil
			}
		}
	}
}

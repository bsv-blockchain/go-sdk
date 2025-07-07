package broadcaster

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

type TAALResponse struct {
	Txid   string `json:"txid"`
	Status uint32 `json:"status"`
	Err    string `json:"error"`
}

type TAALBroadcast struct {
	ApiKey string
	Client util.HTTPClient
}

func (b *TAALBroadcast) Broadcast(t *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return b.BroadcastCtx(context.Background(), t)
}

func (b *TAALBroadcast) BroadcastCtx(ctx context.Context, t *transaction.Transaction) (
	*transaction.BroadcastSuccess,
	*transaction.BroadcastFailure,
) {
	buf := bytes.NewBuffer(t.Bytes())
	url := "https://api.taal.com/api/v1/broadcast"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		url,
		buf,
	)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if b.ApiKey != "" {
		req.Header.Set("Authorization", b.ApiKey)
	}
	if resp, err := b.Client.Do(req); err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	} else {
		defer resp.Body.Close()
		var taalResp TAALResponse
		if err := json.NewDecoder(resp.Body).Decode(&taalResp); err != nil {
			return nil, &transaction.BroadcastFailure{
				Code:        strconv.Itoa(resp.StatusCode),
				Description: "unknown error",
			}
		} else if resp.StatusCode != 200 && !strings.Contains(taalResp.Err, "txn-already-known") {
			return nil, &transaction.BroadcastFailure{
				Code:        strconv.Itoa(resp.StatusCode),
				Description: taalResp.Err,
			}
		} else {
			return &transaction.BroadcastSuccess{
				Txid: t.TxID().String(),
			}, nil
		}
	}
}

package broadcaster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

type ArcStatus string

const (
	REJECTED             ArcStatus = "REJECTED"
	QUEUED               ArcStatus = "QUEUED"
	RECEIVED             ArcStatus = "RECEIVED"
	STORED               ArcStatus = "STORED"
	ANNOUNCED_TO_NETWORK ArcStatus = "ANNOUNCED_TO_NETWORK"
	REQUESTED_BY_NETWORK ArcStatus = "REQUESTED_BY_NETWORK"
	SENT_TO_NETWORK      ArcStatus = "SENT_TO_NETWORK"
	ACCEPTED_BY_NETWORK  ArcStatus = "ACCEPTED_BY_NETWORK"
	SEEN_ON_NETWORK      ArcStatus = "SEEN_ON_NETWORK"
)

type Arc struct {
	ApiUrl                  string
	ApiKey                  string
	CallbackUrl             *string
	CallbackToken           *string
	CallbackBatch           bool
	FullStatusUpdates       bool
	MaxTimeout              *int
	SkipFeeValidation       bool
	SkipScriptValidation    bool
	SkipTxValidation        bool
	CumulativeFeeValidation bool
	WaitForStatus           string
	WaitFor                 ArcStatus
	Client                  util.HTTPClient // Added for testing
	Verbose                 bool
}

type ArcResponse struct {
	BlockHash   string     `json:"blockHash,omitempty"`
	BlockHeight uint32     `json:"blockHeight,omitempty"`
	ExtraInfo   string     `json:"extraInfo,omitempty"`
	Status      int        `json:"status,omitempty"`
	Timestamp   time.Time  `json:"timestamp,omitempty"`
	Title       string     `json:"title,omitempty"`
	TxStatus    *ArcStatus `json:"txStatus,omitempty"`
	Instance    *string    `json:"instance,omitempty"`
	Txid        string     `json:"txid,omitempty"`
	Detail      *string    `json:"detail,omitempty"`
	MerklePath  string     `json:"merklePath,omitempty"`
}

func (a *Arc) Broadcast(t *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return a.BroadcastCtx(context.Background(), t)
}

func (a *Arc) BroadcastCtx(ctx context.Context, t *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	var buf *bytes.Buffer
	for _, input := range t.Inputs {
		if input.SourceTxOutput() == nil {
			buf = bytes.NewBuffer(t.Bytes())
			break
		}
	}
	if buf == nil {
		if ef, err := t.EF(); err != nil {
			return nil, &transaction.BroadcastFailure{
				Code:        "500",
				Description: err.Error(),
			}
		} else {
			buf = bytes.NewBuffer(ef)
		}
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		a.ApiUrl+"/tx",
		buf,
	)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	if a.ApiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.ApiKey)
	}
	if a.CallbackUrl != nil {
		req.Header.Set("X-CallbackUrl", *a.CallbackUrl)
	}
	if a.CallbackToken != nil {
		req.Header.Set("X-CallbackToken", *a.CallbackToken)
	}
	if a.CallbackBatch {
		req.Header.Set("X-CallbackBatch", "true")
	}
	if a.FullStatusUpdates {
		req.Header.Set("X-FullStatusUpdates", "true")
	}
	if a.MaxTimeout != nil {
		req.Header.Set("X-MaxTimeout", fmt.Sprintf("%d", *a.MaxTimeout))
	}
	if a.SkipFeeValidation {
		req.Header.Set("X-SkipFeeValidation", "true")
	}
	if a.SkipScriptValidation {
		req.Header.Set("X-SkipScriptValidation", "true")
	}
	if a.SkipTxValidation {
		req.Header.Set("X-SkipTxValidation", "true")
	}
	if a.CumulativeFeeValidation {
		req.Header.Set("X-CumulativeFeeValidation", "true")
	}
	if a.WaitForStatus != "" {
		req.Header.Set("X-WaitForStatus", a.WaitForStatus)
	}
	if a.WaitFor != "" {
		req.Header.Set("X-WaitFor", string(a.WaitFor))
	}

	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	response := &ArcResponse{}
	if a.Verbose {
		log.Println("msg", string(msg))
	}
	err = json.Unmarshal(msg, &response)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	if response.TxStatus != nil && *response.TxStatus == REJECTED {
		return nil, &transaction.BroadcastFailure{
			Code:        "400",
			Description: response.ExtraInfo,
		}
	}
	if response.Status == 200 {
		return &transaction.BroadcastSuccess{
			Txid:    response.Txid,
			Message: response.Title,
		}, nil
	}

	return nil, &transaction.BroadcastFailure{
		Code:        fmt.Sprintf("%d", response.Status),
		Description: response.Title,
	}
}

func (a *Arc) Status(txid string) (*ArcResponse, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		a.ApiUrl+"/tx/"+txid,
		nil,
	)
	if err != nil {
		return nil, err
	}

	if a.ApiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.ApiKey)
	}

	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := &ArcResponse{}
	err = json.Unmarshal(msg, &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

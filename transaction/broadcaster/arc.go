package broadcaster

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

type ArcStatus string

const (
	REJECTED               ArcStatus = "REJECTED"
	QUEUED                 ArcStatus = "QUEUED"
	RECEIVED               ArcStatus = "RECEIVED"
	STORED                 ArcStatus = "STORED"
	ANNOUNCED_TO_NETWORK   ArcStatus = "ANNOUNCED_TO_NETWORK"
	REQUESTED_BY_NETWORK   ArcStatus = "REQUESTED_BY_NETWORK"
	SENT_TO_NETWORK        ArcStatus = "SENT_TO_NETWORK"
	ACCEPTED_BY_NETWORK    ArcStatus = "ACCEPTED_BY_NETWORK"
	SEEN_ON_NETWORK        ArcStatus = "SEEN_ON_NETWORK"
	MINED                  ArcStatus = "MINED"
	CONFIRMED              ArcStatus = "CONFIRMED"
	DOUBLE_SPEND_ATTEMPTED ArcStatus = "DOUBLE_SPEND_ATTEMPTED"
	SEEN_IN_ORPHAN_MEMPOOL ArcStatus = "SEEN_IN_ORPHAN_MEMPOOL"
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
	BlockHash    string     `json:"blockHash,omitempty"`
	BlockHeight  uint32     `json:"blockHeight,omitempty"`
	ExtraInfo    string     `json:"extraInfo,omitempty"`
	Status       int        `json:"status,omitempty"`
	Timestamp    time.Time  `json:"timestamp,omitempty"`
	Title        string     `json:"title,omitempty"`
	TxStatus     *ArcStatus `json:"txStatus,omitempty"`
	Instance     *string    `json:"instance,omitempty"`
	Txid         string     `json:"txid,omitempty"`
	Detail       *string    `json:"detail,omitempty"`
	MerklePath   string     `json:"merklePath,omitempty"`
	CompetingTxs []string   `json:"competingTxs,omitempty"`

	// httpStatusCode is the real HTTP status code of the response that
	// produced this ArcResponse. It is not part of ARC's JSON envelope (ARC's
	// own success responses carry no "status" field at all — see
	// ArcTxResponse in specs/broadcast/arc.yaml — so BroadcastCtx must not
	// key success/failure off the JSON Status field above) and is populated
	// only by ArcBroadcast/Status from the transport response.
	httpStatusCode int
}

func (a *Arc) Broadcast(t *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return a.BroadcastCtx(context.Background(), t)
}

// rawTxHex returns the hex-encoded transaction ARC expects in the
// {"rawTx": ...} request body: Extended Format when every input carries its
// source output, falling back to plain raw hex otherwise (mirrors ts-sdk's
// ARC.ts transactionHex, which tries toHexEF() and falls back to toHex() on
// the "missing source transactions" error).
func rawTxHex(t *transaction.Transaction) (string, error) {
	for _, input := range t.Inputs {
		if input.SourceTxOutput() == nil {
			return hex.EncodeToString(t.Bytes()), nil
		}
	}
	ef, err := t.EF()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ef), nil
}

func (a *Arc) ArcBroadcast(ctx context.Context, t *transaction.Transaction) (*ArcResponse, error) {
	txHex, err := rawTxHex(t)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"rawTx": txHex})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		a.ApiUrl+"/tx",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

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
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := &ArcResponse{}
	if a.Verbose {
		log.Println("msg", string(msg))
	}
	err = json.Unmarshal(msg, &response)
	if err != nil {
		return nil, err
	}
	response.httpStatusCode = resp.StatusCode

	return response, nil
}

// arcFailureStatuses are the ARC txStatus values that ts-sdk's ARC.broadcast
// treats as a BroadcastFailure even though ARC answered with HTTP 200 (see
// ARC_ERROR_STATUSES in packages/sdk/src/transaction/broadcasters/ARC.ts and
// the ArcTxStatus doc in specs/broadcast/arc.yaml). A status containing
// "ORPHAN" (in either txStatus or extraInfo) is also treated as a failure.
var arcFailureStatuses = map[ArcStatus]bool{
	DOUBLE_SPEND_ATTEMPTED: true,
	REJECTED:               true,
	"INVALID":              true,
	"MALFORMED":            true,
	"MINED_IN_STALE_BLOCK": true,
}

// arcAcceptedStatuses are the txStatus values that count as a successful
// broadcast. It is ts-sdk's ARC_ACCEPTED_STATUSES plus the non-error states
// go-sdk's ArcStatus enum already defines (QUEUED, REQUESTED_BY_NETWORK,
// CONFIRMED), which ARC can legitimately report for an accepted
// transaction. Any other status is an invalid response, as in ts-sdk.
var arcAcceptedStatuses = map[ArcStatus]bool{
	"SUCCESS":            true,
	RECEIVED:             true,
	SENT_TO_NETWORK:      true,
	ANNOUNCED_TO_NETWORK: true,
	ACCEPTED_BY_NETWORK:  true,
	SEEN_ON_NETWORK:      true,
	STORED:               true,
	MINED:                true,
	"IMMUTABLE":          true,
	QUEUED:               true,
	REQUESTED_BY_NETWORK: true,
	CONFIRMED:            true,
}

func isArcFailureStatus(txStatus ArcStatus, extraInfo string) bool {
	upper := strings.ToUpper(string(txStatus))
	if arcFailureStatuses[ArcStatus(upper)] {
		return true
	}
	return strings.Contains(upper, "ORPHAN") ||
		strings.Contains(strings.ToUpper(extraInfo), "ORPHAN")
}

// isTxid reports whether s is a 64-character hex transaction id.
func isTxid(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// otherTxid reports whether ARC echoed a well-formed txid that is not the
// submitted transaction's, which ts-sdk rejects as ERR_TXID_MISMATCH.
func otherTxid(got, expected string) bool {
	return isTxid(got) && !strings.EqualFold(got, expected)
}

func (a *Arc) BroadcastCtx(ctx context.Context, t *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	expectedTxid := t.TxID().String()
	response, err := a.ArcBroadcast(ctx, t)
	if err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	var txStatus ArcStatus
	if response.TxStatus != nil {
		txStatus = *response.TxStatus
	}

	// ARC's success envelope (ArcTxResponse) carries no "status" field at
	// all, so success/failure must be decided from the real HTTP status
	// code, not from response.Status (which only ever appears in ARC's error
	// envelope, ArcErrorResponse, where it happens to restate the HTTP code).
	if response.httpStatusCode >= 200 && response.httpStatusCode < 300 {
		// ts-sdk's successfulArcResponse rejects a missing/empty txStatus as
		// an invalid response rather than treating it as success (it never
		// reaches the ARC_ERROR_STATUSES/ARC_ACCEPTED_STATUSES check at all).
		if txStatus == "" {
			return nil, &transaction.BroadcastFailure{
				Code:        "ERR_INVALID_RESPONSE",
				Description: "ARC returned invalid transaction status metadata.",
			}
		}
		if isArcFailureStatus(txStatus, response.ExtraInfo) {
			if otherTxid(response.Txid, expectedTxid) {
				return nil, &transaction.BroadcastFailure{
					Code:        "ERR_TXID_MISMATCH",
					Description: "ARC returned a failure for another transaction.",
				}
			}
			return nil, &transaction.BroadcastFailure{
				// ts-sdk: description: `${txStatus} ${extraInfo ?? ''}`.trim()
				Code:         string(txStatus),
				Description:  strings.TrimSpace(string(txStatus) + " " + response.ExtraInfo),
				CompetingTxs: response.CompetingTxs,
			}
		}
		if !arcAcceptedStatuses[ArcStatus(strings.ToUpper(string(txStatus)))] {
			return nil, &transaction.BroadcastFailure{
				Code:        "ERR_INVALID_RESPONSE",
				Description: "ARC returned an unknown transaction status.",
			}
		}
		if !isTxid(response.Txid) || !strings.EqualFold(response.Txid, expectedTxid) {
			return nil, &transaction.BroadcastFailure{
				Code:        "ERR_TXID_MISMATCH",
				Description: "ARC acknowledged a transaction other than the submitted transaction.",
			}
		}
		return &transaction.BroadcastSuccess{
			Txid:    expectedTxid,
			Message: strings.TrimSpace(string(txStatus) + " " + response.ExtraInfo),
		}, nil
	}

	if otherTxid(response.Txid, expectedTxid) {
		return nil, &transaction.BroadcastFailure{
			Code:        "ERR_TXID_MISMATCH",
			Description: "ARC returned a failure for another transaction.",
		}
	}

	// ts-sdk's failedArcResponse defaults description to the literal
	// "Unknown error" and only overrides it with the response's "detail"
	// field; it never falls back to "title" (title is only ever populated by
	// ARC's own error envelope, which ts-sdk deliberately ignores here).
	description := "Unknown error"
	if response.Detail != nil && *response.Detail != "" {
		description = *response.Detail
	}
	return nil, &transaction.BroadcastFailure{
		Code:        fmt.Sprintf("%d", response.httpStatusCode),
		Description: description,
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
	response.httpStatusCode = resp.StatusCode

	return response, nil
}

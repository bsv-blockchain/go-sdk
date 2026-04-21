package lookup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// Facilitator defines the interface for overlay lookup facilitators that can execute lookup queries
type Facilitator interface {
	Lookup(ctx context.Context, url string, question *LookupQuestion) (*LookupAnswer, error)
}

// HTTPSOverlayLookupFacilitator implements the Facilitator interface using HTTPS requests
type HTTPSOverlayLookupFacilitator struct {
	Client util.HTTPClient
}

// Lookup executes a lookup question against the specified URL and returns the answer.
// It supports both JSON responses and binary octet-stream responses (aggregated BEEF format).
func (f *HTTPSOverlayLookupFacilitator) Lookup(ctx context.Context, url string, question *LookupQuestion) (*LookupAnswer, error) {
	q, err := json.Marshal(question)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url+"/lookup", bytes.NewBuffer(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aggregation", "yes")

	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &util.HTTPError{
			StatusCode: resp.StatusCode,
			Err:        errors.New("lookup failed"),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.Header.Get("Content-Type") == "application/octet-stream" {
		return parseBinaryLookupAnswer(body)
	}

	answer := &LookupAnswer{}
	if err := json.Unmarshal(body, answer); err != nil {
		return nil, err
	}
	return answer, nil
}

// parseBinaryLookupAnswer decodes the aggregated binary output-list format used by overlay nodes.
//
// Wire format:
//
//	VarInt          nOutpoints
//	[nOutpoints]×{
//	  [32]byte      txid (little-endian / raw hash bytes)
//	  VarInt        outputIndex
//	  VarInt        contextLen
//	  [contextLen]  context (omitted when contextLen == 0)
//	}
//	[]byte          BEEF (shared; contains all referenced transactions)
func parseBinaryLookupAnswer(data []byte) (*LookupAnswer, error) {
	r := util.NewReader(data)

	nOutpoints, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("binary lookup: reading outpoint count: %w", err)
	}

	type outpointMeta struct {
		txid        string
		outputIndex uint32
		context     []byte
	}
	metas := make([]outpointMeta, 0, nOutpoints)

	for i := uint64(0); i < nOutpoints; i++ {
		txidBytes, err := r.ReadBytes(32)
		if err != nil {
			return nil, fmt.Errorf("binary lookup: reading txid[%d]: %w", i, err)
		}
		txid := hex.EncodeToString(txidBytes)

		outputIndex, err := r.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("binary lookup: reading outputIndex[%d]: %w", i, err)
		}

		contextLen, err := r.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("binary lookup: reading contextLen[%d]: %w", i, err)
		}

		var context []byte
		if contextLen > 0 {
			context, err = r.ReadBytes(int(contextLen))
			if err != nil {
				return nil, fmt.Errorf("binary lookup: reading context[%d]: %w", i, err)
			}
		}

		metas = append(metas, outpointMeta{
			txid:        txid,
			outputIndex: uint32(outputIndex),
			context:     context,
		})
	}

	// Remaining bytes are the shared BEEF containing all referenced transactions.
	beefBytes, err := r.ReadBytes(len(r.Data) - r.Pos)
	if err != nil {
		return nil, fmt.Errorf("binary lookup: reading BEEF: %w", err)
	}

	beef, err := transaction.NewBeefFromBytes(beefBytes)
	if err != nil {
		return nil, fmt.Errorf("binary lookup: parsing BEEF: %w", err)
	}

	outputs := make([]*OutputListItem, 0, len(metas))
	for _, m := range metas {
		tx := beef.FindTransaction(m.txid)
		if tx == nil {
			return nil, fmt.Errorf("binary lookup: txid %s not found in BEEF", m.txid)
		}
		txBeef, err := tx.BEEF()
		if err != nil {
			return nil, fmt.Errorf("binary lookup: re-serialising BEEF for txid %s: %w", m.txid, err)
		}
		outputs = append(outputs, &OutputListItem{
			Beef:        txBeef,
			OutputIndex: m.outputIndex,
		})
	}

	return &LookupAnswer{
		Type:    AnswerTypeOutputList,
		Outputs: outputs,
	}, nil
}

package serializer

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// actionResultStatusCode is the numeric representation of ActionResultStatus.
type actionResultStatusCode uint8

const (
	actionResultStatusCodeUnproven actionResultStatusCode = 1
	actionResultStatusCodeSending  actionResultStatusCode = 2
	actionResultStatusCodeFailed   actionResultStatusCode = 3
)

func writeTxidSliceWithStatus(w *util.Writer, results []wallet.SendWithResult) error {
	if results == nil {
		w.WriteVarInt(0)
		return nil
	}
	w.WriteVarInt(uint64(len(results)))
	for _, res := range results {
		txidBytes, err := hex.DecodeString(res.Txid)
		if err != nil {
			return fmt.Errorf("error decoding txid: %w", err)
		}
		w.WriteBytes(txidBytes)

		var statusByte actionResultStatusCode
		switch res.Status {
		case wallet.ActionResultStatusUnproven:
			statusByte = actionResultStatusCodeUnproven
		case wallet.ActionResultStatusSending:
			statusByte = actionResultStatusCodeSending
		case wallet.ActionResultStatusFailed:
			statusByte = actionResultStatusCodeFailed
		default:
			return fmt.Errorf("invalid status: %s", res.Status)
		}
		w.WriteByte(byte(statusByte))
	}
	return nil
}

func readTxidSliceWithStatus(r *util.Reader) ([]wallet.SendWithResult, error) {
	count, err := r.ReadVarInt()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	results := make([]wallet.SendWithResult, 0, count)
	for i := uint64(0); i < count; i++ {
		txid, err := r.ReadBytes(32)
		if err != nil {
			return nil, err
		}

		statusCode, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		var status wallet.ActionResultStatus
		switch actionResultStatusCode(statusCode) {
		case actionResultStatusCodeUnproven:
			status = wallet.ActionResultStatusUnproven
		case actionResultStatusCodeSending:
			status = wallet.ActionResultStatusSending
		case actionResultStatusCodeFailed:
			status = wallet.ActionResultStatusFailed
		default:
			return nil, fmt.Errorf("invalid status code: %d", statusCode)
		}

		results = append(results, wallet.SendWithResult{
			Txid:   hex.EncodeToString(txid),
			Status: status,
		})
	}
	return results, nil
}

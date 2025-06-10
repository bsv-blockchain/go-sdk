package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/chainhash"

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
		w.WriteBytes(res.Txid[:])

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
		txidBytes, err := r.ReadBytes(chainhash.HashSize)
		if err != nil {
			return nil, err
		}
		txid, err := chainhash.NewHash(txidBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid txid: %w", err)
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
			Txid:   *txid,
			Status: status,
		})
	}
	return results, nil
}

package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func writeTxidSliceWithStatus(w *writer, results []wallet.SendWithResult) error {
	if results == nil {
		w.writeVarInt(0)
		return nil
	}
	w.writeVarInt(uint64(len(results)))
	for _, res := range results {
		txidBytes, err := hex.DecodeString(res.Txid)
		if err != nil {
			return fmt.Errorf("error decoding txid: %w", err)
		}
		w.writeBytes(txidBytes)

		var statusByte byte
		switch res.Status {
		case "unproven":
			statusByte = 1
		case "sending":
			statusByte = 2
		case "failed":
			statusByte = 3
		default:
			return fmt.Errorf("invalid status: %s", res.Status)
		}
		w.writeByte(statusByte)
	}
	return nil
}

func readTxidSliceWithStatus(r *reader) ([]wallet.SendWithResult, error) {
	count, err := r.readVarInt()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	results := make([]wallet.SendWithResult, 0, count)
	for i := uint64(0); i < count; i++ {
		txid, err := r.readBytes(32)
		if err != nil {
			return nil, err
		}

		statusCode, err := r.readByte()
		if err != nil {
			return nil, err
		}

		var status string
		switch statusCode {
		case 1:
			status = "unproven"
		case 2:
			status = "sending"
		case 3:
			status = "failed"
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

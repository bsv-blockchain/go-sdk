package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func DeserializeSignActionResult(data []byte) (*wallet.SignActionResult, error) {
	r := newReader(data)
	result := &wallet.SignActionResult{}

	// Txid
	txidFlag, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("reading txid flag: %w", err)
	}
	if txidFlag == 1 {
		txidBytes, err := r.readBytes(32)
		if err != nil {
			return nil, fmt.Errorf("reading txid bytes: %w", err)
		}
		result.Txid = hex.EncodeToString(txidBytes)
	}

	// Tx
	txFlag, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("reading tx flag: %w", err)
	}
	if txFlag == 1 {
		txLen, err := r.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("reading tx length: %w", err)
		}
		result.Tx, err = r.readBytes(int(txLen))
		if err != nil {
			return nil, fmt.Errorf("reading tx bytes: %w", err)
		}
	}

	// SendWithResults
	sendWithLen, err := r.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("reading sendWith length: %w", err)
	}
	if sendWithLen > 0 {
		result.SendWithResults = make([]wallet.SendWithResult, sendWithLen)
		for i := 0; i < int(sendWithLen); i++ {
			txidBytes, err := r.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("reading sendWith txid bytes: %w", err)
			}
			statusByte, err := r.readByte()
			if err != nil {
				return nil, fmt.Errorf("reading status byte: %w", err)
			}

			var status string
			switch statusByte {
			case 1:
				status = "unproven"
			case 2:
				status = "sending"
			case 3:
				status = "failed"
			default:
				return nil, fmt.Errorf("invalid status byte: %d", statusByte)
			}

			result.SendWithResults[i] = wallet.SendWithResult{
				Txid:   hex.EncodeToString(txidBytes),
				Status: status,
			}
		}
	}

	return result, nil
}

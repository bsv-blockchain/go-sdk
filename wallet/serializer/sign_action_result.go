package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionResult(result *wallet.SignActionResult) ([]byte, error) {
	w := newWriter()

	// Txid
	if result.Txid != "" {
		w.writeByte(1)
		txidBytes, err := hex.DecodeString(result.Txid)
		if err != nil {
			return nil, fmt.Errorf("invalid txid hex: %w", err)
		}
		w.writeBytes(txidBytes)
	} else {
		w.writeByte(0)
	}

	// Tx
	if len(result.Tx) > 0 {
		w.writeByte(1)
		w.writeVarInt(uint64(len(result.Tx)))
		w.writeBytes(result.Tx)
	} else {
		w.writeByte(0)
	}

	// SendWithResults
	if len(result.SendWithResults) > 0 {
		w.writeVarInt(uint64(len(result.SendWithResults)))
		for _, res := range result.SendWithResults {
			txidBytes, err := hex.DecodeString(res.Txid)
			if err != nil {
				return nil, fmt.Errorf("invalid sendWith txid hex: %w", err)
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
				return nil, fmt.Errorf("invalid sendWith status: %s", res.Status)
			}
			w.writeByte(statusByte)
		}
	} else {
		w.writeVarInt(0)
	}

	return w.buf, nil
}

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

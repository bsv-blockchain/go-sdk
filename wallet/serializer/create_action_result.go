package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"math"
)

// SerializeCreateActionResult serializes a wallet.CreateActionResult to a byte slice
func SerializeCreateActionResult(result *wallet.CreateActionResult) ([]byte, error) {
	resultWriter := newWriter()

	// Write success byte (0 for success)
	resultWriter.writeByte(0)

	// Write txid and tx if present
	txidBytes, err := hex.DecodeString(result.Txid)
	if err != nil {
		return nil, fmt.Errorf("error decoding txid: %w", err)
	}
	resultWriter.writeOptionalBytes(txidBytes, BytesOptionWithFlag, BytesOptionTxIdLen, BytesOptionZeroIfEmpty)
	resultWriter.writeOptionalBytes(result.Tx, BytesOptionWithFlag, BytesOptionZeroIfEmpty)

	// Write noSendChange
	if result.NoSendChange != nil {
		resultWriter.writeVarInt(uint64(len(result.NoSendChange)))
		for _, outpoint := range result.NoSendChange {
			opBytes, err := encodeOutpoint(outpoint)
			if err != nil {
				return nil, fmt.Errorf("error encoding outpoint: %w", err)
			}
			resultWriter.writeBytes(opBytes)
		}
	} else {
		resultWriter.writeVarInt(math.MaxUint64) // -1 for nil
	}

	// Write sendWithResults
	if result.SendWithResults != nil {
		resultWriter.writeVarInt(uint64(len(result.SendWithResults)))
		for _, res := range result.SendWithResults {
			txidBytes, err := hex.DecodeString(res.Txid)
			if err != nil {
				return nil, fmt.Errorf("error decoding sendWith txid: %w", err)
			}
			resultWriter.writeBytes(txidBytes)

			var statusCode byte
			switch res.Status {
			case "unproven":
				statusCode = 1
			case "sending":
				statusCode = 2
			case "failed":
				statusCode = 3
			default:
				return nil, fmt.Errorf("invalid status: %s", res.Status)
			}
			resultWriter.writeByte(statusCode)
		}
	} else {
		resultWriter.writeVarInt(math.MaxUint64) // -1 for nil
	}

	// Write signableTransaction
	if result.SignableTransaction != nil {
		resultWriter.writeByte(1) // flag present
		resultWriter.writeVarInt(uint64(len(result.SignableTransaction.Tx)))
		resultWriter.writeBytes(result.SignableTransaction.Tx)

		refBytes := []byte(result.SignableTransaction.Reference)
		resultWriter.writeVarInt(uint64(len(refBytes)))
		resultWriter.writeBytes(refBytes)
	} else {
		resultWriter.writeByte(0) // flag not present
	}

	return resultWriter.buf, nil
}

// DeserializeCreateActionResult deserializes a byte slice to a wallet.CreateActionResult
func DeserializeCreateActionResult(data []byte) (*wallet.CreateActionResult, error) {
	if len(data) == 0 {
		return nil, errors.New("empty response data")
	}

	resultReader := newReader(data)
	result := &wallet.CreateActionResult{}

	// Read success byte (0 for success)
	_, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading success byte: %w", err)
	}

	// Parse txid
	txIdBytes, err := resultReader.readOptionalBytes(BytesOptionWithFlag, BytesOptionTxIdLen)
	if err != nil {
		return nil, fmt.Errorf("error reading txid bytes: %w", err)
	}
	result.Txid = hex.EncodeToString(txIdBytes)

	// Parse tx
	result.Tx, err = resultReader.readOptionalBytes(BytesOptionWithFlag)
	if err != nil {
		return nil, fmt.Errorf("error reading tx: %w", err)
	}

	// Parse noSendChange
	noSendChangeLen, err := resultReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading noSendChange length: %w", err)
	}
	if noSendChangeLen != math.MaxUint64 {
		// Limit slice capacity to prevent potential memory exhaustion
		if noSendChangeLen > 1000 {
			return nil, fmt.Errorf("noSendChange length %d exceeds maximum allowed (1000)", noSendChangeLen)
		}
		result.NoSendChange = make([]string, 0, noSendChangeLen)
		for i := uint64(0); i < noSendChangeLen; i++ {
			outpointBytes, err := resultReader.readBytes(36) // 32 txid + 4 index
			if err != nil {
				return nil, fmt.Errorf("error reading outpoint: %w", err)
			}
			outpoint, err := decodeOutpoint(outpointBytes)
			if err != nil {
				return nil, fmt.Errorf("error decoding outpoint: %w", err)
			}
			result.NoSendChange = append(result.NoSendChange, outpoint)
		}
	}

	// Parse sendWithResults
	sendWithResultsLen, err := resultReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading sendWithResults length: %w", err)
	}
	if sendWithResultsLen != math.MaxUint64 {
		// Limit slice capacity to prevent potential memory exhaustion
		if sendWithResultsLen > 1000 {
			return nil, fmt.Errorf("sendWithResults length %d exceeds maximum allowed (1000)", sendWithResultsLen)
		}
		result.SendWithResults = make([]wallet.SendWithResult, 0, sendWithResultsLen)
		for i := uint64(0); i < sendWithResultsLen; i++ {
			txidBytes, err := resultReader.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("error reading sendWith txid: %w", err)
			}
			txid := hex.EncodeToString(txidBytes)

			statusCode, err := resultReader.readByte()
			if err != nil {
				return nil, fmt.Errorf("error reading status code: %w", err)
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

			result.SendWithResults = append(result.SendWithResults, wallet.SendWithResult{
				Txid:   txid,
				Status: status,
			})
		}
	}

	// Parse signableTransaction
	signableTxFlag, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading signable tx flag: %w", err)
	}
	if signableTxFlag == 1 {
		txLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading signable tx length: %w", err)
		}
		txBytes, err := resultReader.readBytes(int(txLen))
		if err != nil {
			return nil, fmt.Errorf("error reading signable tx: %w", err)
		}

		refLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading reference length: %w", err)
		}
		refBytes, err := resultReader.readBytes(int(refLen))
		if err != nil {
			return nil, fmt.Errorf("error reading reference: %w", err)
		}

		result.SignableTransaction = &wallet.SignableTransaction{
			Tx:        txBytes,
			Reference: string(refBytes),
		}
	}

	return result, nil
}

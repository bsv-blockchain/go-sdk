package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// SerializeCreateActionResult serializes a wallet.CreateActionResult to a byte slice
func SerializeCreateActionResult(result *wallet.CreateActionResult) ([]byte, error) {
	// TODO: Implement result serialization matching TS format
	return nil, errors.New("not implemented")
}

// DeserializeCreateActionResult deserializes a byte slice to a wallet.CreateActionResult
func DeserializeCreateActionResult(data []byte) (*wallet.CreateActionResult, error) {
	if len(data) == 0 {
		return nil, errors.New("empty response data")
	}

	resultReader := newReader(data)
	result := &wallet.CreateActionResult{}

	// Read error byte (first byte indicates success/failure)
	errorByte, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %v", err)
	}

	if errorByte != 0 {
		// Handle error case
		errorMsgLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading error message length: %v", err)
		}
		errorMsgBytes, err := resultReader.readBytes(int(errorMsgLen))
		if err != nil {
			return nil, fmt.Errorf("error reading error message: %v", err)
		}
		errorMsg := string(errorMsgBytes)

		stackTraceLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace length: %v", err)
		}
		stackTraceBytes, err := resultReader.readBytes(int(stackTraceLen))
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace: %v", err)
		}
		stackTrace := string(stackTraceBytes)

		return nil, fmt.Errorf("wallet error %d: %s\n%s", errorByte, errorMsg, stackTrace)
	}

	// Parse txid
	txidFlag, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading txid flag: %v", err)
	}
	if txidFlag == 1 {
		txidBytes, err := resultReader.readBytes(32)
		if err != nil {
			return nil, fmt.Errorf("error reading txid: %v", err)
		}
		result.Txid = hex.EncodeToString(txidBytes)
	}

	// Parse tx
	txFlag, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading tx flag: %v", err)
	}
	if txFlag == 1 {
		txLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading tx length: %v", err)
		}
		txBytes, err := resultReader.readBytes(int(txLen))
		if err != nil {
			return nil, fmt.Errorf("error reading tx: %v", err)
		}
		result.Tx = txBytes
	}

	// Parse noSendChange
	noSendChangeLen, err := resultReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading noSendChange length: %v", err)
	}
	if noSendChangeLen >= 0 {
		result.NoSendChange = make([]string, 0, noSendChangeLen)
		for i := uint64(0); i < noSendChangeLen; i++ {
			outpointBytes, err := resultReader.readBytes(36) // 32 txid + 4 index
			if err != nil {
				return nil, fmt.Errorf("error reading outpoint: %v", err)
			}
			outpoint, err := decodeOutpoint(outpointBytes)
			if err != nil {
				return nil, fmt.Errorf("error decoding outpoint: %v", err)
			}
			result.NoSendChange = append(result.NoSendChange, outpoint)
		}
	}

	// Parse sendWithResults
	sendWithResultsLen, err := resultReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading sendWithResults length: %v", err)
	}
	if sendWithResultsLen >= 0 {
		result.SendWithResults = make([]wallet.SendWithResult, 0, sendWithResultsLen)
		for i := uint64(0); i < sendWithResultsLen; i++ {
			txidBytes, err := resultReader.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("error reading sendWith txid: %v", err)
			}
			txid := hex.EncodeToString(txidBytes)

			statusCode, err := resultReader.readByte()
			if err != nil {
				return nil, fmt.Errorf("error reading status code: %v", err)
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
		return nil, fmt.Errorf("error reading signable tx flag: %v", err)
	}
	if signableTxFlag == 1 {
		txLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading signable tx length: %v", err)
		}
		txBytes, err := resultReader.readBytes(int(txLen))
		if err != nil {
			return nil, fmt.Errorf("error reading signable tx: %v", err)
		}

		refLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading reference length: %v", err)
		}
		refBytes, err := resultReader.readBytes(int(refLen))
		if err != nil {
			return nil, fmt.Errorf("error reading reference: %v", err)
		}

		result.SignableTransaction = &wallet.SignableTransaction{
			Tx:        txBytes,
			Reference: string(refBytes),
		}
	}

	return result, nil
}

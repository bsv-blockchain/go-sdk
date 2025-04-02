package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
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
	noSendChangeData, err := encodeOutpoints(result.NoSendChange)
	if err != nil {
		return nil, fmt.Errorf("error encoding noSendChange: %w", err)
	}
	resultWriter.writeOptionalBytes(noSendChangeData)

	// Write sendWithResults
	if err := writeTxidSliceWithStatus(resultWriter, result.SendWithResults); err != nil {
		return nil, fmt.Errorf("error writing sendWith results: %w", err)
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
	noSendChangeData, err := resultReader.readOptionalBytes()
	if err != nil {
		return nil, fmt.Errorf("error reading noSendChange: %w", err)
	}
	result.NoSendChange, err = decodeOutpoints(noSendChangeData)
	if err != nil {
		return nil, fmt.Errorf("error decoding noSendChange: %w", err)
	}

	// Parse sendWithResults
	result.SendWithResults, err = readTxidSliceWithStatus(resultReader)
	if err != nil {
		return nil, fmt.Errorf("error reading sendWith results: %w", err)
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

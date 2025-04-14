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

	resultReader := newReaderHoldError(data)
	result := &wallet.CreateActionResult{}

	// Read success byte (0 for success)
	_ = resultReader.readByte()

	// Parse txid and tx
	txIdBytes := resultReader.readOptionalBytes(BytesOptionWithFlag, BytesOptionTxIdLen)
	result.Txid = hex.EncodeToString(txIdBytes)
	result.Tx = resultReader.readOptionalBytes(BytesOptionWithFlag)
	if resultReader.err != nil {
		return nil, fmt.Errorf("error reading tx: %w", resultReader.err)
	}

	// Parse noSendChange
	noSendChangeData := resultReader.readOptionalBytes()
	noSendChange, err := decodeOutpoints(noSendChangeData)
	if err != nil {
		return nil, fmt.Errorf("error decoding noSendChange: %w", err)
	}
	result.NoSendChange = noSendChange

	// Parse sendWithResults
	result.SendWithResults, err = readTxidSliceWithStatus(&resultReader.reader)
	if err != nil {
		return nil, fmt.Errorf("error reading sendWith results: %w", err)
	}

	// Parse signableTransaction
	signableTxFlag := resultReader.readByte()
	if signableTxFlag == 1 {
		txLen := resultReader.readVarInt()
		txBytes := resultReader.readBytes(int(txLen))

		refLen := resultReader.readVarInt()
		refBytes := resultReader.readBytes(int(refLen))

		result.SignableTransaction = &wallet.SignableTransaction{
			Tx:        txBytes,
			Reference: string(refBytes),
		}
	}
	if resultReader.err != nil {
		return nil, fmt.Errorf("error reading signableTransaction: %w", resultReader.err)
	}

	return result, nil
}

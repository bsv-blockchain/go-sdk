package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// SerializeCreateActionResult serializes a wallet.CreateActionResult to a byte slice
func SerializeCreateActionResult(result *wallet.CreateActionResult) ([]byte, error) {
	resultWriter := util.NewWriter()

	// Write success byte (0 for success)
	resultWriter.WriteByte(0)

	// Write txid and tx if present
	txidBytes, err := hex.DecodeString(result.Txid)
	if err != nil {
		return nil, fmt.Errorf("error decoding txid: %w", err)
	}
	resultWriter.WriteOptionalBytes(txidBytes, util.BytesOptionWithFlag, util.BytesOptionTxIdLen, util.BytesOptionZeroIfEmpty)
	resultWriter.WriteOptionalBytes(result.Tx, util.BytesOptionWithFlag, util.BytesOptionZeroIfEmpty)

	// Write noSendChange
	noSendChangeData, err := encodeOutpoints(result.NoSendChange)
	if err != nil {
		return nil, fmt.Errorf("error encoding noSendChange: %w", err)
	}
	resultWriter.WriteOptionalBytes(noSendChangeData)

	// Write sendWithResults
	if err := writeTxidSliceWithStatus(resultWriter, result.SendWithResults); err != nil {
		return nil, fmt.Errorf("error writing sendWith results: %w", err)
	}

	// Write signableTransaction
	if result.SignableTransaction != nil {
		resultWriter.WriteByte(1) // flag present
		resultWriter.WriteVarInt(uint64(len(result.SignableTransaction.Tx)))
		resultWriter.WriteBytes(result.SignableTransaction.Tx)

		resultWriter.WriteVarInt(uint64(len(result.SignableTransaction.Reference)))
		resultWriter.WriteBytes(result.SignableTransaction.Reference)
	} else {
		resultWriter.WriteByte(0) // flag not present
	}

	return resultWriter.Buf, nil
}

// DeserializeCreateActionResult deserializes a byte slice to a wallet.CreateActionResult
func DeserializeCreateActionResult(data []byte) (*wallet.CreateActionResult, error) {
	if len(data) == 0 {
		return nil, errors.New("empty response data")
	}

	resultReader := util.NewReaderHoldError(data)
	result := &wallet.CreateActionResult{}

	// Read success byte (0 for success)
	if statusByte := resultReader.ReadByte(); statusByte != 0x00 {
		return nil, fmt.Errorf("response indicates failure: %b", statusByte)
	}

	// Parse txid and tx
	txIdBytes := resultReader.ReadOptionalBytes(util.BytesOptionWithFlag, util.BytesOptionTxIdLen)
	result.Txid = hex.EncodeToString(txIdBytes)
	result.Tx = resultReader.ReadOptionalBytes(util.BytesOptionWithFlag)
	if resultReader.Err != nil {
		return nil, fmt.Errorf("error reading tx: %w", resultReader.Err)
	}

	// Parse noSendChange
	noSendChangeData := resultReader.ReadOptionalBytes()
	noSendChange, err := decodeOutpoints(noSendChangeData)
	if err != nil {
		return nil, fmt.Errorf("error decoding noSendChange: %w", err)
	}
	result.NoSendChange = noSendChange

	// Parse sendWithResults
	result.SendWithResults, err = readTxidSliceWithStatus(&resultReader.Reader)
	if err != nil {
		return nil, fmt.Errorf("error reading sendWith results: %w", err)
	}

	// Parse signableTransaction
	signableTxFlag := resultReader.ReadByte()
	if signableTxFlag == 1 {
		result.SignableTransaction = &wallet.SignableTransaction{
			Tx:        resultReader.ReadIntBytes(),
			Reference: resultReader.ReadIntBytes(),
		}
	}

	resultReader.CheckComplete()
	if resultReader.Err != nil {
		return nil, fmt.Errorf("error reading signableTransaction: %w", resultReader.Err)
	}

	return result, nil
}

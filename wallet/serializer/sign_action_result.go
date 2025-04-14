package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionResult(result *wallet.SignActionResult) ([]byte, error) {
	w := newWriter()

	// Txid and tx
	txidBytes, err := hex.DecodeString(result.Txid)
	if err != nil {
		return nil, fmt.Errorf("invalid txid hex: %w", err)
	}
	w.writeOptionalBytes(txidBytes, BytesOptionWithFlag, BytesOptionTxIdLen)
	w.writeOptionalBytes(result.Tx, BytesOptionWithFlag)

	// SendWithResults
	if err := writeTxidSliceWithStatus(w, result.SendWithResults); err != nil {
		return nil, fmt.Errorf("error writing sendWith results: %w", err)
	}

	return w.buf, nil
}

func DeserializeSignActionResult(data []byte) (*wallet.SignActionResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.SignActionResult{}

	// Txid and tx
	txidBytes := r.readOptionalBytes(BytesOptionWithFlag, BytesOptionTxIdLen)
	result.Txid = hex.EncodeToString(txidBytes)
	result.Tx = r.readOptionalBytes(BytesOptionWithFlag)

	// SendWithResults
	results, err := readTxidSliceWithStatus(&r.reader)
	if err != nil {
		return nil, fmt.Errorf("reading sendWith results: %w", err)
	}
	result.SendWithResults = results

	return result, nil
}

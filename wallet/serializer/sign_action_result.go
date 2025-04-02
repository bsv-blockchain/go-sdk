package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionResult(result *wallet.SignActionResult) ([]byte, error) {
	w := newWriter()

	// Txid
	txidBytes, err := hex.DecodeString(result.Txid)
	if err != nil {
		return nil, fmt.Errorf("invalid txid hex: %w", err)
	}
	w.writeOptionalBytes(txidBytes, BytesOptionWithFlag, BytesOptionTxIdLen)

	// Tx
	w.writeOptionalBytes(result.Tx, BytesOptionWithFlag)

	// SendWithResults
	if err := writeTxidSliceWithStatus(w, result.SendWithResults); err != nil {
		return nil, fmt.Errorf("error writing sendWith results: %w", err)
	}

	return w.buf, nil
}

func DeserializeSignActionResult(data []byte) (*wallet.SignActionResult, error) {
	r := newReader(data)
	result := &wallet.SignActionResult{}

	// Txid
	txidBytes, err := r.readOptionalBytes(BytesOptionWithFlag, BytesOptionTxIdLen)
	if err != nil {
		return nil, fmt.Errorf("reading txid: %w", err)
	}
	result.Txid = hex.EncodeToString(txidBytes)

	// Tx
	result.Tx, err = r.readOptionalBytes(BytesOptionWithFlag)
	if err != nil {
		return nil, fmt.Errorf("reading tx: %w", err)
	}

	// SendWithResults
	result.SendWithResults, err = readTxidSliceWithStatus(r)
	if err != nil {
		return nil, fmt.Errorf("reading sendWith results: %w", err)
	}

	return result, nil
}

package serializer

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionResult(result *wallet.SignActionResult) ([]byte, error) {
	w := util.NewWriter()

	// Txid and tx
	txidBytes, err := hex.DecodeString(result.Txid)
	if err != nil {
		return nil, fmt.Errorf("invalid txid hex: %w", err)
	}
	w.WriteOptionalBytes(txidBytes, util.BytesOptionWithFlag, util.BytesOptionTxIdLen)
	w.WriteOptionalBytes(result.Tx, util.BytesOptionWithFlag)

	// SendWithResults
	if err := writeTxidSliceWithStatus(w, result.SendWithResults); err != nil {
		return nil, fmt.Errorf("error writing sendWith results: %w", err)
	}

	return w.Buf, nil
}

func DeserializeSignActionResult(data []byte) (*wallet.SignActionResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.SignActionResult{}

	// Txid and tx
	txidBytes := r.ReadOptionalBytes(util.BytesOptionWithFlag, util.BytesOptionTxIdLen)
	result.Txid = hex.EncodeToString(txidBytes)
	result.Tx = r.ReadOptionalBytes(util.BytesOptionWithFlag)

	// SendWithResults
	results, err := readTxidSliceWithStatus(&r.Reader)
	if err != nil {
		return nil, fmt.Errorf("reading sendWith results: %w", err)
	}
	result.SendWithResults = results

	return result, nil
}

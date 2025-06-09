package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionResult(result *wallet.SignActionResult) ([]byte, error) {
	w := util.NewWriter()

	// Txid and tx
	w.WriteOptionalBytes(result.Txid[:], util.BytesOptionWithFlag, util.BytesOptionTxIdLen)
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
	copy(result.Txid[:], txidBytes)
	result.Tx = r.ReadOptionalBytes(util.BytesOptionWithFlag)

	// SendWithResults
	results, err := readTxidSliceWithStatus(&r.Reader)
	if err != nil {
		return nil, fmt.Errorf("reading sendWith results: %w", err)
	}
	result.SendWithResults = results

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing SignActionResult: %w", r.Err)
	}

	return result, nil
}

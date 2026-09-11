package transaction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
)

const validTxidHex = "0000000000000000000000000000000000000000000000000000000000000000"

func TestOutpointFromStringBadIndex(t *testing.T) {
	t.Parallel()
	_, err := OutpointFromString(validTxidHex + ".notanumber")
	require.Error(t, err)
}

func TestInscribeWithEnrichedOpReturn(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	ia := &script.InscriptionArgs{
		LockingScript: &script.Script{},
		ContentType:   "text/plain",
		Data:          []byte("hello"),
		EnrichedArgs: &script.EnrichedInscriptionArgs{
			OpReturnData: [][]byte{[]byte("a"), []byte("b")},
		},
	}
	require.NoError(t, tx.Inscribe(ia))
	require.Len(t, tx.Outputs, 1)
}

func TestInscribeSpecificOrdinalAccumulates(t *testing.T) {
	t.Parallel()
	src := NewTransaction()
	src.AddOutput(&TransactionOutput{Satoshis: 5000, LockingScript: &script.Script{}})
	tx := NewTransaction()
	tx.AddInputFromTx(src, 0, nil)

	ia := &script.InscriptionArgs{
		LockingScript: &script.Script{},
		ContentType:   "text/plain",
		Data:          []byte("data"),
	}
	require.NoError(t, tx.InscribeSpecificOrdinal(ia, 1, 100, &script.Script{}))
	// One output for the leading satoshis, one for the inscription.
	require.Len(t, tx.Outputs, 2)
	assert.Equal(t, uint64(5100), tx.Outputs[0].Satoshis)
}

func TestInscribeSpecificOrdinalRangeError(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	ia := &script.InscriptionArgs{
		LockingScript: &script.Script{},
		ContentType:   "text/plain",
		Data:          []byte("data"),
	}
	err := tx.InscribeSpecificOrdinal(ia, 5, 0, &script.Script{})
	require.ErrorIs(t, err, ErrOutputNoExist)
}

func TestFeeComputeError(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	err := tx.Fee(errFeeModel{}, ChangeDistributionEqual)
	require.Error(t, err)
}

func TestFeeMissingPreviousTx(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
	err := tx.Fee(&fixedFeeModel{fee: 0}, ChangeDistributionEqual)
	require.ErrorIs(t, err, ErrEmptyPreviousTx)
}

func TestFeeRemovesChangeWhenTooSmall(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	in := &TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber}
	in.SetSourceTxOutput(&TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx.AddInput(in)
	tx.AddOutput(&TransactionOutput{Satoshis: 0, LockingScript: &script.Script{}})
	tx.AddOutput(&TransactionOutput{LockingScript: &script.Script{}, Change: true})
	tx.AddOutput(&TransactionOutput{LockingScript: &script.Script{}, Change: true})

	// change (1000 - 0 - 999 = 1) is less than the 2 change outputs, so they are
	// dropped, leaving the miners the remainder.
	require.NoError(t, tx.Fee(&fixedFeeModel{fee: 999}, ChangeDistributionEqual))
	require.Len(t, tx.Outputs, 1)
	assert.False(t, tx.Outputs[0].Change)
}

func TestAddInputFromErrors(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()

	// Invalid locking script hex.
	err := tx.AddInputFrom(validTxidHex, 0, "zz", 100, nil)
	require.Error(t, err)

	// Invalid source txid hex.
	err = tx.AddInputFrom("nothex", 0, "", 100, nil)
	require.Error(t, err)
}

func TestTransactionMarshalJSONNil(t *testing.T) {
	t.Parallel()
	var tx *Transaction
	_, err := tx.MarshalJSON()
	require.ErrorIs(t, err, ErrTxNil)
}

func TestTransactionUnmarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("invalid-json", func(t *testing.T) {
		t.Parallel()
		var tx Transaction
		require.Error(t, tx.UnmarshalJSON([]byte("not json")))
	})

	t.Run("invalid-hex", func(t *testing.T) {
		t.Parallel()
		var tx Transaction
		require.Error(t, tx.UnmarshalJSON([]byte(`{"hex":"zz"}`)))
	})

	t.Run("no-hex-uses-fields", func(t *testing.T) {
		t.Parallel()
		var tx Transaction
		require.NoError(t, tx.UnmarshalJSON([]byte(`{"hex":"","lockTime":5,"version":2}`)))
		assert.Equal(t, uint32(5), tx.LockTime)
		assert.Equal(t, uint32(2), tx.Version)
	})
}

func TestInputUnmarshalJSONErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid-json", func(t *testing.T) {
		t.Parallel()
		var in TransactionInput
		require.Error(t, in.UnmarshalJSON([]byte("nope")))
	})

	t.Run("invalid-txid", func(t *testing.T) {
		t.Parallel()
		var in TransactionInput
		require.Error(t, in.UnmarshalJSON([]byte(`{"txid":"nothex","unlockingScript":""}`)))
	})

	t.Run("invalid-script", func(t *testing.T) {
		t.Parallel()
		var in TransactionInput
		require.Error(t, in.UnmarshalJSON([]byte(`{"txid":"`+validTxidHex+`","unlockingScript":"zz"}`)))
	})
}

func TestOutputUnmarshalJSONError(t *testing.T) {
	t.Parallel()
	var out TransactionOutput
	require.Error(t, out.UnmarshalJSON([]byte("not json")))
	require.Error(t, out.UnmarshalJSON([]byte(`{"lockingScript":"zz"}`)))
}

func TestPayToAddressInvalid(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	require.Error(t, tx.PayToAddress("not-a-valid-address", 100))
}

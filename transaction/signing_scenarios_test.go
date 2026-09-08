package transaction_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	feemodel "github.com/bsv-blockchain/go-sdk/transaction/fee_model"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// This file is a behavioral safety net for transaction creation and signing.
// It exercises the full build -> sign -> serialize -> verify pipeline across
// many shapes so that upcoming performance work (and go-bt/go-bdk integration)
// cannot silently change what the SDK produces:
//
//   - sign every input and prove the signature satisfies the locking script by
//     running the real script engine (correctness, not just "no error");
//   - a matrix of SIGHASH flags, input counts and output counts;
//   - fee + change distribution;
//   - serialization round-trips (raw, EF, BEEF) preserve the txid.
//
// Signing is deterministic (RFC 6979), so the golden characterization tests at
// the end pin exact txids and raw hex: any refactor that changes the bytes we
// produce for a fixed key + fixed inputs will fail loudly.

// scenWIF is a fixed key so signatures and txids are reproducible.
const scenWIF = "KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS"

// scenKey returns the scenario private key and its P2PKH locking script.
func scenKey(tb testing.TB) (*ec.PrivateKey, *script.Script) {
	tb.Helper()
	priv, err := ec.PrivateKeyFromWif(scenWIF)
	require.NoError(tb, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(tb, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(tb, err)
	return priv, lock
}

// buildP2PKHTx builds an unsigned transaction with nIn P2PKH inputs (each funded
// by a distinct source transaction locked to the scenario key) and nOut P2PKH
// outputs, attaching the given unlocker template to every input.
func buildP2PKHTx(tb testing.TB, unlocker transaction.UnlockingScriptTemplate, lock *script.Script, nIn, nOut int) *transaction.Transaction {
	tb.Helper()
	tx := transaction.NewTransaction()
	for i := range nIn {
		src := transaction.NewTransaction()
		src.LockTime = uint32(i)
		src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
		tx.AddInputFromTx(src, 0, unlocker)
	}
	for range nOut {
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
	}
	return tx
}

// verifyInputScript runs the real script engine over one input, proving the
// unlocking script produced by signing actually satisfies the locking script.
func verifyInputScript(t *testing.T, tx *transaction.Transaction, i int) {
	t.Helper()
	prevOut := tx.Inputs[i].SourceTxOutput()
	require.NotNil(t, prevOut, "input %d has no source output", i)
	err := interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, i, prevOut),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
	require.NoError(t, err, "input %d failed script verification", i)
}

// TestSignAndVerifyP2PKHSigHashFlags signs a 2-in/2-out transaction with each
// SIGHASH flag and proves every input verifies through the script engine.
func TestSignAndVerifyP2PKHSigHashFlags(t *testing.T) {
	priv, lock := scenKey(t)

	flags := []struct {
		name string
		flag sighash.Flag
	}{
		{"AllForkID", sighash.AllForkID},
		{"NoneForkID", sighash.NoneForkID},
		{"SingleForkID", sighash.SingleForkID},
		{"AllForkID_AnyOneCanPay", sighash.AllForkID | sighash.AnyOneCanPay},
		{"NoneForkID_AnyOneCanPay", sighash.NoneForkID | sighash.AnyOneCanPay},
		{"SingleForkID_AnyOneCanPay", sighash.SingleForkID | sighash.AnyOneCanPay},
	}

	for _, tc := range flags {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.flag
			unlocker, err := p2pkh.Unlock(priv, &f)
			require.NoError(t, err)

			tx := buildP2PKHTx(t, unlocker, lock, 2, 2)
			require.NoError(t, tx.Sign())

			for i := range tx.Inputs {
				require.NotNil(t, tx.Inputs[i].UnlockingScript)
				verifyInputScript(t, tx, i)
			}
		})
	}
}

// TestSignAndVerifyP2PKHShapes signs transactions of varying input/output counts
// with the default (AllForkID) flag and verifies every input.
func TestSignAndVerifyP2PKHShapes(t *testing.T) {
	priv, lock := scenKey(t)

	shapes := []struct{ nIn, nOut int }{
		{1, 1}, {1, 2}, {2, 1}, {3, 3}, {5, 2}, {10, 10},
	}
	for _, s := range shapes {
		t.Run(fmt.Sprintf("in=%d_out=%d", s.nIn, s.nOut), func(t *testing.T) {
			unlocker, err := p2pkh.Unlock(priv, nil)
			require.NoError(t, err)

			tx := buildP2PKHTx(t, unlocker, lock, s.nIn, s.nOut)
			require.NoError(t, tx.Sign())

			for i := range tx.Inputs {
				verifyInputScript(t, tx, i)
			}
		})
	}
}

// TestSignFeeAndChangeThenVerify builds a transaction with a change output,
// applies a fee model, signs, and proves the result is spendable and balanced.
func TestSignFeeAndChangeThenVerify(t *testing.T) {
	priv, lock := scenKey(t)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	tx := transaction.NewTransaction()
	// Two 100_000-sat inputs -> 200_000 available.
	for i := range 2 {
		src := transaction.NewTransaction()
		src.LockTime = uint32(i)
		src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
		tx.AddInputFromTx(src, 0, unlocker)
	}
	// One fixed payment output and one change output.
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 50_000, LockingScript: lock})
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: lock, Change: true})

	require.NoError(t, tx.Fee(&feemodel.SatoshisPerKilobyte{Satoshis: 50}, transaction.ChangeDistributionEqual))

	// Change output was filled in, and the transaction balances.
	change := tx.Outputs[1].Satoshis
	require.Positive(t, change)

	fee, err := tx.GetFee()
	require.NoError(t, err)
	totalIn, err := tx.TotalInputSatoshis()
	require.NoError(t, err)
	require.Equal(t, totalIn, 50_000+change+fee)

	require.NoError(t, tx.Sign())
	for i := range tx.Inputs {
		verifyInputScript(t, tx, i)
	}
}

// TestSignedTxSerializationRoundTrips proves that raw, extended-format and BEEF
// serialization of a signed transaction all round-trip to the same txid.
func TestSignedTxSerializationRoundTrips(t *testing.T) {
	priv, lock := scenKey(t)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	tx := buildP2PKHTx(t, unlocker, lock, 3, 2)
	require.NoError(t, tx.Sign())
	want := tx.TxID()

	t.Run("raw", func(t *testing.T) {
		parsed, err := transaction.NewTransactionFromBytes(tx.Bytes())
		require.NoError(t, err)
		require.Equal(t, want.String(), parsed.TxID().String())
	})

	t.Run("EF", func(t *testing.T) {
		ef, err := tx.EF()
		require.NoError(t, err)
		parsed, err := transaction.NewTransactionFromBytes(ef)
		require.NoError(t, err)
		require.Equal(t, want.String(), parsed.TxID().String())
	})

	t.Run("BEEF", func(t *testing.T) {
		beef, err := tx.BEEF()
		require.NoError(t, err)
		parsed, err := transaction.NewTransactionFromBEEF(beef)
		require.NoError(t, err)
		require.Equal(t, want.String(), parsed.TxID().String())
	})
}

// TestGoldenP2PKHSignedTransaction pins the exact txid and raw bytes produced by
// signing a fixed single-input P2PKH transaction. Because signing is
// deterministic (RFC 6979), any change to sighash computation, signature
// encoding or transaction serialization will change these bytes and fail here.
// The pinned transaction is also run through the script engine, so the golden is
// proven spendable rather than merely a snapshot.
func TestGoldenP2PKHSignedTransaction(t *testing.T) {
	const (
		goldenLockHex = "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac"
		goldenTxID    = "b7f1a255e1174241e1db681dcff56987cc87b35f84d3bab292e6ebfbac3b3629"
		goldenRawHex  = "01000000011dd7ad77d93879f00dcfeee50ef258775ab13fe0bcfb8f51994ec6f2d295be45000000006b483045022100a661a4db2550e459ca430ae5ecee163cef7f1b5613feb85996975f2f9ec52aa702201330ad85527db1825083aa7c4cbf3859c52616b33691fcbe11c91769580e41ae412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffff01b8820100000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
	)

	priv, lock := scenKey(t)
	require.Equal(t, goldenLockHex, lock.String(), "scenario key locking script changed")

	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	tx := transaction.NewTransaction()
	require.NoError(t, tx.AddInputFrom(
		"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0,
		goldenLockHex, 100_000, unlocker))
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 99_000, LockingScript: lock})
	require.NoError(t, tx.Sign())

	require.Equal(t, goldenTxID, tx.TxID().String(), "signed txid changed")
	require.Equal(t, goldenRawHex, tx.Hex(), "signed raw bytes changed")

	verifyInputScript(t, tx, 0)
}

// fixedTwoInputTx builds a deterministic 2-in/2-out P2PKH transaction used by the
// sighash golden test.
func fixedTwoInputTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	priv, lock := scenKey(t)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	tx := transaction.NewTransaction()
	require.NoError(t, tx.AddInputFrom(
		"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0,
		lock.String(), 100_000, unlocker))
	require.NoError(t, tx.AddInputFrom(
		"64faeaa2e3cbadaf82d8fa8c7ded508cb043c5d101671f43c084be2ac6163148", 1,
		lock.String(), 200_000, unlocker))
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 90_000, LockingScript: lock})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 200_000, LockingScript: lock})
	return tx
}

// TestGoldenSigHashDigests pins the exact 32-byte signature hash for input 0 of a
// fixed transaction across the SIGHASH flag matrix. This isolates the sighash
// algorithm from signature encoding and serialization, so a regression here
// points directly at the preimage/hashing code.
func TestGoldenSigHashDigests(t *testing.T) {
	golden := map[string]struct {
		flag   sighash.Flag
		digest string
	}{
		"AllForkID":              {sighash.AllForkID, "dbb856e512fe053da7f8e8548b4743a35e3b138c0d888dae0adfb6767cdead09"},
		"NoneForkID":             {sighash.NoneForkID, "e73df49072d920627eeb7cd945c2bf9bb3c1075d0b1043481555102411d78ca9"},
		"SingleForkID":           {sighash.SingleForkID, "8843ce89c0bf1dba90dd547b14c46bd197ba039f3832b60d63940eb7386cf385"},
		"AllForkID_AnyOneCanPay": {sighash.AllForkID | sighash.AnyOneCanPay, "88f1e8cd58838c6571cb2c650ed2cd39ce57cdc7aae5aaa022a1eb39d70d2907"},
	}

	for name, tc := range golden {
		t.Run(name, func(t *testing.T) {
			tx := fixedTwoInputTx(t)
			h, err := tx.CalcInputSignatureHash(0, tc.flag)
			require.NoError(t, err)
			require.Equal(t, tc.digest, hex.EncodeToString(h))
		})
	}
}

// TestSignMixedKeys signs a transaction whose two inputs are locked to different
// keys, each with its own unlocker, and proves both inputs verify. This exercises
// per-input key/template handling rather than a single shared key.
func TestSignMixedKeys(t *testing.T) {
	priv1, lock1 := scenKey(t)

	priv2, err := ec.NewPrivateKey()
	require.NoError(t, err)
	addr2, err := script.NewAddressFromPublicKey(priv2.PubKey(), true)
	require.NoError(t, err)
	lock2, err := p2pkh.Lock(addr2)
	require.NoError(t, err)

	u1, err := p2pkh.Unlock(priv1, nil)
	require.NoError(t, err)
	u2, err := p2pkh.Unlock(priv2, nil)
	require.NoError(t, err)

	tx := transaction.NewTransaction()

	src1 := transaction.NewTransaction()
	src1.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock1})
	tx.AddInputFromTx(src1, 0, u1)

	src2 := transaction.NewTransaction()
	src2.LockTime = 1
	src2.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock2})
	tx.AddInputFromTx(src2, 0, u2)

	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock1})

	require.NoError(t, tx.Sign())
	verifyInputScript(t, tx, 0)
	verifyInputScript(t, tx, 1)
}

// TestSignUnsignedOnlySignsEmptyInputs proves SignUnsigned leaves already-signed
// inputs untouched and only fills in inputs whose unlocking script is nil.
func TestSignUnsignedOnlySignsEmptyInputs(t *testing.T) {
	priv, lock := scenKey(t)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	tx := buildP2PKHTx(t, unlocker, lock, 2, 1)

	sentinel := &script.Script{0x00}
	tx.Inputs[0].UnlockingScript = sentinel

	require.NoError(t, tx.SignUnsigned())

	require.Same(t, sentinel, tx.Inputs[0].UnlockingScript, "pre-signed input must be untouched")
	require.NotNil(t, tx.Inputs[1].UnlockingScript, "empty input must be signed")
	verifyInputScript(t, tx, 1)
}

// TestSignErrorPaths covers the failure modes of the signing/fee pipeline.
func TestSignErrorPaths(t *testing.T) {
	priv, lock := scenKey(t)

	t.Run("missing source output", func(t *testing.T) {
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		tx := transaction.NewTransaction()
		tx.AddInput(&transaction.TransactionInput{
			SourceTXID:              &chainhash.Hash{},
			SourceTxOutIndex:        0,
			UnlockingScriptTemplate: unlocker,
			SequenceNumber:          transaction.DefaultSequenceNumber,
		})
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})

		require.ErrorIs(t, tx.Sign(), transaction.ErrEmptyPreviousTx)
	})

	t.Run("fee not computed blocks signing", func(t *testing.T) {
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		tx := buildP2PKHTx(t, unlocker, lock, 1, 0)
		// A change output with zero satoshis means the fee was never computed.
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: lock, Change: true})

		err = tx.Sign()
		require.Error(t, err)
		require.Contains(t, err.Error(), "fee not computed")
	})

	t.Run("insufficient inputs for fee", func(t *testing.T) {
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		tx := transaction.NewTransaction()
		src := transaction.NewTransaction()
		src.AddOutput(&transaction.TransactionOutput{Satoshis: 100, LockingScript: lock})
		tx.AddInputFromTx(src, 0, unlocker)
		// Spend more than the single tiny input holds.
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})

		err = tx.Fee(&feemodel.SatoshisPerKilobyte{Satoshis: 50}, transaction.ChangeDistributionEqual)
		require.ErrorIs(t, err, transaction.ErrInsufficientInputs)
	})
}

//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package bdk_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"testing"

	bdkscript "github.com/bitcoin-sv/bdk/module/gobdk/script"
	bsm "github.com/bsv-blockchain/go-sdk/compat/bsm"
	"github.com/bsv-blockchain/go-sdk/message"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/bdk"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/stretchr/testify/require"
)

const (
	testBlockHeight = int32(620940)
	testUTXOHeight  = int32(574441)
	testExtendedTx  = "010000000000000000ef0120fa0d2c5974cfe6e3aec71f7f6539cfa1c1e474082d2cdb41fb830f6267b7d7000000006b4830450221008788b545ebd6ebcb15f938045b71c1fa7efafd55d1f4e64e96602a04f3214cda0220717ddadfa7d1dc6a22ccb077350aef7a2073ee58fe780d86b77a31c24c664a21412103ef28c47337b05ec3f14b63d904db7ae023e897389dbdbf531221e13fd5e5b105ffffffffdc3de103000000001976a91437fb14a40d021abbb1763497f963a130286d1ad188ac017239e103000000001976a914962eba38504bcfb140ff0246afa795658812b42788ac00000000"
)

func TestValidator(t *testing.T) {
	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)
	require.NotNil(t, validator.Native())

	tx := mustTestTransaction(t)
	extendedTx, err := tx.EF()
	require.NoError(t, err)
	wantExtendedTx, err := hex.DecodeString(testExtendedTx)
	require.NoError(t, err)
	require.True(t, bytes.Equal(wantExtendedTx, extendedTx))

	utxoHeights := []int32{testUTXOHeight}
	require.NoError(t, validator.ValidateTransaction(tx, utxoHeights, testBlockHeight, true))
	require.NoError(t, validator.VerifyScript(tx, utxoHeights, testBlockHeight, true))

	flags := []uint32{validator.Native().CalculateFlags(testUTXOHeight, testBlockHeight, true)}
	require.NoError(t, validator.VerifyScriptWithCustomFlags(tx, utxoHeights, testBlockHeight, true, flags))

	sigOps, err := validator.GetSigOpCount(tx, utxoHeights, testBlockHeight, true, true)
	require.NoError(t, err)
	require.Equal(t, uint64(1), sigOps)
}

func TestValidatorInputErrors(t *testing.T) {
	_, err := bdk.NewValidator("not-a-network")
	require.ErrorIs(t, err, bdk.ErrUnsupportedNetwork)

	_, err = bdk.WrapValidator(nil)
	require.ErrorIs(t, err, bdk.ErrNilValidator)

	tx := mustTestTransaction(t)
	utxoHeights := []int32{testUTXOHeight}
	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)

	require.ErrorIs(t, validator.ValidateTransaction(nil, nil, testBlockHeight, true), bdk.ErrNilTransaction)
	require.ErrorIs(t, validator.ValidateTransaction(tx, nil, testBlockHeight, true), bdk.ErrUTXOHeightCount)
	require.ErrorIs(
		t,
		validator.VerifyScriptWithCustomFlags(tx, utxoHeights, testBlockHeight, true, []uint32{1, 2}),
		bdk.ErrCustomFlagCount,
	)

	withoutSourceOutput, err := transaction.NewTransactionFromHex(tx.Hex())
	require.NoError(t, err)
	require.ErrorIs(
		t,
		validator.ValidateTransaction(withoutSourceOutput, utxoHeights, testBlockHeight, true),
		transaction.ErrEmptyPreviousTx,
	)

	var nilValidator *bdk.Validator
	require.ErrorIs(t, nilValidator.ValidateTransaction(tx, utxoHeights, testBlockHeight, true), bdk.ErrNilValidator)
	_, err = validator.ValidateBatch(nil)
	require.ErrorIs(t, err, bdk.ErrNilBatch)
}

func TestValidateBatch(t *testing.T) {
	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)

	batch := bdk.NewValidateBatch(2)
	require.NotNil(t, batch)
	require.True(t, batch.Empty())
	batch.Reserve(3)

	heights := []int32{testUTXOHeight}
	require.NoError(t, batch.Add(mustTestTransaction(t), heights, testBlockHeight, true))
	heights[0] = 0

	invalidTx := mustTestTransaction(t)
	invalidUnlockingScript := script.NewFromBytes(*invalidTx.Inputs[0].UnlockingScript)
	(*invalidUnlockingScript)[10] ^= 0x01
	invalidTx.Inputs[0].UnlockingScript = invalidUnlockingScript
	require.NoError(t, batch.Add(invalidTx, []int32{testUTXOHeight}, testBlockHeight, true))
	require.Equal(t, 2, batch.Size())
	require.False(t, batch.Empty())

	runtime.GC()
	results, err := validator.ValidateBatch(batch)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.NoError(t, results[0])
	require.Error(t, results[1])
	var scriptErr bdkscript.ScriptError
	require.ErrorAs(t, results[1], &scriptErr)

	batch.Clear()
	require.Zero(t, batch.Size())
	require.True(t, batch.Empty())

	// Clearing releases the first set of pins without preventing batch reuse.
	require.NoError(t, batch.Add(mustTestTransaction(t), []int32{testUTXOHeight}, testBlockHeight, true))
	runtime.GC()
	results, err = validator.ValidateBatch(batch)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0])
	batch.Clear()
}

func TestInstallSignatureBackend(t *testing.T) {
	bdk.ResetSignatureBackend()
	t.Cleanup(bdk.ResetSignatureBackend)

	privateKey, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	bdk.InstallSignatureBackend()
	digest := sha256.Sum256([]byte("GoBDK signature backend"))
	signature, err := privateKey.Sign(digest[:])
	require.NoError(t, err)
	require.True(t, signature.Verify(digest[:], privateKey.PubKey()))
	require.True(t, ec.Verify(digest[:], signature, privateKey.PubKey().ToECDSA()))

	validPublicKey := privateKey.PubKey()
	invalidPublicKey := &ec.PublicKey{
		Curve: ec.S256(),
		X:     new(big.Int).Set(validPublicKey.X),
		Y:     new(big.Int).Add(validPublicKey.Y, big.NewInt(2)),
	}
	require.False(t, invalidPublicKey.Validate())
	require.Equal(t, validPublicKey.Compressed(), invalidPublicKey.Compressed())
	require.False(t, signature.Verify(digest[:], invalidPublicKey))

	invalidDigest := digest
	invalidDigest[0] ^= 0x01
	require.False(t, signature.Verify(invalidDigest[:], privateKey.PubKey()))
	require.False(t, signature.Verify([]byte("short digest"), privateKey.PubKey()))
	_, err = privateKey.Sign([]byte("short digest"))
	require.EqualError(t, err, "bdk: message digest must be 32 bytes: got 12")

	signedMessage, err := message.Sign([]byte("signed through GoBDK"), privateKey, nil)
	require.NoError(t, err)
	valid, err := message.Verify([]byte("signed through GoBDK"), signedMessage, nil)
	require.NoError(t, err)
	require.True(t, valid)

	address, err := script.NewAddressFromPublicKey(privateKey.PubKey(), true)
	require.NoError(t, err)
	compactMessage := []byte("compact signature through GoBDK")
	compactSignature, err := bsm.SignMessage(privateKey, compactMessage)
	require.NoError(t, err)
	require.NoError(t, bsm.VerifyMessage(address.AddressString, compactSignature, compactMessage))

	lockingScript, err := p2pkh.Lock(address)
	require.NoError(t, err)
	unlocker, err := p2pkh.Unlock(privateKey, nil)
	require.NoError(t, err)

	tx := transaction.NewTransaction()
	require.NoError(t, tx.AddInputFrom(
		"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
		0,
		lockingScript.String(),
		1000,
		unlocker,
	))
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 900, LockingScript: lockingScript})
	require.NoError(t, tx.Sign())

	parts, err := script.DecodeScript(*tx.Inputs[0].UnlockingScript)
	require.NoError(t, err)
	require.Len(t, parts, 2)
	signatureWithHashType := parts[0].Data
	require.NotEmpty(t, signatureWithHashType)
	signature, err = ec.ParseDERSignature(signatureWithHashType[:len(signatureWithHashType)-1])
	require.NoError(t, err)
	digestBytes, err := tx.CalcInputSignatureHash(0, sighash.Flag(signatureWithHashType[len(signatureWithHashType)-1]))
	require.NoError(t, err)
	require.True(t, signature.Verify(digestBytes, privateKey.PubKey()))

	previousOutput := tx.Inputs[0].SourceTxOutput()
	require.NoError(t, interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, 0, previousOutput),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	))

	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)
	require.NoError(t, validator.ValidateTransaction(tx, []int32{899999}, 900000, true))
	require.NoError(t, validator.ValidateTransaction(tx, []int32{899999}, 900000, false))
}

func TestValidateBatchNilReceiver(t *testing.T) {
	var batch *bdk.ValidateBatch
	require.ErrorIs(t, batch.Add(mustTestTransaction(t), []int32{testUTXOHeight}, testBlockHeight, true), bdk.ErrNilBatch)
	require.Zero(t, batch.Size())
	require.True(t, batch.Empty())
	batch.Reserve(1)
	batch.Clear()
}

func ExampleValidator_ValidateTransaction() {
	tx, _ := transaction.NewTransactionFromHex(testExtendedTx)
	validator, _ := bdk.NewValidator("main")
	err := validator.ValidateTransaction(tx, []int32{testUTXOHeight}, testBlockHeight, true)
	fmt.Println(err == nil)
	// Output: true
}

func mustTestTransaction(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx, err := transaction.NewTransactionFromHex(testExtendedTx)
	require.NoError(t, err)
	return tx
}

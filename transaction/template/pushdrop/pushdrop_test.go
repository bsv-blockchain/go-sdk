package pushdrop_test

import (
	"bytes"
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestWallet(t *testing.T) *wallet.CompletedProtoWallet {
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := wallet.NewCompletedProtoWallet(priv)
	require.NoError(t, err)
	return w
}

// createDecodeRedeem is the Go equivalent of the TypeScript createDecodeRedeem function
func createDecodeRedeem(
	t *testing.T,
	testWallet *wallet.CompletedProtoWallet,
	fields [][]byte,
	protocolID wallet.Protocol,
	keyID string,
	counterparty wallet.Counterparty,
	signOutputs wallet.SignOutputs,
	anyoneCanPay bool,
) {
	ctx := context.Background()
	
	// Create template with the provided wallet
	pushDrop := &pushdrop.PushDrop{
		Wallet:     testWallet,
		Originator: "test",
	}

	// Create locking script
	lockingScript, err := pushDrop.Lock(
		ctx,
		fields,
		protocolID,
		keyID,
		counterparty,
		false, // forSelf
		true,  // includeSignature
		pushdrop.LockBefore, // lockPosition
	)
	require.NoError(t, err)
	require.NotNil(t, lockingScript)

	// Decode and verify
	decoded := pushdrop.Decode(lockingScript)
	require.NotNil(t, decoded)
	
	// In TypeScript version, signature is added to fields if includeSignatures is true
	// So we need to compare without the signature field
	expectedFields := fields
	if len(decoded.Fields) > len(fields) {
		// Remove the signature field for comparison
		assert.Equal(t, expectedFields, decoded.Fields[:len(fields)])
	} else {
		assert.Equal(t, expectedFields, decoded.Fields)
	}

	// Verify public key matches
	expectedPubKey, err := testWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        keyID,
			Counterparty: counterparty,
		},
		ForSelf: false,
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedPubKey.PublicKey.Compressed(), decoded.LockingPublicKey.Compressed())

	// Create unlocking template
	unlocker := pushDrop.Unlock(
		ctx,
		protocolID,
		keyID,
		counterparty,
		signOutputs,
		anyoneCanPay,
	)
	require.NotNil(t, unlocker)

	// Verify estimated length
	assert.Equal(t, uint32(73), unlocker.EstimateLength())

	// Create source transaction
	satoshis := uint64(1)
	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:       satoshis,
		LockingScript:  lockingScript,
	})

	// Create spending transaction
	spendTx := transaction.NewTransaction()
	spendTx.AddInputFromTx(sourceTx, 0, nil)

	// Sign the input
	unlockingScript, err := unlocker.Sign(spendTx, 0)
	require.NoError(t, err)
	require.NotNil(t, unlockingScript)

	// Set the unlocking script
	spendTx.Inputs[0].UnlockingScript = unlockingScript


	// Validate the script execution
	err = interpreter.NewEngine().Execute(
		interpreter.WithTx(spendTx, 0, &transaction.TransactionOutput{
			Satoshis:      satoshis,
			LockingScript: lockingScript,
		}),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
	if err != nil {
		t.Logf("Script execution failed: %v", err)
		t.Logf("Locking script: %s", lockingScript)
		t.Logf("Unlocking script: %s", unlockingScript)
	}
	assert.NoError(t, err)
}

func TestPushDrop_TestVectors(t *testing.T) {
	// Create a single wallet to use for all test vectors
	testWallet := createTestWallet(t)
	
	tests := []struct {
		name         string
		fields       [][]byte
		signOutputs  wallet.SignOutputs
		anyoneCanPay bool
	}{
		{
			name:   "empty fields",
			fields: [][]byte{},
		},
		{
			name:   "single zero byte",
			fields: [][]byte{{0}},
		},
		{
			name:   "single one byte",
			fields: [][]byte{{1}},
		},
		{
			name:   "single 0x81 byte",
			fields: [][]byte{{0x81}},
		},
		{
			name:   "pi digits",
			fields: [][]byte{{3, 1, 4, 1, 5, 9}},
		},
		{
			name:   "200 bytes of 0xff",
			fields: [][]byte{bytes.Repeat([]byte{0xff}, 200)},
		},
		{
			name:   "400 bytes of 0xff",
			fields: [][]byte{bytes.Repeat([]byte{0xff}, 400)},
		},
		{
			name:   "70000 bytes of 0xff",
			fields: [][]byte{bytes.Repeat([]byte{0xff}, 70000)},
		},
		{
			name:   "three fields",
			fields: [][]byte{{0}, {1}, {2}},
		},
		{
			name:   "four fields",
			fields: [][]byte{{0}, {1}, {2}, {3}},
		},
		{
			name:        "pi digits with signOutputs none",
			fields:      [][]byte{{3, 1, 4, 1, 5, 9}},
			signOutputs: wallet.SignOutputsNone,
		},
		{
			name:        "pi digits with signOutputs single",
			fields:      [][]byte{{3, 1, 4, 1, 5, 9}},
			signOutputs: wallet.SignOutputsSingle,
		},
		{
			name:         "pi digits with anyoneCanPay",
			fields:       [][]byte{{3, 1, 4, 1, 5, 9}},
			signOutputs:  wallet.SignOutputsAll,
			anyoneCanPay: true,
		},
		{
			name:         "pi digits with signOutputs none and anyoneCanPay",
			fields:       [][]byte{{3, 1, 4, 1, 5, 9}},
			signOutputs:  wallet.SignOutputsNone,
			anyoneCanPay: true,
		},
		{
			name:         "pi digits with signOutputs single and anyoneCanPay",
			fields:       [][]byte{{3, 1, 4, 1, 5, 9}},
			signOutputs:  wallet.SignOutputsSingle,
			anyoneCanPay: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			protocolID := wallet.Protocol{
				SecurityLevel: 0,
				Protocol:      "testing",
			}
			keyID := "test-key"
			counterparty := wallet.Counterparty{
				Type: wallet.CounterpartyTypeSelf,
			}
			
			if tc.signOutputs == 0 {
				tc.signOutputs = wallet.SignOutputsAll
			}

			createDecodeRedeem(
				t,
				testWallet,
				tc.fields,
				protocolID,
				keyID,
				counterparty,
				tc.signOutputs,
				tc.anyoneCanPay,
			)
		})
	}
}

func TestPushDrop_Lock(t *testing.T) {
	ctx := context.Background()
	testWallet := createTestWallet(t)
	pushDrop := &pushdrop.PushDrop{
		Wallet:     testWallet,
		Originator: "test",
	}

	// Test data
	fields := [][]byte{
		[]byte("hello world"),
		[]byte("This is a field"),
		{0xde, 0xad, 0xbe, 0xef},
	}
	protocolID := wallet.Protocol{
		SecurityLevel: 0,
		Protocol:      "testing",
	}
	keyID := "test-key"
	counterparty := wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	}

	// Create locking script
	lockingScript, err := pushDrop.Lock(
		ctx,
		fields,
		protocolID,
		keyID,
		counterparty,
		false, // forSelf
		true,  // includeSignature
		pushdrop.LockBefore, // lockPosition
	)
	require.NoError(t, err)
	require.NotNil(t, lockingScript)

	// Decode and verify
	decoded := pushdrop.Decode(lockingScript)
	require.NotNil(t, decoded)
	
	// Check fields (without signature)
	assert.Equal(t, fields, decoded.Fields[:len(fields)])

	// Check public key
	expectedPubKey, err := testWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        keyID,
			Counterparty: counterparty,
		},
		ForSelf: false,
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedPubKey.PublicKey.Compressed(), decoded.LockingPublicKey.Compressed())
}

func TestPushDrop_Unlock(t *testing.T) {
	ctx := context.Background()
	testWallet := createTestWallet(t)
	pushDrop := &pushdrop.PushDrop{
		Wallet:     testWallet,
		Originator: "test",
	}

	// Test data
	fields := [][]byte{
		[]byte("hello world"),
		[]byte("This is a field"),
		{0xde, 0xad, 0xbe, 0xef},
	}
	protocolID := wallet.Protocol{
		SecurityLevel: 0,
		Protocol:      "testing",
	}
	keyID := "test-key"
	counterparty := wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	}

	// Create locking script
	lockingScript, err := pushDrop.Lock(
		ctx,
		fields,
		protocolID,
		keyID,
		counterparty,
		false, // forSelf
		true,  // includeSignature
		pushdrop.LockBefore, // lockPosition
	)
	require.NoError(t, err)

	// Create unlocking template
	unlocker := pushDrop.Unlock(
		ctx,
		protocolID,
		keyID,
		counterparty,
		wallet.SignOutputsAll,
		false,
	)
	require.NotNil(t, unlocker)

	// Check estimated length
	assert.Equal(t, uint32(73), unlocker.EstimateLength())

	// Create source transaction
	satoshis := uint64(1)
	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:       satoshis,
		LockingScript:  lockingScript,
	})

	// Create spending transaction
	spendTx := transaction.NewTransaction()
	spendTx.AddInputFromTx(sourceTx, 0, nil)

	// Sign the input
	unlockingScript, err := unlocker.Sign(spendTx, 0)
	require.NoError(t, err)
	require.NotNil(t, unlockingScript)

	// Set the unlocking script
	spendTx.Inputs[0].UnlockingScript = unlockingScript


	// Validate the script execution
	err = interpreter.NewEngine().Execute(
		interpreter.WithTx(spendTx, 0, &transaction.TransactionOutput{
			Satoshis:      satoshis,
			LockingScript: lockingScript,
		}),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
	if err != nil {
		t.Logf("Script execution failed: %v", err)
		t.Logf("Locking script: %s", lockingScript)
		t.Logf("Unlocking script: %s", unlockingScript)
	}
	assert.NoError(t, err)
}

func TestPushDrop_Decode(t *testing.T) {
	ctx := context.Background()
	testWallet := createTestWallet(t)
	pushDrop := &pushdrop.PushDrop{
		Wallet:     testWallet,
		Originator: "test",
	}

	// Test data
	fields := [][]byte{
		[]byte("hello world"),
		[]byte("This is a field"),
		{0xde, 0xad, 0xbe, 0xef},
	}
	protocolID := wallet.Protocol{
		SecurityLevel: 0,
		Protocol:      "testing",
	}
	keyID := "test-key"
	counterparty := wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	}

	// Create locking script
	lockingScript, err := pushDrop.Lock(
		ctx,
		fields,
		protocolID,
		keyID,
		counterparty,
		false, // forSelf
		true,  // includeSignature
		pushdrop.LockBefore, // lockPosition
	)
	require.NoError(t, err)

	// Decode
	decoded := pushdrop.Decode(lockingScript)
	require.NotNil(t, decoded)
	
	// Verify fields (without signature)
	assert.Equal(t, fields, decoded.Fields[:len(fields)])

	// Verify public key
	expectedPubKey, err := testWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        keyID,
			Counterparty: counterparty,
		},
		ForSelf: false,
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedPubKey.PublicKey.Compressed(), decoded.LockingPublicKey.Compressed())
}



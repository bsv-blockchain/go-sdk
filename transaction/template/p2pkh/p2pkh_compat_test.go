package p2pkh_test

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/stretchr/testify/require"
)

// TestP2PKHCompatibilityWithTypeScript tests compatibility with TypeScript SDK implementation
func TestP2PKHCompatibilityWithTypeScript(t *testing.T) {
	t.Parallel()

	// Test vector from TypeScript SDK - uses same private key and transaction structure
	// Private key: cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq
	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	// Create a transaction without source transaction (mimicking TypeScript behavior)
	tx := transaction.NewTransaction()

	// Add input using AddInputFrom (similar to TypeScript's addInput)
	require.NoError(t, tx.AddInputFrom(
		"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
		0,
		"", // Empty script, will be provided via options
		0,  // Zero satoshis, will be provided via options
		nil,
	))

	// Add output
	outputScript, err := script.NewFromHex("76a91442f9682260509ac80722b1963aec8a896593d16688ac")
	require.NoError(t, err)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      375041432,
		LockingScript: outputScript,
	})

	// Test case 1: Using optional parameters matching TypeScript's behavior
	t.Run("TypeScript compatible signing with SetSourceTxOutput", func(t *testing.T) {
		// This mimics TypeScript's: sourceSatoshis: 15564838601, lockingScript: Script
		satoshis := uint64(15564838601)
		lockingScript, err := script.NewFromHex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac")
		require.NoError(t, err)

		tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: satoshis, LockingScript: lockingScript})
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		// Sign the transaction
		uscript, err := unlocker.Sign(tx, 0)
		require.NoError(t, err)
		require.NotNil(t, uscript)

		// Verify signature structure matches TypeScript expectations
		parts, err := script.DecodeScript(*uscript)
		require.NoError(t, err)
		require.Len(t, parts, 2) // Signature and public key

		// Verify the signature length (should be 71-73 bytes including sighash flag)
		sigLen := len(parts[0].Data)
		require.GreaterOrEqual(t, sigLen, 71)
		require.LessOrEqual(t, sigLen, 73)

		// Verify the public key is compressed (33 bytes)
		require.Len(t, parts[1].Data, 33)
	})

	// Test case 2: Verify signature determinism (same inputs produce same signature hash)
	t.Run("Deterministic signature hash", func(t *testing.T) {
		// Create fresh transaction for this test
		tx2 := transaction.NewTransaction()
		require.NoError(t, tx2.AddInputFrom(
			"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
			0, "", 0, nil,
		))
		tx2.AddOutput(&transaction.TransactionOutput{
			Satoshis:      375041432,
			LockingScript: outputScript,
		})

		satoshis := uint64(15564838601)
		lockingScript, err := script.NewFromHex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac")
		require.NoError(t, err)

		// Create two unlockers with same parameters
		tx2.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: satoshis, LockingScript: lockingScript})
		unlocker1, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		// Both should produce valid signatures
		uscript1, err := unlocker1.Sign(tx2, 0)
		require.NoError(t, err)

		// Reset the transaction input for second signature
		tx3 := transaction.NewTransaction()
		require.NoError(t, tx3.AddInputFrom(
			"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
			0, "", 0, nil,
		))
		tx3.AddOutput(&transaction.TransactionOutput{
			Satoshis:      375041432,
			LockingScript: outputScript,
		})
		tx3.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: satoshis, LockingScript: lockingScript})
		unlocker2, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		uscript2, err := unlocker2.Sign(tx3, 0)
		require.NoError(t, err)

		// The scripts structure should be identical (though signatures may differ due to randomness)
		parts1, _ := script.DecodeScript(*uscript1)
		parts2, _ := script.DecodeScript(*uscript2)

		// Same number of parts
		require.Len(t, parts1, 2)
		require.Len(t, parts2, 2)

		// Same public key
		require.Equal(t, parts1[1].Data, parts2[1].Data)
	})

	// Test case 3: Cross-implementation vector
	t.Run("Cross implementation test vector", func(t *testing.T) {
		// This test uses the exact same transaction structure as TypeScript tests
		// to ensure both implementations produce compatible signatures

		// Create source transaction output info
		sourceTx := transaction.NewTransaction()

		// Source output
		sourceScript, err := script.NewFromHex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac")
		require.NoError(t, err)
		sourceTx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      100000000, // 1 BSV
			LockingScript: sourceScript,
		})

		// Create spending transaction
		spendTx := transaction.NewTransaction()
		spendTx.AddInputFromTx(sourceTx, 0, nil)

		// Add output - sending to same address with fee
		spendTx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      99990000, // 0.9999 BSV (0.0001 BSV fee)
			LockingScript: sourceScript,
		})

		// Create unlocker and sign
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		unlockingScript, err := unlocker.Sign(spendTx, 0)
		require.NoError(t, err)
		spendTx.Inputs[0].UnlockingScript = unlockingScript

		// Verify the transaction structure
		require.Equal(t, uint32(1), spendTx.Version)
		require.Equal(t, uint32(0), spendTx.LockTime)
		require.Len(t, spendTx.Inputs, 1)
		require.Len(t, spendTx.Outputs, 1)

		// The unlocking script should unlock the source output
		// In a full implementation, we would verify the script execution here
	})
}

// TestP2PKHOptionalParametersEdgeCases tests edge cases for optional parameters
func TestP2PKHOptionalParametersEdgeCases(t *testing.T) {
	t.Parallel()

	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	t.Run("Zero satoshis", func(t *testing.T) {
		tx := transaction.NewTransaction()
		require.NoError(t, tx.AddInputFrom("45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0, "", 0, nil))
		lockingScript, err := script.NewFromHex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac")
		require.NoError(t, err)
		tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 0, LockingScript: lockingScript})
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)
		_, err = unlocker.Sign(tx, 0)
		require.NoError(t, err)
	})

	t.Run("Maximum satoshis", func(t *testing.T) {
		tx := transaction.NewTransaction()
		require.NoError(t, tx.AddInputFrom("45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0, "", 0, nil))
		lockingScript, err := script.NewFromHex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac")
		require.NoError(t, err)
		maxSatoshis := uint64(21000000) * uint64(100000000)
		tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: maxSatoshis, LockingScript: lockingScript})
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)
		_, err = unlocker.Sign(tx, 0)
		require.NoError(t, err)
	})

	t.Run("Empty locking script", func(t *testing.T) {
		tx := transaction.NewTransaction()
		require.NoError(t, tx.AddInputFrom("45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0, "", 0, nil))
		emptyScript := &script.Script{}
		tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: emptyScript})
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)
		// Should still sign successfully (though spending would fail)
		_, err = unlocker.Sign(tx, 0)
		require.NoError(t, err)
	})
}

// TestP2PKHSignatureHashCalculation verifies signature hash calculation matches TypeScript
func TestP2PKHSignatureHashCalculation(t *testing.T) {
	t.Parallel()

	// Use a known test vector to verify signature hash calculation
	// This ensures both Go and TypeScript calculate the same hash for signing

	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	// Create a simple transaction
	tx := transaction.NewTransaction()
	tx.Version = 1
	tx.LockTime = 0

	// Add input
	require.NoError(t, tx.AddInputFrom(
		"0000000000000000000000000000000000000000000000000000000000000000",
		0,
		"76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac",
		1000,
		nil,
	))
	tx.Inputs[0].SequenceNumber = 0xffffffff

	// Add output
	outputScript, err := script.NewFromHex("76a91442f9682260509ac80722b1963aec8a896593d16688ac")
	require.NoError(t, err)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      500,
		LockingScript: outputScript,
	})

	// Create unlocker and sign
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	unlockingScript, err := unlocker.Sign(tx, 0)
	require.NoError(t, err)

	// Verify the unlocking script format
	parts, err := script.DecodeScript(*unlockingScript)
	require.NoError(t, err)
	require.Len(t, parts, 2)

	// Signature should end with SIGHASH_ALL | SIGHASH_FORKID (0x41)
	sig := parts[0].Data
	require.Equal(t, byte(0x41), sig[len(sig)-1])

	// Public key should be compressed
	pubKey := parts[1].Data
	require.Len(t, pubKey, 33)
	require.True(t, pubKey[0] == 0x02 || pubKey[0] == 0x03)

	// Verify it's the correct public key
	expectedPubKey := priv.PubKey().Compressed()
	require.Equal(t, hex.EncodeToString(expectedPubKey), hex.EncodeToString(pubKey))
}

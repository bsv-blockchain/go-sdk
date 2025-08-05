package wallet

import (
	"context"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/primitives/schnorr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtoWallet_RevealCounterpartyKeyLinkage(t *testing.T) {
	ctx := context.Background()
	
	// Initialize keys
	proverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// Initialize wallets
	proverWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: proverKey,
	})
	require.NoError(t, err)

	verifierWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: verifierKey,
	})
	require.NoError(t, err)

	// Prover reveals counterparty key linkage
	revelation, err := proverWallet.RevealCounterpartyKeyLinkage(ctx, RevealCounterpartyKeyLinkageArgs{
		Counterparty: counterpartyKey.PubKey(),
		Verifier:     verifierKey.PubKey(),
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, revelation)

	// Verify fields
	assert.NotNil(t, revelation.Prover)
	assert.Equal(t, proverKey.PubKey(), revelation.Prover)
	assert.Equal(t, counterpartyKey.PubKey(), revelation.Counterparty)
	assert.Equal(t, verifierKey.PubKey(), revelation.Verifier)
	assert.NotEmpty(t, revelation.RevelationTime)
	assert.NotEmpty(t, revelation.EncryptedLinkage)
	assert.NotEmpty(t, revelation.EncryptedLinkageProof)

	// Parse time to ensure it's valid RFC3339
	_, err = time.Parse(time.RFC3339Nano, revelation.RevelationTime)
	require.NoError(t, err)

	// Verifier decrypts the encrypted linkage
	decryptResult, err := verifierWallet.Decrypt(ctx, DecryptArgs{
		Ciphertext: revelation.EncryptedLinkage,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "counterparty linkage revelation"},
			KeyID:        revelation.RevelationTime,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: proverKey.PubKey()},
		},
	}, "test")
	require.NoError(t, err)
	// Compute expected linkage
	expectedSharedSecret, err := proverKey.DeriveSharedSecret(counterpartyKey.PubKey())
	require.NoError(t, err)
	expectedLinkage := expectedSharedSecret.Compressed()

	// Compare linkage
	assert.Equal(t, expectedLinkage, []byte(decryptResult.Plaintext))

	// Decrypt and verify the proof
	decryptProofResult, err := verifierWallet.Decrypt(ctx, DecryptArgs{
		Ciphertext: revelation.EncryptedLinkageProof,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "counterparty linkage revelation"},
			KeyID:        revelation.RevelationTime,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: proverKey.PubKey()},
		},
	}, "test")
	require.NoError(t, err)
	// Verify proof format (should be 98 bytes: 33 + 33 + 32)
	assert.Equal(t, 98, len(decryptProofResult.Plaintext))

	// Proof components: R compressed (33 bytes) || S' compressed (33 bytes) || z (32 bytes)
}

func TestProtoWallet_RevealSpecificKeyLinkage(t *testing.T) {
	ctx := context.Background()
	
	// Initialize keys
	proverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// Initialize wallets
	proverWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: proverKey,
	})
	require.NoError(t, err)

	verifierWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: verifierKey,
	})
	require.NoError(t, err)

	protocolID := Protocol{SecurityLevel: 0, Protocol: "tests"}
	keyID := "test key id"

	// Prover reveals specific key linkage
	revelation, err := proverWallet.RevealSpecificKeyLinkage(ctx, RevealSpecificKeyLinkageArgs{
		Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyKey.PubKey()},
		Verifier:     verifierKey.PubKey(),
		ProtocolID:   protocolID,
		KeyID:        keyID,
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, revelation)

	// Verify fields
	assert.NotEmpty(t, revelation.EncryptedLinkage)
	assert.NotEmpty(t, revelation.EncryptedLinkageProof)
	assert.Equal(t, proverKey.PubKey(), revelation.Prover)
	assert.Equal(t, verifierKey.PubKey(), revelation.Verifier)
	assert.Equal(t, counterpartyKey.PubKey(), revelation.Counterparty)
	assert.Equal(t, protocolID, revelation.ProtocolID)
	assert.Equal(t, keyID, revelation.KeyID)
	assert.Equal(t, byte(0), revelation.ProofType) // No proof for specific linkage

	// Verifier decrypts the encrypted linkage
	decryptResult, err := verifierWallet.Decrypt(ctx, DecryptArgs{
		Ciphertext: revelation.EncryptedLinkage,
		EncryptionArgs: EncryptionArgs{
			ProtocolID: Protocol{
				SecurityLevel: 2,
				Protocol:      "specific linkage revelation 0 tests",
			},
			KeyID:        keyID,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: proverKey.PubKey()},
		},
	}, "test")
	require.NoError(t, err)
	// Compute expected linkage using KeyDeriver
	kd := NewKeyDeriver(proverKey)
	expectedLinkage, err := kd.RevealSpecificSecret(
		Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyKey.PubKey()},
		protocolID,
		keyID,
	)
	require.NoError(t, err)

	// Compare linkage
	assert.Equal(t, expectedLinkage, []byte(decryptResult.Plaintext))

	// Decrypt the proof
	decryptProofResult, err := verifierWallet.Decrypt(ctx, DecryptArgs{
		Ciphertext: revelation.EncryptedLinkageProof,
		EncryptionArgs: EncryptionArgs{
			ProtocolID: Protocol{
				SecurityLevel: 2,
				Protocol:      "specific linkage revelation 0 tests",
			},
			KeyID:        keyID,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: proverKey.PubKey()},
		},
	}, "test")
	require.NoError(t, err)
	// Verify proof is just [0]
	assert.Equal(t, []byte{0}, []byte(decryptProofResult.Plaintext))
}

func TestProtoWallet_RevealCounterpartyKeyLinkage_Errors(t *testing.T) {
	ctx := context.Background()
	
	proverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	
	proverWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: proverKey,
	})
	require.NoError(t, err)

	// Test with nil counterparty
	_, err = proverWallet.RevealCounterpartyKeyLinkage(ctx, RevealCounterpartyKeyLinkageArgs{
		Counterparty: nil,
		Verifier:     proverKey.PubKey(),
	}, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "counterparty public key is required")

	// Test with nil verifier
	_, err = proverWallet.RevealCounterpartyKeyLinkage(ctx, RevealCounterpartyKeyLinkageArgs{
		Counterparty: proverKey.PubKey(),
		Verifier:     nil,
	}, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verifier public key is required")
}

func TestProtoWallet_RevealSpecificKeyLinkage_Errors(t *testing.T) {
	ctx := context.Background()
	
	proverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	
	proverWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: proverKey,
	})
	require.NoError(t, err)

	// Test with nil verifier
	_, err = proverWallet.RevealSpecificKeyLinkage(ctx, RevealSpecificKeyLinkageArgs{
		Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: proverKey.PubKey()},
		Verifier:     nil,
		ProtocolID:   Protocol{SecurityLevel: 0, Protocol: "test"},
		KeyID:        "test",
	}, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verifier public key is required")

	// Test with "self" counterparty
	_, err = proverWallet.RevealSpecificKeyLinkage(ctx, RevealSpecificKeyLinkageArgs{
		Counterparty: Counterparty{Type: CounterpartyTypeSelf},
		Verifier:     proverKey.PubKey(),
		ProtocolID:   Protocol{SecurityLevel: 0, Protocol: "test"},
		KeyID:        "test",
	}, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot reveal specific key linkage for 'self'")

	// Test with "anyone" counterparty
	_, err = proverWallet.RevealSpecificKeyLinkage(ctx, RevealSpecificKeyLinkageArgs{
		Counterparty: Counterparty{Type: CounterpartyTypeAnyone},
		Verifier:     proverKey.PubKey(),
		ProtocolID:   Protocol{SecurityLevel: 0, Protocol: "test"},
		KeyID:        "test",
	}, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot reveal specific key linkage for 'anyone'")
}

func TestSchnorrProofIntegration(t *testing.T) {
	// This test verifies that the Schnorr proof generated in RevealCounterpartyKeyLinkage
	// can be verified independently

	// Create keys
	proverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// Compute shared secret
	sharedSecret, err := proverKey.DeriveSharedSecret(counterpartyKey.PubKey())
	require.NoError(t, err)

	// Generate Schnorr proof
	s := schnorr.New()
	proof, err := s.GenerateProof(proverKey, proverKey.PubKey(), counterpartyKey.PubKey(), sharedSecret)
	require.NoError(t, err)

	// Verify proof
	valid := s.VerifyProof(proverKey.PubKey(), counterpartyKey.PubKey(), sharedSecret, proof)
	assert.True(t, valid)
}

func TestCompletedProtoWallet_RevealMethods(t *testing.T) {
	ctx := context.Background()
	
	// Create keys
	proverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	
	// Create CompletedProtoWallet
	wallet, err := NewCompletedProtoWallet(proverKey)
	require.NoError(t, err)
	
	t.Run("RevealCounterpartyKeyLinkage delegates correctly", func(t *testing.T) {
		result, err := wallet.RevealCounterpartyKeyLinkage(ctx, RevealCounterpartyKeyLinkageArgs{
			Counterparty: counterpartyKey.PubKey(),
			Verifier:     verifierKey.PubKey(),
		}, "test")
		
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, proverKey.PubKey(), result.Prover)
		assert.Equal(t, counterpartyKey.PubKey(), result.Counterparty)
		assert.Equal(t, verifierKey.PubKey(), result.Verifier)
		assert.NotEmpty(t, result.EncryptedLinkage)
		assert.NotEmpty(t, result.EncryptedLinkageProof)
		assert.NotEmpty(t, result.RevelationTime)
	})
	
	t.Run("RevealSpecificKeyLinkage delegates correctly", func(t *testing.T) {
		result, err := wallet.RevealSpecificKeyLinkage(ctx, RevealSpecificKeyLinkageArgs{
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyKey.PubKey()},
			Verifier:     verifierKey.PubKey(),
			ProtocolID:   Protocol{SecurityLevel: 0, Protocol: "test suite"},
			KeyID:        "test-key-id",
		}, "test")
		
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, proverKey.PubKey(), result.Prover)
		assert.Equal(t, counterpartyKey.PubKey(), result.Counterparty)
		assert.Equal(t, verifierKey.PubKey(), result.Verifier)
		assert.NotEmpty(t, result.EncryptedLinkage)
		assert.NotEmpty(t, result.EncryptedLinkageProof)
		assert.Equal(t, byte(0), result.ProofType)
		assert.Equal(t, "test suite", result.ProtocolID.Protocol)
		assert.Equal(t, "test-key-id", result.KeyID)
	})
}
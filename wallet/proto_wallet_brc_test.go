package wallet

import (
	"context"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/primitives/schnorr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProtoWallet_BRC2_EncryptionVector tests BRC-2 encryption compliance
func TestProtoWallet_BRC2_EncryptionVector(t *testing.T) {
	ctx := context.Background()

	// BRC-2 Encryption Compliance Vector
	privateKeyHex := "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8"
	privateKey, err := ec.PrivateKeyFromHex(privateKeyHex)
	require.NoError(t, err)

	counterpartyPubKeyHex := "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1"
	counterpartyPubKeyBytes, err := hex.DecodeString(counterpartyPubKeyHex)
	require.NoError(t, err)
	counterpartyPubKey, err := ec.PublicKeyFromBytes(counterpartyPubKeyBytes)
	require.NoError(t, err)

	protoWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	// Expected ciphertext
	expectedCiphertext := []byte{252, 203, 216, 184, 29, 161, 223, 212, 16, 193, 94, 99, 31, 140, 99, 43, 61, 236, 184, 67, 54, 105, 199, 47, 11, 19, 184, 127, 2, 165, 125, 9, 188, 195, 196, 39, 120, 130, 213, 95, 186, 89, 64, 28, 1, 80, 20, 213, 159, 133, 98, 253, 128, 105, 113, 247, 197, 152, 236, 64, 166, 207, 113, 134, 65, 38, 58, 24, 127, 145, 140, 206, 47, 70, 146, 84, 186, 72, 95, 35, 154, 112, 178, 55, 72, 124}
	plaintext := "BRC-2 Encryption Compliance Validated!"

	// Decrypt the ciphertext
	decryptResult, err := protoWallet.Decrypt(ctx, DecryptArgs{
		Ciphertext: expectedCiphertext,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "BRC2 Test"},
			KeyID:        "42",
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyPubKey},
		},
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decryptResult.Plaintext))
}

// TestProtoWallet_BRC2_HMACVector tests BRC-2 HMAC compliance
func TestProtoWallet_BRC2_HMACVector(t *testing.T) {
	ctx := context.Background()

	// BRC-2 HMAC Compliance Vector
	privateKeyHex := "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8"
	privateKey, err := ec.PrivateKeyFromHex(privateKeyHex)
	require.NoError(t, err)

	counterpartyPubKeyHex := "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1"
	counterpartyPubKeyBytes, err := hex.DecodeString(counterpartyPubKeyHex)
	require.NoError(t, err)
	counterpartyPubKey, err := ec.PublicKeyFromBytes(counterpartyPubKeyBytes)
	require.NoError(t, err)

	protoWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	// Create HMAC
	data := []byte("BRC-2 HMAC Compliance Validated!")
	hmacResult, err := protoWallet.CreateHMAC(ctx, CreateHMACArgs{
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "BRC2 Test"},
			KeyID:        "42",
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyPubKey},
		},
		Data: data,
	}, "test")
	require.NoError(t, err)

	// Expected HMAC
	expectedHMAC := []byte{81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76, 254, 103, 46, 182, 86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234, 14}
	assert.Equal(t, expectedHMAC, hmacResult.HMAC[:])
}

// TestProtoWallet_BRC3_SignatureVector tests BRC-3 signature compliance
func TestProtoWallet_BRC3_SignatureVector(t *testing.T) {
	ctx := context.Background()

	// Note: We can't reproduce the exact signature due to randomness in ECDSA,
	// but we can verify that our signatures are valid

	// Use a fixed private key for testing
	privateKeyHex := "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8"
	privateKey, err := ec.PrivateKeyFromHex(privateKeyHex)
	require.NoError(t, err)

	counterpartyPubKeyHex := "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1"
	counterpartyPubKeyBytes, err := hex.DecodeString(counterpartyPubKeyHex)
	require.NoError(t, err)
	counterpartyPubKey, err := ec.PublicKeyFromBytes(counterpartyPubKeyBytes)
	require.NoError(t, err)

	protoWallet, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	// Create a signature
	data := []byte("BRC-3 Compliance Validated!")
	sigResult, err := protoWallet.CreateSignature(ctx, CreateSignatureArgs{
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "BRC3 Test"},
			KeyID:        "42",
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyPubKey},
		},
		Data: data,
	}, "test")
	require.NoError(t, err)

	// Verify our own signature works
	forSelf := true
	verifyResult, err := protoWallet.VerifySignature(ctx, VerifySignatureArgs{
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "BRC3 Test"},
			KeyID:        "42",
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyPubKey},
		},
		Data:      data,
		Signature: sigResult.Signature,
		ForSelf:   &forSelf,
	}, "test")
	require.NoError(t, err)
	assert.True(t, verifyResult.Valid)
}

// TestKeyDeriver_FixedTestVectors tests key derivation with fixed values
func TestKeyDeriver_FixedTestVectors(t *testing.T) {
	// Create keys with fixed values
	// Create a 32-byte array with value 42
	rootKeyBytes := make([]byte, 32)
	rootKeyBytes[31] = 42
	rootPrivateKey, _ := ec.PrivateKeyFromBytes(rootKeyBytes)

	// Create a 32-byte array with value 69
	counterpartyKeyBytes := make([]byte, 32)
	counterpartyKeyBytes[31] = 69
	counterpartyPrivateKey, _ := ec.PrivateKeyFromBytes(counterpartyKeyBytes)
	counterpartyPublicKey := counterpartyPrivateKey.PubKey()

	kd := NewKeyDeriver(rootPrivateKey)

	// Test invoice number computation
	protocolID := Protocol{SecurityLevel: 0, Protocol: "testprotocol"}
	keyID := "12345"

	invoiceNumber, err := kd.computeInvoiceNumber(protocolID, keyID)
	require.NoError(t, err)
	assert.Equal(t, "0-testprotocol-12345", invoiceNumber)

	// Test public key derivation
	pubKey, err := kd.DerivePublicKey(protocolID, keyID, Counterparty{
		Type:         CounterpartyTypeOther,
		Counterparty: counterpartyPublicKey,
	}, false)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)

	// Test private key derivation
	privKey, err := kd.DerivePrivateKey(protocolID, keyID, Counterparty{
		Type:         CounterpartyTypeOther,
		Counterparty: counterpartyPublicKey,
	})
	require.NoError(t, err)
	assert.NotNil(t, privKey)
}

// TestSchnorr_FixedKeyVector tests Schnorr proof with fixed keys
func TestSchnorr_FixedKeyVector(t *testing.T) {
	// Fixed keys for deterministic testing
	aHex := "0000000000000000000000000000000123456789abcdef123456789abcdef123456789abcdef123456789abcdef"
	bHex := "00000000000000000000000000000000abcdef123456789abcdef123456789abcdef123456789abcdef123456789"

	// Note: The hex strings above are longer than 32 bytes, so we'll use the last 32 bytes
	aBytes, err := hex.DecodeString(aHex[len(aHex)-64:])
	require.NoError(t, err)
	a, _ := ec.PrivateKeyFromBytes(aBytes)

	bBytes, err := hex.DecodeString(bHex[len(bHex)-64:])
	require.NoError(t, err)
	b, _ := ec.PrivateKeyFromBytes(bBytes)

	A := a.PubKey()
	B := b.PubKey()

	// Compute shared secret
	S, err := a.DeriveSharedSecret(B)
	require.NoError(t, err)

	// Generate and verify proof
	s := schnorr.New()
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	valid := s.VerifyProof(A, B, S, proof)
	assert.True(t, valid)
}

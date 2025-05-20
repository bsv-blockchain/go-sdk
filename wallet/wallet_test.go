package wallet_test

import (
	"crypto/sha256"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Create test data
var sampleData = []byte{3, 1, 4, 1, 5, 9}

// Define protocol and key ID
var protocol = wallet.Protocol{
	SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	Protocol:      "tests",
}

const keyID = "4"

func TestEncryptDecryptMessage(t *testing.T) {
	// Generate keys
	userKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating user private key should not error")
	counterpartyKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating counterparty private key should not error")

	// Create wallets with proper initialization
	userWallet, err := wallet.NewWallet(userKey)
	assert.NoError(t, err, "creating user wallet should not error")
	counterpartyWallet, err := wallet.NewWallet(counterpartyKey)
	assert.NoError(t, err, "creating counterparty wallet should not error")

	ctx := t.Context()

	// Encrypt message
	encryptResult, err := userWallet.Encrypt(ctx, wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: protocol,
			KeyID:      keyID,
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyKey.PubKey(),
			},
		},
		Plaintext: sampleData,
	}, "example")
	assert.NoError(t, err, "encrypting message should not error")
	assert.NotEqual(t, sampleData, encryptResult.Ciphertext, "ciphertext should not equal plaintext")

	// Decrypt message
	decryptArgs := wallet.DecryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: protocol,
			KeyID:      keyID,
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: userKey.PubKey(),
			},
		},
		Ciphertext: encryptResult.Ciphertext,
	}
	decryptResult, err := counterpartyWallet.Decrypt(ctx, decryptArgs, "example")
	assert.NoError(t, err, "decrypting message should not error")
	assert.Equal(t, sampleData, []byte(decryptResult.Plaintext), "decrypted plaintext should equal original sample data")

	// Test error cases
	t.Run("wrong protocol", func(t *testing.T) {
		wrongProtocolArgs := decryptArgs
		wrongProtocolArgs.ProtocolID.Protocol = "wrong"
		_, err := counterpartyWallet.Decrypt(t.Context(), wrongProtocolArgs, "example")
		assert.Error(t, err, "decrypting with wrong protocol should error")
		assert.Contains(t, err.Error(), "cipher: message authentication failed", "error message should contain auth failure")
	})

	t.Run("wrong key ID", func(t *testing.T) {
		wrongKeyArgs := decryptArgs
		wrongKeyArgs.KeyID = "5"
		_, err := counterpartyWallet.Decrypt(ctx, wrongKeyArgs, "example")
		assert.Error(t, err, "decrypting with wrong key ID should error")
		assert.Contains(t, err.Error(), "cipher: message authentication failed", "error message should contain auth failure")
	})

	t.Run("wrong counterparty", func(t *testing.T) {
		wrongCounterpartyArgs := decryptArgs
		wrongCounterpartyArgs.Counterparty.Counterparty = counterpartyKey.PubKey()
		_, err := counterpartyWallet.Decrypt(ctx, wrongCounterpartyArgs, "example")
		assert.Error(t, err, "decrypting with wrong counterparty should error")
		assert.Contains(t, err.Error(), "cipher: message authentication failed", "error message should contain auth failure")
	})

	t.Run("invalid protocol name", func(t *testing.T) {
		invalidProtocolArgs := decryptArgs
		invalidProtocolArgs.ProtocolID.Protocol = "x"
		_, err := counterpartyWallet.Decrypt(ctx, invalidProtocolArgs, "example")
		assert.Error(t, err, "decrypting with invalid protocol name should error")
		assert.Contains(t, err.Error(), "protocol names must be 5 characters or more", "error message should mention protocol name length")
	})

	t.Run("invalid key ID", func(t *testing.T) {
		invalidKeyArgs := decryptArgs
		invalidKeyArgs.KeyID = ""
		_, err := counterpartyWallet.Decrypt(ctx, invalidKeyArgs, "example")
		assert.Error(t, err, "decrypting with invalid key ID should error")
		assert.Contains(t, err.Error(), "key IDs must be 1 character or more", "error message should mention key ID length")
	})

	t.Run("invalid security level", func(t *testing.T) {
		invalidSecurityArgs := decryptArgs
		invalidSecurityArgs.ProtocolID.SecurityLevel = -1
		_, err := counterpartyWallet.Decrypt(ctx, invalidSecurityArgs, "example")
		assert.Error(t, err, "decrypting with invalid security level should error")
		assert.Contains(t, err.Error(), "protocol security level must be 0, 1, or 2", "error message should mention valid security levels")
	})

	t.Run("validates BRC-2 encryption compliance vector", func(t *testing.T) {
		privKey, err := ec.PrivateKeyFromHex(
			"6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")
		assert.NoError(t, err, "creating private key from hex should not error")

		counterparty, err := ec.PublicKeyFromString(
			"0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")
		assert.NoError(t, err, "creating public key from string should not error")

		w, err := wallet.NewWallet(privKey)
		assert.NoError(t, err, "creating wallet from private key should not error")
		result, err := w.Decrypt(ctx, wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "BRC2 Test",
				},
				KeyID: "42",
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: counterparty,
				},
			},
			Ciphertext: []byte{
				252, 203, 216, 184, 29, 161, 223, 212, 16, 193, 94, 99, 31, 140, 99, 43,
				61, 236, 184, 67, 54, 105, 199, 47, 11, 19, 184, 127, 2, 165, 125, 9,
				188, 195, 196, 39, 120, 130, 213, 95, 186, 89, 64, 28, 1, 80, 20, 213,
				159, 133, 98, 253, 128, 105, 113, 247, 197, 152, 236, 64, 166, 207, 113,
				134, 65, 38, 58, 24, 127, 145, 140, 206, 47, 70, 146, 84, 186, 72, 95,
				35, 154, 112, 178, 55, 72, 124,
			},
		}, "example")
		assert.NoError(t, err, "decrypting BRC-2 vector should not error")
		assert.Equal(t, []byte("BRC-2 Encryption Compliance Validated!"), []byte(result.Plaintext), "decrypted BRC-2 plaintext should match expected value")
	})
}

func TestDefaultEncryptDecryptOperations(t *testing.T) {
	// Generate keys
	userKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating user private key should not error")
	userWallet, err := wallet.NewWallet(userKey)
	assert.NoError(t, err, "creating user wallet should not error")

	// Base encryption args
	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		KeyID:      keyID,
	}

	ctx := t.Context()

	t.Run("test encrypt/decrypt with implicit self", func(t *testing.T) {
		// Test encryption/decryption with implicit self
		encryptArgs := wallet.EncryptArgs{
			EncryptionArgs: baseArgs,
			Plaintext:      sampleData,
		}
		encryptResult, err := userWallet.Encrypt(ctx, encryptArgs, "example")
		assert.NoError(t, err, "encrypting with implicit self should not error")
		assert.NotEmpty(t, encryptResult.Ciphertext, "ciphertext should not be empty")

		// Decrypt message with implicit self
		decryptArgs := wallet.DecryptArgs{
			EncryptionArgs: baseArgs,
			Ciphertext:     encryptResult.Ciphertext,
		}
		decryptResult, err := userWallet.Decrypt(ctx, decryptArgs, "example")
		assert.NoError(t, err, "decrypting with implicit self should not error")
		assert.Equal(t, sampleData, []byte(decryptResult.Plaintext), "decrypted plaintext should equal original sample data")
	})
}

func TestCreateVerifySignature(t *testing.T) {
	// Generate keys
	userKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating user private key should not error")
	counterpartyKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating counterparty private key should not error")

	// Create wallets with proper initialization
	userWallet, err := wallet.NewWallet(userKey)
	assert.NoError(t, err, "creating user wallet should not error")
	counterpartyWallet, err := wallet.NewWallet(counterpartyKey)
	assert.NoError(t, err, "creating counterparty wallet should not error")

	// Create base args
	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		KeyID:      keyID,
	}

	ctx := t.Context()

	// Create signature
	signArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: baseArgs,
		Data:           sampleData,
	}
	//nolint:staticcheck // Explicit access is clear
	signArgs.EncryptionArgs.Counterparty = wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: counterpartyKey.PubKey(),
	}

	signResult, err := userWallet.CreateSignature(ctx, signArgs, "")
	assert.NoError(t, err, "creating signature should not error")
	assert.NotEmpty(t, signResult.Signature, "signature should not be empty")

	// Verify signature
	verifyArgs := wallet.VerifySignatureArgs{
		EncryptionArgs: baseArgs,
		Signature:      signResult.Signature,
		Data:           sampleData,
	}
	//nolint:staticcheck // Explicit access is clear
	verifyArgs.EncryptionArgs.Counterparty = wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: userKey.PubKey(),
	}

	verifyResult, err := counterpartyWallet.VerifySignature(ctx, verifyArgs, "example")
	assert.NoError(t, err, "verifying signature should not error")
	assert.True(t, verifyResult.Valid, "signature should be valid")

	t.Run("directly signs hash of message", func(t *testing.T) {
		// Hash the sample data
		hash := sha256.Sum256(sampleData)

		// Create signature with hash
		signArgs.HashToDirectlySign = hash[:]
		signArgs.Data = nil

		signResult, err := userWallet.CreateSignature(ctx, signArgs, "")
		assert.NoError(t, err)
		assert.NotEmpty(t, signResult.Signature)

		// Verify signature with data
		verifyArgs.Data = sampleData
		verifyArgs.HashToDirectlyVerify = nil

		verifyResult, err := counterpartyWallet.VerifySignature(ctx, verifyArgs, "example")
		assert.NoError(t, err)
		assert.True(t, verifyResult.Valid)

		// Verify signature with hash directly
		verifyArgs.Data = nil
		verifyArgs.HashToDirectlyVerify = hash[:]

		verifyHashResult, err := counterpartyWallet.VerifySignature(ctx, verifyArgs, "example")
		assert.NoError(t, err)
		assert.True(t, verifyHashResult.Valid)
	})

	t.Run("fails to verify signature with wrong data", func(t *testing.T) {
		// Verify with wrong data
		invalidVerifySignatureArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: verifyArgs.EncryptionArgs,
			Signature:      verifyArgs.Signature,
			Data:           append([]byte{0}, sampleData...),
		}
		_, err := counterpartyWallet.VerifySignature(ctx, invalidVerifySignatureArgs, "example")
		require.Error(t, err)
	})

	t.Run("fails to verify signature with wrong protocol", func(t *testing.T) {
		invalidVerifySignatureArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: verifyArgs.EncryptionArgs,
			Signature:      verifyArgs.Signature,
			Data:           verifyArgs.Data,
		}
		invalidVerifySignatureArgs.ProtocolID.Protocol = "wrong"
		_, err = counterpartyWallet.VerifySignature(ctx, invalidVerifySignatureArgs, "example")
		assert.Error(t, err)
	})

	t.Run("fails to verify signature with wrong key ID", func(t *testing.T) {
		invalidVerifySignatureArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: verifyArgs.EncryptionArgs,
			Signature:      verifyArgs.Signature,
			Data:           verifyArgs.Data,
		}
		invalidVerifySignatureArgs.KeyID = "wrong"
		_, err = counterpartyWallet.VerifySignature(ctx, invalidVerifySignatureArgs, "example")
		assert.Error(t, err)
	})

	t.Run("fails to verify signature with wrong counterparty", func(t *testing.T) {
		invalidVerifySignatureArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: verifyArgs.EncryptionArgs,
			Signature:      verifyArgs.Signature,
			Data:           verifyArgs.Data,
		}
		wrongKey, _ := ec.NewPrivateKey()
		invalidVerifySignatureArgs.Counterparty.Counterparty = wrongKey.PubKey()
		_, err = counterpartyWallet.VerifySignature(ctx, invalidVerifySignatureArgs, "example")
		assert.Error(t, err)
	})

	t.Run("validates the BRC-3 compliance vector", func(t *testing.T) {
		anyoneKey, _ := wallet.AnyoneKey()
		anyoneWallet, err := wallet.NewWallet(anyoneKey)
		assert.NoError(t, err)

		counterparty, err := ec.PublicKeyFromString(
			"0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")
		assert.NoError(t, err)

		signature, err := ec.FromDER([]byte{
			48, 68, 2, 32, 43, 34, 58, 156, 219, 32, 50, 70, 29, 240, 155, 137, 88,
			60, 200, 95, 243, 198, 201, 21, 56, 82, 141, 112, 69, 196, 170, 73, 156,
			6, 44, 48, 2, 32, 118, 125, 254, 201, 44, 87, 177, 170, 93, 11, 193,
			134, 18, 70, 9, 31, 234, 27, 170, 177, 54, 96, 181, 140, 166, 196, 144,
			14, 230, 118, 106, 105,
		})
		assert.NoError(t, err)

		verifyResult, err := anyoneWallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "BRC3 Test",
				},
				KeyID: "42",
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: counterparty,
				},
			},
			Signature: *signature,
			Data:      []byte("BRC-3 Compliance Validated!"),
		}, "example")
		assert.NoError(t, err, "verifying BRC-2 signature should not error")
		assert.True(t, verifyResult.Valid, "BRC-2 signature should be valid")
	})
}

func TestDefaultSignatureOperations(t *testing.T) {
	// Generate keys
	userKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating user private key should not error")
	userWallet, err := wallet.NewWallet(userKey)
	assert.NoError(t, err, "creating user wallet should not error")

	anyoneKey, _ := wallet.AnyoneKey()
	anyoneWallet, err := wallet.NewWallet(anyoneKey)
	assert.NoError(t, err)

	// Base encryption args
	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		KeyID:      keyID,
	}

	ctx := t.Context()

	t.Run("verify self sign signature", func(t *testing.T) {
		// Create signature with self sign
		selfSignArgs := wallet.CreateSignatureArgs{
			EncryptionArgs: baseArgs,
			Data:           sampleData,
		}
		selfSignArgs.Counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
		selfSignResult, err := userWallet.CreateSignature(ctx, selfSignArgs, "")
		assert.NoError(t, err)
		assert.NotEmpty(t, selfSignResult.Signature)

		// Verify signature with explicit self
		selfVerifyExplicitArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: baseArgs,
			Signature:      selfSignResult.Signature,
			Data:           sampleData,
		}
		selfVerifyExplicitArgs.Counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
		selfVerifyExplicitResult, err := userWallet.VerifySignature(ctx, selfVerifyExplicitArgs, "example")
		assert.NoError(t, err)
		assert.True(t, selfVerifyExplicitResult.Valid)

		// Verify signature with implicit self
		selfVerifyArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: baseArgs,
			Signature:      selfSignResult.Signature,
			Data:           sampleData,
		}
		selfVerifyArgs.Counterparty = wallet.Counterparty{}
		selfVerifyResult, err := userWallet.VerifySignature(ctx, selfVerifyArgs, "example")
		assert.NoError(t, err)
		assert.True(t, selfVerifyResult.Valid)
	})

	t.Run("verify anyone sign signature", func(t *testing.T) {
		// Create signature with implicit anyone
		anyoneSignArgs := wallet.CreateSignatureArgs{
			EncryptionArgs: baseArgs,
			Data:           sampleData,
		}
		anyoneSignResult, err := userWallet.CreateSignature(ctx, anyoneSignArgs, "")
		assert.NoError(t, err)
		assert.NotEmpty(t, anyoneSignResult.Signature)

		// Verify signature with explicit counterparty
		verifyArgs := wallet.VerifySignatureArgs{
			EncryptionArgs: baseArgs,
			Signature:      anyoneSignResult.Signature,
			Data:           sampleData,
		}
		verifyArgs.Counterparty = wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: userKey.PubKey(),
		}
		verifyResult, err := anyoneWallet.VerifySignature(ctx, verifyArgs, "example")
		assert.NoError(t, err)
		assert.True(t, verifyResult.Valid)
	})
	t.Run("test get self public key", func(t *testing.T) {
		// Test public key derivation with implicit self
		getPubKeyArgs := wallet.GetPublicKeyArgs{
			EncryptionArgs: baseArgs,
		}
		pubKeyResult, err := userWallet.GetPublicKey(ctx, getPubKeyArgs, "example")
		assert.NoError(t, err)
		assert.NotNil(t, pubKeyResult.PublicKey)

		// Test public key derivation with explicit self
		getExplicitPubKeyArgs := wallet.GetPublicKeyArgs{
			EncryptionArgs: baseArgs,
		}
		getExplicitPubKeyArgs.Counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
		explicitPubKeyResult, err := userWallet.GetPublicKey(ctx, getExplicitPubKeyArgs, "example")
		assert.NoError(t, err)
		assert.NotNil(t, explicitPubKeyResult.PublicKey)

		assert.Equal(t, pubKeyResult.PublicKey, explicitPubKeyResult.PublicKey)
	})
}

func TestGetPublicKeyForCounterparty(t *testing.T) {
	// Generate keys
	userKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating user private key should not error")
	counterpartyKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating counterparty private key should not error")

	// Create wallets
	userWallet, err := wallet.NewWallet(userKey)
	assert.NoError(t, err, "creating user wallet should not error")
	counterpartyWallet, err := wallet.NewWallet(counterpartyKey)
	assert.NoError(t, err, "creating counterparty wallet should not error")

	// Base args
	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		KeyID:      keyID,
	}

	ctx := t.Context()

	// Test public key derivation
	getIdentityPubKeyArgs := wallet.GetPublicKeyArgs{
		EncryptionArgs: baseArgs,
		IdentityKey:    true,
	}
	identityPubKeyResult, err := userWallet.GetPublicKey(ctx, getIdentityPubKeyArgs, "example")
	assert.NoError(t, err)
	assert.Equal(t, identityPubKeyResult.PublicKey, userKey.PubKey())

	// Test get public key for counterparty
	getForCounterpartyPubKeyArgs := wallet.GetPublicKeyArgs{
		EncryptionArgs: baseArgs,
	}
	getForCounterpartyPubKeyArgs.Counterparty = wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: counterpartyKey.PubKey(),
	}
	forCounterpartyPubKeyResult, err := userWallet.GetPublicKey(ctx, getForCounterpartyPubKeyArgs, "example")
	assert.NoError(t, err)

	// Test get public key by counterparty
	getByCounterpartyPubKeyArgs := wallet.GetPublicKeyArgs{
		EncryptionArgs: baseArgs,
		ForSelf:        true,
	}
	getByCounterpartyPubKeyArgs.Counterparty = wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: userKey.PubKey(),
	}
	byCounterpartyPubKeyResult, err := counterpartyWallet.GetPublicKey(ctx, getByCounterpartyPubKeyArgs, "example")
	assert.NoError(t, err)

	// Check keys are equal
	assert.Equal(t, forCounterpartyPubKeyResult.PublicKey.Compressed(),
		byCounterpartyPubKeyResult.PublicKey.Compressed())
}

func TestHmacCreateVerify(t *testing.T) {
	// Generate keys
	userKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating user private key should not error")
	counterpartyKey, err := ec.NewPrivateKey()
	assert.NoError(t, err, "generating counterparty private key should not error")

	// Create wallets
	userWallet, err := wallet.NewWallet(userKey)
	assert.NoError(t, err, "creating user wallet should not error")
	counterpartyWallet, err := wallet.NewWallet(counterpartyKey)
	assert.NoError(t, err, "creating counterparty wallet should not error")

	// Create base args
	baseArgs := wallet.EncryptionArgs{
		ProtocolID: protocol,
		KeyID:      keyID,
	}

	ctx := t.Context()

	// Create HMAC
	createHmacArgs := wallet.CreateHMACArgs{
		EncryptionArgs: baseArgs,
		Data:           sampleData,
	}
	createHmacArgs.Counterparty = wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: counterpartyKey.PubKey(),
	}

	createHmacResult, err := userWallet.CreateHMAC(ctx, createHmacArgs, "example")
	assert.NoError(t, err)
	assert.Len(t, createHmacResult.Hmac, 32)

	// Verify HMAC
	verifyHmacArgs := wallet.VerifyHMACArgs{
		EncryptionArgs: baseArgs,
		Hmac:           createHmacResult.Hmac,
		Data:           sampleData,
	}
	verifyHmacArgs.Counterparty = wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: userKey.PubKey(),
	}

	verifyHmacResult, err := counterpartyWallet.VerifyHMAC(ctx, verifyHmacArgs, "example")
	assert.NoError(t, err)
	assert.True(t, verifyHmacResult.Valid)

	// Test error cases
	t.Run("fails to verify HMAC with wrong data", func(t *testing.T) {
		invalidVerifyHmacArgs := verifyHmacArgs
		invalidVerifyHmacArgs.Data = append([]byte{0}, sampleData...)
		valid, err := counterpartyWallet.VerifyHMAC(ctx, invalidVerifyHmacArgs, "example")
		assert.NoError(t, err)
		assert.False(t, valid.Valid)
	})

	t.Run("fails to verify HMAC with wrong protocol", func(t *testing.T) {
		invalidVerifyHmacArgs := verifyHmacArgs
		invalidVerifyHmacArgs.ProtocolID.Protocol = "wrong"
		valid, err := counterpartyWallet.VerifyHMAC(ctx, invalidVerifyHmacArgs, "example")
		assert.NoError(t, err)
		assert.False(t, valid.Valid)
	})

	t.Run("fails to verify HMAC with wrong key ID", func(t *testing.T) {
		invalidVerifyHmacArgs := verifyHmacArgs
		invalidVerifyHmacArgs.KeyID = "wrong"
		valid, err := counterpartyWallet.VerifyHMAC(ctx, invalidVerifyHmacArgs, "example")
		assert.NoError(t, err)
		assert.False(t, valid.Valid)
	})

	t.Run("fails to verify HMAC with wrong counterparty", func(t *testing.T) {
		invalidVerifyHmacArgs := verifyHmacArgs
		wrongKey, _ := ec.NewPrivateKey()
		invalidVerifyHmacArgs.Counterparty.Counterparty = wrongKey.PubKey()
		valid, err := counterpartyWallet.VerifyHMAC(ctx, invalidVerifyHmacArgs, "example")
		assert.NoError(t, err)
		assert.False(t, valid.Valid)
	})

	t.Run("validates BRC-2 HMAC compliance vector", func(t *testing.T) {
		privKey, err := ec.PrivateKeyFromHex("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")
		assert.NoError(t, err)

		counterparty, err := ec.PublicKeyFromString("0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")
		assert.NoError(t, err)

		w, err := wallet.NewWallet(privKey)
		assert.NoError(t, err)
		verifyResult, err := w.VerifyHMAC(ctx, wallet.VerifyHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "BRC2 Test",
				},
				KeyID: "42",
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: counterparty,
				},
			},
			Data: []byte("BRC-2 HMAC Compliance Validated!"),
			Hmac: []byte{
				81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76,
				254, 103, 46, 182, 86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234, 14,
			},
		}, "example")
		assert.NoError(t, err)
		assert.True(t, verifyResult.Valid)
	})
}

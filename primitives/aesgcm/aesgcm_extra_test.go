package primitives

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESEncrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		plaintext  string
		key        string
		wantErr    bool
		errContain string
	}{
		{
			name:      "AES-128 encrypt",
			plaintext: "00112233445566778899aabbccddeeff",
			key:       "000102030405060708090a0b0c0d0e0f",
			wantErr:   false,
		},
		{
			name:      "AES-192 encrypt",
			plaintext: "00112233445566778899aabbccddeeff",
			key:       "000102030405060708090a0b0c0d0e0f1011121314151617",
			wantErr:   false,
		},
		{
			name:      "AES-256 encrypt",
			plaintext: "00112233445566778899aabbccddeeff",
			key:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			wantErr:   false,
		},
		{
			name:       "plaintext wrong block size",
			plaintext:  "0011223344556677", // 8 bytes, not 16
			key:        "000102030405060708090a0b0c0d0e0f",
			wantErr:    true,
			errContain: "plaintext is not the correct block size",
		},
		{
			name:       "invalid key length",
			plaintext:  "00112233445566778899aabbccddeeff",
			key:        "0102", // 1 byte key
			wantErr:    true,
			errContain: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := hex.DecodeString(tt.plaintext)
			require.NoError(t, err)
			key, err := hex.DecodeString(tt.key)
			require.NoError(t, err)

			result, err := AESEncrypt(plaintext, key)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					require.Contains(t, err.Error(), tt.errContain)
				}
				return
			}
			require.NoError(t, err)
			require.Len(t, result, 16)
		})
	}
}

func TestAESDecrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		plaintextHx string
		keyHex      string
		wantErr     bool
		errContain  string
	}{
		{
			name:        "AES-128 round-trip",
			plaintextHx: "00112233445566778899aabbccddeeff",
			keyHex:      "000102030405060708090a0b0c0d0e0f",
		},
		{
			name:        "AES-256 round-trip",
			plaintextHx: "00112233445566778899aabbccddeeff",
			keyHex:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		},
		{
			name:       "ciphertext wrong block size",
			plaintextHx: "001122334455",
			keyHex:     "000102030405060708090a0b0c0d0e0f",
			wantErr:    true,
			errContain: "ciphertext is not the correct block size",
		},
		{
			name:        "invalid key length",
			plaintextHx: "00112233445566778899aabbccddeeff",
			keyHex:      "0102",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := hex.DecodeString(tt.plaintextHx)
			require.NoError(t, err)
			key, err := hex.DecodeString(tt.keyHex)
			require.NoError(t, err)

			if tt.wantErr {
				// Pass plaintext as "ciphertext" directly to test error paths
				result, err := AESDecrypt(plaintext, key)
				require.Error(t, err)
				_ = result
				if tt.errContain != "" {
					require.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			// Round-trip: encrypt then decrypt
			ciphertext, err := AESEncrypt(plaintext, key)
			require.NoError(t, err)

			recovered, err := AESDecrypt(ciphertext, key)
			require.NoError(t, err)
			require.Equal(t, plaintext, recovered)
		})
	}
}

func TestAESGCMDecrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                        string
		plaintext                   string
		additionalAuthenticatedData string
		initializationVector        string
		key                         string
		wantErr                     bool
	}{
		{
			name:                        "empty plaintext",
			plaintext:                   "",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "00000000000000000000000000000000",
			wantErr:                     false,
		},
		{
			name:                        "16-byte plaintext",
			plaintext:                   "00000000000000000000000000000000",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "00000000000000000000000000000000",
			wantErr:                     false,
		},
		{
			name:                        "with AAD",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308",
			wantErr:                     false,
		},
		{
			name:                        "AES-256 decrypt",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			additionalAuthenticatedData: "",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			wantErr:                     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := hex.DecodeString(tt.plaintext)
			require.NoError(t, err)
			aad, err := hex.DecodeString(tt.additionalAuthenticatedData)
			require.NoError(t, err)
			iv, err := hex.DecodeString(tt.initializationVector)
			require.NoError(t, err)
			key, err := hex.DecodeString(tt.key)
			require.NoError(t, err)

			// Encrypt first
			ciphertext, authTag, err := AESGCMEncrypt(plaintext, key, iv, aad)
			require.NoError(t, err)

			// Now decrypt
			recovered, err := AESGCMDecrypt(ciphertext, key, iv, aad, authTag)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if len(plaintext) == 0 {
				require.Empty(t, recovered)
			} else {
				require.Equal(t, plaintext, recovered)
			}
		})
	}
}

func TestAESGCMDecrypt_WrongTag(t *testing.T) {
	t.Parallel()

	plaintext, _ := hex.DecodeString("00000000000000000000000000000000")
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	iv, _ := hex.DecodeString("000000000000000000000000")
	aad := []byte{}

	ciphertext, authTag, err := AESGCMEncrypt(plaintext, key, iv, aad)
	require.NoError(t, err)

	// Corrupt the authentication tag
	corruptTag := make([]byte, len(authTag))
	copy(corruptTag, authTag)
	corruptTag[0] ^= 0xFF

	_, err = AESGCMDecrypt(ciphertext, key, iv, aad, corruptTag)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decryption failed")
}

func TestAESGCMDecrypt_InvalidKey(t *testing.T) {
	t.Parallel()

	ciphertext := []byte{}
	badKey := []byte{0x01} // invalid key size
	iv, _ := hex.DecodeString("000000000000000000000000")
	authTag := make([]byte, 16)

	_, err := AESGCMDecrypt(ciphertext, badKey, iv, nil, authTag)
	require.Error(t, err)
}

func TestAESEncryptDecrypt_KnownValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		plaintext string
		key       string
		expected  string
	}{
		{
			name:      "AES-128 known value",
			plaintext: "00112233445566778899aabbccddeeff",
			key:       "000102030405060708090a0b0c0d0e0f",
			expected:  "69c4e0d86a7b0430d8cdb78070b4c55a",
		},
		{
			name:      "AES-192 known value",
			plaintext: "00112233445566778899aabbccddeeff",
			key:       "000102030405060708090a0b0c0d0e0f1011121314151617",
			expected:  "dda97ca4864cdfe06eaf70a0ec0d7191",
		},
		{
			name:      "AES-256 known value",
			plaintext: "00112233445566778899aabbccddeeff",
			key:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			expected:  "8ea2b7ca516745bfeafc49904b496089",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(tt.plaintext)
			key, _ := hex.DecodeString(tt.key)
			expected, _ := hex.DecodeString(tt.expected)

			ciphertext, err := AESEncrypt(plaintext, key)
			require.NoError(t, err)
			require.Equal(t, expected, ciphertext)

			// Decrypt back
			recovered, err := AESDecrypt(ciphertext, key)
			require.NoError(t, err)
			require.Equal(t, plaintext, recovered)
		})
	}
}

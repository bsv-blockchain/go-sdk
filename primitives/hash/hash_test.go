package primitives

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testData  = "I am a test"
	testData2 = "this is the data I want to hash"
)

func TestHashFunctions(t *testing.T) {
	t.Parallel()

	hashTests := []struct {
		testName string
		input    string
		expected string
		hashFunc func([]byte) []byte
	}{
		{
			"Test Ripemd160 Empty String",
			"",
			"9c1185a5c5e9fc54612808977ee8f548b2258d31",
			Ripemd160,
		},
		{
			"Test Ripemd160 String",
			testData,
			"09a23f506b4a37cabab8a9e49b541de582fca96b",
			Ripemd160,
		},
		{
			"Test Sha256d Empty String",
			"",
			"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
			Sha256d,
		},
		{
			"Test Sha256 d String",
			testData2,
			"2209ddda5914a3fbad507ff2284c4b6e559c18a669f9fc3ad3b5826a2a999d58",
			Sha256d,
		},
		{
			"Test Sha256 Empty String",
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Sha256,
		},
		{
			"Test Sha256 String",
			testData2,
			"f88eec7ecabf88f9a64c4100cac1e0c0c4581100492137d1b656ea626cad63e3",
			Sha256,
		},
		{
			"Test Hash160 Empty String",
			"",
			"b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
			Hash160,
		},
		{
			"Test Hash160 String",
			testData2,
			"e7fb13ef86fef4203f042fbfc2703fa628301e90",
			Hash160,
		},
		{
			"Test Sha512 Empty String",
			"",
			"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			Sha512,
		},
		{
			"Test Sha512 String",
			testData2,
			"fe917669df24482f19e9fdd305a846ab5778708d75e05bef0eb9b349c22c21c0168892058b26fe9ae0e3488f6b05b5cc6b356f4dd6093cdf9329ed800de3a165",
			Sha512,
		},
	}

	for _, hashTest := range hashTests {
		t.Run(hashTest.testName, func(t *testing.T) {
			// Decode input string to byte
			expectedBytes, err := hex.DecodeString(hashTest.expected)
			require.NoError(t, err)

			// Test the expected bytes
			hashResult := hashTest.hashFunc([]byte(hashTest.input))
			require.True(t, bytes.Equal(hashResult, expectedBytes))
		})
	}
}

func TestSha256HMAC(t *testing.T) {
	tests := []struct {
		name     string
		keyHex   string
		msgHex   string
		expected string
		hashFunc func([]byte, []byte) []byte
	}{
		{
			"nist 1",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
			"Sample message for keylen=blocklen",
			"8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62",
			Sha256HMAC,
		},
		{
			"nist 2",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"Sample message for keylen<blocklen",
			"a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790",
			Sha256HMAC,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tc.keyHex)
			msg := []byte(tc.msgHex) // Assuming msg is ASCII as in JS tests.
			expected, _ := hex.DecodeString(tc.expected)

			result := Sha256HMAC(msg, key)
			assert.Equal(t, expected, result)
		})
	}
}

func TestSha512HMAC(t *testing.T) {
	tests := []struct {
		name     string
		keyHex   string
		msgHex   string
		expected string
	}{
		{
			"Test case 1",
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		},
		{
			"Test case 2",
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tc.keyHex)
			msg, _ := hex.DecodeString(tc.msgHex)
			expected, _ := hex.DecodeString(tc.expected)

			result := Sha512HMAC(msg, key)
			assert.Equal(t, expected, result)
		})
	}
}

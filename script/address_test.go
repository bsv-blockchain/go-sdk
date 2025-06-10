package script_test

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/v2/script"
	"github.com/stretchr/testify/require"
)

const testPublicKeyHash = "00ac6144c4db7b5790f343cf0477a65fb8a02eb7"

func TestNewAddressFromString(t *testing.T) {
	t.Parallel()

	t.Run("mainnet", func(t *testing.T) {
		addressMain := "1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr"

		addr, err := script.NewAddressFromString(addressMain)
		require.NoError(t, err)
		require.NotNil(t, addr)

		require.Equal(t, "8fe80c75c9560e8b56ed64ea3c26e18d2c52211b", addr.PublicKeyHash.String(), addressMain)
		require.Equal(t, addressMain, addr.AddressString)
	})

	t.Run("testnet", func(t *testing.T) {
		addressTestnet := "mtdruWYVEV1wz5yL7GvpBj4MgifCB7yhPd"

		addr, err := script.NewAddressFromString(addressTestnet)
		require.NoError(t, err)
		require.NotNil(t, addr)

		require.Equal(t, "8fe80c75c9560e8b56ed64ea3c26e18d2c52211b", addr.PublicKeyHash.String(), addressTestnet)
		require.Equal(t, addressTestnet, addr.AddressString)
	})

	t.Run("short address", func(t *testing.T) {
		shortAddress := "ADD8E55"
		addr, err := script.NewAddressFromString(shortAddress)
		require.Error(t, err)
		require.Nil(t, addr)
		require.EqualError(t, err, "invalid address length for '"+shortAddress+"'")
	})

	t.Run("unsupported address", func(t *testing.T) {
		unsupportedAddress := "27BvY7rFguYQvEL872Y7Fo77Y3EBApC2EK"
		addr, err := script.NewAddressFromString(unsupportedAddress)
		require.Error(t, err)
		require.Nil(t, addr)
		require.EqualError(t, err, "address not supported "+unsupportedAddress)
	})

}

func TestNewAddressFromPublicKeyString(t *testing.T) {
	t.Parallel()

	t.Run("mainnet", func(t *testing.T) {
		addr, err := script.NewAddressFromPublicKeyString(
			"026cf33373a9f3f6c676b75b543180703df225f7f8edbffedc417718a8ad4e89ce",
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, addr)

		require.Equal(t, testPublicKeyHash, addr.PublicKeyHash.String())
		require.Equal(t, "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS", addr.AddressString)
	})

	t.Run("testnet", func(t *testing.T) {
		addr, err := script.NewAddressFromPublicKeyString(
			"026cf33373a9f3f6c676b75b543180703df225f7f8edbffedc417718a8ad4e89ce",
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, addr)

		require.Equal(t, testPublicKeyHash, addr.PublicKeyHash.String())
		require.Equal(t, "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk", addr.AddressString)
	})
}

func TestNewAddressFromPublicKey(t *testing.T) {
	t.Parallel()

	pubKeyBytes, err := hex.DecodeString("026cf33373a9f3f6c676b75b543180703df225f7f8edbffedc417718a8ad4e89ce")
	require.NoError(t, err)

	var pubKey *ec.PublicKey
	pubKey, err = ec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	var addr *script.Address
	addr, err = script.NewAddressFromPublicKey(pubKey, true)
	require.NoError(t, err)
	require.NotNil(t, addr)

	require.Equal(t, testPublicKeyHash, addr.PublicKeyHash.String())
	require.Equal(t, "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS", addr.AddressString)
}

func TestBase58EncodeMissingChecksum(t *testing.T) {
	t.Parallel()

	input, err := hex.DecodeString("0488b21e000000000000000000362f7a9030543db8751401c387d6a71e870f1895b3a62569d455e8ee5f5f5e5f03036624c6df96984db6b4e625b6707c017eb0e0d137cd13a0c989bfa77a4473fd")
	require.NoError(t, err)

	require.Equal(t,
		"xpub661MyMwAqRbcF5ivRisXcZTEoy7d9DfLF6fLqpu5GWMfeUyGHuWJHVp5uexDqXTWoySh8pNx3ELW7qymwPNg3UEYHjwh1tpdm3P9J2j4g32",
		script.Base58EncodeMissingChecksum(input),
	)
}

func TestNewAddressFromPublicKeyHash(t *testing.T) {
	t.Parallel()

	t.Run("mainnet", func(t *testing.T) {
		hash, err := hex.DecodeString(testPublicKeyHash)
		require.NoError(t, err)

		addr, err := script.NewAddressFromPublicKeyHash(hash, true)
		require.NoError(t, err)
		require.NotNil(t, addr)

		require.Equal(t, testPublicKeyHash, addr.PublicKeyHash.String())
		require.Equal(t, "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS", addr.AddressString)
	})

	t.Run("testnet", func(t *testing.T) {
		hash, err := hex.DecodeString(testPublicKeyHash)
		require.NoError(t, err)

		addr, err := script.NewAddressFromPublicKeyHash(hash, false)
		require.NoError(t, err)
		require.NotNil(t, addr)

		require.Equal(t, testPublicKeyHash, addr.PublicKeyHash.String())
		require.Equal(t, "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk", addr.AddressString)
	})
}

func TestNewAddressFromPublicKeyStringInvalid(t *testing.T) {
	t.Parallel()

	addr, err := script.NewAddressFromPublicKeyString("invalid_pubkey", true)
	require.Error(t, err)
	require.Nil(t, addr)
}

func TestNewAddressFromPublicKeyInvalid(t *testing.T) {
	t.Parallel()

	invalidPubKeyBytes := []byte{0x00, 0x01, 0x02} // Invalid public key
	invalidPubKey, err := ec.ParsePubKey(invalidPubKeyBytes)
	require.Error(t, err)
	require.Nil(t, invalidPubKey)
}

func TestBase58EncodeMissingChecksumEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		result := script.Base58EncodeMissingChecksum([]byte{})
		require.NotEmpty(t, result)
	})

	t.Run("single byte input", func(t *testing.T) {
		result := script.Base58EncodeMissingChecksum([]byte{0x00})
		require.NotEmpty(t, result)
	})

	t.Run("large input", func(t *testing.T) {
		largeInput := make([]byte, 1000)
		for i := range largeInput {
			largeInput[i] = byte(i % 256)
		}
		result := script.Base58EncodeMissingChecksum(largeInput)
		require.NotEmpty(t, result)
	})
}

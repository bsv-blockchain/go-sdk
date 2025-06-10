package script_test

import (
	"testing"

	script "github.com/bsv-blockchain/go-sdk/v2/script"
	"github.com/stretchr/testify/require"
)

func TestValidateAddress(t *testing.T) {
	t.Parallel()

	t.Run("mainnet P2PKH", func(t *testing.T) {
		ok, err := script.ValidateAddress("114ZWApV4EEU8frr7zygqQcB1V2BodGZuS")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("testnet P2PKH", func(t *testing.T) {
		ok, err := script.ValidateAddress("mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("BIP276", func(t *testing.T) {
		ok, err := script.ValidateAddress("bitcoin-script:0101522102e5b3f2970648b5592b7303367ab7d7d49e6e27dd80c7b5da18a22dac67a51a322103da6bf6a0c1a06ae7c4091542e0eaa29f2678e7957b78ba09cbe5a36241a4ad0452aeb245ccc7")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("empty address", func(t *testing.T) {
		ok, err := script.ValidateAddress("")
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("empty script", func(t *testing.T) {
		ok, err := script.ValidateAddress("bitcoin-script:")
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("invalid address", func(t *testing.T) {
		ok, err := script.ValidateAddress("invalid")
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("invalid script", func(t *testing.T) {
		ok, err := script.ValidateAddress("bitcoin-script:invalid")
		require.Error(t, err)
		require.False(t, ok)
	})
}

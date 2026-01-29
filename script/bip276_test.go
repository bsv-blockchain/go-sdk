package script_test

import (
	"fmt"
	"testing"

	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/require"
)

func TestEncodeBIP276(t *testing.T) {
	t.Parallel()

	t.Run("valid encode (mainnet)", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  script.PrefixScript,
				Version: script.CurrentVersion,
				Network: script.NetworkMainnet,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "bitcoin-script:010166616b65207363726970746f0cd86a", s)
	})

	t.Run("valid encode (testnet)", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  script.PrefixScript,
				Version: script.CurrentVersion,
				Network: script.NetworkTestnet,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "bitcoin-script:020166616b65207363726970742577a444", s)
	})

	t.Run("invalid version = 0", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  script.PrefixScript,
				Version: 0,
				Network: script.NetworkMainnet,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "ERROR", s)
	})

	t.Run("invalid version > 255", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  script.PrefixScript,
				Version: 256,
				Network: script.NetworkMainnet,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "ERROR", s)
	})

	t.Run("invalid network = 0", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  script.PrefixScript,
				Version: script.CurrentVersion,
				Network: 0,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "ERROR", s)
	})

	t.Run("different prefix", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  "different-prefix",
				Version: script.CurrentVersion,
				Network: script.NetworkMainnet,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "different-prefix:010166616b6520736372697074effdb090", s)
	})

	t.Run("template prefix", func(t *testing.T) {
		s := script.EncodeBIP276(
			script.BIP276{
				Prefix:  script.PrefixTemplate,
				Version: script.CurrentVersion,
				Network: script.NetworkMainnet,
				Data:    []byte("fake script"),
			},
		)

		require.Equal(t, "bitcoin-template:010166616b65207363726970749e31aa72", s)
	})
}

func TestDecodeBIP276(t *testing.T) {
	t.Parallel()

	t.Run("valid decode", func(t *testing.T) {
		script, err := script.DecodeBIP276("bitcoin-script:010166616b65207363726970746f0cd86a")
		require.NoError(t, err)
		require.Equal(t, `"bitcoin-script"`, fmt.Sprintf("%q", script.Prefix))
		require.Equal(t, 1, script.Network)
		require.Equal(t, 1, script.Version)
		require.Equal(t, "fake script", string(script.Data))
	})

	t.Run("invalid decode", func(t *testing.T) {
		script, err := script.DecodeBIP276("bitcoin-script:01")
		require.Error(t, err)
		require.Nil(t, script)
	})

	t.Run("valid format, bad checksum", func(t *testing.T) {
		script, err := script.DecodeBIP276("bitcoin-script:010166616b65207363726970746f0cd8")
		require.Error(t, err)
		require.Nil(t, script)
	})

	t.Run("decode with hex digits A-F in network/version", func(t *testing.T) {
		// Bug #286: Regex uses \d{2} which only matches 0-9, not hex A-F
		// This tests network=255 (0xFF) and version=170 (0xAA)
		original := script.BIP276{
			Prefix:  script.PrefixScript,
			Version: 170, // 0xAA
			Network: 255, // 0xFF
			Data:    []byte("test"),
		}
		encoded := script.EncodeBIP276(original)
		require.NotEqual(t, "ERROR", encoded, "encoding should succeed")

		decoded, err := script.DecodeBIP276(encoded)
		require.NoError(t, err, "decoding should succeed for hex values with A-F")
		require.NotNil(t, decoded)
		require.Equal(t, original.Network, decoded.Network)
		require.Equal(t, original.Version, decoded.Version)
		require.Equal(t, original.Data, decoded.Data)
	})

	t.Run("decode network and version field order", func(t *testing.T) {
		// Bug #286: Network and Version fields are swapped during decode
		// Encode format is: prefix:network(2hex)version(2hex)data...checksum
		original := script.BIP276{
			Prefix:  script.PrefixScript,
			Version: 1,
			Network: 2, // testnet
			Data:    []byte("hello"),
		}
		encoded := script.EncodeBIP276(original)
		require.NotEqual(t, "ERROR", encoded)

		decoded, err := script.DecodeBIP276(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		// These should match - if swapped, Network will be 1 and Version will be 2
		require.Equal(t, original.Network, decoded.Network, "Network should be 2")
		require.Equal(t, original.Version, decoded.Version, "Version should be 1")
	})

	t.Run("decode with empty data", func(t *testing.T) {
		// Bug #286: Regex uses + for data which requires at least one char
		// BIP276 should allow empty data
		original := script.BIP276{
			Prefix:  script.PrefixScript,
			Version: 1,
			Network: 1,
			Data:    []byte{}, // empty data
		}
		encoded := script.EncodeBIP276(original)
		require.NotEqual(t, "ERROR", encoded)

		decoded, err := script.DecodeBIP276(encoded)
		require.NoError(t, err, "decoding should succeed for empty data")
		require.NotNil(t, decoded)
		require.Equal(t, []byte{}, decoded.Data)
	})

	t.Run("roundtrip encode-decode preserves all fields", func(t *testing.T) {
		// Comprehensive test for encode/decode roundtrip
		testCases := []script.BIP276{
			{Prefix: script.PrefixScript, Version: 1, Network: 1, Data: []byte("test")},
			{Prefix: script.PrefixScript, Version: 1, Network: 2, Data: []byte("test")},
			{Prefix: script.PrefixTemplate, Version: 255, Network: 255, Data: []byte{0x00, 0xff}},
			{Prefix: "custom", Version: 100, Network: 200, Data: []byte("data")},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("v%d_n%d", tc.Version, tc.Network), func(t *testing.T) {
				encoded := script.EncodeBIP276(tc)
				require.NotEqual(t, "ERROR", encoded)

				decoded, err := script.DecodeBIP276(encoded)
				require.NoError(t, err)
				require.Equal(t, tc.Prefix, decoded.Prefix)
				require.Equal(t, tc.Version, decoded.Version)
				require.Equal(t, tc.Network, decoded.Network)
				require.Equal(t, tc.Data, decoded.Data)
			})
		}
	})
}

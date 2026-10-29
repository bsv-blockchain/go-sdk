package serializer

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestListOutputsArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.ListOutputsArgs
	}{
		{
			name: "full args",
			args: &wallet.ListOutputsArgs{
				Basket:                    "test-basket",
				Tags:                      []string{"tag1", "tag2"},
				TagQueryMode:              wallet.QueryModeAny,
				Include:                   wallet.OutputIncludeEntireTransactions,
				IncludeCustomInstructions: util.BoolPtr(true),
				IncludeTags:               util.BoolPtr(true),
				IncludeLabels:             util.BoolPtr(false),
				Limit:                     util.Uint32Ptr(100),
				Offset:                    util.Uint32Ptr(10),
				SeekPermission:            util.BoolPtr(true),
			},
		},
		{
			name: "minimal args",
			args: &wallet.ListOutputsArgs{
				Basket: "minimal-basket",
				Limit:  util.Uint32Ptr(10),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListOutputsArgs(tt.args, false)
			require.NoError(t, err)

			// Test deserialization
			got, gotSpendable, err := DeserializeListOutputsArgs(data)
			require.NoError(t, err)
			require.False(t, gotSpendable)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestListOutputsResult(t *testing.T) {
	script1, err := script.NewFromHex("76a9143cf53c49c322d9d811728182939aee2dca087f9888ac")
	require.NoError(t, err)
	script2, err := script.NewFromHex("76a9143cf53c49c322d9d811728182939aee2dca087f9888ad")
	require.NoError(t, err)
	t.Run("with BEEF and outputs", func(t *testing.T) {
		result := &wallet.ListOutputsResult{
			TotalOutputs: 2,
			BEEF:         []byte{1, 2, 3, 4},
			Outputs: []wallet.Output{
				{
					Satoshis:           1000,
					LockingScript:      script1.Bytes(),
					Spendable:          true,
					CustomInstructions: "instructions",
					Tags:               []string{"tag1"},
					Outpoint:           *tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0"),
					Labels:             []string{"label1"},
				},
				{
					Satoshis:      2000,
					LockingScript: script2.Bytes(),
					Spendable:     true,
					Outpoint:      *tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.1"),
				},
			},
		}

		data, err := SerializeListOutputsResult(result, false)
		require.NoError(t, err)

		got, err := DeserializeListOutputsResult(data, false)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("minimal result", func(t *testing.T) {
		result := &wallet.ListOutputsResult{
			TotalOutputs: 0,
			Outputs:      []wallet.Output{},
		}

		data, err := SerializeListOutputsResult(result, false)
		require.NoError(t, err)

		got, err := DeserializeListOutputsResult(data, false)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}

// legacyListOutputsResultWireHex is the frame-stripped legacy listOutputs result
// wire from the cross-SDK shared vector
// (wallet/substrates/testdata/listOutputs-simple-result.json, authored by the
// TS SDK) with its leading 0x00 result-frame error byte removed.
const legacyListOutputsResultWireHex = "0204010203041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00fde803ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffabcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789002fd8813ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// spendableListOutputsResultWireHex is the SAME shared vector re-encoded in the
// negotiated "spendable" layout: a leading -1 varint marker (9x 0xFF) before
// totalOutputs, and an explicit 0x01 spendable byte inserted after each output's
// lockingScript field. These bytes are derived mechanically from the
// TS-authored legacy bytes above by applying ts-stack WalletWireProcessor's
// exact spendable-mode insertions, so both SDKs are checked against one byte
// string.
const spendableListOutputsResultWireHex = "ffffffffffffffffff0204010203041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00fde803ffffffffffffffffff01ffffffffffffffffffffffffffffffffffffffffffffffffffffffabcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789002fd8813ffffffffffffffffff01ffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// TestListOutputsResultSpendableWire pins the negotiated spendable wire format
// against the shared cross-SDK vector and round-trips it.
func TestListOutputsResultSpendableWire(t *testing.T) {
	// Reconstruct the shared-vector result object from its TS-authored legacy
	// bytes, so this test tracks the same object the shared vector encodes.
	legacy, err := hex.DecodeString(legacyListOutputsResultWireHex)
	require.NoError(t, err)
	result, err := DeserializeListOutputsResult(legacy, false)
	require.NoError(t, err)

	// Serializing the same object in spendable mode must produce exactly the
	// spendable-layout bytes (leading -1 marker + per-output spendable byte).
	got, err := SerializeListOutputsResult(result, true)
	require.NoError(t, err)
	require.Equal(t, spendableListOutputsResultWireHex, hex.EncodeToString(got))

	// And it must round-trip back to the identical object.
	back, err := DeserializeListOutputsResult(got, true)
	require.NoError(t, err)
	require.Equal(t, result, back)
}

// TestListOutputsResultSpendableRoundTrip exercises mixed spendable values,
// which the legacy layout cannot represent.
func TestListOutputsResultSpendableRoundTrip(t *testing.T) {
	script1, err := script.NewFromHex("76a9143cf53c49c322d9d811728182939aee2dca087f9888ac")
	require.NoError(t, err)
	result := &wallet.ListOutputsResult{
		TotalOutputs: 2,
		BEEF:         []byte{1, 2, 3, 4},
		Outputs: []wallet.Output{
			{
				Satoshis:           1000,
				LockingScript:      script1.Bytes(),
				Spendable:          true,
				CustomInstructions: "instructions",
				Tags:               []string{"tag1"},
				Outpoint:           *tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0"),
				Labels:             []string{"label1"},
			},
			{
				Satoshis:  2000,
				Spendable: false, // non-spendable: only representable in spendable mode
				Outpoint:  *tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.1"),
			},
		},
	}

	data, err := SerializeListOutputsResult(result, true)
	require.NoError(t, err)
	// Leading -1 marker (9x 0xFF) distinguishes the extended layout.
	require.Equal(t, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, data[:9])

	got, err := DeserializeListOutputsResult(data, true)
	require.NoError(t, err)
	require.Equal(t, result, got)
	require.True(t, got.Outputs[0].Spendable)
	require.False(t, got.Outputs[1].Spendable)
}

// TestListOutputsResultLegacyRefusesNonSpendable mirrors ts-stack: the legacy
// layout must refuse records that are not spendable rather than silently
// encoding them as spendable.
func TestListOutputsResultLegacyRefusesNonSpendable(t *testing.T) {
	result := &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{
				Satoshis:  1000,
				Spendable: false,
				Outpoint:  *tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0"),
			},
		},
	}
	_, err := SerializeListOutputsResult(result, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Non-spendable listOutputs records require the spendable encoding extension or JSON")
}

// TestListOutputsArgsSpendableExtension covers the optional trailing opt-in
// byte: it is emitted only when negotiating, is read back as the spendable
// flag, and a non-0x01 trailing byte is rejected.
func TestListOutputsArgsSpendableExtension(t *testing.T) {
	args := &wallet.ListOutputsArgs{Basket: "default"}

	legacy, err := SerializeListOutputsArgs(args, false)
	require.NoError(t, err)
	ext, err := SerializeListOutputsArgs(args, true)
	require.NoError(t, err)
	// The spendable request is exactly the legacy request plus one 0x01 byte.
	require.Equal(t, append(append([]byte{}, legacy...), 0x01), ext)

	gotArgs, spendable, err := DeserializeListOutputsArgs(ext)
	require.NoError(t, err)
	require.True(t, spendable)
	require.Equal(t, args, gotArgs)

	gotArgs2, spendable2, err := DeserializeListOutputsArgs(legacy)
	require.NoError(t, err)
	require.False(t, spendable2)
	require.Equal(t, args, gotArgs2)

	// A trailing byte other than 0x01 is rejected (mirrors ts-stack
	// "Invalid listOutputs encoding extension: expected 1").
	bad := append(append([]byte{}, legacy...), 0x02)
	_, _, err = DeserializeListOutputsArgs(bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid listOutputs encoding extension")
}

package serializer

import (
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
			data, err := SerializeListOutputsArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeListOutputsArgs(data)
			require.NoError(t, err)

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

		data, err := SerializeListOutputsResult(result)
		require.NoError(t, err)

		got, err := DeserializeListOutputsResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("minimal result", func(t *testing.T) {
		result := &wallet.ListOutputsResult{
			TotalOutputs: 0,
			Outputs:      []wallet.Output{},
		}

		data, err := SerializeListOutputsResult(result)
		require.NoError(t, err)

		got, err := DeserializeListOutputsResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}

// TestListOutputsResultSpendableRoundTrip exercises mixed spendable values,
// which the legacy layout cannot represent. The legacy wire is pinned against
// the ts-generated SDK 3.2.1 vector in the substrates package (see
// TestListOutputsLegacyWireCompatibility), and the negotiated layout is exercised
// end to end through the processor and transceiver by
// TestListOutputsSpendableNegotiation.
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

	data, err := SerializeListOutputsResultWithEncoding(result, true)
	require.NoError(t, err)
	// Leading -1 marker (9x 0xFF) distinguishes the extended layout.
	require.Equal(t, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, data[:9])

	got, err := DeserializeListOutputsResultWithEncoding(data, true)
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
	_, err := SerializeListOutputsResult(result)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-spendable listOutputs records require the spendable encoding extension or JSON")
}

// TestListOutputsResultSpendableMarkerRejected covers the error branch in
// readListOutputsSpendableMarker: a spendable-mode reader must reject a result
// whose leading varint is not the -1 acknowledgement.
func TestListOutputsResultSpendableMarkerRejected(t *testing.T) {
	w := util.NewWriter()
	w.WriteVarInt(5) // not the -1 acknowledgement marker
	w.WriteVarInt(0) // totalOutputs, never reached

	_, err := DeserializeListOutputsResultWithEncoding(w.Buf, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing listOutputs spendable encoding acknowledgement")
}

// TestListOutputsResultSpendableFlagRejected covers the error branch in
// readOutputSpendableFlag: a per-output spendable byte other than 0 or 1 is
// rejected.
func TestListOutputsResultSpendableFlagRejected(t *testing.T) {
	op := tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0")

	w := util.NewWriter()
	w.WriteNegativeOne()             // spendable acknowledgement marker (-1)
	w.WriteVarInt(1)                 // totalOutputs = 1
	w.WriteNegativeOne()             // BEEF absent
	w.WriteBytes(encodeOutpoint(op)) // outpoint
	w.WriteVarInt(1000)              // satoshis
	w.WriteNegativeOne()             // locking script absent
	w.WriteByteValue(2)              // invalid spendable flag (expected 0 or 1)
	w.WriteOptionalString("")        // customInstructions
	w.WriteStringSlice(nil)          // tags
	w.WriteStringSlice(nil)          // labels

	_, err := DeserializeListOutputsResultWithEncoding(w.Buf, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid listOutputs spendable flag: expected 0 or 1, received 2")
}

// TestListOutputsArgsSpendableExtension covers the optional trailing opt-in
// byte: it is emitted only when negotiating, is read back as the spendable
// flag by the encoding-aware deserializer, a non-0x01 trailing byte is
// rejected, and the legacy deserializer rejects any trailing byte.
func TestListOutputsArgsSpendableExtension(t *testing.T) {
	args := &wallet.ListOutputsArgs{Basket: "default"}

	legacy, err := SerializeListOutputsArgs(args)
	require.NoError(t, err)
	ext, err := SerializeListOutputsArgsWithEncoding(args, true)
	require.NoError(t, err)
	// The spendable request is exactly the legacy request plus one 0x01 byte.
	require.Equal(t, append(append([]byte{}, legacy...), 0x01), ext)

	gotArgs, spendable, err := DeserializeListOutputsArgsWithEncoding(ext)
	require.NoError(t, err)
	require.True(t, spendable)
	require.Equal(t, args, gotArgs)

	gotArgs2, spendable2, err := DeserializeListOutputsArgsWithEncoding(legacy)
	require.NoError(t, err)
	require.False(t, spendable2)
	require.Equal(t, args, gotArgs2)

	// A trailing byte other than 0x01 is rejected (mirrors ts-stack
	// "Invalid listOutputs encoding extension: expected 1").
	bad := append(append([]byte{}, legacy...), 0x02)
	_, _, err = DeserializeListOutputsArgsWithEncoding(bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid listOutputs encoding extension")

	// The legacy deserializer is source-compatible with older releases: it
	// rejects any trailing byte, including the opt-in extension.
	_, err = DeserializeListOutputsArgs(ext)
	require.Error(t, err)
}

package script_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	script "github.com/bsv-blockchain/go-sdk/script"
)

// TestNewFromHexInvalid covers the error branch of NewFromHex.
func TestNewFromHexInvalid(t *testing.T) {
	t.Parallel()

	_, err := script.NewFromHex("zz")
	require.Error(t, err)
}

// TestNewFromASMInvalid covers the error branch of NewFromASM where a section is
// neither a known opcode nor valid push data.
func TestNewFromASMInvalid(t *testing.T) {
	t.Parallel()

	_, err := script.NewFromASM("zzz")
	require.ErrorIs(t, err, script.ErrInvalidOpCode)
}

// TestAppendPushDataHexInvalid covers the error branch of AppendPushDataHex.
func TestAppendPushDataHexInvalid(t *testing.T) {
	t.Parallel()

	s := &script.Script{}
	require.Error(t, s.AppendPushDataHex("zz"))
}

// TestUnmarshalJSONInvalid covers the error branch of UnmarshalJSON.
func TestUnmarshalJSONInvalid(t *testing.T) {
	t.Parallel()

	var s script.Script
	require.Error(t, json.Unmarshal([]byte(`"zz"`), &s))
}

// TestPublicKeyHashErrors covers the error branches of PublicKeyHash.
func TestPublicKeyHashErrors(t *testing.T) {
	t.Parallel()

	t.Run("nil script", func(t *testing.T) {
		t.Parallel()
		var s *script.Script
		_, err := s.PublicKeyHash()
		require.ErrorIs(t, err, script.ErrEmptyScript)
	})

	t.Run("empty script", func(t *testing.T) {
		t.Parallel()
		s := &script.Script{}
		_, err := s.PublicKeyHash()
		require.ErrorIs(t, err, script.ErrEmptyScript)
	})

	t.Run("not P2PKH", func(t *testing.T) {
		t.Parallel()
		s, err := script.NewFromHex("51")
		require.NoError(t, err)
		_, err = s.PublicKeyHash()
		require.ErrorIs(t, err, script.ErrNotP2PKH)
	})
}

// TestAddressNotP2PKH covers the not-P2PKH error branch of Address.
func TestAddressNotP2PKH(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromHex("51")
	require.NoError(t, err)
	_, err = s.Address()
	require.Error(t, err)
}

// TestPubKeyNotP2PK covers the not-P2PK error branches of PubKey and PubKeyHex.
func TestPubKeyNotP2PK(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromHex("51")
	require.NoError(t, err)

	_, err = s.PubKey()
	require.Error(t, err)

	_, err = s.PubKeyHex()
	require.Error(t, err)
}

// TestAddressesNonP2PKH covers the branch of Addresses where the script is not a
// P2PKH script and an empty slice is returned.
func TestAddressesNonP2PKH(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromHex("51")
	require.NoError(t, err)

	addrs, err := s.Addresses()
	require.NoError(t, err)
	require.Empty(t, addrs)
}

// TestMinPushSizeLargeData covers the PUSHDATA2 and PUSHDATA4 size branches of
// MinPushSize as well as the single-byte encodings.
func TestMinPushSizeLargeData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
		want int
	}{
		{name: "empty", size: 0, want: 1},
		{name: "single data byte", size: 1, want: 2},
		{name: "op_data boundary", size: 75, want: 76},
		{name: "pushdata1", size: 200, want: 202},
		{name: "pushdata2", size: 300, want: 303},
		{name: "pushdata4", size: 70000, want: 70005},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := make([]byte, tc.size)
			for i := range data {
				data[i] = 0xab // ensure non-small-int content for size 1
			}
			require.Equal(t, tc.want, script.MinPushSize(data))
		})
	}
}

// TestMinPushSizeSmallInt covers the single-byte small-int / OP_NEGATE branch.
func TestMinPushSizeSmallInt(t *testing.T) {
	t.Parallel()

	require.Equal(t, 1, script.MinPushSize([]byte{0x10})) // 16 -> OP_16
	require.Equal(t, 1, script.MinPushSize([]byte{0x81})) // OP_1NEGATE
}

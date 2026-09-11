package serializer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// txidStatusFixture returns a deterministic 32-byte txid filled with b.
func txidStatusFixture(b byte) chainhash.Hash {
	var h chainhash.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func TestWriteReadTxidSliceWithStatusRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		results []wallet.SendWithResult
		want    []wallet.SendWithResult // nil when the slice is empty (both encode as count 0)
	}{
		"nil slice":   {results: nil, want: nil},
		"empty slice": {results: []wallet.SendWithResult{}, want: nil},
		"single unproven": {
			results: []wallet.SendWithResult{{Txid: txidStatusFixture(0x01), Status: wallet.ActionResultStatusUnproven}},
			want:    []wallet.SendWithResult{{Txid: txidStatusFixture(0x01), Status: wallet.ActionResultStatusUnproven}},
		},
		"all statuses": {
			results: []wallet.SendWithResult{
				{Txid: txidStatusFixture(0x01), Status: wallet.ActionResultStatusUnproven},
				{Txid: txidStatusFixture(0x02), Status: wallet.ActionResultStatusSending},
				{Txid: txidStatusFixture(0x03), Status: wallet.ActionResultStatusFailed},
			},
			want: []wallet.SendWithResult{
				{Txid: txidStatusFixture(0x01), Status: wallet.ActionResultStatusUnproven},
				{Txid: txidStatusFixture(0x02), Status: wallet.ActionResultStatusSending},
				{Txid: txidStatusFixture(0x03), Status: wallet.ActionResultStatusFailed},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			w := util.NewWriter()
			require.NoError(t, writeTxidSliceWithStatus(w, tc.results))

			r := util.NewReader(w.Buf)
			got, err := readTxidSliceWithStatus(r)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestWriteTxidSliceWithStatusInvalidStatus(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	err := writeTxidSliceWithStatus(w, []wallet.SendWithResult{
		{Txid: txidStatusFixture(0x01), Status: wallet.ActionResultStatus("bogus")},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid status")
}

func TestReadTxidSliceWithStatusInvalidStatusCode(t *testing.T) {
	t.Parallel()

	// count=1, valid 32-byte txid, then an out-of-range status byte.
	w := util.NewWriter()
	w.WriteVarInt(1)
	h := txidStatusFixture(0x01)
	w.WriteBytes(h[:])
	w.WriteByteValue(0x09)

	r := util.NewReader(w.Buf)
	_, err := readTxidSliceWithStatus(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid status code")
}

func TestReadTxidSliceWithStatusTruncated(t *testing.T) {
	t.Parallel()

	t.Run("truncated count", func(t *testing.T) {
		r := util.NewReader(nil)
		_, err := readTxidSliceWithStatus(r)
		require.Error(t, err)
	})

	t.Run("truncated txid", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(1)
		w.WriteBytes([]byte{0x01, 0x02}) // fewer than the 32 txid bytes claimed
		r := util.NewReader(w.Buf)
		_, err := readTxidSliceWithStatus(r)
		require.Error(t, err)
	})

	t.Run("missing status byte", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(1)
		h := txidStatusFixture(0x01)
		w.WriteBytes(h[:]) // txid present but no trailing status byte
		r := util.NewReader(w.Buf)
		_, err := readTxidSliceWithStatus(r)
		require.Error(t, err)
	})
}

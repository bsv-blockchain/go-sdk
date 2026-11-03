package serializer

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// The BRC-100 wire carries 32-bit counts and indexes as varints. A frame whose varint
// does not fit in 32 bits must be refused with an error, never narrowed to a small
// value that would then be read as a valid (and different) message.

const beyondUint32 = uint64(math.MaxUint32) + 1 // reads as 0 if narrowed

func TestWireResultsRefuseTotalsAboveUint32(t *testing.T) {
	t.Run("ListCertificatesResult", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(beyondUint32)
		res, err := DeserializeListCertificatesResult(w.Buf)
		require.Error(t, err)
		require.Nil(t, res)
	})

	t.Run("DiscoverCertificatesResult", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(beyondUint32)
		res, err := DeserializeDiscoverCertificatesResult(w.Buf)
		require.Error(t, err)
		require.Nil(t, res)
	})

	t.Run("ListActionsResult", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(beyondUint32)
		res, err := DeserializeListActionsResult(w.Buf)
		require.Error(t, err)
		require.Nil(t, res)
	})

	t.Run("ListOutputsResult", func(t *testing.T) {
		// A well-formed frame for a total of 0 whose total is then replaced by 2^32:
		// narrowed, it would read as the valid empty result it was copied from.
		valid, err := SerializeListOutputsResult(&wallet.ListOutputsResult{})
		require.NoError(t, err)
		require.Equal(t, byte(0), valid[0], "a zero total is a single 0x00 byte")
		w := util.NewWriter()
		w.WriteVarInt(beyondUint32)
		w.WriteBytes(valid[1:])
		res, err := DeserializeListOutputsResult(w.Buf)
		require.Error(t, err)
		require.Nil(t, res)
	})
}

func TestWireOutpointIndexAboveUint32IsRefused(t *testing.T) {
	txid := make([]byte, 32)

	t.Run("decodeOutpoint", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteBytes(txid)
		w.WriteVarInt(beyondUint32)
		op, err := decodeOutpoint(util.NewReader(w.Buf))
		require.Error(t, err)
		require.Nil(t, op)
	})

	t.Run("decodeOutpoints", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(1)
		w.WriteBytes(txid)
		w.WriteVarInt(beyondUint32 + 1) // would read as index 1
		ops, err := decodeOutpoints(w.Buf)
		require.Error(t, err)
		require.Nil(t, ops)
	})

	t.Run("the largest uint32 index still decodes", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteBytes(txid)
		w.WriteVarInt(math.MaxUint32)
		op, err := decodeOutpoint(util.NewReader(w.Buf))
		require.NoError(t, err)
		require.Equal(t, uint32(math.MaxUint32), op.Index)
	})
}

package serializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestEncodeCounterpartyErrors(t *testing.T) {
	t.Parallel()

	t.Run("nil pubkey for type other", func(t *testing.T) {
		w := util.NewWriter()
		err := encodeCounterparty(w, xtBadCounterparty())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty is nil for type other")
	})

	t.Run("unknown counterparty type", func(t *testing.T) {
		w := util.NewWriter()
		err := encodeCounterparty(w, wallet.Counterparty{Type: wallet.CounterpartyType(99)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown counterparty type")
	})
}

func TestEncodeKeyRelatedParamsError(t *testing.T) {
	t.Parallel()

	_, err := encodeKeyRelatedParams(KeyRelatedParams{
		ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "p"},
		Counterparty: xtBadCounterparty(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counterparty is nil for type other")
}

func TestDecodeCounterpartyInvalidPubKey(t *testing.T) {
	t.Parallel()

	// Flag byte 0x01 is not one of the special codes (0/11/12), so it is parsed
	// as the first byte of a compressed public key; 0x01 is an invalid magic.
	data := append([]byte{0x01}, make([]byte, 32)...)
	r := util.NewReaderHoldError(data)
	_, err := decodeCounterparty(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid counterparty bytes")
}

func TestDecodeProtocolTruncated(t *testing.T) {
	t.Parallel()

	r := util.NewReaderHoldError(nil)
	_, err := decodeProtocol(r)
	require.Error(t, err)
}

func TestDecodeKeyRelatedParamsErrors(t *testing.T) {
	t.Parallel()

	validProtocol := encodeProtocol(wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "p"})

	t.Run("protocol read error", func(t *testing.T) {
		r := util.NewReaderHoldError(nil)
		_, err := decodeKeyRelatedParams(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding protocol")
	})

	t.Run("counterparty read error", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteBytes(validProtocol)
		w.WriteString("k")
		w.WriteByteValue(0x01) // invalid pubkey magic for type-other counterparty
		w.WriteBytes(make([]byte, 32))
		r := util.NewReaderHoldError(w.Buf)
		_, err := decodeKeyRelatedParams(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding counterparty")
	})

	t.Run("privileged params read error", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteBytes(validProtocol)
		w.WriteString("k")
		w.WriteByteValue(counterPartyTypeSelfCode) // valid counterparty, then buffer ends
		r := util.NewReaderHoldError(w.Buf)
		_, err := decodeKeyRelatedParams(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding key params")
	})
}

func TestDecodeOutpointsCases(t *testing.T) {
	t.Parallel()

	t.Run("empty data returns nil", func(t *testing.T) {
		got, err := decodeOutpoints(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("negative-one count returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(util.NegativeOne)
		got, err := decodeOutpoints(w.Buf)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("truncated count", func(t *testing.T) {
		_, err := decodeOutpoints([]byte{0xFF})
		require.Error(t, err)
	})

	t.Run("truncated txid", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(1)
		w.WriteBytes([]byte{0x01, 0x02}) // fewer than 32 bytes
		_, err := decodeOutpoints(w.Buf)
		require.Error(t, err)
	})

	t.Run("truncated output index", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(1)
		w.WriteBytes(make([]byte, 32)) // valid txid length
		w.WriteByteValue(0xFF)         // varint prefix demanding more bytes
		_, err := decodeOutpoints(w.Buf)
		require.Error(t, err)
	})
}

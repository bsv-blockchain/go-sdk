package transaction

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
)

func writeBEEFVersion(t *testing.T, buffer *bytes.Buffer, version uint32) {
	t.Helper()
	require.NoError(t, binary.Write(buffer, binary.LittleEndian, version))
}

func minimalBEEFTransaction() []byte {
	// Version, zero inputs, zero outputs, and locktime.
	return []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func minimalBEEFTransactionID(t *testing.T) *chainhash.Hash {
	t.Helper()
	tx := &Transaction{}
	_, err := tx.ReadFrom(bytes.NewReader(minimalBEEFTransaction()))
	require.NoError(t, err)
	return tx.TxID()
}

func writeSingleLeafBUMP(buffer *bytes.Buffer, blockHeight uint64, txid *chainhash.Hash) {
	buffer.Write(util.VarInt(blockHeight).Bytes())
	buffer.WriteByte(1) // tree height
	buffer.Write(util.VarInt(1).Bytes())
	buffer.Write(util.VarInt(0).Bytes())
	buffer.WriteByte(2) // txid leaf, with a hash
	buffer.Write(txid.CloneBytes())
}

func identityBEEFSeeds(t testing.TB) ([]byte, []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/beef-compatibility/identity.json")
	require.NoError(t, err)
	var fixture struct {
		BeefBase64   string `json:"beefBase64"`
		AtomicBase64 string `json:"atomicBEEFBase64"`
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	beef, err := base64.StdEncoding.DecodeString(fixture.BeefBase64)
	require.NoError(t, err)
	atomic, err := base64.StdEncoding.DecodeString(fixture.AtomicBase64)
	require.NoError(t, err)
	return beef, atomic
}

func TestNewBeefFromBytesRejectsMalformedDecoderInputs(t *testing.T) {
	tests := []struct {
		name string
		data func(t *testing.T) []byte
	}{
		{
			name: "truncated V2 txid-only entry",
			data: func(t *testing.T) []byte {
				var buffer bytes.Buffer
				writeBEEFVersion(t, &buffer, BEEF_V2)
				buffer.Write(util.VarInt(0).Bytes()) // BUMPs
				buffer.Write(util.VarInt(1).Bytes()) // transactions
				buffer.WriteByte(byte(TxIDOnly))
				buffer.Write(bytes.Repeat([]byte{0x11}, chainhash.HashSize-1))
				return buffer.Bytes()
			},
		},
		{
			name: "V2 transaction count exceeds remaining bytes",
			data: func(t *testing.T) []byte {
				var buffer bytes.Buffer
				writeBEEFVersion(t, &buffer, BEEF_V2)
				buffer.Write(util.VarInt(0).Bytes())
				buffer.Write(util.VarInt(math.MaxUint64).Bytes())
				return buffer.Bytes()
			},
		},
		{
			name: "V2 BUMP index is out of range",
			data: func(t *testing.T) []byte {
				var buffer bytes.Buffer
				writeBEEFVersion(t, &buffer, BEEF_V2)
				buffer.Write(util.VarInt(0).Bytes()) // BUMPs
				buffer.Write(util.VarInt(1).Bytes()) // transactions
				buffer.WriteByte(byte(RawTxAndBumpIndex))
				buffer.Write(util.VarInt(0).Bytes())
				buffer.Write(minimalBEEFTransaction())
				return buffer.Bytes()
			},
		},
		{
			name: "V1 BUMP index is out of range",
			data: func(t *testing.T) []byte {
				var buffer bytes.Buffer
				writeBEEFVersion(t, &buffer, BEEF_V1)
				buffer.Write(util.VarInt(0).Bytes()) // BUMPs
				buffer.Write(util.VarInt(1).Bytes()) // transactions
				buffer.Write(minimalBEEFTransaction())
				buffer.WriteByte(1)
				buffer.Write(util.VarInt(0).Bytes())
				return buffer.Bytes()
			},
		},
		{
			name: "V1 hasBump value is not a boolean",
			data: func(t *testing.T) []byte {
				var buffer bytes.Buffer
				writeBEEFVersion(t, &buffer, BEEF_V1)
				buffer.Write(util.VarInt(0).Bytes()) // BUMPs
				buffer.Write(util.VarInt(1).Bytes()) // transactions
				buffer.Write(minimalBEEFTransaction())
				buffer.WriteByte(2)
				return buffer.Bytes()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			assert.NotPanics(t, func() {
				_, err = NewBeefFromBytes(tt.data(t))
			})
			require.Error(t, err)
		})
	}
}

func TestNewBeefFromBytesV1RetainsEncodedBUMPIndex(t *testing.T) {
	txid := minimalBEEFTransactionID(t)
	var buffer bytes.Buffer
	writeBEEFVersion(t, &buffer, BEEF_V1)
	buffer.Write(util.VarInt(2).Bytes())
	writeSingleLeafBUMP(&buffer, 100, txid)
	writeSingleLeafBUMP(&buffer, 101, txid)
	buffer.Write(util.VarInt(1).Bytes())
	buffer.Write(minimalBEEFTransaction())
	buffer.WriteByte(1)
	buffer.Write(util.VarInt(0).Bytes()) // The first BUMP is explicitly selected.

	beef, err := NewBeefFromBytes(buffer.Bytes())
	require.NoError(t, err)

	entry := beef.Transactions[*txid]
	require.NotNil(t, entry)
	assert.Equal(t, RawTxAndBumpIndex, entry.DataFormat)
	assert.Equal(t, 0, entry.BumpIndex)
	require.NotNil(t, entry.Transaction)
	assert.Same(t, beef.BUMPs[0], entry.Transaction.MerklePath)
}

func TestNewBeefFromBytesRejectsV1ZeroDepthBUMP(t *testing.T) {
	var buffer bytes.Buffer
	writeBEEFVersion(t, &buffer, BEEF_V1)
	buffer.Write(util.VarInt(1).Bytes())
	buffer.Write(util.VarInt(0).Bytes())
	buffer.WriteByte(0) // tree height
	buffer.Write(util.VarInt(1).Bytes())
	buffer.Write(minimalBEEFTransaction())
	buffer.WriteByte(1)
	buffer.Write(util.VarInt(0).Bytes())

	var err error
	assert.NotPanics(t, func() {
		_, err = NewBeefFromBytes(buffer.Bytes())
	})
	require.ErrorContains(t, err, "has no path levels")
}

func TestBEEFDecodersRejectTruncatedIdentityFixtures(t *testing.T) {
	beef, atomic := identityBEEFSeeds(t)
	for _, fixture := range []struct {
		name string
		data []byte
	}{
		{name: "BEEF V1", data: beef},
		{name: "Atomic BEEF", data: atomic},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			for length := range fixture.data {
				_, err := NewBeefFromBytes(fixture.data[:length])
				require.Errorf(t, err, "prefix length %d", length)
			}
		})
	}
}

func FuzzNewBeefFromBytesDoesNotPanic(f *testing.F) {
	validV2 := binary.LittleEndian.AppendUint32(nil, BEEF_V2)
	validV2 = append(validV2, 0, 0) // zero BUMPs and zero transactions
	f.Add(validV2)
	f.Add([]byte{})
	f.Add([]byte{0x02, 0x00, 0xbe, 0xef, 0x00, 0x01, byte(TxIDOnly)})
	beef, atomic := identityBEEFSeeds(f)
	f.Add(beef)
	f.Add(atomic)

	f.Fuzz(func(t *testing.T, beef []byte) {
		if len(beef) > 64*1024 {
			return
		}
		var receiver Transaction
		assert.NotPanics(t, func() { _ = receiver.FromBEEF(beef) })
		assert.NotPanics(t, func() {
			_, _ = NewBeefFromBytes(beef)
		})
		assert.NotPanics(t, func() {
			_, _ = NewTransactionFromBEEF(beef)
		})
		assert.NotPanics(t, func() {
			_, _, _, _ = ParseBeef(beef)
		})
		assert.NotPanics(t, func() {
			_, _, _ = NewBeefFromAtomicBytes(beef)
		})
	})
}

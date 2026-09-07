package transaction

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

// nonLenReader is an io.Reader that deliberately does not expose Len(), so
// guardParseCount cannot bound it and must fall through.
type nonLenReader struct{ r *bytes.Reader }

func (n nonLenReader) Read(p []byte) (int, error) { return n.r.Read(p) }

func TestGuardParseCount(t *testing.T) {
	tests := []struct {
		name      string
		remaining int
		count     uint64
		wantErr   bool
	}{
		{name: "count within remaining", remaining: 100, count: 50, wantErr: false},
		{name: "count equals remaining", remaining: 100, count: 100, wantErr: false},
		{name: "count exceeds remaining", remaining: 10, count: 5000, wantErr: true},
		{name: "absurd count on tiny reader", remaining: 4, count: 1 << 62, wantErr: true},
		{name: "zero count", remaining: 0, count: 0, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(make([]byte, tt.remaining))
			err := guardParseCount(r, tt.count, "thing")
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, "exceeds")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestGuardParseCountUnboundedReader verifies that a reader which cannot report
// its remaining length is left unguarded (returns nil).
func TestGuardParseCountUnboundedReader(t *testing.T) {
	r := nonLenReader{r: bytes.NewReader(make([]byte, 4))}
	require.NoError(t, guardParseCount(r, 1<<62, "thing"))
}

// TestNewTransactionFromBEEFBumpIndexGuard is a regression test for the BEEF
// parser: a transaction that references a BUMP index beyond the number of BUMPs
// present must return an error instead of panicking with index-out-of-range.
func TestNewTransactionFromBEEFBumpIndexGuard(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, BEEF_V1))
	buf.Write(util.VarInt(0).Bytes()) // 0 BUMPs
	buf.Write(util.VarInt(1).Bytes()) // 1 transaction
	// Minimal empty transaction: version, 0 inputs, 0 outputs, locktime.
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00})
	buf.Write(util.VarInt(0).Bytes())
	buf.Write(util.VarInt(0).Bytes())
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	buf.WriteByte(0x01)               // hasBump = true
	buf.Write(util.VarInt(5).Bytes()) // references BUMP index 5, but 0 exist

	_, err := NewTransactionFromBEEF(buf.Bytes())
	require.Error(t, err)
	require.ErrorContains(t, err, "BUMP index")
}

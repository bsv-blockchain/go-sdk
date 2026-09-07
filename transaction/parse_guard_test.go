package transaction

import (
	"bytes"
	"encoding/binary"
	"math"
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
		minBytes  int
		wantErr   bool
	}{
		{name: "byte slice within remaining", remaining: 100, count: 50, minBytes: 1, wantErr: false},
		{name: "byte slice equals remaining", remaining: 100, count: 100, minBytes: 1, wantErr: false},
		{name: "byte slice exceeds remaining", remaining: 10, count: 5000, minBytes: 1, wantErr: true},
		{name: "absurd count on tiny reader", remaining: 4, count: 1 << 62, minBytes: 1, wantErr: true},
		{name: "zero count", remaining: 0, count: 0, minBytes: 1, wantErr: false},
		// Per-element minimum tightens the bound for pointer slices: 100 bytes can
		// describe at most 10 ten-byte elements.
		{name: "pointer slice within capacity", remaining: 100, count: 10, minBytes: 10, wantErr: false},
		{name: "pointer slice exceeds capacity", remaining: 100, count: 11, minBytes: 10, wantErr: true},
		{name: "min bytes clamped to one", remaining: 8, count: 8, minBytes: 0, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(make([]byte, tt.remaining))
			err := guardParseCount(r, tt.count, tt.minBytes, "thing")
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
// its remaining length still rejects an implausibly large count (so make cannot
// panic) while allowing a plausible one.
func TestGuardParseCountUnboundedReader(t *testing.T) {
	r := nonLenReader{r: bytes.NewReader(make([]byte, 4))}

	// A count beyond the streamed-reader ceiling is rejected instead of reaching
	// make() and panicking.
	require.ErrorContains(t, guardParseCount(r, 1<<62, 1, "thing"), "exceeds")

	// A modest count is still allowed on an unbounded reader.
	require.NoError(t, guardParseCount(r, 1024, 1, "thing"))
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

// TestNewTransactionFromBEEFHugeTxCount is a regression test for the BEEF parser:
// a transaction count that would overflow an int loop bound must return an error
// instead of silently parsing nothing and reporting success.
func TestNewTransactionFromBEEFHugeTxCount(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, BEEF_V1))
	buf.Write(util.VarInt(0).Bytes())              // 0 BUMPs
	buf.Write(util.VarInt(math.MaxUint64).Bytes()) // absurd transaction count

	_, err := NewTransactionFromBEEF(buf.Bytes())
	require.Error(t, err)
	require.ErrorContains(t, err, "exceeds")
}

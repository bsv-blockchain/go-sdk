package transaction

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// TestReadVarInt locks that the allocation-free readVarInt is byte-for-byte
// semantically identical to util.VarInt.ReadFrom: for the same input bytes it
// must return the same value, the same number of bytes read, and agree on
// whether the read errored. It covers every CompactSize size class, non-minimal
// encodings (which both decoders accept unchanged), and truncated inputs.
func TestReadVarInt(t *testing.T) {
	// Canonical encodings across every size-class boundary.
	values := []uint64{
		0, 1, 252, // 1-byte
		253, 65535, // 3-byte (0xfd)
		65536, 4294967295, // 5-byte (0xfe)
		4294967296, math.MaxUint64, // 9-byte (0xff)
	}
	inputs := make([][]byte, 0, len(values)+8) // canonical + 4 non-minimal + 4 truncated
	for _, v := range values {
		inputs = append(inputs, util.VarInt(v).Bytes())
	}
	// Non-minimal encodings: a value written with a wider prefix than needed.
	// Neither decoder enforces minimality, so both must accept these identically.
	inputs = append(inputs,
		[]byte{0xfd, 0x01, 0x00},                                     // 1 as 3-byte
		[]byte{0xfe, 0x01, 0x00, 0x00, 0x00},                         // 1 as 5-byte
		[]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 1 as 9-byte
		[]byte{0xfd, 0xfc, 0x00},                                     // 252 as 3-byte
	)
	// Truncated inputs: an empty read and wide prefixes with too few value bytes.
	inputs = append(inputs,
		[]byte{},
		[]byte{0xff, 0x01},
		[]byte{0xfe},
		[]byte{0xfd, 0x00},
	)

	scratch := make([]byte, 32)
	for _, in := range inputs {
		t.Run(fmt.Sprintf("len%d_%x", len(in), in), func(t *testing.T) {
			gotVal, gotN, gotErr := readVarInt(bytes.NewReader(in), scratch)

			var want util.VarInt
			wantN, wantErr := want.ReadFrom(bytes.NewReader(in))

			require.Equal(t, wantN, gotN, "bytes read must match util.VarInt.ReadFrom")
			require.Equal(t, wantErr != nil, gotErr != nil, "error presence must match")
			if wantErr == nil {
				require.Equal(t, uint64(want), gotVal, "decoded value must match")
			}
		})
	}
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

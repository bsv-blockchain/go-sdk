package serializer

import (
	"encoding/hex"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWriterReader(t *testing.T) {
	tests := []struct {
		name     string
		writeFn  func(*writer)
		readFn   func(*reader) (interface{}, error)
		expected interface{}
	}{
		{
			name: "writeByte/readByte",
			writeFn: func(w *writer) {
				w.writeByte(0xAB)
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readByte()
			},
			expected: byte(0xAB),
		},
		{
			name: "writeBytes/readBytes",
			writeFn: func(w *writer) {
				w.writeBytes([]byte{0x01, 0x02, 0x03})
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readBytes(3)
			},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "writeVarInt/readVarInt",
			writeFn: func(w *writer) {
				w.writeVarInt(123456)
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readVarInt()
			},
			expected: uint64(123456),
		},
		{
			name: "writeVarInt/readVarInt zero",
			writeFn: func(w *writer) {
				w.writeVarInt(0)
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readVarInt()
			},
			expected: uint64(0),
		},
		{
			name: "readRemaining",
			writeFn: func(w *writer) {
				w.writeBytes([]byte{0x01, 0x02, 0x03})
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readRemaining(), nil
			},
			expected: []byte{0x01, 0x02, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWriter()
			tt.writeFn(w)

			r := newReader(w.buf)
			got, err := tt.readFn(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			require.Equal(t, tt.expected, got)
		})
	}
}

func TestReaderErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		readFn  func(*reader) (interface{}, error)
		wantErr string
	}{
		{
			name: "readByte past end",
			data: []byte{},
			readFn: func(r *reader) (interface{}, error) {
				return r.readByte()
			},
			wantErr: "read past end of data",
		},
		{
			name: "readBytes past end",
			data: []byte{0x01},
			readFn: func(r *reader) (interface{}, error) {
				return r.readBytes(2)
			},
			wantErr: "read past end of data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReader(tt.data)
			_, err := tt.readFn(r)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("got error %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestKeyRelatedParams(t *testing.T) {
	testPrivKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name   string
		params KeyRelatedParams
	}{
		{
			name: "full params",
			params: KeyRelatedParams{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "test-protocol",
				},
				KeyID: "test-key-id",
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: testPrivKey.PubKey(),
				},
				Privileged:       boolPtr(true),
				PrivilegedReason: "test-reason",
			},
		},
		{
			name: "minimal params",
			params: KeyRelatedParams{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "default",
				},
				KeyID: "",
				Counterparty: wallet.Counterparty{
					Type: wallet.CounterpartyUninitialized,
				},
			},
		},
		{
			name: "self counterparty",
			params: KeyRelatedParams{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "self-protocol",
				},
				Counterparty: wallet.Counterparty{
					Type: wallet.CounterpartyTypeSelf,
				},
			},
		},
		{
			name: "anyone counterparty",
			params: KeyRelatedParams{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "anyone-protocol",
				},
				Counterparty: wallet.Counterparty{
					Type: wallet.CounterpartyTypeAnyone,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := encodeKeyRelatedParams(tt.params)
			require.NoError(t, err)

			// Test deserialization
			got, err := decodeKeyRelatedParams(newReaderHoldError(data))
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.params.ProtocolID, got.ProtocolID)
			require.Equal(t, tt.params.KeyID, got.KeyID)
			require.Equal(t, tt.params.Counterparty.Type, got.Counterparty.Type)

			// Compare counterparty pubkey if present
			if tt.params.Counterparty.Type == wallet.CounterpartyTypeOther {
				require.Equal(t,
					tt.params.Counterparty.Counterparty.ToDER(),
					got.Counterparty.Counterparty.ToDER())
			}

			require.Equal(t, tt.params.Privileged, got.Privileged)
			require.Equal(t, tt.params.PrivilegedReason, got.PrivilegedReason)
		})
	}
}

func TestCounterpartyEncoding(t *testing.T) {
	testPrivKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name         string
		counterparty wallet.Counterparty
	}{
		{
			name: "uninitialized counterparty",
			counterparty: wallet.Counterparty{
				Type: wallet.CounterpartyUninitialized,
			},
		},
		{
			name: "self counterparty",
			counterparty: wallet.Counterparty{
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		{
			name: "anyone counterparty",
			counterparty: wallet.Counterparty{
				Type: wallet.CounterpartyTypeAnyone,
			},
		},
		{
			name: "other counterparty with pubkey",
			counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: testPrivKey.PubKey(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWriter()
			err := encodeCounterparty(w, tt.counterparty)
			require.NoError(t, err)

			r := newReaderHoldError(w.buf)
			got, err := decodeCounterparty(r)
			require.NoError(t, err)

			require.Equal(t, tt.counterparty.Type, got.Type)
			if tt.counterparty.Type == wallet.CounterpartyTypeOther {
				require.Equal(t,
					tt.counterparty.Counterparty.ToDER(),
					got.Counterparty.ToDER())
			}
		})
	}
}

func TestPrivilegedParams(t *testing.T) {
	tests := []struct {
		name             string
		privileged       *bool
		privilegedReason string
	}{
		{
			name:             "privileged true with reason",
			privileged:       boolPtr(true),
			privilegedReason: "test-reason",
		},
		{
			name:             "privileged false with reason",
			privileged:       boolPtr(false),
			privilegedReason: "test-reason",
		},
		{
			name:             "privileged nil with reason",
			privilegedReason: "test-reason",
		},
		{
			name:       "privileged true no reason",
			privileged: boolPtr(true),
		},
		{
			name: "all nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data := encodePrivilegedParams(tt.privileged, tt.privilegedReason)

			// Test deserialization
			gotPrivileged, gotReason := decodePrivilegedParams(newReaderHoldError(data))

			// Compare results
			if tt.privileged == nil {
				require.Nil(t, gotPrivileged)
			} else {
				require.Equal(t, *tt.privileged, *gotPrivileged)
			}
			require.Equal(t, tt.privilegedReason, gotReason)
		})
	}
}

// boolPtr is a helper function to create a pointer to a boolean value
func boolPtr(b bool) *bool {
	return &b
}

// fromHex is a helper function to create a public key from a hex string
func fromHex(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	require.NoError(t, err)
	return data
}

// newCounterparty is a helper function to create a new counterparty
func newCounterparty(t *testing.T, pubKeyHex string) wallet.Counterparty {
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err)
	return wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: pubKey,
	}
}

// newSignature is a helper function to create a new signature from a byte slice
func newSignature(t *testing.T, data []byte) *ec.Signature {
	sig, err := ec.FromDER(data)
	require.NoError(t, err)
	return sig
}

func newTestSignature(t *testing.T) *ec.Signature {
	return newSignature(t, []byte{0x30, 0x25, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69,
		0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61, 0xa1, 0xd3, 0xa1,
		0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6,
		0x24, 0xc6, 0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd,
		0x41, 0x02, 0x01, 0x00,
	})
}

// padOrTrim returns (size) bytes from input (bb)
// Short bb gets zeros prefixed, Long bb gets left/MSB bits trimmed
func padOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}
	if l > size {
		return bb[l-size:]
	}
	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)
	return tmp
}

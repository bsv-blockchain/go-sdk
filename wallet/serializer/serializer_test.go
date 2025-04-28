package serializer

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestKeyRelatedParams(t *testing.T) {
	testPrivKey, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating test private key should not error")

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
				Privileged:       util.BoolPtr(true),
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
			require.NoError(t, err, "encoding key related params should not error")

			// Test deserialization
			r := util.NewReaderHoldError(data)
			got, err := decodeKeyRelatedParams(r)
			require.NoError(t, err, "decoding key related params should not error")
			require.NoError(t, r.Err, "reader should not have an error after decoding")

			// Compare results
			require.Equal(t, tt.params.ProtocolID, got.ProtocolID, "decoded ProtocolID should match")
			require.Equal(t, tt.params.KeyID, got.KeyID, "decoded KeyID should match")
			require.Equal(t, tt.params.Counterparty.Type, got.Counterparty.Type, "decoded Counterparty Type should match")

			// Compare counterparty pubkey if present
			if tt.params.Counterparty.Type == wallet.CounterpartyTypeOther {
				require.NotNil(t, tt.params.Counterparty.Counterparty, "original counterparty pubkey should not be nil")
				require.NotNil(t, got.Counterparty.Counterparty, "decoded counterparty pubkey should not be nil")
				require.Equal(t,
					tt.params.Counterparty.Counterparty.ToDER(),
					got.Counterparty.Counterparty.ToDER(),
					"decoded Counterparty pubkey should match")
			} else {
				require.Nil(t, got.Counterparty.Counterparty, "decoded counterparty pubkey should be nil for non-other types")
			}

			require.Equal(t, tt.params.Privileged, got.Privileged, "decoded Privileged flag should match")
			require.Equal(t, tt.params.PrivilegedReason, got.PrivilegedReason, "decoded PrivilegedReason should match")
		})
	}
}

func TestCounterpartyEncoding(t *testing.T) {
	testPrivKey, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating test private key should not error")

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
			w := util.NewWriter()
			err := encodeCounterparty(w, tt.counterparty)
			require.NoError(t, err, "encoding counterparty should not error")

			r := util.NewReaderHoldError(w.Buf)
			got, err := decodeCounterparty(r)
			require.NoError(t, err, "decoding counterparty should not error")
			require.NoError(t, r.Err, "reader should not have an error after decoding counterparty")

			require.Equal(t, tt.counterparty.Type, got.Type, "decoded counterparty type should match")
			if tt.counterparty.Type == wallet.CounterpartyTypeOther {
				require.NotNil(t, tt.counterparty.Counterparty, "original counterparty pubkey should not be nil for type other")
				require.NotNil(t, got.Counterparty, "decoded counterparty pubkey should not be nil for type other")
				require.Equal(t,
					tt.counterparty.Counterparty.ToDER(),
					got.Counterparty.ToDER(), "decoded counterparty pubkey should match original")
			} else {
				require.Nil(t, got.Counterparty, "decoded counterparty pubkey should be nil for non-other types")
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
			privileged:       util.BoolPtr(true),
			privilegedReason: "test-reason",
		},
		{
			name:             "privileged false with reason",
			privileged:       util.BoolPtr(false),
			privilegedReason: "test-reason",
		},
		{
			name:             "privileged nil with reason",
			privilegedReason: "test-reason",
		},
		{
			name:       "privileged true no reason",
			privileged: util.BoolPtr(true),
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
			r := util.NewReaderHoldError(data)
			gotPrivileged, gotReason := decodePrivilegedParams(r)
			require.NoError(t, r.Err, "reader should not have an error after decoding privileged params")

			// Compare results
			if tt.privileged == nil {
				require.Nil(t, gotPrivileged, "decoded privileged flag should be nil when original is nil")
			} else {
				require.NotNil(t, gotPrivileged, "decoded privileged flag should not be nil when original is not nil")
				require.Equal(t, *tt.privileged, *gotPrivileged, "decoded privileged flag value should match original")
			}
			require.Equal(t, tt.privilegedReason, gotReason, "decoded privileged reason should match original")
		})
	}
}

func TestDecodeOutpoint(t *testing.T) {
	validTxid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validIndex := uint32(42)

	// Create valid outpoint bytes
	txidBytes, err := hex.DecodeString(validTxid)
	require.NoError(t, err, "decoding valid txid hex should not error")
	validData := make([]byte, OutpointSize)
	copy(validData[:32], txidBytes)
	binary.BigEndian.PutUint32(validData[32:36], validIndex)

	tests := []struct {
		name      string
		input     []byte
		want      string
		expectErr bool
	}{
		{
			name:      "valid outpoint",
			input:     validData,
			want:      fmt.Sprintf("%s.%d", validTxid, validIndex),
			expectErr: false,
		},
		{
			name:      "invalid length - too short",
			input:     validData[:OutpointSize-1],
			want:      "",
			expectErr: true,
		},
		{
			name:      "invalid length - too long",
			input:     append(validData, 0x00), // Add an extra byte
			want:      "",
			expectErr: true,
		},
		{
			name:      "nil input",
			input:     nil,
			want:      "",
			expectErr: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			want:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeOutpoint(tt.input)

			if tt.expectErr {
				require.Error(t, err, "expected an error but got none")
				require.Empty(t, got, "expected empty string on error")
			} else {
				require.NoError(t, err, "did not expect an error but got one")
				require.Equal(t, tt.want, got, "decoded outpoint string does not match expected")
			}
		})
	}
}

func TestEncodeOutpoint(t *testing.T) {
	validTxid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validIndex := uint32(42)
	validOutpointStr := fmt.Sprintf("%s.%d", validTxid, validIndex)

	// Expected valid binary output
	expectedBytes := make([]byte, OutpointSize)
	txidBytes, _ := hex.DecodeString(validTxid)
	copy(expectedBytes[:32], txidBytes)
	binary.BigEndian.PutUint32(expectedBytes[32:36], validIndex)

	tests := []struct {
		name           string
		input          string
		expectErr      bool
		expectedOutput []byte
	}{
		{
			name:           "valid outpoint",
			input:          validOutpointStr,
			expectErr:      false,
			expectedOutput: expectedBytes,
		},
		{
			name:           "invalid format - no dot",
			input:          "nodothere",
			expectErr:      true,
			expectedOutput: nil,
		},
		{
			name:           "invalid format - multiple dots",
			input:          "too.many.dots",
			expectErr:      true,
			expectedOutput: nil,
		},
		{
			name:           "invalid txid - non-hex",
			input:          "nothex.123",
			expectErr:      true,
			expectedOutput: nil,
		},
		{
			name:           "invalid txid - wrong length",
			input:          "0123456789abcdef.123", // Too short
			expectErr:      true,
			expectedOutput: nil,
		},
		{
			name:           "invalid index - non-numeric",
			input:          fmt.Sprintf("%s.abc", validTxid),
			expectErr:      true,
			expectedOutput: nil,
		},
		{
			name:           "invalid index - negative",
			input:          fmt.Sprintf("%s.-1", validTxid),
			expectErr:      true,
			expectedOutput: nil,
		},
		{
			name:           "empty input",
			input:          "",
			expectErr:      true,
			expectedOutput: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := encodeOutpoint(tt.input)

			if tt.expectErr {
				require.Error(t, err, "expected an error but got none")
				require.Nil(t, gotBytes, "expected nil bytes on error")
			} else {
				require.NoError(t, err, "did not expect an error but got one: %v", err)
				require.Equal(t, tt.expectedOutput, gotBytes, "encoded bytes do not match expected")

				// Round trip test
				decodedStr, decodeErr := decodeOutpoint(gotBytes)
				require.NoError(t, decodeErr, "decoding the encoded bytes failed")
				require.Equal(t, tt.input, decodedStr, "round trip failed: decoded string does not match original input")
			}
		})
	}
}

// fromHex is a helper function to create a public key from a hex string
func fromHex(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	require.NoError(t, err, "decoding hex string should not error")
	return data
}

// newCounterparty is a helper function to create a new counterparty
func newCounterparty(t *testing.T, pubKeyHex string) wallet.Counterparty {
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err, "creating public key from string should not error")
	return wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: pubKey,
	}
}

// newSignature is a helper function to create a new signature from a byte slice
func newSignature(t *testing.T, data []byte) *ec.Signature {
	sig, err := ec.FromDER(data)
	require.NoError(t, err, "creating signature from DER bytes should not error")
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

package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
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
	validTxIDHash, err := chainhash.NewHashFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err, "creating valid txid hash should not error")
	validIndex := uint32(42)

	// Create valid outpoint bytes
	var validData []byte
	validData = append(validData, util.ReverseBytes(validTxIDHash[:])...)
	validData = append(validData, util.VarInt(validIndex).Bytes()...)

	tests := []struct {
		name      string
		input     []byte
		want      *transaction.Outpoint
		expectErr bool
	}{
		{
			name:      "valid outpoint",
			input:     validData,
			want:      &transaction.Outpoint{Txid: *validTxIDHash, Index: validIndex},
			expectErr: false,
		},
		{
			name:      "invalid length - too short",
			input:     validData[:len(validData)-1],
			expectErr: true,
		},
		{
			name:      "invalid length - too long",
			input:     append(validData, 0x00), // Add an extra byte
			expectErr: true,
		},
		{
			name:      "nil input",
			input:     nil,
			expectErr: true,
		},
		{
			name:      "empty input",
			input:     []byte{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := util.NewReaderHoldError(tt.input)
			got, err := decodeOutpoint(&r.Reader)
			r.CheckComplete()

			if err == nil && r.Err != nil {
				err = r.Err
				got = nil
			}

			if tt.expectErr {
				require.Error(t, err, "expected an error but got none")
				require.Empty(t, got, "expected nil on error")
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

	validTxIDHash, err := chainhash.NewHashFromHex(validTxid)
	require.NoError(t, err, "creating valid txid hash should not error")

	validOutpoint := &transaction.Outpoint{
		Txid:  *validTxIDHash,
		Index: validIndex,
	}

	// Expected valid binary output
	var expectedBytes []byte
	expectedBytes = append(expectedBytes, util.ReverseBytes(validTxIDHash[:])...)
	expectedBytes = append(expectedBytes, util.VarInt(validIndex).Bytes()...)

	tests := []struct {
		name           string
		input          *transaction.Outpoint
		expectedOutput []byte
	}{
		{
			name:           "valid outpoint",
			input:          validOutpoint,
			expectedOutput: expectedBytes,
		},
		{
			name:           "empty outpoint",
			input:          &transaction.Outpoint{},
			expectedOutput: make([]byte, 33),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes := encodeOutpoint(tt.input)

			require.Equal(t, tt.expectedOutput, gotBytes, "encoded bytes do not match expected")

			// Round trip test
			decodedObj, decodeErr := decodeOutpoint(util.NewReader(gotBytes))
			require.NoError(t, decodeErr, "decoding the encoded bytes failed")
			require.Equal(t, tt.input, decodedObj, "round trip failed: decoded string does not match original input")
		})
	}
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

func newTestSignature(t *testing.T) *ec.Signature {
	return tu.GetSigFromHex(t, "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020101")
}

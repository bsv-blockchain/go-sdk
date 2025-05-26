package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAcquireCertificateArgs(t *testing.T) {
	revocationOutpoint, err := wallet.OutpointFromString("0000000000000000000000000000000000000000000000000000000000000000.0")
	require.NoError(t, err)
	tests := []struct {
		name string
		args *wallet.AcquireCertificateArgs
	}{{
		name: "direct acquisition",
		args: &wallet.AcquireCertificateArgs{
			Type:                base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("test-type"), sizeType)),
			Certifier:           [33]byte{1},
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			SerialNumber:       [32]byte{1},
			RevocationOutpoint: *revocationOutpoint,
			Signature:          make([]byte, 64),
			KeyringRevealer:    wallet.KeyringRevealerCertifier,
			KeyringForSubject: map[string]string{
				"field1": base64.StdEncoding.EncodeToString([]byte("keyring1")),
			},
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "issuance acquisition",
		args: &wallet.AcquireCertificateArgs{
			Type:                base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("issuance-type"), sizeType)),
			Certifier:           [33]byte{2},
			AcquisitionProtocol: wallet.AcquisitionProtocolIssuance,
			Fields: map[string]string{
				"field1": "value1",
			},
			CertifierUrl: "https://certifier.example.com",
		},
	}, {
		name: "minimal args",
		args: &wallet.AcquireCertificateArgs{
			Type:                base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("minimal"), sizeType)),
			Certifier:           [33]byte{3},
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			SerialNumber:        [32]byte{3},
			RevocationOutpoint:  *revocationOutpoint,
			Signature:           make([]byte, 64),
			KeyringRevealer:     hex.EncodeToString(make([]byte, sizeRevealer)),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeAcquireCertificateArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeAcquireCertificateArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

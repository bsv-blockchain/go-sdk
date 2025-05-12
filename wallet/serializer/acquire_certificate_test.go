package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAcquireCertificateArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.AcquireCertificateArgs
	}{{
		name: "direct acquisition",
		args: &wallet.AcquireCertificateArgs{
			Type:                base64.StdEncoding.EncodeToString(padOrTrim([]byte("test-type"), SizeType)),
			Certifier:           hex.EncodeToString(make([]byte, SizeCertifier)),
			AcquisitionProtocol: "direct",
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			SerialNumber:       base64.StdEncoding.EncodeToString(make([]byte, SizeSerial)),
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
			Signature:          hex.EncodeToString(make([]byte, 64)),
			KeyringRevealer:    "certifier",
			KeyringForSubject: map[string]string{
				"field1": base64.StdEncoding.EncodeToString([]byte("keyring1")),
			},
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "issuance acquisition",
		args: &wallet.AcquireCertificateArgs{
			Type:                base64.StdEncoding.EncodeToString(padOrTrim([]byte("issuance-type"), SizeType)),
			Certifier:           hex.EncodeToString(make([]byte, SizeCertifier)),
			AcquisitionProtocol: "issuance",
			Fields: map[string]string{
				"field1": "value1",
			},
			CertifierUrl: "https://certifier.example.com",
		},
	}, {
		name: "minimal args",
		args: &wallet.AcquireCertificateArgs{
			Type:                base64.StdEncoding.EncodeToString(padOrTrim([]byte("minimal"), SizeType)),
			Certifier:           hex.EncodeToString(make([]byte, SizeCertifier)),
			AcquisitionProtocol: "direct",
			SerialNumber:        base64.StdEncoding.EncodeToString(make([]byte, SizeSerial)),
			RevocationOutpoint:  "0000000000000000000000000000000000000000000000000000000000000000.0",
			Signature:           hex.EncodeToString(make([]byte, 64)),
			KeyringRevealer:     hex.EncodeToString(make([]byte, SizeRevealer)),
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

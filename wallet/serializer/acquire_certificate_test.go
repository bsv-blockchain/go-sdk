package serializer

import (
	"encoding/base64"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestAcquireCertificateArgs(t *testing.T) {
	revocationOutpoint := tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0")
	sig := tu.GetSigFromHex(t, "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a")
	tests := []struct {
		name string
		args *wallet.AcquireCertificateArgs
	}{{
		name: "direct acquisition",
		args: &wallet.AcquireCertificateArgs{
			Type:                tu.GetByte32FromString("test-type"),
			Certifier:           tu.GetPKFromBytes([]byte{1}),
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			SerialNumber:       &wallet.SerialNumber{1},
			RevocationOutpoint: revocationOutpoint,
			Signature:          sig,
			KeyringRevealer:    &wallet.KeyringRevealer{Certifier: true},
			KeyringForSubject: map[string]string{
				"field1": base64.StdEncoding.EncodeToString([]byte("keyring1")),
			},
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "issuance acquisition",
		args: &wallet.AcquireCertificateArgs{
			Type:                tu.GetByte32FromString("issuance-type"),
			Certifier:           tu.GetPKFromBytes([]byte{2}),
			AcquisitionProtocol: wallet.AcquisitionProtocolIssuance,
			Fields: map[string]string{
				"field1": "value1",
			},
			CertifierUrl: "https://certifier.example.com",
		},
	}, {
		name: "minimal args",
		args: &wallet.AcquireCertificateArgs{
			Type:                tu.GetByte32FromString("minimal"),
			Certifier:           tu.GetPKFromBytes([]byte{3}),
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			SerialNumber:        &wallet.SerialNumber{3},
			RevocationOutpoint:  revocationOutpoint,
			KeyringRevealer:     &wallet.KeyringRevealer{Certifier: true},
		},
	}, {
		name: "long privileged reason > 255 bytes",
		args: &wallet.AcquireCertificateArgs{
			Type:                tu.GetByte32FromString("minimal"),
			Certifier:           tu.GetPKFromBytes([]byte{3}),
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			SerialNumber:        &wallet.SerialNumber{3},
			RevocationOutpoint:  revocationOutpoint,
			KeyringRevealer:     &wallet.KeyringRevealer{Certifier: true},
			Privileged:          util.BoolPtr(true),
			PrivilegedReason:    "a very long reason that exceeds the 255 byte limit for privileged reasons in acquire certificate args, this is just a test to ensure that we can handle long strings properly without any issues or errors, it should be truncated or handled gracefully in the serialization process",
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

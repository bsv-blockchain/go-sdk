package serializer

import (
	"encoding/base64"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestIdentityCertificate(t *testing.T) {
	sig := tu.GetSigFromHex(t, "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a")
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating private key should not error")
	cert := &wallet.IdentityCertificate{
		Certificate: wallet.Certificate{
			Type:               tu.GetByte32FromString("test-type"),
			Subject:            pk.PubKey(),
			SerialNumber:       tu.GetByte32FromString("test-serial"),
			Certifier:          pk.PubKey(),
			RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
			Signature:          sig,
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
		},
		CertifierInfo: wallet.IdentityCertifier{
			Name:        "Test Certifier",
			IconUrl:     "https://example.com/icon.png",
			Description: "Test description",
			Trust:       5,
		},
		PubliclyRevealedKeyring: map[string]string{
			"key1": base64.StdEncoding.EncodeToString([]byte("value1")),
			"key2": base64.StdEncoding.EncodeToString([]byte("value2")),
		},
		DecryptedFields: map[string]string{
			"field1": "decrypted1",
			"field2": "decrypted2",
		},
	}

	// Test serialization
	data, err := SerializeIdentityCertificate(cert)
	require.NoError(t, err, "serializing IdentityCertificate should not error")

	// Test deserialization
	reader := util.NewReaderHoldError(data)
	got, err := DeserializeIdentityCertificate(reader)
	require.NoError(t, err, "deserializing IdentityCertificate should not error")
	require.NoError(t, reader.Err, "deserializing IdentityCertificate should not reader error")

	// Compare results
	require.Equal(t, cert, got, "deserialized certificate should match original certificate")
}

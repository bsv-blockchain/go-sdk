package serializer

import (
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestIdentityCertificate(t *testing.T) {
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating private key should not error")
	cert := &wallet.IdentityCertificate{
		Certificate: wallet.Certificate{
			Type:               tu.GetByte32FromString("test-type"),
			Subject:            pk.PubKey(),
			SerialNumber:       tu.GetByte32FromString("test-serial"),
			Certifier:          pk.PubKey(),
			RevocationOutpoint: tu.WalletOutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
			Signature:          make([]byte, 64),
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
			"key1": "value1",
			"key2": "value2",
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
	got, err := DeserializeIdentityCertificate(data)
	require.NoError(t, err, "deserializing IdentityCertificate should not error")

	// Compare results
	require.Equal(t, cert, got, "deserialized certificate should match original certificate")
}

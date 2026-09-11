package serializer

import (
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// xtPub returns a fresh, valid secp256k1 public key for use in tests.
func xtPub(t *testing.T) *ec.PublicKey {
	t.Helper()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating private key should not error")
	return pk.PubKey()
}

// xtBadCounterparty returns a Counterparty of type Other whose public key is nil,
// which makes encodeCounterparty (and every encodeKeyRelatedParams caller) fail.
func xtBadCounterparty() wallet.Counterparty {
	return wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: nil}
}

// xtValidCertificate builds a fully populated, serializable wallet.Certificate.
func xtValidCertificate(t *testing.T) wallet.Certificate {
	t.Helper()
	pub := xtPub(t)
	c := wallet.Certificate{
		Subject:            pub,
		Certifier:          pub,
		RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
		Signature:          newTestSignature(t),
		Fields:             map[string]string{"field1": "value1"},
	}
	copy(c.Type[:], []byte("test-cert"))
	copy(c.SerialNumber[:], []byte("serial-1"))
	return c
}

// xtValidIdentityCertificate builds a fully populated wallet.IdentityCertificate.
func xtValidIdentityCertificate(t *testing.T) wallet.IdentityCertificate {
	t.Helper()
	return wallet.IdentityCertificate{
		Certificate: xtValidCertificate(t),
		CertifierInfo: wallet.IdentityCertifier{
			Name:        "Test Certifier",
			IconUrl:     "https://example.com/icon.png",
			Description: "desc",
			Trust:       5,
		},
		PubliclyRevealedKeyring: map[string]string{"key1": "dmFsdWUx"},
		DecryptedFields:         map[string]string{"field1": "decrypted1"},
	}
}

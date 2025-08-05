package utils

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestGetVerifiableCertificates(t *testing.T) {
	ctx := context.Background()
	// Create a single verifier key to be used by all tests
	pubKeyBytes := []byte{
		0x02, // Compressed key prefix (even y)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	verifierKey, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, verifierKey)

	certType1 := tu.GetByte32FromString("certType1")
	certType2 := tu.GetByte32FromString("certType2")
	serial1 := tu.GetByte32FromString("serial1")
	const TestSigHex = "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a"
	testSig := tu.GetSigFromHex(t, TestSigHex)

	// Test case 1: Retrieves matching certificates based on requested set
	t.Run("retrieves matching certificates based on requested set", func(t *testing.T) {
		// Create a fresh mock for each test to avoid unexpected state
		mockWallet := wallet.NewTestWalletForRandomKey(t)

		// Create base64-encoded field values as required by the standard
		field1ValueBase64 := base64.StdEncoding.EncodeToString([]byte("encryptedData1"))
		field2ValueBase64 := base64.StdEncoding.EncodeToString([]byte("encryptedData2"))
		keyring1Base64 := base64.StdEncoding.EncodeToString([]byte("key1"))
		keyring2Base64 := base64.StdEncoding.EncodeToString([]byte("key2"))

		requestedCerts := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1"), tu.GetPKFromString("certifier2")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				certType1: {"field1", "field2"},
				certType2: {"field3"},
			},
		}

		// Create a mock subject and certifier public key
		subject, _ := ec.PublicKeyFromBytes([]byte{0x04, 0x05, 0x06})
		certifier, _ := ec.PublicKeyFromBytes([]byte{0x07, 0x08, 0x09})

		// Mock wallet.ListCertificates response with base64-encoded values
		revocationOutpoint, _ := transaction.OutpointFromString("abcd1234:0")
		mockListResult := &wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{
				{
					Certificate: wallet.Certificate{
						Type:               certType1,
						SerialNumber:       serial1,
						Subject:            subject,
						Certifier:          certifier,
						RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
						Fields:             map[string]string{"field1": field1ValueBase64, "field2": field2ValueBase64}, // Use base64-encoded field values
						Signature:          testSig,
					},
				},
			},
		}
		mockWallet.OnListCertificates().ReturnSuccess(mockListResult)

		// Mock wallet.ProveCertificate response with base64-encoded keyring values
		mockProveResult := &wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"field1": keyring1Base64, "field2": keyring2Base64}, // Use base64-encoded keyring values
		}

		mockWallet.OnProveCertificate().ReturnSuccess(mockProveResult)

		options := GetVerifiableCertificatesOptions{
			Wallet:                mockWallet,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		}

		certs, err := GetVerifiableCertificates(ctx, &options)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		if len(certs) > 0 {
			cert := certs[0]
			// Compare against base64 encoded values
			expectedTypeBase64 := wallet.StringBase64FromArray(certType1)
			expectedSerialBase64 := wallet.StringBase64FromArray(serial1)
			require.Equal(t, expectedTypeBase64, cert.Type)
			require.Equal(t, expectedSerialBase64, cert.SerialNumber)
			require.NotNil(t, cert.RevocationOutpoint)
			if cert.RevocationOutpoint != nil && revocationOutpoint != nil {
				require.Equal(t, revocationOutpoint.Index, cert.RevocationOutpoint.Index)
			}
		}
	})

	// Test case 2: Returns an empty array when no matching certificates are found
	t.Run("returns an empty array when no matching certificates are found", func(t *testing.T) {
		// Create a fresh mock for each test to avoid unexpected state
		mockWallet := wallet.NewTestWalletForRandomKey(t)

		requestedCerts := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				certType1: {"field1"},
			},
		}

		options := GetVerifiableCertificatesOptions{
			Wallet:                mockWallet,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		}

		certs, err := GetVerifiableCertificates(ctx, &options)
		require.NoError(t, err)
		require.Empty(t, certs)
	})

	// Test case 3: Propagates errors from ListCertificates
	t.Run("propagates errors from ListCertificates", func(t *testing.T) {
		// Create a fresh mock for each test to avoid unexpected state
		mockWallet := wallet.NewTestWalletForRandomKey(t)

		requestedCerts := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				certType1: {"field1"},
			},
		}

		// Mock ListCertificates to return an error
		mockWallet.OnListCertificates().ReturnError(errors.New("listCertificates failed"))

		options := GetVerifiableCertificatesOptions{
			Wallet:                mockWallet,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		}

		certs, err := GetVerifiableCertificates(ctx, &options)
		require.Error(t, err)
		require.Nil(t, certs)
		require.Contains(t, err.Error(), "listCertificates failed")
	})

	// Test case 4: Handles nil requested certificates gracefully
	t.Run("handles nil requested certificates gracefully", func(t *testing.T) {
		// Create a fresh mock for each test to avoid unexpected state
		mockWallet := wallet.NewTestWalletForRandomKey(t)
		options := GetVerifiableCertificatesOptions{
			Wallet:                mockWallet,
			RequestedCertificates: nil,
			VerifierIdentityKey:   verifierKey,
		}

		certs, err := GetVerifiableCertificates(ctx, &options)
		require.NoError(t, err)
		require.Empty(t, certs)
	})
}

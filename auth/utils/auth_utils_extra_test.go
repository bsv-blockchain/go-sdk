package utils_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	tcu "github.com/bsv-blockchain/go-sdk/util/test_cert_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRandomBase64 covers the RandomBase64 function in base64.go
func TestRandomBase64(t *testing.T) {
	t.Run("returns a non-empty base64 string", func(t *testing.T) {
		result := utils.RandomBase64(32)
		require.NotEmpty(t, result)

		// Verify it is valid base64
		decoded, err := base64.StdEncoding.DecodeString(string(result))
		require.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("returns different values on successive calls", func(t *testing.T) {
		a := utils.RandomBase64(32)
		b := utils.RandomBase64(32)
		assert.NotEqual(t, a, b)
	})

	t.Run("length parameter controls decoded byte length", func(t *testing.T) {
		for _, length := range []int{1, 16, 64, 128} {
			result := utils.RandomBase64(length)
			decoded, err := base64.StdEncoding.DecodeString(string(result))
			require.NoError(t, err)
			assert.Len(t, decoded, length)
		}
	})

	t.Run("zero length returns empty base64 string", func(t *testing.T) {
		result := utils.RandomBase64(0)
		decoded, err := base64.StdEncoding.DecodeString(string(result))
		require.NoError(t, err)
		assert.Empty(t, decoded)
	})
}

// TestValidateCertificateEncoding covers ValidateCertificateEncoding in certificate_debug.go
func TestValidateCertificateEncoding(t *testing.T) {
	t.Run("returns error for empty type", func(t *testing.T) {
		cert := wallet.Certificate{
			// Type is zero-value [32]byte
			// SerialNumber is zero-value [32]byte
		}
		errs := utils.ValidateCertificateEncoding(cert)
		assert.True(t, len(errs) >= 2, "expected at least 2 errors for empty type and serial")
	})

	t.Run("returns error for empty serial number", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")
		cert := wallet.Certificate{
			Type: certType,
			// SerialNumber is zero-value
		}
		errs := utils.ValidateCertificateEncoding(cert)
		assert.True(t, len(errs) >= 1, "expected error for empty serial number")
		found := false
		for _, e := range errs {
			if contains(e, "SerialNumber") {
				found = true
			}
		}
		assert.True(t, found, "expected SerialNumber error")
	})

	t.Run("returns error for invalid base64 field value", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")
		var serial [32]byte
		copy(serial[:], "some_serial")
		cert := wallet.Certificate{
			Type:         certType,
			SerialNumber: serial,
			Fields:       map[string]string{"field1": "not-valid-base64!!!"},
		}
		errs := utils.ValidateCertificateEncoding(cert)
		assert.True(t, len(errs) >= 1, "expected error for invalid base64 field")
		found := false
		for _, e := range errs {
			if contains(e, "field1") {
				found = true
			}
		}
		assert.True(t, found, "expected error mentioning field1")
	})

	t.Run("returns no errors for valid certificate", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")
		var serial [32]byte
		copy(serial[:], "some_serial")
		cert := wallet.Certificate{
			Type:         certType,
			SerialNumber: serial,
			Fields:       map[string]string{"field1": base64.StdEncoding.EncodeToString([]byte("value"))},
		}
		errs := utils.ValidateCertificateEncoding(cert)
		assert.Empty(t, errs)
	})

	t.Run("nil fields does not panic", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")
		var serial [32]byte
		copy(serial[:], "some_serial")
		cert := wallet.Certificate{
			Type:         certType,
			SerialNumber: serial,
			Fields:       nil,
		}
		errs := utils.ValidateCertificateEncoding(cert)
		assert.Empty(t, errs)
	})
}

// TestGetEncodedCertificateForDebug covers GetEncodedCertificateForDebug in certificate_debug.go
func TestGetEncodedCertificateForDebug(t *testing.T) {
	t.Run("encodes plain text field values to base64", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")
		cert := wallet.Certificate{
			Type:   certType,
			Fields: map[string]string{"name": "plain text value"},
		}
		result := utils.GetEncodedCertificateForDebug(cert)
		require.NotNil(t, result.Fields)

		decoded, err := base64.StdEncoding.DecodeString(result.Fields["name"])
		require.NoError(t, err)
		assert.Equal(t, "plain text value", string(decoded))
	})

	t.Run("leaves already-base64-encoded fields unchanged", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")
		encoded := base64.StdEncoding.EncodeToString([]byte("already encoded"))
		cert := wallet.Certificate{
			Type:   certType,
			Fields: map[string]string{"field": encoded},
		}
		result := utils.GetEncodedCertificateForDebug(cert)
		assert.Equal(t, encoded, result.Fields["field"])
	})

	t.Run("nil fields returns certificate with nil fields", func(t *testing.T) {
		cert := wallet.Certificate{Fields: nil}
		result := utils.GetEncodedCertificateForDebug(cert)
		assert.Nil(t, result.Fields)
	})
}

// TestSignCertificateForTest covers SignCertificateForTest in certificate_debug.go
func TestSignCertificateForTest(t *testing.T) {
	ctx := context.Background()

	subject, err := ec.NewPrivateKey()
	require.NoError(t, err)
	subjectKey := subject.PubKey()

	certifier, err := ec.NewPrivateKey()
	require.NoError(t, err)

	var certType [32]byte
	copy(certType[:], tcu.CertificateTypeName.String())
	var serial [32]byte
	copy(serial[:], "test_serial_number_123")

	revocationOutpoint, err := transaction.OutpointFromString("a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0")
	require.NoError(t, err)

	cert := wallet.Certificate{
		Type:               certType,
		SerialNumber:       serial,
		Subject:            subjectKey,
		RevocationOutpoint: revocationOutpoint,
		Fields:             map[string]string{"field1": base64.StdEncoding.EncodeToString([]byte("test value"))},
	}

	t.Run("signs a certificate successfully", func(t *testing.T) {
		signed, err := utils.SignCertificateForTest(ctx, cert, certifier)
		require.NoError(t, err)
		assert.NotNil(t, signed.Signature)
		assert.NotEmpty(t, signed.Signature)
	})

	t.Run("signed certificate has certifier set to signer's public key", func(t *testing.T) {
		signed, err := utils.SignCertificateForTest(ctx, cert, certifier)
		require.NoError(t, err)
		certifierKey := certifier.PubKey()
		require.NotNil(t, signed.Certifier)
		assert.True(t, signed.Certifier.IsEqual(certifierKey))
	})
}

// TestSignCertificateWithWalletForTest covers SignCertificateWithWalletForTest
func TestSignCertificateWithWalletForTest(t *testing.T) {
	ctx := context.Background()

	subject, err := ec.NewPrivateKey()
	require.NoError(t, err)
	subjectKey := subject.PubKey()

	certifier, err := ec.NewPrivateKey()
	require.NoError(t, err)

	signerWallet, err := wallet.NewCompletedProtoWallet(certifier)
	require.NoError(t, err)

	var certType [32]byte
	copy(certType[:], tcu.CertificateTypeName.String())
	var serial [32]byte
	copy(serial[:], "test_serial_wallet_456")

	revocationOutpoint2, err := transaction.OutpointFromString("a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0")
	require.NoError(t, err)

	cert := wallet.Certificate{
		Type:               certType,
		SerialNumber:       serial,
		Subject:            subjectKey,
		RevocationOutpoint: revocationOutpoint2,
		Fields:             map[string]string{"field1": base64.StdEncoding.EncodeToString([]byte("test value"))},
	}

	t.Run("signs a certificate using wallet interface", func(t *testing.T) {
		signed, err := utils.SignCertificateWithWalletForTest(ctx, cert, signerWallet)
		require.NoError(t, err)
		assert.NotNil(t, signed.Signature)
		assert.NotEmpty(t, signed.Signature)
	})

	t.Run("preserves original certificate fields after signing", func(t *testing.T) {
		signed, err := utils.SignCertificateWithWalletForTest(ctx, cert, signerWallet)
		require.NoError(t, err)
		assert.EqualValues(t, certType, signed.Type)
		assert.EqualValues(t, serial, signed.SerialNumber)
	})
}

// TestRequestedCertificateTypeIDAndFieldListJSON covers MarshalJSON and UnmarshalJSON
func TestRequestedCertificateTypeIDAndFieldListJSON(t *testing.T) {
	t.Run("marshal and unmarshal round-trip", func(t *testing.T) {
		var type1 [32]byte
		copy(type1[:], "type_one")
		var type2 [32]byte
		copy(type2[:], "type_two")

		original := utils.RequestedCertificateTypeIDAndFieldList{
			type1: []string{"fieldA", "fieldB"},
			type2: []string{"fieldC"},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored utils.RequestedCertificateTypeIDAndFieldList
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, original[type1], restored[type1])
		assert.Equal(t, original[type2], restored[type2])
	})

	t.Run("marshal produces valid JSON with base64 keys", func(t *testing.T) {
		var certType [32]byte
		copy(certType[:], "some_type")

		m := utils.RequestedCertificateTypeIDAndFieldList{
			certType: []string{"field1"},
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		// Parse as generic map to verify keys are base64
		var raw map[string][]string
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		assert.Len(t, raw, 1)

		for k := range raw {
			decoded, err := base64.StdEncoding.DecodeString(k)
			require.NoError(t, err)
			assert.Len(t, decoded, 32)
		}
	})

	t.Run("unmarshal fails on non-base64 key", func(t *testing.T) {
		badJSON := `{"not-base64!!!": ["field1"]}`
		var m utils.RequestedCertificateTypeIDAndFieldList
		err := json.Unmarshal([]byte(badJSON), &m)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64 key")
	})

	t.Run("unmarshal fails when decoded key is not 32 bytes", func(t *testing.T) {
		// base64 of only 10 bytes — not 32
		shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
		badJSON, _ := json.Marshal(map[string][]string{shortKey: {"field1"}})
		var m utils.RequestedCertificateTypeIDAndFieldList
		err := json.Unmarshal(badJSON, &m)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 32 bytes")
	})

	t.Run("unmarshal fails on invalid JSON", func(t *testing.T) {
		var m utils.RequestedCertificateTypeIDAndFieldList
		err := json.Unmarshal([]byte(`not json`), &m)
		assert.Error(t, err)
	})
}

// contains is a helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

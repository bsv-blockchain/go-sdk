package auth

import (
	"encoding/base64"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateCertificates tests the validateCertificates function
func TestValidateCertificates(t *testing.T) {
	t.Run("Rejects empty certificates", func(t *testing.T) {
		mockWallet := wallet.NewTestWalletForRandomKey(t)
		message := &AuthMessage{
			Certificates: nil,
		}

		err := ValidateCertificates(t.Context(), mockWallet, message, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no certificates were provided")
	})

	t.Run("Validates certificate requirements structure", func(t *testing.T) {
		var certType wallet.CertificateType
		copy(certType[:], "requested_type")
		// Test validate certificate requirements struct
		reqs := &utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("valid_certifier")},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				certType: {"field1"},
			},
		}

		assert.NotNil(t, reqs)
		assert.Len(t, reqs.Certifiers, 1)
		assert.Len(t, reqs.CertificateTypes, 1)
		assert.Contains(t, reqs.CertificateTypes, certType)
		assert.Contains(t, reqs.CertificateTypes[certType], "field1")
	})

	// Example: Create a valid certificate using CompletedProtoWallet
	t.Run("Validates single certificate with required fields", func(t *testing.T) {
		// Create keys for subject and certifier
		subjectPrivateKey, _ := ec.NewPrivateKey()
		certifierPrivateKey, _ := ec.NewPrivateKey()

		// Create CompletedProtoWallets
		subjectWallet, err := wallet.NewCompletedProtoWallet(subjectPrivateKey)
		require.NoError(t, err)
		certifierWallet, err := wallet.NewCompletedProtoWallet(certifierPrivateKey)
		require.NoError(t, err)

		// Get identity keys
		subjectIdentityKey, err := subjectWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		require.NoError(t, err)
		certifierIdentityKey, err := certifierWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		require.NoError(t, err)

		// Create counterparty for subject
		subjectCounterparty := wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: subjectIdentityKey.PublicKey,
		}

		// Certificate fields
		plaintextFields := map[string]string{
			"name":  "Test User",
			"email": "test@example.com",
			"role":  "Developer",
		}

		// Create revocation outpoint
		revocationOutpoint := &transaction.Outpoint{
			Txid:  chainhash.HashH([]byte("test_txid_000000000000000000000000000000000000000000000000000000000000")),
			Index: 0,
		}

		// Issue certificate
		masterCert, err := certificates.IssueCertificateForSubject(
			t.Context(),
			certifierWallet.ProtoWallet,
			subjectCounterparty,
			plaintextFields,
			string(utils.RandomBase64(32)), // certificate type
			func(serial string) (*transaction.Outpoint, error) {
				return revocationOutpoint, nil
			},
			"", // auto-generate serial number
		)
		require.NoError(t, err)
		require.NotNil(t, masterCert)

		// Create a verifiable certificate from the master certificate
		// First, create keyring for a verifier (in this case, we'll use "anyone")
		fieldNames := []wallet.CertificateFieldNameUnder50Bytes{"name", "email", "role"}
		certifierCounterparty := wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: certifierIdentityKey.PublicKey,
		}
		anyoneCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}

		keyringForVerifier, err := certificates.CreateKeyringForVerifier(
			t.Context(),
			subjectWallet.ProtoWallet,
			certifierCounterparty,
			anyoneCounterparty,
			masterCert.Fields,
			fieldNames,
			masterCert.MasterKeyring,
			masterCert.SerialNumber,
			false,
			"",
		)
		require.NoError(t, err)

		// Convert keyring to expected format
		keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)
		for k, v := range keyringForVerifier {
			keyringMap[k] = wallet.StringBase64(v)
		}

		// Create VerifiableCertificate
		verifiableCert := certificates.NewVerifiableCertificate(&masterCert.Certificate, keyringMap)

		// Create AuthMessage with the certificate - USE SUBJECT'S IDENTITY KEY, NOT CERTIFIER'S
		message := &AuthMessage{
			Certificates: []*certificates.VerifiableCertificate{verifiableCert},
			IdentityKey:  subjectIdentityKey.PublicKey, // Fixed: use subject's key
		}

		// Convert masterCert.Type from StringBase64 to Base64Bytes32
		var certType32 wallet.CertificateType
		typeBytes, _ := base64.StdEncoding.DecodeString(string(masterCert.Type))
		copy(certType32[:], typeBytes)

		certReqs := &utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{certifierIdentityKey.PublicKey},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				certType32: []string{"name", "email"},
			},
		}

		// Validate certificates - using an "anyone" wallet for verification
		anyoneWallet, err := wallet.NewCompletedProtoWallet(nil)
		require.NoError(t, err)

		err = ValidateCertificates(t.Context(), anyoneWallet, message, certReqs)
		assert.NoError(t, err)
	})

	t.Run("Validates self-signed certificate", func(t *testing.T) {
		// Create key for subject who will also be certifier
		subjectPrivateKey, _ := ec.NewPrivateKey()

		// Create CompletedProtoWallet
		subjectWallet, err := wallet.NewCompletedProtoWallet(subjectPrivateKey)
		require.NoError(t, err)

		// Get identity key
		subjectIdentityKey, err := subjectWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		require.NoError(t, err)

		// Self counterparty
		selfCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

		// Certificate fields
		plaintextFields := map[string]string{
			"owner": "Self Signer",
			"type":  "Identity",
		}

		// Generate a proper 32-byte certificate type to avoid AES key size issues
		certType := make([]byte, 32)
		copy(certType, []byte("self-signed-cert-type"))
		certTypeBase64 := string(utils.RandomBase64(32)) // This ensures exactly 32 bytes

		// Issue self-signed certificate
		masterCert, err := certificates.IssueCertificateForSubject(
			t.Context(),
			subjectWallet.ProtoWallet,
			selfCounterparty,
			plaintextFields,
			certTypeBase64, // Use proper 32-byte type
			nil,            // no revocation
			"",
		)
		require.NoError(t, err)

		// For self-signed certificates, the subject can decrypt their own fields
		// Create keyring for self
		fieldNames := []wallet.CertificateFieldNameUnder50Bytes{"owner", "type"}
		keyringForSelf, err := certificates.CreateKeyringForVerifier(
			t.Context(),
			subjectWallet.ProtoWallet,
			selfCounterparty,
			selfCounterparty,
			masterCert.Fields,
			fieldNames,
			masterCert.MasterKeyring,
			masterCert.SerialNumber,
			false,
			"",
		)
		require.NoError(t, err)

		// Convert keyring
		keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)
		for k, v := range keyringForSelf {
			keyringMap[k] = v
		}

		// Create VerifiableCertificate
		verifiableCert := certificates.NewVerifiableCertificate(&masterCert.Certificate, keyringMap)

		// Create message
		message := &AuthMessage{
			Certificates: []*certificates.VerifiableCertificate{verifiableCert},
			IdentityKey:  subjectIdentityKey.PublicKey,
		}

		// Convert certTypeBase64 from string to Base64Bytes32
		var certType32 wallet.CertificateType
		typeBytes, _ := base64.StdEncoding.DecodeString(certTypeBase64)
		copy(certType32[:], typeBytes)

		certReqs := &utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{subjectIdentityKey.PublicKey},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				certType32: []string{"owner"},
			},
		}

		// Validate
		err = ValidateCertificates(t.Context(), subjectWallet, message, certReqs)
		assert.NoError(t, err)
	})

	t.Run("Rejects certificate with invalid signature", func(t *testing.T) {
		// Create keys
		subjectPrivateKey, _ := ec.NewPrivateKey()
		certifierPrivateKey, _ := ec.NewPrivateKey()
		differentPrivateKey, _ := ec.NewPrivateKey()

		// Create wallets
		subjectWallet, _ := wallet.NewCompletedProtoWallet(subjectPrivateKey)
		certifierWallet, _ := wallet.NewCompletedProtoWallet(certifierPrivateKey)

		// Get identity keys
		subjectIdentityKey, _ := subjectWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		certifierIdentityKey, _ := certifierWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")

		// Create certificate
		subjectCounterparty := wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: subjectIdentityKey.PublicKey,
		}

		masterCert, _ := certificates.IssueCertificateForSubject(
			t.Context(),
			certifierWallet.ProtoWallet,
			subjectCounterparty,
			map[string]string{"field1": "value1"},
			string(utils.RandomBase64(32)),
			nil,
			"",
		)

		// Tamper with the signature by replacing it with a different signature
		tamperedSig, _ := differentPrivateKey.Sign([]byte("wrong data"))
		masterCert.Signature = tamperedSig.Serialize()

		// Create verifiable certificate
		anyoneCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
		keyring, _ := certificates.CreateKeyringForVerifier(
			t.Context(),
			subjectWallet.ProtoWallet,
			wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: certifierIdentityKey.PublicKey,
			},
			anyoneCounterparty,
			masterCert.Fields,
			[]wallet.CertificateFieldNameUnder50Bytes{"field1"},
			masterCert.MasterKeyring,
			masterCert.SerialNumber,
			false,
			"",
		)

		keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)
		for k, v := range keyring {
			keyringMap[k] = v
		}

		verifiableCert := certificates.NewVerifiableCertificate(&masterCert.Certificate, keyringMap)

		// Create message - USE SUBJECT'S IDENTITY KEY, NOT CERTIFIER'S
		message := &AuthMessage{
			Certificates: []*certificates.VerifiableCertificate{verifiableCert},
			IdentityKey:  subjectIdentityKey.PublicKey, // Fixed: use subject's key
		}

		// Validate should fail due to invalid signature
		anyoneWallet, _ := wallet.NewCompletedProtoWallet(nil)
		err := ValidateCertificates(t.Context(), anyoneWallet, message, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature")
	})
}

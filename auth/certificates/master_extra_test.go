package certificates_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var errBoom = errors.New("boom")

func TestNewMasterCertificateErrors(t *testing.T) {
	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("missing keyring entry for a field", func(t *testing.T) {
		baseCert := &certificates.Certificate{
			Type:         utils.RandomBase64(32),
			SerialNumber: utils.RandomBase64(32),
			Subject:      *subjectKey.PubKey(),
			Certifier:    *certifierKey.PubKey(),
			Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
				"name": "encrypted-value",
			},
		}
		// keyring is non-empty but is missing the "name" field
		masterKeyring := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
			"other": "some-key",
		}

		_, err := certificates.NewMasterCertificate(baseCert, masterKeyring)
		require.Error(t, err)
		require.Contains(t, err.Error(), "master keyring must contain a value for every field")
	})
}

func TestCreateCertificateFieldsErrors(t *testing.T) {
	t.Run("wallet encrypt failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnEncrypt().ReturnError(errBoom)

		_, err := certificates.CreateCertificateFields(
			t.Context(),
			tw,
			wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			map[wallet.CertificateFieldNameUnder50Bytes]string{"name": "Alice"},
			false,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to encrypt field revelation key")
	})
}

func TestIssueCertificateForSubjectErrors(t *testing.T) {
	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	subjectCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: subjectKey.PubKey()}

	certType := string(utils.RandomBase64(32))

	t.Run("field name exceeds 50 bytes", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		longName := "this-field-name-is-definitely-longer-than-fifty-bytes-limit"
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			subjectCounterparty,
			map[string]string{longName: "value"},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds 50 bytes limit")
	})

	t.Run("create certificate fields failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnEncrypt().ReturnError(errBoom)
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create certificate fields")
	})

	t.Run("get certifier public key failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnGetPublicKey().ReturnError(errBoom)
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get certifier public key")
	})

	t.Run("certifier public key is not valid", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		// Return a non-nil result whose PublicKey has a nil X coordinate.
		tw.OnGetPublicKey().ReturnSuccess(&wallet.GetPublicKeyResult{PublicKey: &ec.PublicKey{}})
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get a valid certifier public key")
	})

	t.Run("revocation outpoint func failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			certType,
			func(string) (*transaction.Outpoint, error) { return nil, errBoom },
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get revocation outpoint")
	})

	t.Run("subject TypeOther with nil counterparty", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		// Empty fields so field encryption (which uses the subject counterparty) is skipped
		// and the counterparty-type switch is reached.
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: nil},
			map[string]string{},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil public key")
	})

	t.Run("subject TypeAnyone succeeds using certifier key", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		cert, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
			map[string]string{"name": "Alice"},
			certType,
			nil,
			"",
		)
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("subject uninitialized counterparty", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			wallet.Counterparty{Type: wallet.CounterpartyUninitialized},
			map[string]string{},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unhandled subject counterparty type")
	})

	t.Run("subject unknown counterparty type", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			wallet.Counterparty{Type: wallet.CounterpartyType(99)},
			map[string]string{},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unhandled subject counterparty type")
	})

	t.Run("sign failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnCreateSignature().ReturnError(errBoom)
		_, err := certificates.IssueCertificateForSubject(
			t.Context(),
			tw,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			certType,
			nil,
			"",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign certificate")
	})
}

func TestDecryptFieldErrors(t *testing.T) {
	fieldName := wallet.CertificateFieldNameUnder50Bytes("name")
	certifierCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

	t.Run("empty master keyring", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.DecryptField(
			t.Context(), tw,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
			fieldName, "value", certifierCounterparty, false, "",
		)
		require.ErrorIs(t, err, certificates.ErrMissingMasterKeyring)
	})

	t.Run("field key not in keyring", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.DecryptField(
			t.Context(), tw,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{"other": "key"},
			fieldName, "value", certifierCounterparty, false, "",
		)
		require.ErrorIs(t, err, certificates.ErrKeyNotFoundInKeyring)
	})

	t.Run("master key base64 decode failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.DecryptField(
			t.Context(), tw,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{fieldName: "!!!not-base64!!!"},
			fieldName, "value", certifierCounterparty, false, "",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode master key")
	})

	t.Run("encrypted field value base64 decode failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		// Let decryption of the revelation key succeed with a 32-byte key.
		tw.OnDecrypt().ReturnSuccess(&wallet.DecryptResult{Plaintext: make([]byte, 32)})
		validBase64Key := wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("some-encrypted-key-bytes")))
		_, err := certificates.DecryptField(
			t.Context(), tw,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{fieldName: validBase64Key},
			fieldName, "!!!not-base64!!!", certifierCounterparty, false, "",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode encrypted field value")
	})

	t.Run("symmetric decryption failure", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnDecrypt().ReturnSuccess(&wallet.DecryptResult{Plaintext: make([]byte, 32)})
		validBase64Key := wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("some-encrypted-key-bytes")))
		// A valid base64 string that is garbage as ciphertext, so symmetric decrypt fails.
		garbageValue := wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("garbage-ciphertext-that-cannot-be-decrypted")))
		_, err := certificates.DecryptField(
			t.Context(), tw,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{fieldName: validBase64Key},
			fieldName, garbageValue, certifierCounterparty, false, "",
		)
		require.ErrorIs(t, err, certificates.ErrDecryptionFailed)
	})
}

func TestDecryptFieldsErrors(t *testing.T) {
	t.Run("nil fields map", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		_, err := certificates.DecryptFields(
			t.Context(), tw,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{"name": "key"},
			nil,
			wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			false, "",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fields map cannot be nil")
	})
}

func TestCreateKeyringForVerifierErrors(t *testing.T) {
	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	certifierWallet, err := wallet.NewCompletedProtoWallet(certifierKey)
	require.NoError(t, err)

	subjectCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: subjectKey.PubKey()}
	certifierCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: certifierKey.PubKey()}
	verifierCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: verifierKey.PubKey()}

	t.Run("empty master keyring", func(t *testing.T) {
		subjectWallet, err := wallet.NewCompletedProtoWallet(subjectKey)
		require.NoError(t, err)
		_, err = certificates.CreateKeyringForVerifier(
			t.Context(), subjectWallet, certifierCounterparty, verifierCounterparty,
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
			[]wallet.CertificateFieldNameUnder50Bytes{"name"},
			map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
			"serial", false, "",
		)
		require.ErrorIs(t, err, certificates.ErrMissingMasterKeyring)
	})

	t.Run("encrypt for verifier failure", func(t *testing.T) {
		// Issue a real certificate so DecryptField succeeds against the real subject key,
		// but wrap the subject wallet so the re-encryption for the verifier fails.
		issued, err := certificates.IssueCertificateForSubject(
			t.Context(),
			certifierWallet,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			string(utils.RandomBase64(32)),
			nil,
			"",
		)
		require.NoError(t, err)

		subjectTestWallet := wallet.NewTestWallet(t, subjectKey)
		subjectTestWallet.OnEncrypt().ReturnError(errBoom)

		_, err = certificates.CreateKeyringForVerifier(
			t.Context(),
			subjectTestWallet,
			certifierCounterparty,
			verifierCounterparty,
			issued.Fields,
			[]wallet.CertificateFieldNameUnder50Bytes{"name"},
			issued.MasterKeyring,
			issued.SerialNumber,
			false, "",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to encrypt field key for verifier")
	})

	t.Run("field to reveal not present", func(t *testing.T) {
		issued, err := certificates.IssueCertificateForSubject(
			t.Context(),
			certifierWallet,
			subjectCounterparty,
			map[string]string{"name": "Alice"},
			string(utils.RandomBase64(32)),
			nil,
			"",
		)
		require.NoError(t, err)

		subjectWallet, err := wallet.NewCompletedProtoWallet(subjectKey)
		require.NoError(t, err)

		_, err = certificates.CreateKeyringForVerifier(
			t.Context(),
			subjectWallet,
			certifierCounterparty,
			verifierCounterparty,
			issued.Fields,
			[]wallet.CertificateFieldNameUnder50Bytes{"nonexistent"},
			issued.MasterKeyring,
			issued.SerialNumber,
			false, "",
		)
		require.ErrorIs(t, err, certificates.ErrFieldNotFound)
	})
}

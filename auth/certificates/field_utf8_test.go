package certificates

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// utf8StubWallet hands back a fixed field key, so DecryptField reaches the
// symmetric decryption and the text check without a full wallet.
type utf8StubWallet struct{ key []byte }

func (utf8StubWallet) Encrypt(context.Context, wallet.EncryptArgs, string) (*wallet.EncryptResult, error) {
	return nil, errors.New("encrypt is not used by this stub")
}

func (w utf8StubWallet) Decrypt(context.Context, wallet.DecryptArgs, string) (*wallet.DecryptResult, error) {
	return &wallet.DecryptResult{Plaintext: w.key}, nil
}

func decryptStubField(t *testing.T, plaintext []byte, flipTag bool) (*DecryptFieldResult, error) {
	t.Helper()
	sk := ec.NewSymmetricKeyFromRandom()
	ct, err := sk.Encrypt(plaintext)
	require.NoError(t, err)
	if flipTag {
		ct[len(ct)-1] ^= 1
	}
	ring := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
		"tier": wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("wrapped-key-placeholder"))),
	}
	return DecryptField(t.Context(), utf8StubWallet{key: sk.ToBytes()}, ring, "tier",
		wallet.StringBase64(base64.StdEncoding.EncodeToString(ct)),
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, false, "")
}

func TestDecryptFieldRefusesInvalidUTF8(t *testing.T) {
	t.Run("invalid UTF-8 after a valid decrypt is refused", func(t *testing.T) {
		res, err := decryptStubField(t, []byte{'3', 0xff, 0xfe, 0xc3, 0x28, 0xa0, 0xa1}, false)
		require.ErrorIs(t, err, ErrInvalidFieldEncoding)
		require.Nil(t, res)
	})

	t.Run("valid UTF-8, including a NUL and a multi-byte rune, passes unchanged", func(t *testing.T) {
		for _, v := range []string{"hello", "3\x00junk", "café \U0001F600", ""} {
			res, err := decryptStubField(t, []byte(v), false)
			require.NoError(t, err, "value %q", v)
			require.Equal(t, v, res.DecryptedFieldValue)
		}
	})

	t.Run("a flipped GCM tag still fails as a decryption error, not an encoding error", func(t *testing.T) {
		_, err := decryptStubField(t, []byte("hello"), true)
		require.ErrorIs(t, err, ErrDecryptionFailed)
		require.NotErrorIs(t, err, ErrInvalidFieldEncoding)
	})
}

func TestVerifiableDecryptFieldsRefusesInvalidUTF8(t *testing.T) {
	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	subjectWallet, err := wallet.NewCompletedProtoWallet(subjectKey)
	require.NoError(t, err)
	verifierWallet, err := wallet.NewCompletedProtoWallet(verifierKey)
	require.NoError(t, err)

	certifier := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: certifierKey.PubKey()}
	verifier := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: verifierKey.PubKey()}
	serial := wallet.StringBase64(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))

	made, err := CreateCertificateFields(t.Context(), subjectWallet.ProtoWallet, certifier,
		map[wallet.CertificateFieldNameUnder50Bytes]string{"tier": "gold"}, false, "")
	require.NoError(t, err)
	names := []wallet.CertificateFieldNameUnder50Bytes{"tier"}
	keyring, err := CreateKeyringForVerifier(t.Context(), subjectWallet.ProtoWallet, certifier, verifier,
		made.CertificateFields, names, made.MasterKeyring, serial, false, "")
	require.NoError(t, err)
	keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, len(keyring))
	for k, v := range keyring {
		keyringMap[k] = v
	}

	newCert := func(fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64) *VerifiableCertificate {
		return NewVerifiableCertificate(&Certificate{
			Type:         wallet.StringBase64(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))),
			SerialNumber: serial,
			Subject:      *subjectKey.PubKey(),
			Certifier:    *certifierKey.PubKey(),
			Fields:       fields,
		}, keyringMap)
	}

	// Control: the honest certificate decrypts.
	got, err := newCert(made.CertificateFields).DecryptFields(t.Context(), verifierWallet, false, "")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"tier": "gold"}, got)

	// Re-encrypt the same field key over bytes that are not valid UTF-8, which
	// is what a malicious subject can hand a verifier.
	revealed, err := DecryptField(t.Context(), subjectWallet.ProtoWallet, made.MasterKeyring, "tier",
		made.CertificateFields["tier"], certifier, false, "")
	require.NoError(t, err)
	bad, err := ec.NewSymmetricKey(revealed.FieldRevelationKey).Encrypt([]byte{'3', 0xff, 0xfe, 0xc3, 0x28})
	require.NoError(t, err)
	forged := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
		"tier": wallet.StringBase64(base64.StdEncoding.EncodeToString(bad)),
	}

	_, err = newCert(forged).DecryptFields(t.Context(), verifierWallet, false, "")
	require.ErrorIs(t, err, ErrInvalidFieldEncoding)
	require.ErrorIs(t, err, ErrFieldDecryption)
}

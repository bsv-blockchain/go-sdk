package serializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestListActionsResultAllStatuses(t *testing.T) {
	t.Parallel()

	txid := tu.HashFromString(t, "b1f4d452814bba0ac422318083850b706d5f23ce232c789eefe5cbdcf2cc47de")
	statuses := []wallet.ActionStatus{
		wallet.ActionStatusCompleted,
		wallet.ActionStatusUnprocessed,
		wallet.ActionStatusSending,
		wallet.ActionStatusUnproven,
		wallet.ActionStatusUnsigned,
		wallet.ActionStatusNoSend,
		wallet.ActionStatusNonFinal,
	}

	result := &wallet.ListActionsResult{}
	for i, s := range statuses {
		result.Actions = append(result.Actions, wallet.Action{
			Txid:        txid,
			Satoshis:    int64(i),
			Status:      s,
			Description: "a",
		})
	}
	result.TotalActions = uint32(len(result.Actions)) //nolint:gosec // G115 -- fixed small test slice length

	data, err := SerializeListActionsResult(result)
	require.NoError(t, err)

	got, err := DeserializeListActionsResult(data)
	require.NoError(t, err)
	require.Len(t, got.Actions, len(statuses))
	for i, s := range statuses {
		assert.Equal(t, s, got.Actions[i].Status)
	}
}

func TestSerializeProveCertificateResultInvalidBase64(t *testing.T) {
	t.Parallel()

	_, err := SerializeProveCertificateResult(&wallet.ProveCertificateResult{
		KeyringForVerifier: map[string]string{"k": "!!!not-base64"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid keyring value base64")
}

func TestSerializeListCertificatesResultErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid keyring base64", func(t *testing.T) {
		result := &wallet.ListCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.CertificateResult{{
				Certificate: xtValidCertificate(t),
				Keyring:     map[string]string{"k": "!!!not-base64"},
			}},
		}
		_, err := SerializeListCertificatesResult(result)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid keyring value base64")
	})

	t.Run("inner certificate error", func(t *testing.T) {
		cert := xtValidCertificate(t)
		cert.Type = [32]byte{}
		result := &wallet.ListCertificatesResult{
			TotalCertificates: 1,
			Certificates:      []wallet.CertificateResult{{Certificate: cert}},
		}
		_, err := SerializeListCertificatesResult(result)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cert type is empty")
	})
}

func TestSerializeIdentityCertificateInvalidBase64(t *testing.T) {
	t.Parallel()

	idcert := xtValidIdentityCertificate(t)
	idcert.PubliclyRevealedKeyring = map[string]string{"k": "!!!not-base64"}
	_, err := SerializeIdentityCertificate(&idcert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error decoding base64 value")
}

func TestDeserializeSignActionResultTrailingBytes(t *testing.T) {
	t.Parallel()

	result := &wallet.SignActionResult{
		Txid: tu.GetByte32FromHexString(t, "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72"),
		Tx:   []byte{1, 2, 3},
	}
	data, err := SerializeSignActionResult(result)
	require.NoError(t, err)

	// Appending an unexpected trailing byte makes CheckComplete fail.
	_, err = DeserializeSignActionResult(append(data, 0x00))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error deserializing SignActionResult")
}

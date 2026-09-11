package serializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestSerializeKeyParamsEncodeErrors(t *testing.T) {
	t.Parallel()

	badEnc := wallet.EncryptionArgs{Counterparty: xtBadCounterparty()}

	tests := []struct {
		name string
		fn   func() ([]byte, error)
	}{
		{"CreateHMACArgs", func() ([]byte, error) {
			return SerializeCreateHMACArgs(&wallet.CreateHMACArgs{EncryptionArgs: badEnc})
		}},
		{"CreateSignatureArgs", func() ([]byte, error) {
			return SerializeCreateSignatureArgs(&wallet.CreateSignatureArgs{EncryptionArgs: badEnc})
		}},
		{"DecryptArgs", func() ([]byte, error) {
			return SerializeDecryptArgs(&wallet.DecryptArgs{EncryptionArgs: badEnc})
		}},
		{"EncryptArgs", func() ([]byte, error) {
			return SerializeEncryptArgs(&wallet.EncryptArgs{EncryptionArgs: badEnc})
		}},
		{"VerifyHMACArgs", func() ([]byte, error) {
			return SerializeVerifyHMACArgs(&wallet.VerifyHMACArgs{EncryptionArgs: badEnc})
		}},
		{"VerifySignatureArgs", func() ([]byte, error) {
			return SerializeVerifySignatureArgs(&wallet.VerifySignatureArgs{EncryptionArgs: badEnc})
		}},
		{"GetPublicKeyArgs", func() ([]byte, error) {
			return SerializeGetPublicKeyArgs(&wallet.GetPublicKeyArgs{EncryptionArgs: badEnc})
		}},
		{"RevealSpecificKeyLinkageArgs", func() ([]byte, error) {
			return SerializeRevealSpecificKeyLinkageArgs(&wallet.RevealSpecificKeyLinkageArgs{Counterparty: xtBadCounterparty()})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error encoding key params")
		})
	}
}

func TestSerializeResultCountMismatch(t *testing.T) {
	t.Parallel()

	t.Run("ListActionsResult", func(t *testing.T) {
		_, err := SerializeListActionsResult(&wallet.ListActionsResult{TotalActions: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("ListOutputsResult", func(t *testing.T) {
		_, err := SerializeListOutputsResult(&wallet.ListOutputsResult{TotalOutputs: 3})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("ListCertificatesResult", func(t *testing.T) {
		_, err := SerializeListCertificatesResult(&wallet.ListCertificatesResult{TotalCertificates: 2})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("DiscoverCertificatesResult", func(t *testing.T) {
		_, err := SerializeDiscoverCertificatesResult(&wallet.DiscoverCertificatesResult{TotalCertificates: 2})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})
}

func TestSerializeDiscoverCertificatesResultInnerError(t *testing.T) {
	t.Parallel()

	// An identity certificate whose base certificate has an empty type makes the
	// inner SerializeCertificate call fail.
	idcert := xtValidIdentityCertificate(t)
	idcert.Type = [32]byte{}
	_, err := SerializeDiscoverCertificatesResult(&wallet.DiscoverCertificatesResult{
		TotalCertificates: 1,
		Certificates:      []wallet.IdentityCertificate{idcert},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert type is empty")
}

func TestSerializeProveCertificateArgsEmptyType(t *testing.T) {
	t.Parallel()

	args := &wallet.ProveCertificateArgs{Certificate: xtValidCertificate(t)}
	args.Certificate.Type = [32]byte{}
	_, err := SerializeProveCertificateArgs(args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate type is empty")
}

func TestSerializeRelinquishCertificateArgsErrors(t *testing.T) {
	t.Parallel()

	nonZero := tu.GetByte32FromString("x")

	t.Run("empty type", func(t *testing.T) {
		_, err := SerializeRelinquishCertificateArgs(&wallet.RelinquishCertificateArgs{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "type is empty")
	})

	t.Run("empty serial number", func(t *testing.T) {
		_, err := SerializeRelinquishCertificateArgs(&wallet.RelinquishCertificateArgs{Type: nonZero})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialNumber is empty")
	})

	t.Run("nil certifier", func(t *testing.T) {
		_, err := SerializeRelinquishCertificateArgs(&wallet.RelinquishCertificateArgs{Type: nonZero, SerialNumber: nonZero})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certifier is empty")
	})
}

func TestSerializeDiscoverByIdentityKeyArgsNilKey(t *testing.T) {
	t.Parallel()

	_, err := SerializeDiscoverByIdentityKeyArgs(&wallet.DiscoverByIdentityKeyArgs{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identityKey cannot be empty")
}

func TestSerializeInternalizeActionArgsErrors(t *testing.T) {
	t.Parallel()

	t.Run("nil payment remittance", func(t *testing.T) {
		_, err := SerializeInternalizeActionArgs(&wallet.InternalizeActionArgs{
			Outputs: []wallet.InternalizeOutput{{Protocol: wallet.InternalizeProtocolWalletPayment}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "payment remittance is required")
	})

	t.Run("nil insertion remittance", func(t *testing.T) {
		_, err := SerializeInternalizeActionArgs(&wallet.InternalizeActionArgs{
			Outputs: []wallet.InternalizeOutput{{Protocol: wallet.InternalizeProtocolBasketInsertion}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insertion remittance is required")
	})
}

func TestSerializeRevealCounterpartyKeyLinkageErrors(t *testing.T) {
	t.Parallel()

	pub := xtPub(t)

	t.Run("args nil counterparty", func(t *testing.T) {
		_, err := SerializeRevealCounterpartyKeyLinkageArgs(&wallet.RevealCounterpartyKeyLinkageArgs{Verifier: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty public key is required")
	})

	t.Run("args nil verifier", func(t *testing.T) {
		_, err := SerializeRevealCounterpartyKeyLinkageArgs(&wallet.RevealCounterpartyKeyLinkageArgs{Counterparty: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier public key is required")
	})

	t.Run("result nil prover", func(t *testing.T) {
		_, err := SerializeRevealCounterpartyKeyLinkageResult(&wallet.RevealCounterpartyKeyLinkageResult{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover public key is required")
	})

	t.Run("result nil verifier", func(t *testing.T) {
		_, err := SerializeRevealCounterpartyKeyLinkageResult(&wallet.RevealCounterpartyKeyLinkageResult{Prover: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier public key is required")
	})

	t.Run("result nil counterparty", func(t *testing.T) {
		_, err := SerializeRevealCounterpartyKeyLinkageResult(&wallet.RevealCounterpartyKeyLinkageResult{Prover: pub, Verifier: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty public key is required")
	})
}

func TestSerializeRevealSpecificKeyLinkageErrors(t *testing.T) {
	t.Parallel()

	pub := xtPub(t)
	validKey := wallet.RevealSpecificKeyLinkageArgs{
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "p"},
	}

	t.Run("args nil verifier", func(t *testing.T) {
		args := validKey
		_, err := SerializeRevealSpecificKeyLinkageArgs(&args)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier public key is required")
	})

	t.Run("result nil prover", func(t *testing.T) {
		_, err := SerializeRevealSpecificKeyLinkageResult(&wallet.RevealSpecificKeyLinkageResult{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover public key is required")
	})

	t.Run("result nil verifier", func(t *testing.T) {
		_, err := SerializeRevealSpecificKeyLinkageResult(&wallet.RevealSpecificKeyLinkageResult{Prover: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier public key is required")
	})

	t.Run("result nil counterparty", func(t *testing.T) {
		_, err := SerializeRevealSpecificKeyLinkageResult(&wallet.RevealSpecificKeyLinkageResult{Prover: pub, Verifier: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty public key is required")
	})
}

func TestSerializeVerifySignatureArgsErrors(t *testing.T) {
	t.Parallel()

	validEnc := wallet.EncryptionArgs{
		ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "p"},
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
	}

	t.Run("nil signature", func(t *testing.T) {
		_, err := SerializeVerifySignatureArgs(&wallet.VerifySignatureArgs{EncryptionArgs: validEnc, Data: []byte{1}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature cannot be nil")
	})

	t.Run("invalid data or hash", func(t *testing.T) {
		_, err := SerializeVerifySignatureArgs(&wallet.VerifySignatureArgs{
			EncryptionArgs:       validEnc,
			Signature:            newTestSignature(t),
			HashToDirectlyVerify: []byte{1, 2, 3}, // wrong size, and no Data
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data or hash")
	})
}

func TestSerializeListActionsArgsLimitExceeds(t *testing.T) {
	t.Parallel()

	_, err := SerializeListActionsArgs(&wallet.ListActionsArgs{Limit: util.Uint32Ptr(wallet.MaxActionsLimit + 1)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit exceeds maximum")
}

func TestSerializeAcquireCertificateArgsErrors(t *testing.T) {
	t.Parallel()

	pub := xtPub(t)
	op := tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0")

	t.Run("invalid acquisition protocol", func(t *testing.T) {
		_, err := SerializeAcquireCertificateArgs(&wallet.AcquireCertificateArgs{
			Certifier:           pub,
			AcquisitionProtocol: wallet.AcquisitionProtocol("bogus"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid acquisition protocol")
	})

	t.Run("direct nil serial number", func(t *testing.T) {
		_, err := SerializeAcquireCertificateArgs(&wallet.AcquireCertificateArgs{
			Certifier:           pub,
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialNumber is empty")
	})

	t.Run("nil keyring revealer", func(t *testing.T) {
		_, err := SerializeAcquireCertificateArgs(&wallet.AcquireCertificateArgs{
			Certifier:           pub,
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			SerialNumber:        &wallet.SerialNumber{1},
			RevocationOutpoint:  op,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keyringRevealer cannot be nil")
	})

	t.Run("keyring revealer pubkey nil when not certifier", func(t *testing.T) {
		_, err := SerializeAcquireCertificateArgs(&wallet.AcquireCertificateArgs{
			Certifier:           pub,
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			SerialNumber:        &wallet.SerialNumber{1},
			RevocationOutpoint:  op,
			KeyringRevealer:     &wallet.KeyringRevealer{Certifier: false},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keyringRevealer PubKey cannot be nil if not certifier")
	})
}

func TestSerializeCreateActionResultInvalidSendWithStatus(t *testing.T) {
	t.Parallel()

	_, err := SerializeCreateActionResult(&wallet.CreateActionResult{
		SendWithResults: []wallet.SendWithResult{
			{Txid: tu.GetByte32FromHexString(t, "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72"), Status: wallet.ActionResultStatus("bogus")},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sendWith results")
}

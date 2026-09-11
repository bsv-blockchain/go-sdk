package substrates_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
)

// frameForCall builds a request frame for the given call with the provided params.
func frameForCall(call substrates.Call, params []byte) []byte {
	return serializer.WriteRequestFrame(serializer.RequestFrame{
		Call:   byte(call),
		Params: params,
	})
}

// TestProcessorDeserializeArgErrors feeds malformed params to each call so the
// per-method "failed to deserialize" branch is exercised in the processor.
func TestProcessorDeserializeArgErrors(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	processor := substrates.NewWalletWireProcessor(tw)

	// badParams is a single 0xFF byte: as a varint prefix it demands 8 more
	// bytes that are not present, so the first length-prefixed read fails; for
	// methods that read a leading flag byte, the subsequent read then fails.
	badParams := []byte{0xFF}

	calls := map[string]substrates.Call{
		"CreateAction":                 substrates.CallCreateAction,
		"SignAction":                   substrates.CallSignAction,
		"ListActions":                  substrates.CallListActions,
		"InternalizeAction":            substrates.CallInternalizeAction,
		"ListOutputs":                  substrates.CallListOutputs,
		"RelinquishOutput":             substrates.CallRelinquishOutput,
		"GetPublicKey":                 substrates.CallGetPublicKey,
		"RevealCounterpartyKeyLinkage": substrates.CallRevealCounterpartyKeyLinkage,
		"RevealSpecificKeyLinkage":     substrates.CallRevealSpecificKeyLinkage,
		"Encrypt":                      substrates.CallEncrypt,
		"Decrypt":                      substrates.CallDecrypt,
		"CreateHMAC":                   substrates.CallCreateHMAC,
		"VerifyHMAC":                   substrates.CallVerifyHMAC,
		"CreateSignature":              substrates.CallCreateSignature,
		"VerifySignature":              substrates.CallVerifySignature,
		"AcquireCertificate":           substrates.CallAcquireCertificate,
		"ListCertificates":             substrates.CallListCertificates,
		"ProveCertificate":             substrates.CallProveCertificate,
		"RelinquishCertificate":        substrates.CallRelinquishCertificate,
		"DiscoverByIdentityKey":        substrates.CallDiscoverByIdentityKey,
		"DiscoverByAttributes":         substrates.CallDiscoverByAttributes,
		"GetHeaderForHeight":           substrates.CallGetHeaderForHeight,
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			_, err := processor.TransmitToWallet(context.Background(), frameForCall(call, badParams))
			require.Error(t, err)
		})
	}
}

// ---- Transceiver serialize-arg error branches ----
//
// A Counterparty of type "other" with a nil public key cannot be serialized,
// so the transceiver's "failed to serialize" branch is exercised before any
// transmit happens.

func badEncryptionArgs() wallet.EncryptionArgs {
	return wallet.EncryptionArgs{
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		KeyID: "k1",
		Counterparty: wallet.Counterparty{
			Type: wallet.CounterpartyTypeOther, // nil Counterparty key -> serialize error
		},
	}
}

func TestTransceiverSerializeErrors(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)
	ctx := context.Background()

	t.Run("GetPublicKey", func(t *testing.T) {
		_, err := transceiver.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
			EncryptionArgs: badEncryptionArgs(),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("Encrypt", func(t *testing.T) {
		_, err := transceiver.Encrypt(ctx, wallet.EncryptArgs{
			EncryptionArgs: badEncryptionArgs(),
			Plaintext:      []byte("x"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("Decrypt", func(t *testing.T) {
		_, err := transceiver.Decrypt(ctx, wallet.DecryptArgs{
			EncryptionArgs: badEncryptionArgs(),
			Ciphertext:     []byte("x"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("CreateHMAC", func(t *testing.T) {
		_, err := transceiver.CreateHMAC(ctx, wallet.CreateHMACArgs{
			EncryptionArgs: badEncryptionArgs(),
			Data:           []byte("x"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("VerifyHMAC", func(t *testing.T) {
		_, err := transceiver.VerifyHMAC(ctx, wallet.VerifyHMACArgs{
			EncryptionArgs: badEncryptionArgs(),
			Data:           []byte("x"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("CreateSignature", func(t *testing.T) {
		_, err := transceiver.CreateSignature(ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: badEncryptionArgs(),
			Data:           []byte("x"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("VerifySignature", func(t *testing.T) {
		_, err := transceiver.VerifySignature(ctx, wallet.VerifySignatureArgs{
			EncryptionArgs: badEncryptionArgs(),
			Data:           []byte("x"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("RevealSpecificKeyLinkage", func(t *testing.T) {
		verifierKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		_, err = transceiver.RevealSpecificKeyLinkage(ctx, wallet.RevealSpecificKeyLinkageArgs{
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther}, // nil key -> serialize error
			ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:        "k1",
			Verifier:     verifierKey.PubKey(),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("RevealCounterpartyKeyLinkage", func(t *testing.T) {
		// nil Counterparty public key -> serialize error
		_, err := transceiver.RevealCounterpartyKeyLinkage(ctx, wallet.RevealCounterpartyKeyLinkageArgs{}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("ListActions", func(t *testing.T) {
		_, err := transceiver.ListActions(ctx, wallet.ListActionsArgs{
			LabelQueryMode: wallet.QueryMode("bogus"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("InternalizeAction", func(t *testing.T) {
		_, err := transceiver.InternalizeAction(ctx, wallet.InternalizeActionArgs{
			Tx:          []byte{0x01},
			Description: "d",
			Outputs: []wallet.InternalizeOutput{
				{Protocol: wallet.InternalizeProtocolWalletPayment}, // nil PaymentRemittance -> error
			},
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("AcquireCertificate", func(t *testing.T) {
		certifierKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		_, err = transceiver.AcquireCertificate(ctx, wallet.AcquireCertificateArgs{
			Certifier:           certifierKey.PubKey(),
			AcquisitionProtocol: wallet.AcquisitionProtocol("bogus"),
		}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("ProveCertificate", func(t *testing.T) {
		// zero-value certificate type -> "certificate type is empty"
		_, err := transceiver.ProveCertificate(ctx, wallet.ProveCertificateArgs{}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("RelinquishCertificate", func(t *testing.T) {
		// zero-value type -> "type is empty"
		_, err := transceiver.RelinquishCertificate(ctx, wallet.RelinquishCertificateArgs{}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})

	t.Run("DiscoverByIdentityKey", func(t *testing.T) {
		// nil IdentityKey -> "identityKey cannot be empty"
		_, err := transceiver.DiscoverByIdentityKey(ctx, wallet.DiscoverByIdentityKeyArgs{}, testAppOriginator)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serialize")
	})
}

// ---- Transceiver transmit / processor wallet-error branches ----
//
// These drive the remaining per-method transmit-error branch in the
// transceiver together with the wallet-error branch in the processor by
// having the backing wallet return an error for a successfully-serialized call.

func TestTransceiverWalletErrorEncrypt(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.Encrypt(context.Background(), wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Plaintext: []byte("hello"),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorDecrypt(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.Decrypt(context.Background(), wallet.DecryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Ciphertext: []byte("hello"),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorCreateHMAC(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.CreateHMAC(context.Background(), wallet.CreateHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Data: []byte("data"),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorVerifyHMAC(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.VerifyHMAC(context.Background(), wallet.VerifyHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Data: []byte("data"),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorCreateSignature(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Data: []byte("data"),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorVerifySignature(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sig, err := privKey.Sign([]byte("data"))
	require.NoError(t, err)
	_, err = transceiver.VerifySignature(context.Background(), wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Data:      []byte("data"),
		Signature: sig,
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorRevealCounterpartyKeyLinkage(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	_, err = transceiver.RevealCounterpartyKeyLinkage(context.Background(), wallet.RevealCounterpartyKeyLinkageArgs{
		Counterparty: counterpartyKey.PubKey(),
		Verifier:     verifierKey.PubKey(),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorRevealSpecificKeyLinkage(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	_, err = transceiver.RevealSpecificKeyLinkage(context.Background(), wallet.RevealSpecificKeyLinkageArgs{
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: counterpartyKey.PubKey(),
		},
		Verifier:   verifierKey.PubKey(),
		ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
		KeyID:      "k1",
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorAcquireCertificate(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	_, err = transceiver.AcquireCertificate(context.Background(), wallet.AcquireCertificateArgs{
		Certifier:           certifierKey.PubKey(),
		AcquisitionProtocol: wallet.AcquisitionProtocolIssuance,
		CertifierUrl:        "https://certifier.example.com",
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorProveCertificate(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	ct, _ := wallet.CertificateTypeFromString("provecert12345678901234567890123")
	var serial wallet.SerialNumber
	copy(serial[:], []byte("serial1234567890123456789012345"))
	_, err = transceiver.ProveCertificate(context.Background(), wallet.ProveCertificateArgs{
		Certificate: wallet.Certificate{
			Type:               ct,
			Subject:            certifierKey.PubKey(),
			Certifier:          certifierKey.PubKey(),
			SerialNumber:       serial,
			RevocationOutpoint: &transaction.Outpoint{},
		},
		Verifier: verifierKey.PubKey(),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorRelinquishCertificate(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	ct, _ := wallet.CertificateTypeFromString("relinquishcert12345678901234567")
	var serial wallet.SerialNumber
	copy(serial[:], []byte("serial1234567890123456789012345"))
	_, err = transceiver.RelinquishCertificate(context.Background(), wallet.RelinquishCertificateArgs{
		Type:         ct,
		SerialNumber: serial,
		Certifier:    certifierKey.PubKey(),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorDiscoverByIdentityKey(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	_, err = transceiver.DiscoverByIdentityKey(context.Background(), wallet.DiscoverByIdentityKeyArgs{
		IdentityKey: privKey.PubKey(),
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorDiscoverByAttributes(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.DiscoverByAttributes(context.Background(), wallet.DiscoverByAttributesArgs{
		Attributes: map[string]string{"key": "val"},
	}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorWaitForAuthentication(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.WaitForAuthentication(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorGetHeaderForHeight(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.GetHeaderForHeight(context.Background(), wallet.GetHeaderArgs{Height: 100}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

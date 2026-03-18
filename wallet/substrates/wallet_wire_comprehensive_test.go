package substrates_test

import (
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAppOriginator = "test-app"

// buildTransceiverPair creates a processor backed by a TestWallet and a transceiver that talks to it.
func buildTransceiverPair(t *testing.T) (*wallet.TestWallet, *substrates.WalletWireTransceiver) {
	t.Helper()
	tw := wallet.NewTestWalletForRandomKey(t)
	processor := substrates.NewWalletWireProcessor(tw)
	transceiver := substrates.NewWalletWireTransceiver(processor)
	return tw, transceiver
}

// ---- WalletWireProcessor ----

func TestWalletWireProcessorEmptyMessage(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	processor := substrates.NewWalletWireProcessor(tw)

	_, err := processor.TransmitToWallet(context.Background(), []byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty message")
}

func TestWalletWireProcessorUnknownCallType(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	processor := substrates.NewWalletWireProcessor(tw)

	// Build a message with an unknown call byte (0xFF)
	msg := []byte{0xFF, 0x00} // call=255, no originator, no params
	_, err := processor.TransmitToWallet(context.Background(), msg)
	assert.Error(t, err)
}

// ---- WalletWireTransceiver - all operations ----

func TestTransceiverGetPublicKey(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)
	result, err := transceiver.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result.PublicKey)
}

func TestTransceiverCreateAction(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{})

	result, err := transceiver.CreateAction(context.Background(), wallet.CreateActionArgs{
		Description: "test action",
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTransceiverSignAction(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnSignAction().ReturnSuccess(&wallet.SignActionResult{})

	result, err := transceiver.SignAction(context.Background(), wallet.SignActionArgs{
		Reference: []byte("ref"),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTransceiverAbortAction(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnAbortAction().ReturnSuccess(&wallet.AbortActionResult{Aborted: true})

	result, err := transceiver.AbortAction(context.Background(), wallet.AbortActionArgs{
		Reference: []byte("ref"),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, result.Aborted)
}

func TestTransceiverListActions(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	// TotalActions must equal len(Actions) for the serializer to accept the result
	tw.OnListActions().ReturnSuccess(&wallet.ListActionsResult{TotalActions: 0, Actions: []wallet.Action{}})

	result, err := transceiver.ListActions(context.Background(), wallet.ListActionsArgs{}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), result.TotalActions)
}

func TestTransceiverInternalizeAction(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnInternalizeAction().ReturnSuccess(&wallet.InternalizeActionResult{Accepted: true})

	result, err := transceiver.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{
		Tx:          []byte{0x01, 0x02},
		Description: "test",
	}, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, result.Accepted)
}

func TestTransceiverListOutputs(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	// TotalOutputs must equal len(Outputs) for the serializer to accept the result
	tw.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{TotalOutputs: 0, Outputs: []wallet.Output{}})

	result, err := transceiver.ListOutputs(context.Background(), wallet.ListOutputsArgs{
		Basket: "default",
	}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), result.TotalOutputs)
}

func TestTransceiverRelinquishOutput(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnRelinquishOutput().ReturnSuccess(&wallet.RelinquishOutputResult{Relinquished: true})

	result, err := transceiver.RelinquishOutput(context.Background(), wallet.RelinquishOutputArgs{
		Basket: "default",
	}, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, result.Relinquished)
}

func TestTransceiverEncrypt(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)

	result, err := transceiver.Encrypt(context.Background(), wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "k1",
		},
		Plaintext: []byte("hello"),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Ciphertext)
}

func TestTransceiverDecrypt(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)
	ctx := context.Background()

	args := wallet.EncryptionArgs{
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		KeyID: "k1",
	}
	plaintext := []byte("hello secret")

	enc, err := transceiver.Encrypt(ctx, wallet.EncryptArgs{
		EncryptionArgs: args,
		Plaintext:      plaintext,
	}, testAppOriginator)
	require.NoError(t, err)

	dec, err := transceiver.Decrypt(ctx, wallet.DecryptArgs{
		EncryptionArgs: args,
		Ciphertext:     enc.Ciphertext,
	}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, plaintext, []byte(dec.Plaintext))
}

func TestTransceiverCreateHMAC(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)

	result, err := transceiver.CreateHMAC(context.Background(), wallet.CreateHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "k1",
		},
		Data: []byte("data"),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, result.HMAC)
}

func TestTransceiverVerifyHMAC(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)
	ctx := context.Background()

	args := wallet.EncryptionArgs{
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		KeyID: "k1",
	}
	data := []byte("hmac-data")

	createResult, err := transceiver.CreateHMAC(ctx, wallet.CreateHMACArgs{
		EncryptionArgs: args,
		Data:           data,
	}, testAppOriginator)
	require.NoError(t, err)

	verifyResult, err := transceiver.VerifyHMAC(ctx, wallet.VerifyHMACArgs{
		EncryptionArgs: args,
		Data:           data,
		HMAC:           createResult.HMAC,
	}, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, verifyResult.Valid)
}

func TestTransceiverCreateSignature(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)

	result, err := transceiver.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "k1",
		},
		Data: []byte("message to sign"),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result.Signature)
}

func TestTransceiverVerifySignature(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)
	ctx := context.Background()

	args := wallet.EncryptionArgs{
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		KeyID: "k1",
	}
	data := []byte("message to sign")

	createResult, err := transceiver.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: args,
		Data:           data,
	}, testAppOriginator)
	require.NoError(t, err)

	verifyResult, err := transceiver.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: args,
		Signature:      createResult.Signature,
		Data:           data,
	}, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, verifyResult.Valid)
}

func TestTransceiverAcquireCertificate(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	ct, _ := wallet.CertificateTypeFromString("testcert12345678901234567890123")
	var serial wallet.SerialNumber
	copy(serial[:], []byte("serial1234567890123456789012345"))
	// Certificate serializer requires non-nil Subject, Certifier, RevocationOutpoint and non-empty Type
	outpoint := &transaction.Outpoint{}
	expectedCert := &wallet.Certificate{
		Type:               ct,
		Subject:            subjectKey.PubKey(),
		Certifier:          certifierKey.PubKey(),
		SerialNumber:       serial,
		RevocationOutpoint: outpoint,
	}
	tw.OnAcquireCertificate().ReturnSuccess(expectedCert)

	// Certifier, AcquisitionProtocol and CertifierUrl must be set for the serializer (issuance path)
	result, err := transceiver.AcquireCertificate(context.Background(), wallet.AcquireCertificateArgs{
		Certifier:           certifierKey.PubKey(),
		AcquisitionProtocol: wallet.AcquisitionProtocolIssuance,
		CertifierUrl:        "https://certifier.example.com",
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTransceiverListCertificates(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	// TotalCertificates must equal len(Certificates) for the serializer
	tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{TotalCertificates: 0, Certificates: []wallet.CertificateResult{}})

	result, err := transceiver.ListCertificates(context.Background(), wallet.ListCertificatesArgs{}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), result.TotalCertificates)
}

func TestTransceiverProveCertificate(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
		KeyringForVerifier: map[string]string{},
	})

	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	ct, _ := wallet.CertificateTypeFromString("provecert12345678901234567890123")
	var serial wallet.SerialNumber
	copy(serial[:], []byte("serial1234567890123456789012345"))

	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	result, err := transceiver.ProveCertificate(context.Background(), wallet.ProveCertificateArgs{
		Certificate: wallet.Certificate{
			Type:               ct,
			Subject:            certifierKey.PubKey(),
			Certifier:          certifierKey.PubKey(),
			SerialNumber:       serial,
			RevocationOutpoint: &transaction.Outpoint{},
		},
		Verifier: verifierKey.PubKey(),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTransceiverRelinquishCertificate(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnRelinquishCertificate().ReturnSuccess(&wallet.RelinquishCertificateResult{Relinquished: true})

	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	ct, _ := wallet.CertificateTypeFromString("relinquishcert12345678901234567")
	var serial wallet.SerialNumber
	copy(serial[:], []byte("serial1234567890123456789012345"))

	result, err := transceiver.RelinquishCertificate(context.Background(), wallet.RelinquishCertificateArgs{
		Type:         ct,
		SerialNumber: serial,
		Certifier:    certifierKey.PubKey(),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, result.Relinquished)
}

func TestTransceiverDiscoverByIdentityKey(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	// TotalCertificates must equal len(Certificates) for the serializer
	tw.OnDiscoverByIdentityKey().ReturnSuccess(&wallet.DiscoverCertificatesResult{
		TotalCertificates: 0,
		Certificates:      []wallet.IdentityCertificate{},
	})

	privKey, _ := ec.NewPrivateKey()
	result, err := transceiver.DiscoverByIdentityKey(context.Background(), wallet.DiscoverByIdentityKeyArgs{
		IdentityKey: privKey.PubKey(),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), result.TotalCertificates)
}

func TestTransceiverDiscoverByAttributes(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	// TotalCertificates must equal len(Certificates) for the serializer
	tw.OnDiscoverByAttributes().ReturnSuccess(&wallet.DiscoverCertificatesResult{
		TotalCertificates: 0,
		Certificates:      []wallet.IdentityCertificate{},
	})

	result, err := transceiver.DiscoverByAttributes(context.Background(), wallet.DiscoverByAttributesArgs{
		Attributes: map[string]string{"key": "val"},
	}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), result.TotalCertificates)
}

func TestTransceiverIsAuthenticated(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnIsAuthenticated().ReturnSuccess(&wallet.AuthenticatedResult{Authenticated: true})

	result, err := transceiver.IsAuthenticated(context.Background(), nil, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, result.Authenticated)
}

func TestTransceiverWaitForAuthentication(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnWaitForAuthentication().ReturnSuccess(&wallet.AuthenticatedResult{Authenticated: true})

	result, err := transceiver.WaitForAuthentication(context.Background(), nil, testAppOriginator)
	require.NoError(t, err)
	assert.True(t, result.Authenticated)
}

func TestTransceiverGetHeight(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnGetHeight().ReturnSuccess(&wallet.GetHeightResult{Height: 999})

	result, err := transceiver.GetHeight(context.Background(), nil, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, uint32(999), result.Height)
}

func TestTransceiverGetHeaderForHeight(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnGetHeaderForHeight().ReturnSuccess(&wallet.GetHeaderResult{Header: []byte{0xAB, 0xCD}})

	result, err := transceiver.GetHeaderForHeight(context.Background(), wallet.GetHeaderArgs{Height: 100}, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xAB, 0xCD}, result.Header)
}

func TestTransceiverGetNetwork(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{Network: wallet.NetworkMainnet})

	result, err := transceiver.GetNetwork(context.Background(), nil, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, wallet.NetworkMainnet, result.Network)
}

func TestTransceiverGetVersion(t *testing.T) {
	tw, transceiver := buildTransceiverPair(t)
	tw.OnGetVersion().ReturnSuccess(&wallet.GetVersionResult{Version: "1.2.3"})

	result, err := transceiver.GetVersion(context.Background(), nil, testAppOriginator)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", result.Version)
}

func TestTransceiverRevealCounterpartyKeyLinkage(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)

	counterpartyKey, _ := ec.NewPrivateKey()
	verifierKey, _ := ec.NewPrivateKey()

	result, err := transceiver.RevealCounterpartyKeyLinkage(context.Background(), wallet.RevealCounterpartyKeyLinkageArgs{
		Counterparty: counterpartyKey.PubKey(),
		Verifier:     verifierKey.PubKey(),
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.EncryptedLinkage)
}

func TestTransceiverRevealSpecificKeyLinkage(t *testing.T) {
	_, transceiver := buildTransceiverPair(t)

	counterpartyKey, _ := ec.NewPrivateKey()
	verifierKey, _ := ec.NewPrivateKey()

	result, err := transceiver.RevealSpecificKeyLinkage(context.Background(), wallet.RevealSpecificKeyLinkageArgs{
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: counterpartyKey.PubKey(),
		},
		Verifier: verifierKey.PubKey(),
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		KeyID: "k1",
	}, testAppOriginator)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

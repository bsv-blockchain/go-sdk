package substrates_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
	"github.com/stretchr/testify/require"
)

type VectorTest struct {
	Filename string
	IsResult bool
	Object   any
	Skip     bool
}

func base64ToBytes(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestVectors(t *testing.T) {
	privKey, err := ec.PrivateKeyFromHex("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")
	require.NoError(t, err)
	const PubKeyBase64 = "AlrUOiKsONC8H4usqrsyO11jRwO3p3TEJo9qCeTd95CX"
	pubKey, err := ec.PublicKeyFromString("025ad43a22ac38d0bc1f8bacaabb323b5d634703b7a774c4268f6a09e4ddf79097")
	require.NoError(t, err)
	require.Equal(t, privKey.PubKey(), pubKey)

	counterparty := tu.GetPKFromHex(t, "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")
	verifier := tu.GetPKFromHex(t, "03b106dae20ae8fca0f4e8983d974c4b583054573eecdcdcfad261c035415ce1ee")
	prover := tu.GetPKFromHex(t, "02e14bb4fbcd33d02a0bad2b60dcd14c36506fa15599e3c28ec87eff440a97a2b8")
	certifier := tu.GetPKFromHex(t, "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")

	const nameKeyBase64 = "bmFtZS1rZXk="
	typeArray := tu.GetByte32FromBase64String(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0ZXN0LXR5cGU=")
	serialArray := tu.GetByte32FromBase64String(t, "AAAAAAAAAAAAAAAAAAB0ZXN0LXNlcmlhbC1udW1iZXI=")
	serialNumber := wallet.SerialNumber(serialArray)

	ref, err := base64.StdEncoding.DecodeString("dGVzdA==")
	require.NoError(t, err)

	outpoint, err := transaction.OutpointFromString("aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d.0")
	require.NoError(t, err)

	lockScript, err := hex.DecodeString("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	require.NoError(t, err)
	lockingScript, err := hex.DecodeString("76a9143cf53c49c322d9d811728182939aee2dca087f9888ac")
	require.NoError(t, err, "decoding locking script should not error")

	// pk = 95c5931552e547d72a292e9d6f59eef2b9f7e1576d8c7b49731b505117c0cdfa
	// msg = test message
	const sigHex = "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a"
	signature := tu.GetSigFromHex(t, sigHex)

	txID, err := chainhash.NewHashFromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	require.NoError(t, err, "creating txID from hex should not error")

	tests := []VectorTest{{
		Filename: "abortAction-simple-args",
		Object: wallet.AbortActionArgs{
			Reference: base64ToBytes(t, "dGVzdA=="),
		},
	}, {
		Filename: "abortAction-simple-result",
		IsResult: true,
		Object: wallet.AbortActionResult{
			Aborted: true,
		},
	}, {
		Filename: "signAction-simple-args",
		Object: wallet.SignActionArgs{
			Reference: ref,
			Spends: map[uint32]wallet.SignActionSpend{
				0: {
					UnlockingScript: lockScript,
				},
			},
		},
	}, {
		Filename: "createAction-1-out-args",
		Object: wallet.CreateActionArgs{
			Description: "Test action description",
			Outputs: []wallet.CreateActionOutput{{
				LockingScript:      lockingScript,
				Satoshis:           999,
				OutputDescription:  "Test output",
				Basket:             "test-basket",
				CustomInstructions: "Test instructions",
				Tags:               []string{"test-tag"},
			}},
			Labels: []string{"test-label"},
		},
	}, {
		Filename: "listActions-simple-args",
		Object: wallet.ListActionsArgs{
			Labels:         []string{"test-label"},
			Limit:          util.Uint32Ptr(10),
			IncludeOutputs: util.BoolPtr(true),
		},
	}, {
		Filename: "listActions-simple-result",
		IsResult: true,
		Object: wallet.ListActionsResult{
			TotalActions: 1,
			Actions: []wallet.Action{{
				Txid:        *txID,
				Satoshis:    1000,
				Status:      wallet.ActionStatusCompleted,
				IsOutgoing:  true,
				Description: "Test transaction 1",
				Version:     1,
				LockTime:    10,
				Outputs: []wallet.ActionOutput{{
					OutputIndex:       1,
					OutputDescription: "Test output",
					Basket:            "basket1",
					Spendable:         true,
					Tags:              []string{"tag1", "tag2"},
					Satoshis:          1000,
					LockingScript:     lockingScript,
				}},
			}},
		},
	}, {
		Filename: "internalizeAction-simple-args",
		Object: wallet.InternalizeActionArgs{
			Tx: []byte{1, 2, 3, 4},
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    wallet.InternalizeProtocolWalletPayment,
					PaymentRemittance: &wallet.Payment{
						DerivationPrefix:  []byte("prefix"),
						DerivationSuffix:  []byte("suffix"),
						SenderIdentityKey: verifier,
					},
				},
				{
					OutputIndex: 1,
					Protocol:    wallet.InternalizeProtocolBasketInsertion,
					InsertionRemittance: &wallet.BasketInsertion{
						Basket:             "test-basket",
						CustomInstructions: "instruction",
						Tags:               []string{"tag1", "tag2"},
					},
				},
			},
			Description:    "test transaction",
			Labels:         []string{"label1", "label2"},
			SeekPermission: util.BoolPtr(true),
		},
	}, {
		Filename: "internalizeAction-simple-result",
		IsResult: true,
		Object: wallet.InternalizeActionResult{
			Accepted: true,
		},
	}, {
		Filename: "listOutputs-simple-args",
		Object: wallet.ListOutputsArgs{
			Basket:       "test-basket",
			Tags:         []string{"tag1", "tag2"},
			TagQueryMode: wallet.QueryModeAny,
			Include:      wallet.OutputIncludeLockingScripts,
			IncludeTags:  util.BoolPtr(true),
			Limit:        util.Uint32Ptr(10),
		},
	}, {
		Filename: "listOutputs-simple-result",
		IsResult: true,
		Object: wallet.ListOutputsResult{
			TotalOutputs: 2,
			BEEF:         []byte{1, 2, 3, 4},
			Outputs: []wallet.Output{{
				Satoshis:  1000,
				Spendable: true,
				Outpoint:  *tu.OutpointFromString(t, fmt.Sprintf("%s.0", txID)),
			}, {
				Satoshis:  5000,
				Spendable: true,
				Outpoint:  *tu.OutpointFromString(t, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.2"),
			}},
		},
	}, {
		Filename: "relinquishOutput-simple-args",
		Object: wallet.RelinquishOutputArgs{
			Basket: "test-basket",
			Output: *tu.OutpointFromString(t, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.2"),
		},
	}, {
		Filename: "relinquishOutput-simple-result",
		IsResult: true,
		Object: wallet.RelinquishOutputResult{
			Relinquished: true,
		},
	}, {
		Filename: "getPublicKey-simple-args",
		Object: wallet.GetPublicKeyArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "tests",
				},
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: counterparty,
				},
				KeyID:            "test-key-id",
				Privileged:       true,
				PrivilegedReason: "privileged reason",
				SeekPermission:   true,
			},
		},
	}, {
		Filename: "getPublicKey-simple-result",
		IsResult: true,
		Object: wallet.GetPublicKeyResult{
			PublicKey: pubKey,
		},
	}, {
		Filename: "revealCounterpartyKeyLinkage-simple-args",
		Object: wallet.RevealCounterpartyKeyLinkageArgs{
			Counterparty:     counterparty,
			Verifier:         verifier,
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		Filename: "revealCounterpartyKeyLinkage-simple-result",
		IsResult: true,
		Object: wallet.RevealCounterpartyKeyLinkageResult{
			Prover:                prover,
			Counterparty:          counterparty,
			Verifier:              verifier,
			RevelationTime:        "2023-01-01T00:00:00Z",
			EncryptedLinkage:      []byte{1, 2, 3, 4},
			EncryptedLinkageProof: []byte{5, 6, 7, 8},
		},
	}, {
		Filename: "revealSpecificKeyLinkage-simple-args",
		Object: wallet.RevealSpecificKeyLinkageArgs{
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterparty,
			},
			Verifier: verifier,
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "tests",
			},
			KeyID:            "test-key-id",
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		Filename: "revealSpecificKeyLinkage-simple-result",
		IsResult: true,
		Object: wallet.RevealSpecificKeyLinkageResult{
			EncryptedLinkage:      []byte{1, 2, 3, 4},
			EncryptedLinkageProof: []byte{5, 6, 7, 8},
			Prover:                prover,
			Verifier:              verifier,
			Counterparty:          counterparty,
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "tests",
			},
			KeyID:     "test-key-id",
			ProofType: 1,
		},
	}, {
		Filename: "encrypt-simple-args",
		Object: wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Plaintext: []byte{1, 2, 3, 4},
		},
	}, {
		Filename: "encrypt-simple-result",
		IsResult: true,
		Object: wallet.EncryptResult{
			Ciphertext: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	}, {
		Filename: "decrypt-simple-args",
		Object: wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			},
			Ciphertext: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	}, {
		Filename: "decrypt-simple-result",
		IsResult: true,
		Object: wallet.DecryptResult{
			Plaintext: []byte{1, 2, 3, 4},
		},
	}, {
		Filename: "createHMAC-simple-args",
		Object: wallet.CreateHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Data: []byte{10, 20, 30, 40},
		},
	}, {
		Filename: "createHMAC-simple-result",
		IsResult: true,
		Object: wallet.CreateHMACResult{
			HMAC: [32]byte{50, 60, 70, 80, 90, 100, 110, 120,
				50, 60, 70, 80, 90, 100, 110, 120,
				50, 60, 70, 80, 90, 100, 110, 120,
				50, 60, 70, 80, 90, 100, 110, 120},
		},
	}, {
		Filename: "verifyHMAC-simple-args",
		Object: wallet.VerifyHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Data: []byte{10, 20, 30, 40},
			HMAC: [32]byte{50, 60, 70, 80, 90, 100, 110, 120,
				50, 60, 70, 80, 90, 100, 110, 120,
				50, 60, 70, 80, 90, 100, 110, 120,
				50, 60, 70, 80, 90, 100, 110, 120},
		},
	}, {
		Filename: "verifyHMAC-simple-result",
		IsResult: true,
		Object: wallet.VerifyHMACResult{
			Valid: true,
		},
	}, {
		Filename: "createSignature-simple-args",
		Object: wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Data: []byte{11, 22, 33, 44},
			// HashToDirectlySign: nil, // Omitting for simple test
		},
	}, {
		Filename: "createSignature-simple-result",
		IsResult: true,
		Object: wallet.CreateSignatureResult{
			Signature: tu.GetSigFromHex(t, "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020101"),
		},
	}, {
		Filename: "verifySignature-simple-args",
		Object: wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Data:      []byte{11, 22, 33, 44},
			Signature: tu.GetSigFromHex(t, "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020101"),
		},
	}, {
		Filename: "verifySignature-simple-result",
		IsResult: true,
		Object: wallet.VerifySignatureResult{
			Valid: true,
		},
	}, {
		Filename: "acquireCertificate-simple-args",
		Object: wallet.AcquireCertificateArgs{
			Type:                typeArray,
			Certifier:           certifier,
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			Fields:              map[string]string{"name": "Alice", "email": "alice@example.com"},
			SerialNumber:        &serialNumber,
			RevocationOutpoint:  outpoint,
			Signature:           signature,
			KeyringRevealer:     &wallet.KeyringRevealer{PubKey: pubKey},
			KeyringForSubject:   map[string]string{"field1": "key1", "field2": "key2"},
			Privileged:          util.BoolPtr(false),
		},
	}, {
		Filename: "acquireCertificate-issuance-args",
		Object: wallet.AcquireCertificateArgs{
			Type:                typeArray,
			Certifier:           certifier,
			AcquisitionProtocol: wallet.AcquisitionProtocolIssuance,
			Fields:              map[string]string{"name": "Alice", "email": "alice@example.com"},
			CertifierUrl:        "https://certifier.example.com",
			Privileged:          util.BoolPtr(false),
		},
	}, {
		Filename: "acquireCertificate-simple-result",
		IsResult: true,
		Object: wallet.Certificate{
			Type:               typeArray,
			SerialNumber:       serialArray,
			Subject:            pubKey,       // Use key from test setup
			Certifier:          counterparty, // Use key from test setup
			RevocationOutpoint: outpoint,
			Fields:             map[string]string{"name": "Alice", "email": "alice@example.com"},
			Signature:          signature,
		},
	}, {
		Filename: "listCertificates-simple-args",
		Object: wallet.ListCertificatesArgs{
			Certifiers:       []*ec.PublicKey{counterparty, verifier},
			Types:            []wallet.CertificateType{tu.GetByte32FromBase64String(t, "dGVzdC10eXBlMSAgICAgICAgICAgICAgICAgICAgICA="), tu.GetByte32FromBase64String(t, "dGVzdC10eXBlMiAgICAgICAgICAgICAgICAgICAgICA=")},
			Limit:            util.Uint32Ptr(5),
			Offset:           util.Uint32Ptr(0),
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "list-cert-reason",
		},
	}, {
		Filename: "listCertificates-simple-result",
		IsResult: true,
		Skip:     true, // ts-sdk doesn't serialize Keyring and Verifier, so this test fails
		Object: wallet.ListCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.CertificateResult{{
				Certificate: wallet.Certificate{
					Type:               typeArray,
					SerialNumber:       serialArray,
					Subject:            pubKey,
					Certifier:          counterparty,
					RevocationOutpoint: outpoint,
					Fields:             map[string]string{"name": "Alice", "email": "alice@example.com"},
					Signature:          signature,
				},
			}},
		},
	}, {
		Filename: "listCertificates-full-result",
		IsResult: true,
		Skip:     true, // ts-sdk doesn't serialize Keyring and Verifier, so this test fails
		Object: wallet.ListCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.CertificateResult{{
				Certificate: wallet.Certificate{
					Type:               typeArray,
					SerialNumber:       serialArray,
					Subject:            pubKey,
					Certifier:          counterparty,
					RevocationOutpoint: outpoint,
					Fields:             map[string]string{"name": "Alice", "email": "alice@example.com"},
					Signature:          signature,
				},
				Keyring:  map[string]string{"field1": "key1", "field2": "key2"},
				Verifier: verifier.ToDER(),
			}},
		},
	}, {
		Filename: "proveCertificate-simple-args",
		Object: wallet.ProveCertificateArgs{
			Certificate: wallet.Certificate{
				Type:               typeArray,
				SerialNumber:       serialArray,
				Subject:            pubKey,
				Certifier:          counterparty,
				RevocationOutpoint: outpoint,
				Fields:             map[string]string{"email": "alice@example.com", "name": "Alice"},
				Signature:          signature,
			},
			FieldsToReveal:   []string{"name"},
			Verifier:         verifier,
			Privileged:       util.BoolPtr(false),
			PrivilegedReason: "prove-reason",
		},
	}, {
		Filename: "proveCertificate-simple-result",
		IsResult: true,
		Object: wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"name": nameKeyBase64},
		},
	}, {
		Filename: "relinquishCertificate-simple-args",
		Object: wallet.RelinquishCertificateArgs{
			Type:         typeArray,
			SerialNumber: serialArray,
			Certifier:    certifier,
		},
	}, {
		Filename: "relinquishCertificate-simple-result",
		IsResult: true,
		Object: wallet.RelinquishCertificateResult{
			Relinquished: true,
		},
	}, {
		Filename: "discoverByIdentityKey-simple-args",
		Object: wallet.DiscoverByIdentityKeyArgs{
			IdentityKey:    counterparty,
			Limit:          util.Uint32Ptr(10),
			Offset:         util.Uint32Ptr(0),
			SeekPermission: util.BoolPtr(true),
		},
	}, {
		Filename: "discoverByIdentityKey-simple-result",
		IsResult: true,
		Object: wallet.DiscoverCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.IdentityCertificate{
				{
					Certificate: wallet.Certificate{
						Type:               typeArray,
						SerialNumber:       serialArray,
						Subject:            pubKey,
						Certifier:          counterparty,
						RevocationOutpoint: outpoint,
						Fields:             map[string]string{"name": "Alice", "email": "alice@example.com"},
						Signature:          signature,
					},
					CertifierInfo: wallet.IdentityCertifier{
						Name:        "Test Certifier",
						IconUrl:     "https://example.com/icon.png",
						Description: "Certifier description",
						Trust:       5,
					},
					PubliclyRevealedKeyring: map[string]string{"pubField": PubKeyBase64},
					DecryptedFields:         map[string]string{"name": "Alice"},
				},
			},
		},
	}, {
		Filename: "discoverByAttributes-simple-args",
		Object: wallet.DiscoverByAttributesArgs{
			Attributes:     map[string]string{"email": "alice@example.com", "role": "admin"},
			Limit:          util.Uint32Ptr(5),
			Offset:         util.Uint32Ptr(0),
			SeekPermission: util.BoolPtr(false),
		},
	}, {
		Filename: "discoverByAttributes-simple-result",
		IsResult: true,
		Object: wallet.DiscoverCertificatesResult{ // Reusing the same result structure for simplicity
			TotalCertificates: 1,
			Certificates: []wallet.IdentityCertificate{
				{
					Certificate: wallet.Certificate{
						Type:               typeArray,
						SerialNumber:       serialArray,
						Subject:            pubKey,
						Certifier:          counterparty,
						RevocationOutpoint: outpoint,
						Fields:             map[string]string{"name": "Alice", "email": "alice@example.com"},
						Signature:          signature,
					},
					CertifierInfo: wallet.IdentityCertifier{
						Name:        "Test Certifier",
						IconUrl:     "https://example.com/icon.png",
						Description: "Certifier description",
						Trust:       5,
					},
					PubliclyRevealedKeyring: map[string]string{"pubField": PubKeyBase64},
					DecryptedFields:         map[string]string{"name": "Alice"},
				},
			},
		},
	}, {
		Filename: "isAuthenticated-simple-result",
		IsResult: true,
		Object: wallet.AuthenticatedResult{
			Authenticated: true,
		},
	}, {
		// WaitForAuthentication also uses AuthenticatedResult
		Filename: "waitForAuthentication-simple-result",
		IsResult: true,
		Object: wallet.AuthenticatedResult{
			Authenticated: true,
		},
	}, {
		// GetHeight doesn't have specific args
		Filename: "getHeight-simple-result",
		IsResult: true,
		Object: wallet.GetHeightResult{
			Height: 850000,
		},
	}, {
		Filename: "getHeaderForHeight-simple-args",
		Object: wallet.GetHeaderArgs{
			Height: 850000,
		},
	}, {
		Filename: "getHeaderForHeight-simple-result",
		IsResult: true,
		Object: wallet.GetHeaderResult{
			Header: tu.GetByteFromHexString(t, "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"),
		},
	}, {
		Filename: "getNetwork-simple-result",
		IsResult: true,
		Object: wallet.GetNetworkResult{
			Network: wallet.NetworkMainnet,
		},
	}, {
		Filename: "getVersion-simple-result",
		IsResult: true,
		Object: wallet.GetVersionResult{
			Version: "1.0.0",
		},
	}}
	for _, tt := range tests {
		t.Run(tt.Filename, func(t *testing.T) {
			if tt.Skip {
				t.Skip()
			}
			// Read test vector file
			data, err := os.ReadFile(filepath.Join("testdata", tt.Filename+".json"))
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Parse test vector
			var vectorFile map[string]json.RawMessage
			if err := json.Unmarshal(data, &vectorFile); err != nil {
				t.Fatalf("Failed to parse test vector file: %v", err)
			} else if len(vectorFile["json"]) == 0 || len(vectorFile["wire"]) == 0 {
				t.Fatalf("Both json and wire format requried in test vector file")
			}

			// Test JSON marshaling
			t.Run("JSON", func(t *testing.T) {
				// Define a function to check JSON serialization and deserialization
				val := reflect.ValueOf(tt.Object)
				typ := val.Type()

				reflectEmptyObj := reflect.New(typ)
				reflectExpectedObj := reflect.New(typ)
				reflectExpectedObj.Elem().Set(val)
				emptyObj := reflectEmptyObj.Interface()
				expectedObj := reflectExpectedObj.Interface()

				// Unmarshall the vector file into a Go object to compare with test Go object
				require.NoError(t, json.Unmarshal(vectorFile["json"], emptyObj), "Failed unmarshal JSON to object")
				require.EqualValues(t, expectedObj, emptyObj, "Deserialized object mismatch")

				// Marshal the test Go object to JSON to compare with the vector file
				marshaled, err := json.MarshalIndent(expectedObj, "  ", "  ")
				require.NoError(t, err, "Failed to marshal object to JSON")
				require.JSONEq(t, string(vectorFile["json"]), string(marshaled), "Marshaled JSON mismatch") // Use JSONEq for map order robustness
			})

			// TODO: Implement wire tests
			// Currently discrepancies in varInt handling of negative numbers, so most wire tests don't match ts-sdk
			// For now serializer tests verify wire objects are consistent between serializing and deserializing

			// Test wire format serialization
			t.Run("Wire", func(t *testing.T) {
				var wireString string
				require.NoError(t, json.Unmarshal(vectorFile["wire"], &wireString))
				wire, err := hex.DecodeString(wireString)
				require.NoError(t, err)

				var frameCall substrates.Call
				var frameParams []byte
				if tt.IsResult {
					frame, err := serializer.ReadResultFrame(wire)
					require.NoError(t, err)
					frameParams = frame
				} else {
					frame, err := serializer.ReadRequestFrame(wire)
					require.NoError(t, err)
					frameCall = substrates.Call(frame.Call)
					require.Equal(t, frame.Originator, "")
					frameParams = frame.Params
				}

				// Define a function to check wire serialization and deserialization
				checkWireSerialize := func(call substrates.Call, obj any,
					serialized []byte, errSerialize error, deserialized any, errDeserialize error) {
					require.Equalf(t, frameCall, call, "Frame call mismatch: call=%d", call)
					require.NoErrorf(t, errSerialize, "Serializing object error: call=%d", call)
					var serializedWithFrame []byte
					if tt.IsResult {
						serializedWithFrame = serializer.WriteResultFrame(serialized, nil)
					} else {
						serializedWithFrame = serializer.WriteRequestFrame(serializer.RequestFrame{
							Call:   byte(call),
							Params: serialized,
						})
					}
					require.NoErrorf(t, errDeserialize, "Deserializing wire error: call=%d", call)
					require.EqualValuesf(t, obj, deserialized, "Deserialized object mismatch: call=%d", call)
					require.Equalf(t, wire, serializedWithFrame, "Serialized wire mismatch: call=%d", call)
				}

				// Serialize and deserialize using the wire binary format
				// TODO: Use reflect instead of switch statement, similar to JSON test
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					serialized, err1 := serializer.SerializeAbortActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeAbortActionArgs(frameParams)
					checkWireSerialize(substrates.CallAbortAction, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateActionArgs:
					serialized, err1 := serializer.SerializeCreateActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeCreateActionArgs(frameParams)
					checkWireSerialize(substrates.CallCreateAction, &obj, serialized, err1, deserialized, err2)
				case wallet.AbortActionResult:
					serialized, err1 := serializer.SerializeAbortActionResult(&obj)
					deserialized, err2 := serializer.DeserializeAbortActionResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.SignActionArgs:
					serialized, err1 := serializer.SerializeSignActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeSignActionArgs(frameParams)
					checkWireSerialize(substrates.CallSignAction, &obj, serialized, err1, deserialized, err2)
				case wallet.InternalizeActionArgs:
					serialized, err1 := serializer.SerializeInternalizeActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeInternalizeActionArgs(frameParams)
					checkWireSerialize(substrates.CallInternalizeAction, &obj, serialized, err1, deserialized, err2)
				case wallet.InternalizeActionResult:
					serialized, err1 := serializer.SerializeInternalizeActionResult(&obj)
					deserialized, err2 := serializer.DeserializeInternalizeActionResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.EncryptArgs:
					serialized, err1 := serializer.SerializeEncryptArgs(&obj)
					deserialized, err2 := serializer.DeserializeEncryptArgs(frameParams)
					checkWireSerialize(substrates.CallEncrypt, &obj, serialized, err1, deserialized, err2)
				case wallet.EncryptResult:
					serialized, err1 := serializer.SerializeEncryptResult(&obj)
					deserialized, err2 := serializer.DeserializeEncryptResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.DecryptArgs:
					serialized, err1 := serializer.SerializeDecryptArgs(&obj)
					deserialized, err2 := serializer.DeserializeDecryptArgs(frameParams)
					checkWireSerialize(substrates.CallDecrypt, &obj, serialized, err1, deserialized, err2)
				case wallet.DecryptResult:
					serialized, err1 := serializer.SerializeDecryptResult(&obj)
					deserialized, err2 := serializer.DeserializeDecryptResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateHMACArgs:
					serialized, err1 := serializer.SerializeCreateHMACArgs(&obj)
					deserialized, err2 := serializer.DeserializeCreateHMACArgs(frameParams)
					checkWireSerialize(substrates.CallCreateHMAC, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateHMACResult:
					serialized, err1 := serializer.SerializeCreateHMACResult(&obj)
					deserialized, err2 := serializer.DeserializeCreateHMACResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.VerifyHMACArgs:
					serialized, err1 := serializer.SerializeVerifyHMACArgs(&obj)
					deserialized, err2 := serializer.DeserializeVerifyHMACArgs(frameParams)
					checkWireSerialize(substrates.CallVerifyHMAC, &obj, serialized, err1, deserialized, err2)
				case wallet.VerifyHMACResult:
					serialized, err1 := serializer.SerializeVerifyHMACResult(&obj)
					deserialized, err2 := serializer.DeserializeVerifyHMACResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateSignatureArgs:
					serialized, err1 := serializer.SerializeCreateSignatureArgs(&obj)
					deserialized, err2 := serializer.DeserializeCreateSignatureArgs(frameParams)
					checkWireSerialize(substrates.CallCreateSignature, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateSignatureResult:
					serialized, err1 := serializer.SerializeCreateSignatureResult(&obj)
					deserialized, err2 := serializer.DeserializeCreateSignatureResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.VerifySignatureArgs:
					serialized, err1 := serializer.SerializeVerifySignatureArgs(&obj)
					deserialized, err2 := serializer.DeserializeVerifySignatureArgs(frameParams)
					checkWireSerialize(substrates.CallVerifySignature, &obj, serialized, err1, deserialized, err2)
				case wallet.VerifySignatureResult:
					serialized, err1 := serializer.SerializeVerifySignatureResult(&obj)
					deserialized, err2 := serializer.DeserializeVerifySignatureResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.AcquireCertificateArgs:
					serialized, err1 := serializer.SerializeAcquireCertificateArgs(&obj)
					deserialized, err2 := serializer.DeserializeAcquireCertificateArgs(frameParams)
					checkWireSerialize(substrates.CallAcquireCertificate, &obj, serialized, err1, deserialized, err2)
				case wallet.Certificate:
					serialized, err1 := serializer.SerializeCertificate(&obj)
					deserialized, err2 := serializer.DeserializeCertificate(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.ListCertificatesArgs:
					serialized, err1 := serializer.SerializeListCertificatesArgs(&obj)
					deserialized, err2 := serializer.DeserializeListCertificatesArgs(frameParams)
					checkWireSerialize(substrates.CallListCertificates, &obj, serialized, err1, deserialized, err2)
				case wallet.ListCertificatesResult:
					serialized, err1 := serializer.SerializeListCertificatesResult(&obj)
					deserialized, err2 := serializer.DeserializeListCertificatesResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.ProveCertificateArgs:
					serialized, err1 := serializer.SerializeProveCertificateArgs(&obj)
					deserialized, err2 := serializer.DeserializeProveCertificateArgs(frameParams)
					checkWireSerialize(substrates.CallProveCertificate, &obj, serialized, err1, deserialized, err2)
				case wallet.ProveCertificateResult:
					serialized, err1 := serializer.SerializeProveCertificateResult(&obj)
					deserialized, err2 := serializer.DeserializeProveCertificateResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.RelinquishCertificateArgs:
					serialized, err1 := serializer.SerializeRelinquishCertificateArgs(&obj)
					deserialized, err2 := serializer.DeserializeRelinquishCertificateArgs(frameParams)
					checkWireSerialize(substrates.CallRelinquishCertificate, &obj, serialized, err1, deserialized, err2)
				case wallet.RelinquishCertificateResult:
					serialized, err1 := serializer.SerializeRelinquishCertificateResult(&obj)
					deserialized, err2 := serializer.DeserializeRelinquishCertificateResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.DiscoverByIdentityKeyArgs:
					serialized, err1 := serializer.SerializeDiscoverByIdentityKeyArgs(&obj)
					deserialized, err2 := serializer.DeserializeDiscoverByIdentityKeyArgs(frameParams)
					checkWireSerialize(substrates.CallDiscoverByIdentityKey, &obj, serialized, err1, deserialized, err2)
				case wallet.DiscoverCertificatesResult:
					serialized, err1 := serializer.SerializeDiscoverCertificatesResult(&obj)
					deserialized, err2 := serializer.DeserializeDiscoverCertificatesResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.DiscoverByAttributesArgs:
					serialized, err1 := serializer.SerializeDiscoverByAttributesArgs(&obj)
					deserialized, err2 := serializer.DeserializeDiscoverByAttributesArgs(frameParams)
					checkWireSerialize(substrates.CallDiscoverByAttributes, &obj, serialized, err1, deserialized, err2)
				case wallet.AuthenticatedResult:
					if strings.Contains(tt.Filename, "wait") {
						serialized, err1 := serializer.SerializeWaitAuthenticatedResult(&obj)
						deserialized, err2 := serializer.DeserializeWaitAuthenticatedResult(frameParams)
						checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
					} else {
						serialized, err1 := serializer.SerializeIsAuthenticatedResult(&obj)
						deserialized, err2 := serializer.DeserializeIsAuthenticatedResult(frameParams)
						checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
					}
				case wallet.GetHeightResult:
					serialized, err1 := serializer.SerializeGetHeightResult(&obj)
					deserialized, err2 := serializer.DeserializeGetHeightResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.GetHeaderArgs:
					serialized, err1 := serializer.SerializeGetHeaderArgs(&obj)
					deserialized, err2 := serializer.DeserializeGetHeaderArgs(frameParams)
					checkWireSerialize(substrates.CallGetHeaderForHeight, &obj, serialized, err1, deserialized, err2)
				case wallet.GetHeaderResult:
					serialized, err1 := serializer.SerializeGetHeaderResult(&obj)
					deserialized, err2 := serializer.DeserializeGetHeaderResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.GetNetworkResult:
					serialized, err1 := serializer.SerializeGetNetworkResult(&obj)
					deserialized, err2 := serializer.DeserializeGetNetworkResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.GetVersionResult:
					serialized, err1 := serializer.SerializeGetVersionResult(&obj)
					deserialized, err2 := serializer.DeserializeGetVersionResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.GetPublicKeyArgs:
					serialized, err1 := serializer.SerializeGetPublicKeyArgs(&obj)
					deserialized, err2 := serializer.DeserializeGetPublicKeyArgs(frameParams)
					checkWireSerialize(substrates.CallGetPublicKey, &obj, serialized, err1, deserialized, err2)
				case wallet.GetPublicKeyResult:
					serialized, err1 := serializer.SerializeGetPublicKeyResult(&obj)
					deserialized, err2 := serializer.DeserializeGetPublicKeyResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.RevealCounterpartyKeyLinkageArgs:
					serialized, err1 := serializer.SerializeRevealCounterpartyKeyLinkageArgs(&obj)
					deserialized, err2 := serializer.DeserializeRevealCounterpartyKeyLinkageArgs(frameParams)
					checkWireSerialize(substrates.CallRevealCounterpartyKeyLinkage, &obj, serialized, err1, deserialized, err2)
				case wallet.RevealCounterpartyKeyLinkageResult:
					serialized, err1 := serializer.SerializeRevealCounterpartyKeyLinkageResult(&obj)
					deserialized, err2 := serializer.DeserializeRevealCounterpartyKeyLinkageResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.RevealSpecificKeyLinkageArgs:
					serialized, err1 := serializer.SerializeRevealSpecificKeyLinkageArgs(&obj)
					deserialized, err2 := serializer.DeserializeRevealSpecificKeyLinkageArgs(frameParams)
					checkWireSerialize(substrates.CallRevealSpecificKeyLinkage, &obj, serialized, err1, deserialized, err2)
				case wallet.RevealSpecificKeyLinkageResult:
					serialized, err1 := serializer.SerializeRevealSpecificKeyLinkageResult(&obj)
					deserialized, err2 := serializer.DeserializeRevealSpecificKeyLinkageResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.ListActionsArgs:
					serialized, err1 := serializer.SerializeListActionsArgs(&obj)
					deserialized, err2 := serializer.DeserializeListActionsArgs(frameParams)
					checkWireSerialize(substrates.CallListActions, &obj, serialized, err1, deserialized, err2)
				case wallet.ListActionsResult:
					serialized, err1 := serializer.SerializeListActionsResult(&obj)
					deserialized, err2 := serializer.DeserializeListActionsResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.ListOutputsArgs:
					serialized, err1 := serializer.SerializeListOutputsArgs(&obj)
					deserialized, err2 := serializer.DeserializeListOutputsArgs(frameParams)
					checkWireSerialize(substrates.CallListOutputs, &obj, serialized, err1, deserialized, err2)
				case wallet.ListOutputsResult:
					serialized, err1 := serializer.SerializeListOutputsResult(&obj)
					deserialized, err2 := serializer.DeserializeListOutputsResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.RelinquishOutputArgs:
					serialized, err1 := serializer.SerializeRelinquishOutputArgs(&obj)
					deserialized, err2 := serializer.DeserializeRelinquishOutputArgs(frameParams)
					checkWireSerialize(substrates.CallRelinquishOutput, &obj, serialized, err1, deserialized, err2)
				case wallet.RelinquishOutputResult:
					serialized, err1 := serializer.SerializeRelinquishOutputResult(&obj)
					deserialized, err2 := serializer.DeserializeRelinquishOutputResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})
		})
	}
}

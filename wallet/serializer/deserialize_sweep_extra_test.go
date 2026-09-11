package serializer

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// runDeserializeSweep verifies a full round-trip decode succeeds, an empty input
// errors, and then feeds every truncated prefix to the deserializer to exercise
// the short-buffer error branches. Truncated calls must never panic.
func runDeserializeSweep(t *testing.T, good []byte, deser func([]byte) error) {
	t.Helper()
	require.NoError(t, deser(good), "full buffer should deserialize without error")
	require.Error(t, deser(nil), "empty buffer should error")
	for n := 1; n < len(good); n++ {
		_ = deser(good[:n]) // exercise truncation error paths
	}
}

func TestDeserializeTruncationSweep(t *testing.T) {
	t.Parallel()

	pub := xtPub(t)
	sig := newTestSignature(t)
	op := tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0")
	hash := tu.HashFromString(t, "b1f4d452814bba0ac422318083850b706d5f23ce232c789eefe5cbdcf2cc47de")
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	serOK := func(data []byte, err error) []byte {
		t.Helper()
		require.NoError(t, err, "serializing the valid fixture should not error")
		require.NotEmpty(t, data, "serialized fixture should not be empty")
		return data
	}

	encArgs := wallet.EncryptionArgs{
		ProtocolID:       wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "p"},
		KeyID:            "k",
		Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: pub},
		Privileged:       true,
		PrivilegedReason: "r",
		SeekPermission:   true,
	}

	t.Run("AcquireCertificateArgs", func(t *testing.T) {
		args := &wallet.AcquireCertificateArgs{
			Type:                tu.GetByte32FromString("test-type"),
			Certifier:           pub,
			AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
			Fields:              map[string]string{"f1": "v1"},
			SerialNumber:        &wallet.SerialNumber{1},
			RevocationOutpoint:  op,
			Signature:           sig,
			KeyringRevealer:     &wallet.KeyringRevealer{PubKey: pub},
			KeyringForSubject:   map[string]string{"f1": b64("k1")},
			Privileged:          util.BoolPtr(true),
			PrivilegedReason:    "reason",
		}
		good := serOK(SerializeAcquireCertificateArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeAcquireCertificateArgs(d)
			return err
		})
	})

	t.Run("Certificate", func(t *testing.T) {
		cert := xtValidCertificate(t)
		good := serOK(SerializeCertificate(&cert))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCertificate(d)
			return err
		})
	})

	t.Run("IdentityCertificate", func(t *testing.T) {
		idcert := xtValidIdentityCertificate(t)
		good := serOK(SerializeIdentityCertificate(&idcert))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeIdentityCertificate(util.NewReaderHoldError(d))
			return err
		})
	})

	t.Run("CreateActionArgs", func(t *testing.T) {
		args := &wallet.CreateActionArgs{
			Description: "desc",
			InputBEEF:   []byte{1, 2, 3},
			Inputs: []wallet.CreateActionInput{{
				Outpoint:              *op,
				InputDescription:      "in1",
				UnlockingScript:       []byte{0xab, 0xcd},
				UnlockingScriptLength: 2,
				SequenceNumber:        util.Uint32Ptr(1),
			}},
			Outputs: []wallet.CreateActionOutput{{
				LockingScript:      []byte{0x76, 0xa9},
				Satoshis:           1000,
				OutputDescription:  "out1",
				Basket:             "b1",
				CustomInstructions: "ci",
				Tags:               []string{"t1"},
			}},
			LockTime: util.Uint32Ptr(100),
			Version:  util.Uint32Ptr(1),
			Labels:   []string{"l1"},
			Options: &wallet.CreateActionOptions{
				SignAndProcess:         util.BoolPtr(true),
				AcceptDelayedBroadcast: util.BoolPtr(false),
				TrustSelf:              wallet.TrustSelfKnown,
				KnownTxids:             []chainhash.Hash{hash},
				ReturnTXIDOnly:         util.BoolPtr(true),
				NoSend:                 util.BoolPtr(false),
				NoSendChange:           []transaction.Outpoint{*op},
				SendWith:               []chainhash.Hash{hash},
				RandomizeOutputs:       util.BoolPtr(true),
			},
		}
		good := serOK(SerializeCreateActionArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCreateActionArgs(d)
			return err
		})
	})

	t.Run("CreateActionResult", func(t *testing.T) {
		result := &wallet.CreateActionResult{
			Txid:         tu.GetByte32FromHexString(t, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			Tx:           []byte{1, 2, 3},
			NoSendChange: []transaction.Outpoint{*op},
			SendWithResults: []wallet.SendWithResult{
				{Txid: tu.GetByte32FromHexString(t, "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72"), Status: wallet.ActionResultStatusUnproven},
			},
			SignableTransaction: &wallet.SignableTransaction{Tx: []byte{4, 5, 6}, Reference: []byte("ref")},
		}
		good := serOK(SerializeCreateActionResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCreateActionResult(d)
			return err
		})
	})

	t.Run("CreateHMACArgs", func(t *testing.T) {
		args := &wallet.CreateHMACArgs{EncryptionArgs: encArgs, Data: []byte{1, 2, 3}}
		good := serOK(SerializeCreateHMACArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCreateHMACArgs(d)
			return err
		})
	})

	t.Run("CreateHMACResult", func(t *testing.T) {
		good := serOK(SerializeCreateHMACResult(&wallet.CreateHMACResult{HMAC: [32]byte{1, 2, 3, 4}}))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCreateHMACResult(d)
			return err
		})
	})

	t.Run("CreateSignatureArgs", func(t *testing.T) {
		args := &wallet.CreateSignatureArgs{EncryptionArgs: encArgs, Data: []byte{5, 6, 7, 8}}
		good := serOK(SerializeCreateSignatureArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCreateSignatureArgs(d)
			return err
		})
	})

	t.Run("CreateSignatureResult", func(t *testing.T) {
		good := serOK(SerializeCreateSignatureResult(&wallet.CreateSignatureResult{Signature: sig}))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeCreateSignatureResult(d)
			return err
		})
	})

	t.Run("DecryptArgs", func(t *testing.T) {
		args := &wallet.DecryptArgs{EncryptionArgs: encArgs, Ciphertext: []byte{9, 9, 9}}
		good := serOK(SerializeDecryptArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeDecryptArgs(d)
			return err
		})
	})

	t.Run("EncryptArgs", func(t *testing.T) {
		args := &wallet.EncryptArgs{EncryptionArgs: encArgs, Plaintext: []byte{7, 7, 7}}
		good := serOK(SerializeEncryptArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeEncryptArgs(d)
			return err
		})
	})

	t.Run("DiscoverByAttributesArgs", func(t *testing.T) {
		args := &wallet.DiscoverByAttributesArgs{
			Attributes:     map[string]string{"a": "b"},
			Limit:          util.Uint32Ptr(10),
			Offset:         util.Uint32Ptr(5),
			SeekPermission: util.BoolPtr(true),
		}
		good := serOK(SerializeDiscoverByAttributesArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeDiscoverByAttributesArgs(d)
			return err
		})
	})

	t.Run("DiscoverByIdentityKeyArgs", func(t *testing.T) {
		args := &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey:    pub,
			Limit:          util.Uint32Ptr(10),
			Offset:         util.Uint32Ptr(5),
			SeekPermission: util.BoolPtr(true),
		}
		good := serOK(SerializeDiscoverByIdentityKeyArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeDiscoverByIdentityKeyArgs(d)
			return err
		})
	})

	t.Run("DiscoverCertificatesResult", func(t *testing.T) {
		idcert := xtValidIdentityCertificate(t)
		result := &wallet.DiscoverCertificatesResult{
			TotalCertificates: 1,
			Certificates:      []wallet.IdentityCertificate{idcert},
		}
		good := serOK(SerializeDiscoverCertificatesResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeDiscoverCertificatesResult(d)
			return err
		})
	})

	t.Run("GetHeaderArgs", func(t *testing.T) {
		good := serOK(SerializeGetHeaderArgs(&wallet.GetHeaderArgs{Height: 123456}))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeGetHeaderArgs(d)
			return err
		})
	})

	t.Run("GetNetworkResult", func(t *testing.T) {
		good := serOK(SerializeGetNetworkResult(&wallet.GetNetworkResult{Network: wallet.NetworkTestnet}))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeGetNetworkResult(d)
			return err
		})
	})

	t.Run("GetPublicKeyArgs", func(t *testing.T) {
		args := &wallet.GetPublicKeyArgs{
			ForSelf:        util.BoolPtr(true),
			EncryptionArgs: encArgs,
		}
		good := serOK(SerializeGetPublicKeyArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeGetPublicKeyArgs(d)
			return err
		})
	})

	t.Run("GetPublicKeyResult", func(t *testing.T) {
		good := serOK(SerializeGetPublicKeyResult(&wallet.GetPublicKeyResult{PublicKey: pub}))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeGetPublicKeyResult(d)
			return err
		})
	})

	t.Run("InternalizeActionArgs", func(t *testing.T) {
		args := &wallet.InternalizeActionArgs{
			Tx: []byte{1, 2, 3, 4},
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    wallet.InternalizeProtocolWalletPayment,
					PaymentRemittance: &wallet.Payment{
						DerivationPrefix:  []byte("prefix"),
						DerivationSuffix:  []byte("suffix"),
						SenderIdentityKey: pub,
					},
				},
				{
					OutputIndex: 1,
					Protocol:    wallet.InternalizeProtocolBasketInsertion,
					InsertionRemittance: &wallet.BasketInsertion{
						Basket:             "b",
						CustomInstructions: "ci",
						Tags:               []string{"t1"},
					},
				},
			},
			Description:    "desc",
			Labels:         []string{"l1"},
			SeekPermission: util.BoolPtr(true),
		}
		good := serOK(SerializeInternalizeActionArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeInternalizeActionArgs(d)
			return err
		})
	})

	t.Run("ListActionsArgs", func(t *testing.T) {
		args := &wallet.ListActionsArgs{
			Labels:         []string{"l1", "l2"},
			LabelQueryMode: wallet.QueryModeAll,
			IncludeLabels:  util.BoolPtr(true),
			Limit:          util.Uint32Ptr(100),
			Offset:         util.Uint32Ptr(10),
			SeekPermission: util.BoolPtr(false),
		}
		good := serOK(SerializeListActionsArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeListActionsArgs(d)
			return err
		})
	})

	t.Run("ListActionsResult", func(t *testing.T) {
		result := &wallet.ListActionsResult{
			TotalActions: 1,
			Actions: []wallet.Action{{
				Txid:        hash,
				Satoshis:    1000,
				Status:      wallet.ActionStatusCompleted,
				IsOutgoing:  true,
				Description: "a1",
				Labels:      []string{"l1"},
				Version:     1,
				Inputs: []wallet.ActionInput{{
					SourceOutpoint:      transaction.Outpoint{Txid: hash},
					SourceSatoshis:      500,
					SourceLockingScript: []byte{0x76, 0xa9},
					UnlockingScript:     []byte{0x48, 0x30},
					InputDescription:    "in1",
					SequenceNumber:      0xffffffff,
				}},
				Outputs: []wallet.ActionOutput{{
					OutputIndex:        0,
					Satoshis:           1000,
					LockingScript:      []byte{0x76, 0xa9},
					Spendable:          true,
					OutputDescription:  "out1",
					Basket:             "b1",
					Tags:               []string{"t1"},
					CustomInstructions: "ci",
				}},
			}},
		}
		good := serOK(SerializeListActionsResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeListActionsResult(d)
			return err
		})
	})

	t.Run("ListCertificatesArgs", func(t *testing.T) {
		args := &wallet.ListCertificatesArgs{
			Certifiers:       []*ec.PublicKey{pub},
			Types:            []wallet.CertificateType{tu.GetByte32FromString("type1")},
			Limit:            util.Uint32Ptr(10),
			Offset:           util.Uint32Ptr(5),
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "r",
		}
		good := serOK(SerializeListCertificatesArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeListCertificatesArgs(d)
			return err
		})
	})

	t.Run("ListCertificatesResult", func(t *testing.T) {
		result := &wallet.ListCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.CertificateResult{{
				Certificate: xtValidCertificate(t),
				Keyring:     map[string]string{"key1": b64("value1")},
				Verifier:    []byte("verifier1"),
			}},
		}
		good := serOK(SerializeListCertificatesResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeListCertificatesResult(d)
			return err
		})
	})

	t.Run("ListOutputsArgs", func(t *testing.T) {
		args := &wallet.ListOutputsArgs{
			Basket:                    "b1",
			Tags:                      []string{"t1"},
			TagQueryMode:              wallet.QueryModeAll,
			Include:                   wallet.OutputIncludeLockingScripts,
			IncludeCustomInstructions: util.BoolPtr(true),
			IncludeTags:               util.BoolPtr(true),
			IncludeLabels:             util.BoolPtr(true),
			Limit:                     util.Uint32Ptr(10),
			Offset:                    util.Uint32Ptr(5),
			SeekPermission:            util.BoolPtr(true),
		}
		good := serOK(SerializeListOutputsArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeListOutputsArgs(d)
			return err
		})
	})

	t.Run("ListOutputsResult", func(t *testing.T) {
		result := &wallet.ListOutputsResult{
			TotalOutputs: 1,
			BEEF:         []byte{1, 2, 3},
			Outputs: []wallet.Output{{
				Outpoint:           *op,
				Satoshis:           1000,
				LockingScript:      []byte{0x76, 0xa9},
				Spendable:          true,
				CustomInstructions: "ci",
				Tags:               []string{"t1"},
				Labels:             []string{"l1"},
			}},
		}
		good := serOK(SerializeListOutputsResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeListOutputsResult(d)
			return err
		})
	})

	t.Run("ProveCertificateArgs", func(t *testing.T) {
		args := &wallet.ProveCertificateArgs{
			Certificate:      xtValidCertificate(t),
			FieldsToReveal:   []string{"field1"},
			Verifier:         pub,
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "r",
		}
		good := serOK(SerializeProveCertificateArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeProveCertificateArgs(d)
			return err
		})
	})

	t.Run("ProveCertificateResult", func(t *testing.T) {
		result := &wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"field1": b64("value1")},
		}
		good := serOK(SerializeProveCertificateResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeProveCertificateResult(d)
			return err
		})
	})

	t.Run("RelinquishCertificateArgs", func(t *testing.T) {
		args := &wallet.RelinquishCertificateArgs{
			Type:         tu.GetByte32FromString("type1"),
			SerialNumber: tu.GetByte32FromString("serial1"),
			Certifier:    pub,
		}
		good := serOK(SerializeRelinquishCertificateArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeRelinquishCertificateArgs(d)
			return err
		})
	})

	t.Run("RelinquishOutputArgs", func(t *testing.T) {
		args := &wallet.RelinquishOutputArgs{Basket: "b1", Output: *op}
		good := serOK(SerializeRelinquishOutputArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeRelinquishOutputArgs(d)
			return err
		})
	})

	t.Run("RevealCounterpartyKeyLinkageArgs", func(t *testing.T) {
		args := &wallet.RevealCounterpartyKeyLinkageArgs{
			Counterparty:     pub,
			Verifier:         pub,
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "r",
		}
		good := serOK(SerializeRevealCounterpartyKeyLinkageArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeRevealCounterpartyKeyLinkageArgs(d)
			return err
		})
	})

	t.Run("RevealCounterpartyKeyLinkageResult", func(t *testing.T) {
		result := &wallet.RevealCounterpartyKeyLinkageResult{
			Prover:                pub,
			Verifier:              pub,
			Counterparty:          pub,
			RevelationTime:        "2023-01-01T00:00:00Z",
			EncryptedLinkage:      []byte{1, 2, 3},
			EncryptedLinkageProof: []byte{4, 5, 6},
		}
		good := serOK(SerializeRevealCounterpartyKeyLinkageResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeRevealCounterpartyKeyLinkageResult(d)
			return err
		})
	})

	t.Run("RevealSpecificKeyLinkageArgs", func(t *testing.T) {
		args := &wallet.RevealSpecificKeyLinkageArgs{
			Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: pub},
			Verifier:         pub,
			ProtocolID:       wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "p"},
			KeyID:            "k",
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "r",
		}
		good := serOK(SerializeRevealSpecificKeyLinkageArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeRevealSpecificKeyLinkageArgs(d)
			return err
		})
	})

	t.Run("RevealSpecificKeyLinkageResult", func(t *testing.T) {
		result := &wallet.RevealSpecificKeyLinkageResult{
			Prover:                pub,
			Verifier:              pub,
			Counterparty:          pub,
			ProtocolID:            wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "p"},
			KeyID:                 "k",
			EncryptedLinkage:      []byte{1, 2, 3},
			EncryptedLinkageProof: []byte{4, 5, 6},
			ProofType:             1,
		}
		good := serOK(SerializeRevealSpecificKeyLinkageResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeRevealSpecificKeyLinkageResult(d)
			return err
		})
	})

	t.Run("SignActionArgs", func(t *testing.T) {
		args := &wallet.SignActionArgs{
			Spends: map[uint32]wallet.SignActionSpend{
				0: {UnlockingScript: []byte{0x48, 0x30}, SequenceNumber: util.Uint32Ptr(1)},
			},
			Reference: []byte("ref"),
			Options: &wallet.SignActionOptions{
				AcceptDelayedBroadcast: util.BoolPtr(true),
				ReturnTXIDOnly:         util.BoolPtr(false),
				NoSend:                 util.BoolPtr(false),
				SendWith:               []chainhash.Hash{hash},
			},
		}
		good := serOK(SerializeSignActionArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeSignActionArgs(d)
			return err
		})
	})

	t.Run("SignActionResult", func(t *testing.T) {
		result := &wallet.SignActionResult{
			Txid: tu.GetByte32FromHexString(t, "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72"),
			Tx:   []byte{1, 2, 3},
			SendWithResults: []wallet.SendWithResult{
				{Txid: tu.GetByte32FromHexString(t, "490c292a700c55d5e62379828d60bf6c61850fbb4d13382f52021d3796221981"), Status: wallet.ActionResultStatusSending},
			},
		}
		good := serOK(SerializeSignActionResult(result))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeSignActionResult(d)
			return err
		})
	})

	t.Run("VerifyHMACArgs", func(t *testing.T) {
		args := &wallet.VerifyHMACArgs{EncryptionArgs: encArgs, Data: []byte{1, 2, 3}, HMAC: [32]byte{9}}
		good := serOK(SerializeVerifyHMACArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeVerifyHMACArgs(d)
			return err
		})
	})

	t.Run("VerifySignatureArgs", func(t *testing.T) {
		args := &wallet.VerifySignatureArgs{
			EncryptionArgs: encArgs,
			ForSelf:        util.BoolPtr(true),
			Signature:      sig,
			Data:           []byte{5, 6, 7, 8},
		}
		good := serOK(SerializeVerifySignatureArgs(args))
		runDeserializeSweep(t, good, func(d []byte) error {
			_, err := DeserializeVerifySignatureArgs(d)
			return err
		})
	})
}

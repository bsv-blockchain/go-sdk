// Package auth_test holds the BRC-103/BRC-104/BRC-31 wire-conformance suite
// for the auth stack, run against the pinned ts-stack vector corpus.
package auth_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// authriteSignatureArgs mirrors the "args" object every
// messaging/brc31/authrite-signature.json vector carries: a BRC-43-derived
// createSignature/verifySignature call, expressed the same way the TS
// dispatcher (conformance/runner/ts/dispatchers/messaging.ts,
// dispatchAuthriteSignature) reads it.
type authriteSignatureArgs struct {
	Data         string `json:"data"`
	ProtocolID   []any  `json:"protocolID"`
	KeyID        string `json:"keyID"`
	Counterparty string `json:"counterparty"`
	Signature    string `json:"signature"`
}

type authriteSignatureInput struct {
	RootKey string                `json:"root_key"`
	Method  string                `json:"method"`
	Args    authriteSignatureArgs `json:"args"`
}

type authriteSignatureExpected struct {
	Signature string `json:"signature"`
	Valid     *bool  `json:"valid"`
	Error     bool   `json:"error"`
}

// TestAuthriteSignatureConformance exercises wallet.ProtoWallet.CreateSignature
// and VerifySignature with protocolID=[2,'authrite message signature'] (BRC-31,
// via BRC-43 key derivation) and checks the result against signatures recorded
// from the TS reference (@bsv/sdk ProtoWallet). Go's ECDSA signing is
// RFC6979-deterministic, matching the TS reference, so these signatures must
// be byte-for-byte identical, not just independently valid.
func TestAuthriteSignatureConformance(t *testing.T) {
	file := conformance.Load(t, "messaging/brc31/authrite-signature.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in authriteSignatureInput
		v.DecodeInput(t, &in)
		var exp authriteSignatureExpected
		v.DecodeExpected(t, &exp)

		if in.RootKey == "" || in.Method == "" {
			t.Fatalf("%s: vector missing root_key or method", v.ID)
		}

		privKey, err := ec.PrivateKeyFromHex(in.RootKey)
		if err != nil {
			t.Fatalf("%s: bad root_key: %v", v.ID, err)
		}
		pw, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
			Type:       wallet.ProtoWalletArgsTypePrivateKey,
			PrivateKey: privKey,
		})
		if err != nil {
			t.Fatalf("%s: NewProtoWallet: %v", v.ID, err)
		}

		protocolID := decodeWalletProtocol(t, v.ID, in.Args.ProtocolID)
		data := decodeHexOrEmpty(t, v.ID, "data", in.Args.Data)
		counterparty := decodeCounterparty(t, v.ID, in.Args.Counterparty)

		switch in.Method {
		case "createSignature":
			sigRes, sigErr := pw.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
				EncryptionArgs: wallet.EncryptionArgs{
					ProtocolID:   protocolID,
					KeyID:        in.Args.KeyID,
					Counterparty: counterparty,
				},
				Data: data,
			}, "")
			if sigErr != nil {
				t.Fatalf("%s: CreateSignature: %v", v.ID, sigErr)
			}
			got := hex.EncodeToString(sigRes.Signature.Serialize())
			if got != exp.Signature {
				t.Errorf("%s: signature = %s, want %s", v.ID, got, exp.Signature)
			}

		case "verifySignature":
			sigBytes := decodeHexOrEmpty(t, v.ID, "signature", in.Args.Signature)
			sig, parseErr := ec.ParseSignature(sigBytes)
			verifyArgs := wallet.VerifySignatureArgs{
				EncryptionArgs: wallet.EncryptionArgs{
					ProtocolID:   protocolID,
					KeyID:        in.Args.KeyID,
					Counterparty: counterparty,
				},
				Data:      data,
				Signature: sig,
			}
			var res *wallet.VerifySignatureResult
			if parseErr == nil {
				res, err = pw.VerifySignature(context.Background(), verifyArgs, "")
			} else {
				err = parseErr
			}

			if exp.Error {
				if err == nil {
					t.Errorf("%s: expected verification to fail, got valid=%v", v.ID, res.Valid)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: VerifySignature: %v", v.ID, err)
			}
			wantValid := exp.Valid == nil || *exp.Valid
			if res.Valid != wantValid {
				t.Errorf("%s: valid = %v, want %v", v.ID, res.Valid, wantValid)
			}

		default:
			t.Fatalf("%s: unknown method %q", v.ID, in.Method)
		}
	})
}

func decodeHexOrEmpty(t *testing.T, vectorID, field, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: bad %s hex: %v", vectorID, field, err)
	}
	return b
}

func decodeCounterparty(t *testing.T, vectorID, hexKey string) wallet.Counterparty {
	t.Helper()
	if hexKey == "" {
		return wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
	}
	pub, err := ec.PublicKeyFromString(hexKey)
	if err != nil {
		t.Fatalf("%s: bad counterparty key: %v", vectorID, err)
	}
	return wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: pub}
}

func decodeWalletProtocol(t *testing.T, vectorID string, raw []any) wallet.Protocol {
	t.Helper()
	if len(raw) != 2 {
		t.Fatalf("%s: protocolID must be a [securityLevel, name] tuple, got %v", vectorID, raw)
	}
	levelF, ok := raw[0].(float64)
	if !ok {
		t.Fatalf("%s: protocolID[0] must be a number, got %T", vectorID, raw[0])
	}
	name, ok := raw[1].(string)
	if !ok {
		t.Fatalf("%s: protocolID[1] must be a string, got %T", vectorID, raw[1])
	}
	return wallet.Protocol{SecurityLevel: wallet.SecurityLevel(levelF), Protocol: name}
}

package primitives

import (
	e "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

var (
	// Generate a new private key for the test
	privateHex = "1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5"
)

func TestECDSA(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name       string
		messageHex string
		expectPass bool
		expectSign bool
		forceLowS  bool
		customK    *big.Int
	}{
		{
			name:       "Valid Signature",
			messageHex: "deadbeef",
			expectSign: true,
			expectPass: true,
		},
		// TODO: This is a test from ts but not sure why this is expected to fail it seems to work fine
		// https://github.com/bitcoin-sv/ts-sdk/blob/master/src//__tests/ECDSA.test.ts#L48
		// {
		// 	name:       "Incorrect Signed Message",
		// 	messageHex: "BA5AABBE1AA9B6EC1E2ADB2DF99699344345678901234567890ABCDEFABCDEF02",
		// 	expectSign: true,
		// 	expectPass: false,
		// },
		{
			name:       "Signature with Low S Value",
			messageHex: "deadbeef",
			forceLowS:  true,
			expectSign: true,
			expectPass: true,
		},
		{
			name:       "Signature with Custom K",
			messageHex: "deadbeef",
			customK:    big.NewInt(1358),
			expectSign: true,
			expectPass: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msgBytes, _ := hex.DecodeString(tc.messageHex)
			privKeyInt := new(big.Int)
			privKeyInt.SetString(privateHex, 16)

			// Convert the private key to *ecdsa.PrivateKey
			privateKey := &e.PrivateKey{
				D: privKeyInt,
				PublicKey: e.PublicKey{
					Curve: elliptic.P256(),
					X:     nil,
					Y:     nil,
				},
			}
			privateKey.X, privateKey.Y = privateKey.ScalarBaseMult(privateKey.D.Bytes())

			signature, err := Sign(msgBytes, privateKey, tc.forceLowS, tc.customK)
			if err != nil {
				if tc.expectSign {
					t.Fatalf("Failed to sign: %v", err)
				} else {
					return
				}
			}

			ok := Verify(msgBytes, signature, &privateKey.PublicKey)
			if ok != tc.expectPass {
				t.Fatalf("Verification failed: expected %v, got %v", tc.expectPass, ok)
			}
		})
	}

	// Separate test for "Signature with Wrong Public Key"
	t.Run("Signature with Wrong Public Key", func(t *testing.T) {
		msgBytes, _ := hex.DecodeString("deadbeef")
		privKeyInt := new(big.Int)
		privKeyInt.SetString(privateHex, 16)

		privateKey := &e.PrivateKey{
			D: privKeyInt,
			PublicKey: e.PublicKey{
				Curve: elliptic.P256(),
			},
		}
		privateKey.X, privateKey.Y = privateKey.ScalarBaseMult(privateKey.D.Bytes())

		signature, err := Sign(msgBytes, privateKey, false, nil)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Generate a different private key
		differentPrivKey, err := e.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate different private key: %v", err)
		}

		// Verify with the different public key
		ok := Verify(msgBytes, signature, &differentPrivKey.PublicKey)
		if ok {
			t.Fatal("Verification succeeded with a different public key, expected failure")
		}
	})
}

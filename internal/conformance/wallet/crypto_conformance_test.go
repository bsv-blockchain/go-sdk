package wallet_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestGetPublicKeyConformance runs wallet/brc100/getpublickey.json (ProtoWallet
// crypto-only method; the ts-stack dispatcher calls this directly on a bare
// ProtoWallet, so we do the same).
func TestGetPublicKeyConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/getpublickey.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)

		var args wallet.GetPublicKeyArgs
		if err := json.Unmarshal(in.Args, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.GetPublicKey(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
		require.NotNil(t, result.PublicKey, v.ID)

		var expected struct {
			PublicKey string `json:"publicKey"`
		}
		v.DecodeExpected(t, &expected)
		if expected.PublicKey != "" {
			require.Equal(t, expected.PublicKey, result.PublicKey.ToDERHex(), v.ID)
		}
	})
}

// TestCreateHMACConformance runs wallet/brc100/createhmac.json.
func TestCreateHMACConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/createhmac.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)
		rawArgs := normalizeDataField(t, in.Args, "data")

		var args wallet.CreateHMACArgs
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.CreateHMAC(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)

		var expected struct {
			HMAC wallet.BytesList `json:"hmac"`
		}
		v.DecodeExpected(t, &expected)
		if len(expected.HMAC) > 0 {
			require.Equal(t, []byte(expected.HMAC), result.HMAC[:], v.ID)
		}
	})
}

// TestVerifyHMACConformance runs wallet/brc100/verifyhmac.json. ProtoWallet's
// VerifyHMAC errors (rather than returning {Valid: false}) when the HMAC
// doesn't match, matching the TS reference SDK.
func TestVerifyHMACConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/verifyhmac.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)
		rawArgs := normalizeDataField(t, in.Args, "data")

		var args wallet.VerifyHMACArgs
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.VerifyHMAC(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
		require.True(t, result.Valid, v.ID)

		var expected struct {
			Valid *bool `json:"valid"`
		}
		v.DecodeExpected(t, &expected)
		if expected.Valid != nil {
			require.Equal(t, *expected.Valid, result.Valid, v.ID)
		}
	})
}

// TestCreateSignatureConformance runs wallet/brc100/createsignature.json.
func TestCreateSignatureConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/createsignature.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)
		rawArgs := normalizeDataField(t, in.Args, "data", "hashToDirectlySign")

		var args wallet.CreateSignatureArgs
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.CreateSignature(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
		require.NotNil(t, result.Signature, v.ID)

		var expected struct {
			Signature wallet.BytesList `json:"signature"`
		}
		v.DecodeExpected(t, &expected)
		if len(expected.Signature) > 0 {
			require.Equal(t, []byte(expected.Signature), result.Signature.Serialize(), v.ID)
		}
	})
}

// TestVerifySignatureConformance runs wallet/brc100/verifysignature.json.
// ProtoWallet's VerifySignature errors (rather than returning
// {Valid: false}) when the signature doesn't verify, matching the TS
// reference SDK.
func TestVerifySignatureConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/verifysignature.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)
		rawArgs := normalizeDataField(t, in.Args, "data", "hashToDirectlyVerify")

		var args wallet.VerifySignatureArgs
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.VerifySignature(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
		require.True(t, result.Valid, v.ID)

		var expected struct {
			Valid *bool `json:"valid"`
		}
		v.DecodeExpected(t, &expected)
		if expected.Valid != nil {
			require.Equal(t, *expected.Valid, result.Valid, v.ID)
		}
	})
}

// TestEncryptConformance runs wallet/brc100/encrypt.json. Like the ts-stack
// reference runner (see its dispatchEncrypt MISMATCH comment),
// ProtoWallet.Encrypt prepends a random IV, so ciphertext bytes are
// non-deterministic; we assert a decrypt(encrypt(plaintext)) round trip
// instead of an exact ciphertext match.
func TestEncryptConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/encrypt.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)
		rawArgs := normalizeDataField(t, in.Args, "data")

		var rawMap map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rawArgs, &rawMap), v.ID)
		var args wallet.EncryptArgs
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}
		// The vector's byte data is authored under the "data" key; map it to
		// EncryptArgs.Plaintext (Encrypt has no "data" field of its own).
		if raw, ok := rawMap["data"]; ok {
			require.NoError(t, json.Unmarshal(raw, &args.Plaintext), v.ID)
		}

		encResult, err := pw.Encrypt(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
		require.NotEmpty(t, encResult.Ciphertext, v.ID)

		var expected struct {
			Ciphertext wallet.BytesList `json:"ciphertext"`
		}
		v.DecodeExpected(t, &expected)
		require.NotEmpty(t, expected.Ciphertext, "%s: fixture must document a ciphertext", v.ID)

		decArgs := wallet.DecryptArgs{
			EncryptionArgs: args.EncryptionArgs,
			Ciphertext:     encResult.Ciphertext,
		}
		decResult, err := pw.Decrypt(context.Background(), decArgs, in.Originator)
		require.NoError(t, err, v.ID)
		require.Equal(t, []byte(args.Plaintext), []byte(decResult.Plaintext), v.ID)
	})
}

// TestDecryptConformance runs wallet/brc100/decrypt.json. Unlike Encrypt,
// this is fully deterministic (fixed ciphertext in, fixed plaintext out).
func TestDecryptConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/decrypt.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)

		var args wallet.DecryptArgs
		if err := json.Unmarshal(in.Args, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.Decrypt(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)

		var expected struct {
			Plaintext wallet.BytesList `json:"plaintext"`
		}
		v.DecodeExpected(t, &expected)
		if len(expected.Plaintext) > 0 {
			require.Equal(t, []byte(expected.Plaintext), []byte(result.Plaintext), v.ID)
		}
	})
}

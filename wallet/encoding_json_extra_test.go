package wallet_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestUnmarshalJSONMalformedInput feeds invalid JSON to every custom
// json.Unmarshaler in the wallet package, exercising the shared
// "json.Unmarshal returned an error" branch in each implementation.
func TestUnmarshalJSONMalformedInput(t *testing.T) {
	t.Parallel()

	// A bare JSON number is a valid top-level token (so each custom UnmarshalJSON
	// is actually invoked) but cannot be decoded into the target struct/string/slice,
	// which exercises the internal json.Unmarshal error branch.
	const invalid = "123"

	unmarshalers := map[string]func([]byte) error{
		"Protocol":     func(b []byte) error { var v wallet.Protocol; return json.Unmarshal(b, &v) },
		"Counterparty": func(b []byte) error { var v wallet.Counterparty; return json.Unmarshal(b, &v) },
		"CreateSignatureResult": func(b []byte) error {
			var v wallet.CreateSignatureResult
			return json.Unmarshal(b, &v)
		},
		"VerifySignatureArgs": func(b []byte) error { var v wallet.VerifySignatureArgs; return json.Unmarshal(b, &v) },
		"Certificate":         func(b []byte) error { var v wallet.Certificate; return json.Unmarshal(b, &v) },
		"CreateActionInput":   func(b []byte) error { var v wallet.CreateActionInput; return json.Unmarshal(b, &v) },
		"CreateActionOutput":  func(b []byte) error { var v wallet.CreateActionOutput; return json.Unmarshal(b, &v) },
		"SignActionSpend":     func(b []byte) error { var v wallet.SignActionSpend; return json.Unmarshal(b, &v) },
		"ActionInput":         func(b []byte) error { var v wallet.ActionInput; return json.Unmarshal(b, &v) },
		"ActionOutput":        func(b []byte) error { var v wallet.ActionOutput; return json.Unmarshal(b, &v) },
		"InternalizeActionArgs": func(b []byte) error {
			var v wallet.InternalizeActionArgs
			return json.Unmarshal(b, &v)
		},
		"Output":            func(b []byte) error { var v wallet.Output; return json.Unmarshal(b, &v) },
		"ListOutputsResult": func(b []byte) error { var v wallet.ListOutputsResult; return json.Unmarshal(b, &v) },
		"CertificateResult": func(b []byte) error { var v wallet.CertificateResult; return json.Unmarshal(b, &v) },
		"RevealCounterpartyKeyLinkageResult": func(b []byte) error {
			var v wallet.RevealCounterpartyKeyLinkageResult
			return json.Unmarshal(b, &v)
		},
		"RevealSpecificKeyLinkageResult": func(b []byte) error {
			var v wallet.RevealSpecificKeyLinkageResult
			return json.Unmarshal(b, &v)
		},
		"IdentityCertificate": func(b []byte) error { var v wallet.IdentityCertificate; return json.Unmarshal(b, &v) },
		"KeyringRevealer":     func(b []byte) error { var v wallet.KeyringRevealer; return json.Unmarshal(b, &v) },
		"AcquireCertificateArgs": func(b []byte) error {
			var v wallet.AcquireCertificateArgs
			return json.Unmarshal(b, &v)
		},
		"GetHeaderResult": func(b []byte) error { var v wallet.GetHeaderResult; return json.Unmarshal(b, &v) },
		"VerifyHMACArgs":  func(b []byte) error { var v wallet.VerifyHMACArgs; return json.Unmarshal(b, &v) },
		"CreateHMACResult": func(b []byte) error {
			var v wallet.CreateHMACResult
			return json.Unmarshal(b, &v)
		},
	}

	for name, fn := range unmarshalers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Error(t, fn([]byte(invalid)))
		})
	}
}

// ---- Protocol edge cases ----

func TestProtocolUnmarshalProtocolNotString(t *testing.T) {
	t.Parallel()
	var p wallet.Protocol
	err := json.Unmarshal([]byte(`[2, 123]`), &p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Protocol to be a string")
}

// ---- Counterparty MarshalJSON edge cases ----

func TestCounterpartyMarshalOtherNil(t *testing.T) {
	t.Parallel()
	c := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: nil}
	data, err := json.Marshal(&c)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

func TestCounterpartyMarshalUninitialized(t *testing.T) {
	t.Parallel()
	c := wallet.Counterparty{Type: wallet.CounterpartyUninitialized}
	data, err := json.Marshal(&c)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

func TestCounterpartyMarshalUnknownType(t *testing.T) {
	t.Parallel()
	c := wallet.Counterparty{Type: wallet.CounterpartyType(99)}
	data, err := json.Marshal(&c)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

// ---- VerifySignatureArgs JSON round trip (custom marshaler + unmarshaler) ----

func TestVerifySignatureArgsMarshalUnmarshalJSON(t *testing.T) {
	t.Parallel()
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sig, err := privKey.Sign(make([]byte, 32))
	require.NoError(t, err)

	args := wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "testprotocol"},
			KeyID:      "k1",
		},
		Data:      []byte{1, 2, 3},
		Signature: sig,
	}

	data, err := json.Marshal(args)
	require.NoError(t, err)

	var decoded wallet.VerifySignatureArgs
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, args.Data, decoded.Data)
	require.NotNil(t, decoded.Signature)
}

func TestVerifySignatureArgsUnmarshalInvalidSignature(t *testing.T) {
	t.Parallel()
	// Valid JSON structure, but the signature byte array cannot be parsed.
	data := []byte(`{"data":[1,2,3],"signature":[1,2,3],"protocolID":[0,"test"],"keyID":"k"}`)
	var decoded wallet.VerifySignatureArgs
	err := json.Unmarshal(data, &decoded)
	assert.Error(t, err)
}

// ---- Certificate signature branches ----

func TestCertificateMarshalWithSignature(t *testing.T) {
	t.Parallel()
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sig, err := privKey.Sign(make([]byte, 32))
	require.NoError(t, err)

	ct, err := wallet.CertificateTypeFromString("testcert")
	require.NoError(t, err)
	cert := wallet.Certificate{
		Type:      ct,
		Subject:   privKey.PubKey(),
		Signature: sig,
	}
	data, err := json.Marshal(cert)
	require.NoError(t, err)

	var decoded wallet.Certificate
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.NotNil(t, decoded.Signature)
}

func TestCertificateUnmarshalInvalidSignature(t *testing.T) {
	t.Parallel()
	// "01" is valid hex but not a parseable signature.
	data := []byte(`{"signature":"01"}`)
	var cert wallet.Certificate
	err := json.Unmarshal(data, &cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing signature")
}

// ---- KeyringRevealer invalid public key ----

func TestKeyringRevealerUnmarshalInvalidPubKey(t *testing.T) {
	t.Parallel()
	var r wallet.KeyringRevealer
	err := json.Unmarshal([]byte(`"not-a-valid-pubkey"`), &r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing revealer public key")
}

// ---- AcquireCertificateArgs invalid signature ----

func TestAcquireCertificateArgsUnmarshalInvalidSignature(t *testing.T) {
	t.Parallel()
	// signature is valid hex but not a parseable signature.
	data := []byte(`{"signature":"01"}`)
	var args wallet.AcquireCertificateArgs
	err := json.Unmarshal(data, &args)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing signature")
}

// ---- CertificateResult keyring/verifier error branches ----

func TestCertificateResultUnmarshalFieldErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid keyring", func(t *testing.T) {
		t.Parallel()
		// Base certificate decodes fine; keyring is the wrong JSON type.
		var cr wallet.CertificateResult
		err := json.Unmarshal([]byte(`{"keyring":123}`), &cr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keyring")
	})

	t.Run("invalid verifier", func(t *testing.T) {
		t.Parallel()
		var cr wallet.CertificateResult
		err := json.Unmarshal([]byte(`{"verifier":123}`), &cr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verifier")
	})
}

// ---- IdentityCertificate field error branches ----

func TestIdentityCertificateUnmarshalFieldErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid certifierInfo", func(t *testing.T) {
		t.Parallel()
		var ic wallet.IdentityCertificate
		err := json.Unmarshal([]byte(`{"certifierInfo":123}`), &ic)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certifierInfo")
	})

	t.Run("invalid publiclyRevealedKeyring", func(t *testing.T) {
		t.Parallel()
		var ic wallet.IdentityCertificate
		err := json.Unmarshal([]byte(`{"publiclyRevealedKeyring":123}`), &ic)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "publiclyRevealedKeyring")
	})

	t.Run("invalid decryptedFields", func(t *testing.T) {
		t.Parallel()
		var ic wallet.IdentityCertificate
		err := json.Unmarshal([]byte(`{"decryptedFields":123}`), &ic)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decryptedFields")
	})
}

package wallet_test

import (
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- CertificateType JSON ----

func TestCertificateTypeMarshalUnmarshalJSON(t *testing.T) {
	ct, err := wallet.CertificateTypeFromString("testcert")
	require.NoError(t, err)

	data, err := json.Marshal(ct)
	require.NoError(t, err)

	var decoded wallet.CertificateType
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, ct, decoded)
}

// ---- SerialNumber JSON ----

func TestSerialNumberMarshalUnmarshalJSON(t *testing.T) {
	var sn wallet.SerialNumber
	copy(sn[:], []byte("test-serial-1234"))

	data, err := json.Marshal(sn)
	require.NoError(t, err)

	var decoded wallet.SerialNumber
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, sn, decoded)
}

// ---- Protocol JSON ----

func TestProtocolMarshalJSON(t *testing.T) {
	p := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryApp,
		Protocol:      "myprotocol",
	}
	data, err := json.Marshal(&p)
	require.NoError(t, err)
	assert.Contains(t, string(data), "myprotocol")
}

func TestProtocolUnmarshalJSON(t *testing.T) {
	data := []byte(`[2, "testprotocol"]`)
	var p wallet.Protocol
	err := json.Unmarshal(data, &p)
	require.NoError(t, err)
	assert.Equal(t, wallet.SecurityLevelEveryAppAndCounterparty, p.SecurityLevel)
	assert.Equal(t, "testprotocol", p.Protocol)
}

func TestProtocolUnmarshalInvalidLength(t *testing.T) {
	data := []byte(`[1]`)
	var p wallet.Protocol
	err := json.Unmarshal(data, &p)
	assert.Error(t, err)
}

func TestProtocolUnmarshalInvalidType(t *testing.T) {
	data := []byte(`["notanumber", "protocol"]`)
	var p wallet.Protocol
	err := json.Unmarshal(data, &p)
	assert.Error(t, err)
}

// ---- Counterparty JSON ----

func TestCounterpartyMarshalAnyone(t *testing.T) {
	c := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
	data, err := json.Marshal(&c)
	require.NoError(t, err)
	assert.Equal(t, `"anyone"`, string(data))
}

func TestCounterpartyMarshalSelf(t *testing.T) {
	c := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}
	data, err := json.Marshal(&c)
	require.NoError(t, err)
	assert.Equal(t, `"self"`, string(data))
}

func TestCounterpartyMarshalOther(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	c := wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: privKey.PubKey(),
	}
	data, err := json.Marshal(&c)
	require.NoError(t, err)
	assert.Contains(t, string(data), privKey.PubKey().ToDERHex())
}

func TestCounterpartyUnmarshalAnyone(t *testing.T) {
	var c wallet.Counterparty
	err := json.Unmarshal([]byte(`"anyone"`), &c)
	require.NoError(t, err)
	assert.Equal(t, wallet.CounterpartyTypeAnyone, c.Type)
}

func TestCounterpartyUnmarshalSelf(t *testing.T) {
	var c wallet.Counterparty
	err := json.Unmarshal([]byte(`"self"`), &c)
	require.NoError(t, err)
	assert.Equal(t, wallet.CounterpartyTypeSelf, c.Type)
}

func TestCounterpartyUnmarshalEmpty(t *testing.T) {
	var c wallet.Counterparty
	err := json.Unmarshal([]byte(`""`), &c)
	require.NoError(t, err)
	assert.Equal(t, wallet.CounterpartyUninitialized, c.Type)
}

func TestCounterpartyUnmarshalPubKey(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	pubKeyHex := privKey.PubKey().ToDERHex()

	jsonStr, _ := json.Marshal(pubKeyHex)
	var c wallet.Counterparty
	err = json.Unmarshal(jsonStr, &c)
	require.NoError(t, err)
	assert.Equal(t, wallet.CounterpartyTypeOther, c.Type)
	assert.NotNil(t, c.Counterparty)
}

func TestCounterpartyUnmarshalInvalid(t *testing.T) {
	var c wallet.Counterparty
	err := json.Unmarshal([]byte(`"notapubkey"`), &c)
	assert.Error(t, err)
}

// ---- CreateSignatureResult JSON ----

func TestCreateSignatureResultMarshalUnmarshalJSON(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	hash := make([]byte, 32)
	sig, err := privKey.Sign(hash)
	require.NoError(t, err)

	result := wallet.CreateSignatureResult{Signature: sig}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded wallet.CreateSignatureResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.NotNil(t, decoded.Signature)
}

func TestCreateSignatureResultMarshalNilSignature(t *testing.T) {
	result := wallet.CreateSignatureResult{Signature: nil}
	_, err := json.Marshal(result)
	assert.Error(t, err)
}

// ---- CreateActionInput JSON ----

func TestCreateActionInputMarshalUnmarshalJSON(t *testing.T) {
	input := wallet.CreateActionInput{
		InputDescription: "test input",
		UnlockingScript:  []byte{0xde, 0xad, 0xbe, 0xef},
	}
	data, err := json.Marshal(input)
	require.NoError(t, err)

	var decoded wallet.CreateActionInput
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, input.InputDescription, decoded.InputDescription)
	assert.Equal(t, input.UnlockingScript, decoded.UnlockingScript)
}

// ---- CreateActionOutput JSON ----

func TestCreateActionOutputMarshalUnmarshalJSON(t *testing.T) {
	output := wallet.CreateActionOutput{
		Satoshis:      1000,
		LockingScript: []byte{0x76, 0xa9},
	}
	data, err := json.Marshal(output)
	require.NoError(t, err)

	var decoded wallet.CreateActionOutput
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, output.Satoshis, decoded.Satoshis)
	assert.Equal(t, output.LockingScript, decoded.LockingScript)
}

// ---- SignActionSpend JSON ----

func TestSignActionSpendMarshalUnmarshalJSON(t *testing.T) {
	spend := wallet.SignActionSpend{
		UnlockingScript: []byte{0x01, 0x02, 0x03},
	}
	data, err := json.Marshal(spend)
	require.NoError(t, err)

	var decoded wallet.SignActionSpend
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, spend.UnlockingScript, decoded.UnlockingScript)
}

// ---- ActionInput JSON ----

func TestActionInputMarshalUnmarshalJSON(t *testing.T) {
	ai := wallet.ActionInput{
		InputDescription:    "test",
		SourceLockingScript: []byte{0x76, 0xa9, 0x14},
		UnlockingScript:     []byte{0x48, 0x30, 0x45},
	}
	data, err := json.Marshal(ai)
	require.NoError(t, err)

	var decoded wallet.ActionInput
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, ai.InputDescription, decoded.InputDescription)
	assert.Equal(t, ai.SourceLockingScript, decoded.SourceLockingScript)
	assert.Equal(t, ai.UnlockingScript, decoded.UnlockingScript)
}

// ---- ActionOutput JSON ----

func TestActionOutputMarshalUnmarshalJSON(t *testing.T) {
	ao := wallet.ActionOutput{
		Satoshis:      500,
		LockingScript: []byte{0x76, 0xa9},
	}
	data, err := json.Marshal(ao)
	require.NoError(t, err)

	var decoded wallet.ActionOutput
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, ao.Satoshis, decoded.Satoshis)
	assert.Equal(t, ao.LockingScript, decoded.LockingScript)
}

// ---- InternalizeActionArgs JSON ----

func TestInternalizeActionArgsMarshalUnmarshalJSON(t *testing.T) {
	args := wallet.InternalizeActionArgs{
		Tx:          []byte{1, 2, 3},
		Description: "test internalize",
	}
	data, err := json.Marshal(args)
	require.NoError(t, err)

	var decoded wallet.InternalizeActionArgs
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, args.Description, decoded.Description)
	assert.Equal(t, args.Tx, []byte(decoded.Tx))
}

// ---- Output JSON ----

func TestOutputMarshalUnmarshalJSON(t *testing.T) {
	o := wallet.Output{
		Satoshis:      1000,
		LockingScript: []byte{0x76, 0xa9, 0x14},
		Spendable:     true,
	}
	data, err := json.Marshal(o)
	require.NoError(t, err)

	var decoded wallet.Output
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, o.Satoshis, decoded.Satoshis)
	assert.Equal(t, o.LockingScript, decoded.LockingScript)
	assert.Equal(t, o.Spendable, decoded.Spendable)
}

// ---- ListOutputsResult JSON ----

func TestListOutputsResultMarshalUnmarshalJSON(t *testing.T) {
	result := wallet.ListOutputsResult{
		TotalOutputs: 2,
		BEEF:         []byte{0xde, 0xad},
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded wallet.ListOutputsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result.TotalOutputs, decoded.TotalOutputs)
	assert.Equal(t, result.BEEF, decoded.BEEF)
}

// ---- CertificateResult JSON ----

func TestCertificateResultMarshalUnmarshalJSON(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	ct, _ := wallet.CertificateTypeFromString("testcert")
	cr := wallet.CertificateResult{
		Certificate: wallet.Certificate{
			Type:    ct,
			Subject: privKey.PubKey(),
		},
		Keyring:  map[string]string{"field1": "value1"},
		Verifier: []byte{0x01, 0x02},
	}

	data, err := json.Marshal(&cr)
	require.NoError(t, err)

	var decoded wallet.CertificateResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cr.Keyring, decoded.Keyring)
	assert.Equal(t, cr.Verifier, decoded.Verifier)
}

// ---- IdentityCertificate JSON ----

func TestIdentityCertificateMarshalUnmarshalJSON(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	ct, _ := wallet.CertificateTypeFromString("identity")
	ic := wallet.IdentityCertificate{
		Certificate: wallet.Certificate{
			Type:    ct,
			Subject: privKey.PubKey(),
		},
		CertifierInfo: wallet.IdentityCertifier{
			Name:  "Test Certifier",
			Trust: 5,
		},
		PubliclyRevealedKeyring: map[string]string{"pubfield": "pubval"},
		DecryptedFields:         map[string]string{"privfield": "privval"},
	}

	data, err := json.Marshal(&ic)
	require.NoError(t, err)

	var decoded wallet.IdentityCertificate
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, ic.CertifierInfo.Name, decoded.CertifierInfo.Name)
	assert.Equal(t, ic.PubliclyRevealedKeyring, decoded.PubliclyRevealedKeyring)
	assert.Equal(t, ic.DecryptedFields, decoded.DecryptedFields)
}

// ---- RevealCounterpartyKeyLinkageResult JSON ----

func TestRevealCounterpartyKeyLinkageResultMarshalUnmarshalJSON(t *testing.T) {
	result := wallet.RevealCounterpartyKeyLinkageResult{
		RevelationTime:        "2024-01-01T00:00:00Z",
		EncryptedLinkage:      []byte{1, 2, 3},
		EncryptedLinkageProof: []byte{4, 5, 6},
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded wallet.RevealCounterpartyKeyLinkageResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result.EncryptedLinkage, []byte(decoded.EncryptedLinkage))
	assert.Equal(t, result.EncryptedLinkageProof, []byte(decoded.EncryptedLinkageProof))
}

// ---- RevealSpecificKeyLinkageResult JSON ----

func TestRevealSpecificKeyLinkageResultMarshalUnmarshalJSON(t *testing.T) {
	result := wallet.RevealSpecificKeyLinkageResult{
		EncryptedLinkage:      []byte{7, 8, 9},
		EncryptedLinkageProof: []byte{10, 11},
		KeyID:                 "key1",
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded wallet.RevealSpecificKeyLinkageResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result.EncryptedLinkage, []byte(decoded.EncryptedLinkage))
	assert.Equal(t, result.EncryptedLinkageProof, []byte(decoded.EncryptedLinkageProof))
}

// ---- KeyringRevealer JSON ----

func TestKeyringRevealerMarshalCertifier(t *testing.T) {
	r := wallet.KeyringRevealer{Certifier: true}
	data, err := json.Marshal(r)
	require.NoError(t, err)
	assert.Contains(t, string(data), "certifier")
}

func TestKeyringRevealerMarshalPubKey(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	r := wallet.KeyringRevealer{PubKey: privKey.PubKey()}
	data, err := json.Marshal(r)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestKeyringRevealerUnmarshalCertifier(t *testing.T) {
	var r wallet.KeyringRevealer
	err := json.Unmarshal([]byte(`"certifier"`), &r)
	require.NoError(t, err)
	assert.True(t, r.Certifier)
}

func TestKeyringRevealerUnmarshalEmpty(t *testing.T) {
	var r wallet.KeyringRevealer
	err := json.Unmarshal([]byte(`""`), &r)
	require.NoError(t, err)
	assert.False(t, r.Certifier)
}

func TestKeyringRevealerUnmarshalPubKey(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	jsonStr, _ := json.Marshal(privKey.PubKey().ToDERHex())

	var r wallet.KeyringRevealer
	err = json.Unmarshal(jsonStr, &r)
	require.NoError(t, err)
	assert.NotNil(t, r.PubKey)
}

// ---- AcquireCertificateArgs JSON ----

func TestAcquireCertificateArgsMarshalUnmarshalJSON(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	hash := make([]byte, 32)
	sig, err := privKey.Sign(hash)
	require.NoError(t, err)

	ct, _ := wallet.CertificateTypeFromString("testcert")
	args := wallet.AcquireCertificateArgs{
		Type:                ct,
		Certifier:           privKey.PubKey(),
		AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
		Signature:           sig,
	}

	data, err := json.Marshal(args)
	require.NoError(t, err)

	var decoded wallet.AcquireCertificateArgs
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.NotNil(t, decoded.Signature)
}

// ---- GetHeaderResult JSON ----

func TestGetHeaderResultMarshalUnmarshalJSON(t *testing.T) {
	result := wallet.GetHeaderResult{
		Header: []byte{0x01, 0x23, 0x45, 0x67},
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded wallet.GetHeaderResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result.Header, decoded.Header)
}

// ---- VerifyHMACArgs JSON ----

func TestVerifyHMACArgsMarshalUnmarshalJSON(t *testing.T) {
	var hmac [32]byte
	copy(hmac[:], []byte("test-hmac-32-bytes-here-exactly!"))

	args := wallet.VerifyHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelSilent,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Data: []byte{1, 2, 3},
		HMAC: hmac,
	}

	data, err := json.Marshal(args)
	require.NoError(t, err)

	var decoded wallet.VerifyHMACArgs
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, args.HMAC, decoded.HMAC)
	assert.Equal(t, args.Data, []byte(decoded.Data))
}

func TestVerifyHMACArgsUnmarshalWrongHMACLength(t *testing.T) {
	// HMAC of wrong length should fail
	data := []byte(`{"data":[1,2,3],"hmac":[1,2,3],"protocolID":[0,"test"],"keyID":"k"}`)
	var decoded wallet.VerifyHMACArgs
	err := json.Unmarshal(data, &decoded)
	assert.Error(t, err)
}

// ---- CreateHMACResult JSON ----

func TestCreateHMACResultMarshalUnmarshalJSON(t *testing.T) {
	var hmacBytes [32]byte
	copy(hmacBytes[:], []byte("test-hmac-value-32-bytes-here!!!"))

	result := wallet.CreateHMACResult{HMAC: hmacBytes}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded wallet.CreateHMACResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result.HMAC, decoded.HMAC)
}

func TestCreateHMACResultUnmarshalWrongLength(t *testing.T) {
	// HMAC of wrong length
	data := []byte(`{"hmac":[1,2,3]}`)
	var decoded wallet.CreateHMACResult
	err := json.Unmarshal(data, &decoded)
	assert.Error(t, err)
}

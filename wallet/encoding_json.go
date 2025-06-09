package wallet

import (
	"encoding/json"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func (c CertificateType) MarshalJSON() ([]byte, error) {
	// Convert the CertificateType to a base64 string
	return Bytes32Base64(c).MarshalJSON()
}

func (c *CertificateType) UnmarshalJSON(data []byte) error {
	return (*Bytes32Base64)(c).UnmarshalJSON(data)
}

func (s SerialNumber) MarshalJSON() ([]byte, error) {
	return Bytes32Base64(s).MarshalJSON()
}

func (s *SerialNumber) UnmarshalJSON(data []byte) error {
	return (*Bytes32Base64)(s).UnmarshalJSON(data)
}

// MarshalJSON implements the json.Marshaler interface for Protocol.
// It serializes the Protocol as a JSON array containing [SecurityLevel, Protocol].
func (p *Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{p.SecurityLevel, p.Protocol})
}

// UnmarshalJSON implements the json.Unmarshaler interface for Protocol.
// It deserializes a JSON array [SecurityLevel, Protocol] into the Protocol struct.
func (p *Protocol) UnmarshalJSON(data []byte) error {
	var temp []interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	if len(temp) != 2 {
		return fmt.Errorf("expected array of length 2, but got %d", len(temp))
	}

	securityLevel, ok := temp[0].(float64)
	if !ok {
		return fmt.Errorf("expected SecurityLevel to be a number, but got %T", temp[0])
	}
	p.SecurityLevel = SecurityLevel(securityLevel)

	protocol, ok := temp[1].(string)
	if !ok {
		return fmt.Errorf("expected Protocol to be a string, but got %T", temp[1])
	}
	p.Protocol = protocol

	return nil
}

// MarshalJSON implements the json.Marshaler interface for Counterparty.
// It serializes special counterparty types as strings ("anyone", "self") and
// specific counterparties as their DER-encoded hex public key.
func (c *Counterparty) MarshalJSON() ([]byte, error) {
	switch c.Type {
	case CounterpartyTypeAnyone:
		return json.Marshal("anyone")
	case CounterpartyTypeSelf:
		return json.Marshal("self")
	case CounterpartyTypeOther:
		if c.Counterparty == nil {
			return json.Marshal(nil) // Or handle this as an error if it should never happen
		}
		return json.Marshal(c.Counterparty.ToDERHex())
	default:
		return json.Marshal(nil) // Or handle this as an error if it should never happen
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for Counterparty.
// It deserializes "anyone", "self", or a DER-encoded hex public key string
// into the appropriate Counterparty struct.
func (c *Counterparty) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("could not unmarshal Counterparty from JSON: %s", string(data))
	}
	switch s {
	case "anyone":
		c.Type = CounterpartyTypeAnyone
	case "self":
		c.Type = CounterpartyTypeSelf
	case "":
		c.Type = CounterpartyUninitialized
	default:
		// Attempt to parse as a public key string
		pubKey, err := ec.PublicKeyFromString(s)
		if err != nil {
			return fmt.Errorf("error unmarshaling counterparty: %w", err)
		}
		c.Type = CounterpartyTypeOther
		c.Counterparty = pubKey
	}
	return nil
}

type aliasCreateSignatureResult CreateSignatureResult
type jsonCreateSignatureResult struct {
	Signature Signature `json:"signature"`
	*aliasCreateSignatureResult
}

// MarshalJSON implements the json.Marshaler interface for CreateSignatureResult.
func (c CreateSignatureResult) MarshalJSON() ([]byte, error) {
	if c.Signature == nil {
		return nil, fmt.Errorf("CreateSignatureResult has nil Signature")
	}
	return json.Marshal(&jsonCreateSignatureResult{
		aliasCreateSignatureResult: (*aliasCreateSignatureResult)(&c),
		Signature:                  Signature(*c.Signature),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for CreateSignatureResult.
func (c *CreateSignatureResult) UnmarshalJSON(data []byte) error {
	aux := jsonCreateSignatureResult{aliasCreateSignatureResult: (*aliasCreateSignatureResult)(c)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.Signature = (*ec.Signature)(&aux.Signature)
	return nil
}

type aliasVerifySignatureArgs VerifySignatureArgs
type jsonVerifySignatureArgs struct {
	Signature Signature `json:"signature"`
	*aliasVerifySignatureArgs
}

// MarshalJSON implements the json.Marshaler interface for VerifySignatureArgs.
func (v VerifySignatureArgs) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonVerifySignatureArgs{
		aliasVerifySignatureArgs: (*aliasVerifySignatureArgs)(&v),
		Signature:                Signature(*v.Signature),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for VerifySignatureArgs.
func (v *VerifySignatureArgs) UnmarshalJSON(data []byte) error {
	aux := &jsonVerifySignatureArgs{aliasVerifySignatureArgs: (*aliasVerifySignatureArgs)(v)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	v.Signature = (*ec.Signature)(&aux.Signature)
	return nil
}

// aliasCertificate uses an alias to avoid recursion
type aliasCertificate Certificate
type jsonCertificate struct {
	Signature BytesHex `json:"signature"`
	*aliasCertificate
}

// MarshalJSON implements json.Marshaler interface for Certificate
func (c Certificate) MarshalJSON() ([]byte, error) {
	var sig BytesHex
	if c.Signature != nil {
		sig = c.Signature.Serialize()
	}
	return json.Marshal(&jsonCertificate{
		Signature:        sig,
		aliasCertificate: (*aliasCertificate)(&c),
	})
}

// UnmarshalJSON implements json.Unmarshaler interface for Certificate
func (c *Certificate) UnmarshalJSON(data []byte) error {
	aux := &jsonCertificate{
		aliasCertificate: (*aliasCertificate)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling certificate: %w", err)
	}

	if len(aux.Signature) > 0 {
		sig, err := ec.ParseSignature(aux.Signature)
		if err != nil {
			return fmt.Errorf("error parsing signature from bytes: %w", err)
		}
		c.Signature = sig
	}

	return nil
}

type aliasCreateActionInput CreateActionInput
type jsonCreateActionInput struct {
	UnlockingScript BytesHex `json:"unlockingScript,omitempty"`
	*aliasCreateActionInput
}

func (i CreateActionInput) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonCreateActionInput{
		UnlockingScript:        i.UnlockingScript,
		aliasCreateActionInput: (*aliasCreateActionInput)(&i),
	})
}

func (i *CreateActionInput) UnmarshalJSON(data []byte) error {
	aux := &jsonCreateActionInput{
		aliasCreateActionInput: (*aliasCreateActionInput)(i),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling CreateActionInput: %w", err)
	}

	i.UnlockingScript = aux.UnlockingScript

	return nil
}

type aliasCreateActionOutput CreateActionOutput
type jsonCreateActionOutput struct {
	LockingScript BytesHex `json:"lockingScript,omitempty"`
	*aliasCreateActionOutput
}

func (o CreateActionOutput) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonCreateActionOutput{
		LockingScript:           o.LockingScript,
		aliasCreateActionOutput: (*aliasCreateActionOutput)(&o),
	})
}

func (o *CreateActionOutput) UnmarshalJSON(data []byte) error {
	aux := &jsonCreateActionOutput{
		aliasCreateActionOutput: (*aliasCreateActionOutput)(o),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling CreateActionOutput: %w", err)
	}

	o.LockingScript = aux.LockingScript

	return nil
}

type aliasSignActionSpend SignActionSpend
type jsonSignActionSpend struct {
	UnlockingScript BytesHex `json:"unlockingScript"`
	*aliasSignActionSpend
}

func (s SignActionSpend) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonSignActionSpend{
		UnlockingScript:      s.UnlockingScript,
		aliasSignActionSpend: (*aliasSignActionSpend)(&s),
	})
}

func (s *SignActionSpend) UnmarshalJSON(data []byte) error {
	aux := &jsonSignActionSpend{
		aliasSignActionSpend: (*aliasSignActionSpend)(s),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling SignActionSpend: %w", err)
	}

	s.UnlockingScript = aux.UnlockingScript

	return nil
}

type aliasActionInput ActionInput
type jsonActionInput struct {
	SourceLockingScript BytesHex `json:"sourceLockingScript,omitempty"`
	UnlockingScript     BytesHex `json:"unlockingScript,omitempty"`
	*aliasActionInput
}

func (a ActionInput) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonActionInput{
		SourceLockingScript: a.SourceLockingScript,
		UnlockingScript:     a.UnlockingScript,
		aliasActionInput:    (*aliasActionInput)(&a),
	})
}

func (a *ActionInput) UnmarshalJSON(data []byte) error {
	aux := &jsonActionInput{
		aliasActionInput: (*aliasActionInput)(a),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling ActionInput: %w", err)
	}

	a.SourceLockingScript = aux.SourceLockingScript
	a.UnlockingScript = aux.UnlockingScript

	return nil
}

type aliasActionOutput ActionOutput
type jsonActionOutput struct {
	LockingScript BytesHex `json:"lockingScript,omitempty"`
	*aliasActionOutput
}

func (o ActionOutput) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonActionOutput{
		LockingScript:     o.LockingScript,
		aliasActionOutput: (*aliasActionOutput)(&o),
	})
}

func (o *ActionOutput) UnmarshalJSON(data []byte) error {
	aux := &jsonActionOutput{
		aliasActionOutput: (*aliasActionOutput)(o),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling ActionOutput: %w", err)
	}

	o.LockingScript = aux.LockingScript

	return nil
}

type aliasInternalizeActionArgs InternalizeActionArgs
type jsonInternalizeActionArgs struct {
	Tx BytesList `json:"tx"`
	*aliasInternalizeActionArgs
}

func (i InternalizeActionArgs) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonInternalizeActionArgs{
		Tx:                         i.Tx,
		aliasInternalizeActionArgs: (*aliasInternalizeActionArgs)(&i),
	})
}

func (i *InternalizeActionArgs) UnmarshalJSON(data []byte) error {
	aux := &jsonInternalizeActionArgs{
		aliasInternalizeActionArgs: (*aliasInternalizeActionArgs)(i),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling InternalizeActionArgs: %w", err)
	}

	i.Tx = aux.Tx

	return nil
}

type aliasOutput Output
type jsonOutput struct {
	LockingScript BytesHex `json:"lockingScript,omitempty"`
	*aliasOutput
}

func (o Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonOutput{
		LockingScript: BytesHex(o.LockingScript),
		aliasOutput:   (*aliasOutput)(&o),
	})
}

func (o *Output) UnmarshalJSON(data []byte) error {
	aux := &jsonOutput{
		aliasOutput: (*aliasOutput)(o),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling Output: %w", err)
	}

	o.LockingScript = []byte(aux.LockingScript)

	return nil
}

type aliasListOutputsResult ListOutputsResult
type jsonListOutputsResult struct {
	BEEF    BytesList `json:"BEEF,omitempty"`
	Outputs []Output  `json:"outputs"` // This will use Output's custom marshaler
	*aliasListOutputsResult
}

func (l ListOutputsResult) MarshalJSON() ([]byte, error) {
	// Note: TotalOutputs is part of aliasListOutputsResult and will be marshaled directly.
	return json.Marshal(&jsonListOutputsResult{
		BEEF:                   BytesList(l.BEEF),
		Outputs:                l.Outputs,
		aliasListOutputsResult: (*aliasListOutputsResult)(&l),
	})
}

func (l *ListOutputsResult) UnmarshalJSON(data []byte) error {
	aux := &jsonListOutputsResult{
		aliasListOutputsResult: (*aliasListOutputsResult)(l),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling ListOutputsResult: %w", err)
	}

	l.BEEF = []byte(aux.BEEF)
	l.Outputs = aux.Outputs // This will use Output's custom unmarshaler

	return nil
}

// MarshalJSON implements the json.Marshaler interface for CertificateResult
// It handles the flattening of the embedded Certificate fields.
func (cr *CertificateResult) MarshalJSON() ([]byte, error) {
	// Start with marshaling the embedded Certificate
	certData, err := json.Marshal(&cr.Certificate)
	if err != nil {
		return nil, fmt.Errorf("error marshaling embedded Certificate: %w", err)
	}

	// Unmarshal certData into a map
	var certMap map[string]interface{}
	if err := json.Unmarshal(certData, &certMap); err != nil {
		return nil, fmt.Errorf("error unmarshaling cert data into map: %w", err)
	}

	// Add Keyring and Verifier to the map
	if cr.Keyring != nil {
		certMap["keyring"] = cr.Keyring
	}
	if len(cr.Verifier) > 0 {
		certMap["verifier"] = BytesHex(cr.Verifier) // Ensure Verifier is hex-encoded
	}

	// Marshal the final map
	return json.Marshal(certMap)
}

// UnmarshalJSON implements the json.Unmarshaler interface for CertificateResult
// It handles the flattening of the embedded Certificate fields.
func (cr *CertificateResult) UnmarshalJSON(data []byte) error {
	// Unmarshal into the embedded Certificate first
	if err := json.Unmarshal(data, &cr.Certificate); err != nil {
		return fmt.Errorf("error unmarshaling embedded Certificate: %w", err)
	}

	// Unmarshal into a temporary map to get Keyring and Verifier
	var temp map[string]json.RawMessage
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("error unmarshaling into temp map: %w", err)
	}

	// Unmarshal Keyring
	if keyringData, ok := temp["keyring"]; ok {
		if err := json.Unmarshal(keyringData, &cr.Keyring); err != nil {
			return fmt.Errorf("error unmarshaling keyring: %w", err)
		}
	}

	// Unmarshal Verifier
	if verifierData, ok := temp["verifier"]; ok {
		var verifierHex BytesHex
		if err := json.Unmarshal(verifierData, &verifierHex); err != nil {
			return fmt.Errorf("error unmarshaling verifier: %w", err)
		}
		cr.Verifier = []byte(verifierHex)
	}

	return nil
}

// Custom marshalling for RevealCounterpartyKeyLinkageResult
type aliasRevealCounterpartyKeyLinkageResult RevealCounterpartyKeyLinkageResult
type jsonRevealCounterpartyKeyLinkageResult struct {
	EncryptedLinkage      BytesList `json:"encryptedLinkage"`
	EncryptedLinkageProof BytesList `json:"encryptedLinkageProof"`
	*aliasRevealCounterpartyKeyLinkageResult
}

func (r RevealCounterpartyKeyLinkageResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonRevealCounterpartyKeyLinkageResult{
		EncryptedLinkage:                        r.EncryptedLinkage,
		EncryptedLinkageProof:                   r.EncryptedLinkageProof,
		aliasRevealCounterpartyKeyLinkageResult: (*aliasRevealCounterpartyKeyLinkageResult)(&r),
	})
}

func (r *RevealCounterpartyKeyLinkageResult) UnmarshalJSON(data []byte) error {
	aux := &jsonRevealCounterpartyKeyLinkageResult{
		aliasRevealCounterpartyKeyLinkageResult: (*aliasRevealCounterpartyKeyLinkageResult)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling RevealCounterpartyKeyLinkageResult: %w", err)
	}
	r.EncryptedLinkage = aux.EncryptedLinkage
	r.EncryptedLinkageProof = aux.EncryptedLinkageProof
	return nil
}

// Custom marshalling for RevealSpecificKeyLinkageResult
type aliasRevealSpecificKeyLinkageResult RevealSpecificKeyLinkageResult
type jsonRevealSpecificKeyLinkageResult struct {
	EncryptedLinkage      BytesList `json:"encryptedLinkage"`
	EncryptedLinkageProof BytesList `json:"encryptedLinkageProof"`
	*aliasRevealSpecificKeyLinkageResult
}

func (r RevealSpecificKeyLinkageResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonRevealSpecificKeyLinkageResult{
		EncryptedLinkage:                    r.EncryptedLinkage,
		EncryptedLinkageProof:               r.EncryptedLinkageProof,
		aliasRevealSpecificKeyLinkageResult: (*aliasRevealSpecificKeyLinkageResult)(&r),
	})
}

func (r *RevealSpecificKeyLinkageResult) UnmarshalJSON(data []byte) error {
	aux := &jsonRevealSpecificKeyLinkageResult{
		aliasRevealSpecificKeyLinkageResult: (*aliasRevealSpecificKeyLinkageResult)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling RevealSpecificKeyLinkageResult: %w", err)
	}
	r.EncryptedLinkage = aux.EncryptedLinkage
	r.EncryptedLinkageProof = aux.EncryptedLinkageProof
	return nil
}

// MarshalJSON implements the json.Marshaler interface for IdentityCertificate.
// It handles the flattening of the embedded Certificate fields.
func (ic *IdentityCertificate) MarshalJSON() ([]byte, error) {
	// Start with marshaling the embedded Certificate
	certData, err := json.Marshal(&ic.Certificate)
	if err != nil {
		return nil, fmt.Errorf("error marshaling embedded Certificate: %w", err)
	}

	// Unmarshal certData into a map
	var certMap map[string]interface{}
	if err := json.Unmarshal(certData, &certMap); err != nil {
		return nil, fmt.Errorf("error unmarshaling cert data into map: %w", err)
	}

	// Add IdentityCertificate specific fields to the map
	certMap["certifierInfo"] = ic.CertifierInfo
	if ic.PubliclyRevealedKeyring != nil {
		certMap["publiclyRevealedKeyring"] = ic.PubliclyRevealedKeyring
	}
	if ic.DecryptedFields != nil {
		certMap["decryptedFields"] = ic.DecryptedFields
	}

	// Marshal the final map
	return json.Marshal(certMap)
}

// UnmarshalJSON implements the json.Unmarshaler interface for IdentityCertificate.
// It handles the flattening of the embedded Certificate fields.
func (ic *IdentityCertificate) UnmarshalJSON(data []byte) error {
	// Unmarshal into the embedded Certificate first
	if err := json.Unmarshal(data, &ic.Certificate); err != nil {
		return fmt.Errorf("error unmarshaling embedded Certificate: %w", err)
	}

	// Unmarshal into a temporary map to get the other fields
	var temp map[string]json.RawMessage
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("error unmarshaling into temp map: %w", err)
	}

	// Unmarshal CertifierInfo
	if certInfoData, ok := temp["certifierInfo"]; ok {
		if err := json.Unmarshal(certInfoData, &ic.CertifierInfo); err != nil {
			return fmt.Errorf("error unmarshaling certifierInfo: %w", err)
		}
	}

	// Unmarshal PubliclyRevealedKeyring
	if pubKeyringData, ok := temp["publiclyRevealedKeyring"]; ok {
		if err := json.Unmarshal(pubKeyringData, &ic.PubliclyRevealedKeyring); err != nil {
			return fmt.Errorf("error unmarshaling publiclyRevealedKeyring: %w", err)
		}
	}

	// Unmarshal DecryptedFields
	if decryptedData, ok := temp["decryptedFields"]; ok {
		if err := json.Unmarshal(decryptedData, &ic.DecryptedFields); err != nil {
			return fmt.Errorf("error unmarshaling decryptedFields: %w", err)
		}
	}

	return nil
}

func (r KeyringRevealer) MarshalJSON() ([]byte, error) {
	if r.Certifier {
		return json.Marshal(KeyringRevealerCertifier)
	}
	return json.Marshal(r.PubKey)
}

func (r *KeyringRevealer) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("error unmarshaling revealer: %w", err)
	}

	if str == "" {
		return nil
	}
	if str == KeyringRevealerCertifier {
		r.Certifier = true
		return nil
	}
	pk, err := ec.PublicKeyFromString(str)
	if err != nil {
		return fmt.Errorf("error parsing revealer public key from bytes: %w", err)
	}
	r.PubKey = pk
	return nil
}

// Custom marshalling for AcquireCertificateArgs
type aliasAcquireCertificateArgs AcquireCertificateArgs
type jsonAcquireCertificateArgs struct {
	Signature BytesHex `json:"signature"`
	*aliasAcquireCertificateArgs
}

func (a AcquireCertificateArgs) MarshalJSON() ([]byte, error) {
	var sigBytes BytesHex
	if a.Signature != nil {
		sigBytes = a.Signature.Serialize()
	}
	return json.Marshal(&jsonAcquireCertificateArgs{
		Signature:                   sigBytes,
		aliasAcquireCertificateArgs: (*aliasAcquireCertificateArgs)(&a),
	})
}

func (a *AcquireCertificateArgs) UnmarshalJSON(data []byte) error {
	aux := &jsonAcquireCertificateArgs{
		aliasAcquireCertificateArgs: (*aliasAcquireCertificateArgs)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling AcquireCertificateArgs: %w", err)
	}
	if len(aux.Signature) > 0 {
		sig, err := ec.ParseSignature(aux.Signature)
		if err != nil {
			return fmt.Errorf("error parsing signature from bytes: %w", err)
		}
		a.Signature = sig
	}
	return nil
}

// Custom marshalling for GetHeaderResult
type aliasGetHeaderResult GetHeaderResult
type jsonGetHeaderResult struct {
	Header BytesHex `json:"header"`
	*aliasGetHeaderResult
}

func (r GetHeaderResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonGetHeaderResult{
		Header:               BytesHex(r.Header),
		aliasGetHeaderResult: (*aliasGetHeaderResult)(&r),
	})
}

func (r *GetHeaderResult) UnmarshalJSON(data []byte) error {
	aux := &jsonGetHeaderResult{
		aliasGetHeaderResult: (*aliasGetHeaderResult)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling GetHeaderResult: %w", err)
	}
	r.Header = []byte(aux.Header)
	return nil
}

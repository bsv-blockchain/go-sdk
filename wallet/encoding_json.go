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

func (s PubKey) MarshalJSON() ([]byte, error) {
	return Bytes33Hex(s).MarshalJSON()
}

func (s *PubKey) UnmarshalJSON(data []byte) error {
	return (*Bytes33Hex)(s).UnmarshalJSON(data)
}

// aliasCertificate uses an alias to avoid recursion
type aliasCertificate Certificate
type jsonCertificate struct {
	Subject   *string  `json:"subject"`
	Certifier *string  `json:"certifier"`
	Signature BytesHex `json:"signature"`
	*aliasCertificate
}

// MarshalJSON implements json.Marshaler interface for Certificate
func (c Certificate) MarshalJSON() ([]byte, error) {
	var subjectHex, certifierHex *string
	if c.Subject != nil {
		s := c.Subject.ToDERHex()
		subjectHex = &s
	}
	if c.Certifier != nil {
		cs := c.Certifier.ToDERHex()
		certifierHex = &cs
	}

	return json.Marshal(&jsonCertificate{
		Signature:        c.Signature,
		Subject:          subjectHex,
		Certifier:        certifierHex,
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

	// Decode public key hex strings
	if aux.Subject != nil {
		sub, err := ec.PublicKeyFromString(*aux.Subject)
		if err != nil {
			return fmt.Errorf("error decoding subject public key hex: %w", err)
		}
		c.Subject = sub
	}
	if aux.Certifier != nil {
		cert, err := ec.PublicKeyFromString(*aux.Certifier)
		if err != nil {
			return fmt.Errorf("error decoding certifier public key hex: %w", err)
		}
		c.Certifier = cert
	}

	c.Type = aux.Type
	c.SerialNumber = aux.SerialNumber
	c.Signature = aux.Signature

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

func (o *Outpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o *Outpoint) UnmarshalJSON(data []byte) error {
	var outpointStr string
	if err := json.Unmarshal(data, &outpointStr); err != nil {
		return fmt.Errorf("error unmarshaling outpoint string: %w", err)
	}
	outpoint, err := OutpointFromString(outpointStr)
	if err != nil {
		return fmt.Errorf("error parsing outpoint string: %w", err)
	}
	o.Txid = outpoint.Txid
	o.Index = outpoint.Index
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
		EncryptedLinkage:                        BytesList(r.EncryptedLinkage),
		EncryptedLinkageProof:                   BytesList(r.EncryptedLinkageProof),
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
	r.EncryptedLinkage = []byte(aux.EncryptedLinkage)
	r.EncryptedLinkageProof = []byte(aux.EncryptedLinkageProof)
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

// Custom marshalling for AcquireCertificateArgs
type aliasAcquireCertificateArgs AcquireCertificateArgs
type jsonAcquireCertificateArgs struct {
	Signature BytesHex `json:"signature"`
	*aliasAcquireCertificateArgs
}

func (a AcquireCertificateArgs) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonAcquireCertificateArgs{
		Signature:                   BytesHex(a.Signature),
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
	a.Signature = []byte(aux.Signature)
	// Other fields are handled by alias or have their own marshallers
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

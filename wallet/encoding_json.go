package wallet

import (
	"encoding/json"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// aliasCertificate uses an alias to avoid recursion
type aliasCertificate Certificate

type jsonCertificate struct {
	Type         Bytes32Base64 `json:"type"`
	SerialNumber Bytes32Base64 `json:"serialNumber"`
	Subject      *string       `json:"subject"`
	Certifier    *string       `json:"certifier"`
	Signature    BytesHex      `json:"signature"`
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
		Type:             c.Type,
		SerialNumber:     c.SerialNumber,
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

type aliasAcquireCertificateArgs AcquireCertificateArgs

type jsonAcquireCertificateArgs struct {
	Type         Bytes32Base64 `json:"type"`
	SerialNumber Bytes32Base64 `json:"serialNumber"`
	Certifier    Bytes33Hex    `json:"certifier"`
	*aliasAcquireCertificateArgs
}

func (a AcquireCertificateArgs) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonAcquireCertificateArgs{
		Type:                        a.Type,
		SerialNumber:                a.SerialNumber,
		Certifier:                   a.Certifier,
		aliasAcquireCertificateArgs: (*aliasAcquireCertificateArgs)(&a),
	})
}

func (a *AcquireCertificateArgs) UnmarshalJSON(data []byte) error {
	type Alias AcquireCertificateArgs
	aux := &jsonAcquireCertificateArgs{
		aliasAcquireCertificateArgs: (*aliasAcquireCertificateArgs)(a),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling AcquireCertificateArgs: %w", err)
	}

	a.Type = aux.Type
	a.SerialNumber = aux.SerialNumber
	a.Certifier = aux.Certifier

	return nil
}

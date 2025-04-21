package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// MessageType defines the type of message exchanged in auth
type MessageType string

const (
	// Message types following the TypeScript SDK
	MessageTypeInitialRequest      MessageType = "initialRequest"
	MessageTypeInitialResponse     MessageType = "initialResponse"
	MessageTypeCertificateRequest  MessageType = "certificateRequest"
	MessageTypeCertificateResponse MessageType = "certificateResponse"
	MessageTypeGeneral             MessageType = "general"
)

// AuthMessage represents a message exchanged during the auth protocol
type AuthMessage struct {
	// Version of the auth protocol
	Version string `json:"version"`

	// Type of message
	MessageType MessageType `json:"messageType"`

	// Sender's identity key
	IdentityKey *ec.PublicKey `json:"identityKey"`

	// Sender's nonce (256-bit random value)
	Nonce string `json:"nonce,omitempty"`

	// The initial nonce from the initial request (for initial responses)
	InitialNonce string `json:"initialNonce,omitempty"`

	// The recipient's nonce from a previous message (if applicable)
	YourNonce string `json:"yourNonce,omitempty"`

	// Optional: List of certificates (if required/requested)
	Certificates []*certificates.VerifiableCertificate `json:"certificates,omitempty"`

	// Optional: List of requested certificates
	RequestedCertificates utils.RequestedCertificateSet `json:"requestedCertificates,omitempty"`

	// The actual message data (optional)
	Payload []byte `json:"payload,omitempty"`

	// Digital signature covering the entire message
	Signature []byte `json:"signature,omitempty"`
}

// ValidateCertificates validates and processes the certificates received from a peer.
// The certificatesRequested parameter can be nil or a RequestedCertificateSet
func ValidateCertificates(
	verifierWallet wallet.Interface,
	message *AuthMessage,
	certificatesRequested *utils.RequestedCertificateSet,
) error {
	// Check if certificates are provided
	if message.Certificates == nil {
		return fmt.Errorf("no certificates were provided in the AuthMessage")
	}

	// Use a wait group to wait for all certificate validations to complete
	var wg sync.WaitGroup
	errCh := make(chan error, len(message.Certificates))

	// Process each certificate concurrently
	for _, incomingCert := range message.Certificates {
		wg.Add(1)
		go func(cert *certificates.VerifiableCertificate) {
			defer wg.Done()

			// Check that the certificate subject matches the message identity key
			subjectKey := cert.Subject.ToDER()
			messageIdentityKey := message.IdentityKey.ToDER()
			if !bytes.Equal(subjectKey, messageIdentityKey) {
				errCh <- fmt.Errorf(
					"the subject of one of your certificates (\"%x\") is not the same as the request sender (\"%x\")",
					subjectKey,
					messageIdentityKey,
				)
				return
			}

			// Verify Certificate structure and signature
			err := cert.Verify()
			if err != nil {
				errCh <- fmt.Errorf("the signature for the certificate with serial number %s is invalid: %v",
					cert.SerialNumber, err)
				return
			}

			// Check if the certificate matches requested certifiers, types, and fields
			if certificatesRequested != nil {
				certifiers := certificatesRequested.Certifiers
				types := certificatesRequested.CertificateTypes

				// Check certifier matches
				certifierKey := cert.Certifier.ToDERHex()
				if !slices.Contains(certifiers, certifierKey) {
					errCh <- fmt.Errorf(
						"certificate with serial number %s has an unrequested certifier: %s",
						cert.SerialNumber,
						certifierKey,
					)
					return
				}

				// Check type match
				_, typeExists := types[string(cert.Type)]
				if !typeExists {
					errCh <- fmt.Errorf("certificate with type %s was not requested", cert.Type)
					return
				}
			}

			_, err = cert.DecryptFields(verifierWallet, false, "")
			if err != nil {
				errCh <- fmt.Errorf("failed to decrypt certificate fields: %v", err)
				return
			}
		}(incomingCert)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(errCh)

	// Check if any errors occurred
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// Transport defines the interface for sending and receiving AuthMessages
// This matches the TypeScript SDK's Transport interface exactly
type Transport interface {
	// Send sends an AuthMessage to its destination
	Send(message *AuthMessage) error

	// OnData registers a callback to be called when a message is received
	OnData(callback func(message *AuthMessage) error) error
}

// PeerSession represents a session with a peer
type PeerSession struct {
	// Whether the session is authenticated
	IsAuthenticated bool

	// The session nonce
	SessionNonce string

	// The peer's nonce
	PeerNonce string

	// The peer's identity key
	PeerIdentityKey *ec.PublicKey

	// The last time the session was updated (milliseconds since epoch)
	LastUpdate int64
}

// CertificateQuery defines criteria for retrieving certificates
type CertificateQuery struct {
	// List of certifier identity keys (hex-encoded public keys)
	Certifiers []string

	// List of certificate type IDs
	Types []string

	// Subject identity key (who the certificate is about)
	Subject string
}

func (m *AuthMessage) MarshalJSON() ([]byte, error) {
	type Alias AuthMessage

	if m.IdentityKey == nil {
		return nil, fmt.Errorf("IdentityKey is required for marshaling AuthMessage")
	}

	return json.Marshal(&struct {
		IdentityKey string `json:"identityKey"`
		Payload     string `json:"payload,omitempty"`
		Signature   string `json:"signature,omitempty"`
		*Alias
	}{
		IdentityKey: m.IdentityKey.ToDERHex(),
		Payload:     base64.StdEncoding.EncodeToString(m.Payload),
		Signature:   base64.StdEncoding.EncodeToString(m.Signature),
		Alias:       (*Alias)(m),
	})
}

func (m *AuthMessage) UnmarshalJSON(data []byte) error {
	type Alias AuthMessage

	aux := &struct {
		IdentityKey string `json:"identityKey"`
		Payload     string `json:"payload,omitempty"`
		Signature   string `json:"signature,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling AuthMessage: %w", err)
	}

	pubKey, err := ec.PublicKeyFromString(aux.IdentityKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	m.IdentityKey = pubKey

	if aux.Payload != "" {
		m.Payload, err = base64.StdEncoding.DecodeString(aux.Payload)
		if err != nil {
			return fmt.Errorf("invalid payload base64: %w", err)
		}
	}

	if aux.Signature != "" {
		m.Signature, err = base64.StdEncoding.DecodeString(aux.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature base64: %w", err)
		}
	}

	return nil
}

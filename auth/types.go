package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

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
	ctx context.Context,
	verifierWallet wallet.Interface,
	message *AuthMessage,
	certificatesRequested *utils.RequestedCertificateSet,
) error {
	err := utils.ValidateCertificates(ctx, verifierWallet, message.Certificates, message.IdentityKey, certificatesRequested)
	if err != nil {
		return fmt.Errorf("invalid certificates in Auth Message: %w", err)
	}
	return nil
}

// Transport defines the interface for sending and receiving AuthMessages
// This matches the TypeScript SDK's Transport interface exactly
type Transport interface {
	// GetRegisteredOnData returns the current callback function for handling incoming AuthMessages
	GetRegisteredOnData() (func(context.Context, *AuthMessage) error, error)

	// Send sends an AuthMessage to its destination
	Send(ctx context.Context, message *AuthMessage) error

	// OnData registers a callback to be called when a message is received
	OnData(callback func(ctx context.Context, message *AuthMessage) error) error
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

// MarshalJSON customizes the JSON marshaling for AuthMessage to ensure proper formatting
// of identity keys, payload, and signature fields as base64-encoded strings.
func (m *AuthMessage) MarshalJSON() ([]byte, error) {
	type Alias AuthMessage

	if m.IdentityKey == nil {
		return nil, fmt.Errorf("IdentityKey is required for marshaling AuthMessage")
	}

	// For certificates, ensure signature format is correct
	formattedCerts := make([]*certificates.VerifiableCertificate, 0, len(m.Certificates))
	for _, cert := range m.Certificates {
		certCopy := *cert

		// If signature is base64 encoded, decode it to raw bytes
		if len(cert.Signature) > 0 {
			// Check if it's already a valid ASN.1 DER signature
			if _, err := ec.ParseSignature(cert.Signature); err != nil {
				// It's not, try to decode from base64
				if sigBytes, err := base64.StdEncoding.DecodeString(string(cert.Signature)); err == nil {
					certCopy.Signature = sigBytes
				}
			}
		}

		formattedCerts = append(formattedCerts, &certCopy)
	}

	return json.Marshal(&struct {
		IdentityKey  string                                `json:"identityKey"`
		Certificates []*certificates.VerifiableCertificate `json:"certificates,omitempty"`
		Payload      wallet.BytesList                      `json:"payload,omitempty"`
		Signature    wallet.BytesList                      `json:"signature,omitempty"`
		*Alias
	}{
		IdentityKey:  m.IdentityKey.ToDERHex(),
		Certificates: formattedCerts,
		Payload:      m.Payload,
		Signature:    m.Signature,
		Alias:        (*Alias)(m),
	})
}

// UnmarshalJSON customizes the JSON unmarshaling for AuthMessage to properly decode
// base64-encoded fields and reconstruct the public key from the hex-encoded identity key.
func (m *AuthMessage) UnmarshalJSON(data []byte) error {
	type Alias AuthMessage

	aux := &struct {
		IdentityKey string           `json:"identityKey"`
		Payload     wallet.BytesList `json:"payload,omitempty"`
		Signature   wallet.BytesList `json:"signature,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("error unmarshaling AuthMessage: %w", err)
	}

	m.Payload = aux.Payload
	m.Signature = aux.Signature

	pubKey, err := ec.PublicKeyFromString(aux.IdentityKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	m.IdentityKey = pubKey

	// Process certificates to ensure signature is in correct format for validation
	for i, cert := range m.Certificates {
		if cert != nil && len(cert.Signature) > 0 {
			// If it's a base64 encoded string
			sigStr := string(cert.Signature)
			if _, err := base64.StdEncoding.DecodeString(sigStr); err == nil {
				decodedSig, _ := base64.StdEncoding.DecodeString(sigStr)
				m.Certificates[i].Signature = decodedSig
			}
		}
	}

	return nil
}

package auth

import (
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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
	IdentityKey ec.PublicKey `json:"identityKey"`

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
	PeerIdentityKey string

	// The last time the session was updated (milliseconds since epoch)
	LastUpdate int64
}

package auth

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type RequestedCertificateTypeIDAndFieldList map[string][]string

type RequesredCertificateSet struct {
	Certifiers       []string
	CertificateTypes RequestedCertificateTypeIDAndFieldList
}

type MessageType string

var (
	MessageTypeInitialRequest      MessageType = "initialRequest"
	MessageTypeInitialResponse     MessageType = "initialResponse"
	MessageTypeCertificateRequest  MessageType = "certificateRequest"
	MessageTypeCertificateResponse MessageType = "certificateResponse"
	MessageTypeGeneral             MessageType = "general"
)

type AuthMessage struct {
	Version               string
	MessageType           MessageType
	IdentityKey           ec.PublicKey
	Nonce                 string
	InitialNonce          string
	YourNonce             string
	RequestedCertificates RequesredCertificateSet
	Payload               []byte
	Signature             []byte
}

type Transport interface {
	Send(*AuthMessage) error
	OnData(func(*AuthMessage) error) error
}

type PeerSession struct {
	IsAuthenticated bool
	SessionNonce    string
	PeerNonce       string
	PeerIdentityKey string
	LastUpdated     int
}

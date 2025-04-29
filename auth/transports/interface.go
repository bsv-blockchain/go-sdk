package transports

import (
	"github.com/bsv-blockchain/go-sdk/auth"
)

// Transport defines the interface for communication transports used in authentication
type Transport interface {
	// Send transmits an AuthMessage through the transport
	Send(message *auth.AuthMessage) error

	// OnData registers a callback function to handle incoming AuthMessages
	OnData(callback func(*auth.AuthMessage) error) error
}

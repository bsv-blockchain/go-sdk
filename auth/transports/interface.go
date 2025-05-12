package transports

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/auth"
)

// Transport defines the interface for communication transports used in authentication
type Transport interface {
	// Send transmits an AuthMessage through the transport
	Send(ctx context.Context, message *auth.AuthMessage) error

	// OnData registers a callback function to handle incoming AuthMessages
	OnData(callback func(context.Context, *auth.AuthMessage) error) error
}

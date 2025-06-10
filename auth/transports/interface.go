// Package transports provides abstractions for different communication protocols used in
// authentication. It defines a common Transport interface that can be implemented by various
// protocols such as HTTP and WebSocket, enabling flexible peer-to-peer communication patterns.
// The package includes implementations for simplified HTTP transport and full-duplex WebSocket
// transport, both supporting authenticated message exchange.
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

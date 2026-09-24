// Package messaging_test runs the ts-stack messaging/message-box-http.json
// conformance vectors against go-sdk.
package messaging_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestMessagingMessageBoxHTTP declares a GoGap for every vector. Verified
// against the whole repository: message/** only implements the BRC-78
// encrypted envelope and BRC-77 signed-message primitives; there is no
// MessageBoxClient or HTTP client anywhere in go-sdk for the message-box-server
// REST API (sendMessage/listMessages/acknowledgeMessage, WebSocket rooms,
// etc.) that these vectors describe (reference_impl: message-box-server@2.0.0).
// Building that client from scratch is a new feature, out of scope for a
// conformance-parity fix.
func TestMessagingMessageBoxHTTP(t *testing.T) {
	f := conformance.Load(t, "messaging/message-box-http.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no message-box-server HTTP client; message/** only "+
			"implements BRC-78/BRC-77 envelope primitives, not the message box relay REST API")
	})
}

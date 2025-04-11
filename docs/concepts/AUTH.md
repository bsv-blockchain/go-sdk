# Authentication Package

The `auth` package provides certificate-based authentication for peer-to-peer communication. It allows peers to establish authenticated sessions, verify identities, and exchange verifiable credentials.

## Key Components

### Peer

The `Peer` class is the main interface for authentication operations. It handles:

- Session establishment via mutual authentication
- Message exchange with authenticated peers
- Certificate requests and responses
- General-purpose authenticated messaging

### SessionManager

Manages authenticated sessions, allowing for multiple concurrent sessions with different peers.

### Transport

Abstracts the communication layer. Implementations can use various protocols (WebSockets, HTTP, etc.)

### AuthMessage

Represents different types of authentication messages, including:
- Initial authentication requests and responses
- Certificate requests and responses
- General authenticated messages

### Certificates

The `certificates` subpackage provides verifiable certificate functionality including:
- Certificate creation and verification
- Selective disclosure of fields
- Certificate chain validation

## Getting Started

Here's a basic example of using the authentication system:

```go
import (
    "github.com/bsv-blockchain/go-sdk/auth"
    "github.com/bsv-blockchain/go-sdk/wallet"
)

// Create a peer with a wallet and transport implementation
peer := auth.NewPeer(&auth.PeerOptions{
    Wallet:    myWallet,
    Transport: myTransport,
})

// Listen for incoming messages
peer.ListenForGeneralMessages(func(senderPublicKey string, payload []byte) error {
    // Process received message
    return nil
})

// Send a message to a peer
err := peer.ToPeer([]byte("Hello, world!"), peerIdentityKey, 5000)
if err != nil {
    // Handle error
}
```

## Clients

The `clients` subpackage provides authentication-enabled clients for various protocols:

- `authhttp`: Authenticated HTTP client

## Utils

The `utils` subpackage contains utilities for certificate management and validation.

## Integration with Wallet

The authentication system integrates with the wallet system for:
- Identity key operations
- Certificate management
- Message signing and verification 
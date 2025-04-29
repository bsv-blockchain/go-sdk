# Authentication Package

The `auth` package provides certificate-based authentication for peer-to-peer communication. It allows peers to establish authenticated sessions, verify identities, and exchange verifiable credentials.

## Key Components

### Peer

The `Peer` is the main interface for authentication operations. It handles:

- Session establishment via mutual authentication
- Message exchange with authenticated peers
- Certificate requests and responses
- General-purpose authenticated messaging

```go
// Create a peer with a wallet and transport implementation
peer := auth.NewPeer(&auth.PeerOptions{
    Wallet:                myWallet,
    Transport:             myTransport,
    CertificatesToRequest: certificateRequirements, // Optional
    SessionManager:        sessionManager,          // Optional
})

// Listen for incoming messages
callbackID := peer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
    // Process received message
    return nil
})

// Send a message to a peer
ctx := context.Background()
err := peer.ToPeer(ctx, []byte("Hello, world!"), peerIdentityKey, 5000)
if err != nil {
    // Handle error
}
```

### SessionManager

Manages authenticated sessions, allowing for multiple concurrent sessions with different peers:

```go
// Create a session manager
sessionManager := auth.NewSessionManager()

// Add, update or retrieve sessions
session := &auth.PeerSession{
    IsAuthenticated: true,
    SessionNonce:    "nonce123",
    PeerNonce:       "peernonce456",
    PeerIdentityKey: peerPublicKey,
    LastUpdate:      time.Now().UnixMilli(),
}
sessionManager.AddSession(session)
```

### Transport

Abstracts the communication layer. The SDK provides two implementations:

1. **SimplifiedHTTPTransport**: For HTTP-based authentication
   ```go
   transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
       BaseURL: "https://example.com",
   })
   ```

2. **WebSocketTransport**: For WebSocket connections
   ```go
   transport, err := transports.NewWebSocketTransport(&transports.WebSocketTransportOptions{
       URL: "wss://example.com/ws",
   })
   ```

### AuthMessage

Represents different types of authentication messages:

```go
message := &auth.AuthMessage{
    Version:     "0.1",
    MessageType: auth.MessageTypeInitialRequest,
    IdentityKey: myIdentityKey,
    Nonce:       myNonce,
    // Other fields depending on message type
}
```

Message types include:
- Initial authentication requests and responses
- Certificate requests and responses
- General authenticated messages

### Certificates

The `certificates` subpackage provides verifiable certificate functionality:

```go
// Create a certificate
cert := certificates.NewCertificate(
    certificateType,
    serialNumber,
    subjectKey,
    certifierKey,
    revocationOutpoint,
    fields,
    nil, // signature
)

// Sign a certificate
err := cert.Sign(ctx, certifierWallet)

// Verify a certificate
err := cert.Verify(ctx)
```

Certificate types include:
- `Certificate`: Base certificate structure
- `MasterCertificate`: For certificate issuance and key management
- `VerifiableCertificate`: With selective disclosure capabilities

## AuthHTTP Client

The `authhttp` package provides an authenticated HTTP client:

```go
// Create an AuthFetch client
client := authhttp.New(
    myWallet,
    requestedCertificates, // Optional
    sessionManager,        // Optional
)

// Make an authenticated request
ctx := context.Background()
response, err := client.Fetch(ctx, "https://example.com/api", &authhttp.SimplifiedFetchRequestOptions{
    Method:  "POST",
    Headers: map[string]string{"Content-Type": "application/json"},
    Body:    []byte(`{"data":"value"}`),
})
```

Features:
- Automatic mutual authentication with servers
- Certificate exchange when required
- Automatic payment handling for 402 Payment Required responses

## Utility Functions

The `utils` subpackage contains helpers for authentication operations:

```go
// Create a random nonce
nonce := utils.CreateNonce(ctx, wallet, "counterparty-id")

// Verify a nonce
isValid := utils.VerifyNonce(ctx, nonceToVerify, wallet, "counterparty-id")

// Get verifiable certificates matching requirements
certs, err := utils.GetVerifiableCertificates(
    wallet,
    requestedCertificateSet,
    verifierPublicKey,
)

// Validate received certificates
err := auth.ValidateCertificates(
    ctx,
    verifierWallet,
    authMessage,
    &requestedCertificateSet,
)
```

## Integration with Wallet

The authentication system integrates with the wallet system for:
- Identity key operations
- Certificate management
- Message signing and verification 
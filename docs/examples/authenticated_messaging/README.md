# Authenticated Messaging Example

This example demonstrates how to use the `auth` package for establishing a secure, authenticated communication channel between two peers.

## Overview

The `authenticated_messaging` example showcases:
1. Creating and connecting two `Peer` instances using an in-memory transport.
2. Deriving identity keys for each peer.
3. Sending an encrypted and signed message from one peer to another.
4. Receiving and decrypting the message on the recipient's side.
5. Sending a reply back to the original sender.

## Code Walkthrough

### Setting Up Peers and Transport

```go
// Create two transport pairs
aliceTransport := NewMemoryTransport()
bobTransport := NewMemoryTransport()

// Connect the transports
aliceTransport.Connect(bobTransport)
bobTransport.Connect(aliceTransport)

// Create two wallets with random keys
// ... (wallet creation code) ...

// Create peers
alicePeer := auth.NewPeer(&auth.PeerOptions{
    Wallet:    aliceWallet,
    Transport: aliceTransport,
})

bobPeer := auth.NewPeer(&auth.PeerOptions{
    Wallet:    bobWallet,
    Transport: bobTransport,
})
```

This section explains the initial setup of in-memory transport, wallets, and peer instances for Alice and Bob.

### Sending and Receiving Messages

```go
// Get identity keys
// ... (identity key retrieval code) ...

// Set up message listeners
alicePeer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
    fmt.Printf("Alice received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))
    return nil
})

bobPeer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
    fmt.Printf("Bob received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))

    // Reply to Alice
    err := bobPeer.ToPeer(context.Background(), []byte("Hello back, Alice!"), senderPublicKey, 5000)
    if err != nil {
        log.Printf("Bob failed to reply: %v", err)
    }
    return nil
})

// Alice sends a message to Bob
err = alicePeer.ToPeer(context.Background(), []byte("Hello, Bob!"), bobIdentityResult.PublicKey, 5000)
if err != nil {
    log.Fatalf("Failed to send message: %v", err)
}
```

This section details how peers listen for messages and how Alice sends an initial message to Bob, who then replies. The `ToPeer` method handles encryption and signing.

## Running the Example

To run this example:

```bash
go run authenticated_messaging.go
```

**Note**: This example uses an in-memory transport (`MemoryTransport`) for simplicity. In a real-world application, you would use a network-based transport like WebSockets. It also uses a `MinimalWalletImpl` which is a mock; a full wallet implementation would be required for production use.

## Integration Steps

To integrate authenticated messaging into your application:
1. Implement `auth.Transport` for your chosen communication protocol (e.g., WebSockets, HTTP).
2. Ensure both peers have a fully implemented `wallet.Interface`.
3. Initialize `auth.Peer` for each communicating party with their respective wallets and the chosen transport.
4. Use `peer.ToPeer()` to send authenticated messages and `peer.ListenForGeneralMessages()` to receive them.

## Additional Resources

For more information, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/auth)
- [Identity Client Example](../identity_client/)
- [Websocket Peer Example](../websocket_peer/)

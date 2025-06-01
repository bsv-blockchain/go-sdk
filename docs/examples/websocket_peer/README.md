# WebSocket Peer Example

This example demonstrates how to use the `auth` package with a WebSocket-like transport for establishing a secure, authenticated communication channel between multiple peers. It simulates a client-server WebSocket architecture where messages are broadcasted.

## Overview

The `websocket_peer` example showcases:
1. Setting up multiple `Peer` instances, each with its own wallet and transport.
2. Peers connecting to the mock server.
3. One peer (Alice) broadcasting a message.
4. Other peers (Bob and Charlie) receiving and decrypting the broadcast message.
5. Handling graceful shutdown on interrupt signals.

## Code Walkthrough

### Setting Up Peers

```go
// Create mock WebSocket server
server := newMockWebSocketServer()

// Create wallets
// ... (wallet creation for Alice, Bob, Charlie) ...

// Create peers with mock transport
alicePeer := auth.NewPeer(&auth.PeerOptions{
    Wallet:    aliceWallet,
    Transport: newMockTransport("alice", server),
})
// ... (similarly for Bob and Charlie) ...
```
Multiple peers are created, each with a unique wallet and a `mockTransport` instance connected to the central `server`.

### Connecting and Communicating

```go
// Connect peers
ctx := context.Background()
if err := alicePeer.Transport().Connect(ctx); err != nil { /* ... */ }
// ... (connect Bob and Charlie) ...

// Set up message listeners for Bob and Charlie
bobPeer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
    fmt.Printf("Bob received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))
    return nil
})
// ... (listener for Charlie) ...

// Alice broadcasts a message
aliceIdentityKey, _ := aliceWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "example")
msg := []byte("Hello, everyone from Alice!")
if err := alicePeer.Broadcast(ctx, msg, 5000); err != nil {
    log.Fatalf("Alice failed to broadcast message: %v", err)
}
```
Peers connect their transports. Listeners are set up for Bob and Charlie. Alice then uses `Broadcast` to send a message, which the mock server relays to Bob and Charlie. `Broadcast` is a convenience method that essentially sends a message to an "all" or "broadcast" recipient type, which the transport layer (here, our mock server) interprets.

## Running the Example

To run this example:

```bash
go run websocket_peer.go
```
The example will show Alice broadcasting a message, and Bob and Charlie receiving it. It will then wait for an interrupt signal (Ctrl+C) to gracefully disconnect peers.

**Note**: This example uses a `MinimalWalletImpl` (a mock) and a `mockTransport` for demonstration. For a real application, you would need:
- A full `wallet.Interface` implementation.
- An `auth.Transport` implementation that uses a real WebSocket library (client-side) and interacts with a corresponding WebSocket server. The `Broadcast` functionality would depend on the server's capabilities to relay messages to multiple clients.

## Integration Steps

To integrate similar functionality:
1. Implement `auth.Transport` for your WebSocket client. This transport should connect to your WebSocket server and handle sending/receiving `AuthMessage` structures.
2. Your WebSocket server needs to be able to route messages. For broadcasting, it might maintain lists of connected clients or use pub/sub topics.
3. Initialize `auth.Peer` with the wallet and WebSocket transport.
4. Use `peer.ToPeer()` for direct messages if the recipient's public key is known, or implement a broadcast/group message concept if your server supports it, potentially using `peer.ToRecipients()` with a special recipient for broadcasts if your protocol defines one. The `peer.Broadcast()` method used in the example is a high-level abstraction; its actual implementation for a real WebSocket scenario would involve the transport sending a message that the server understands as a broadcast request.

## Additional Resources

For more information, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/auth)
- [Authenticated Messaging Example](../authenticated_messaging/)

# Examples

Here, you will find a number of common usage examples for the go-sdk.

## Storage
- [Storage Downloader](./storage_downloader/storage_downloader.md) - Download files using UHRP URLs
- [Storage Uploader](./storage_uploader/storage_uploader.md) - Upload, manage, and renew files

## Keys and Addresses
- [Address From WIF](./address_from_wif/) - Generate an address from a WIF private key.
- [Derive Child Key](./derive_child/) - Derive a child key from a parent HD key.
- [Generate HD Key](./generate_hd_key/) - Generate a new Hierarchical Deterministic (HD) key.
- [HD Key From XPub](./hd_key_from_xpub/) - Create an HD key from an extended public key (xPub).
- [Keyshares PK From Backup](./keyshares_pk_from_backup/) - Reconstruct a private key from key shares backup.
- [Keyshares PK To Backup](./keyshares_pk_to_backup/) - Backup a private key using key shares.

## Transactions
- [Broadcaster](./broadcaster/) - Broadcast a transaction to the network.
- [Create Simple TX](./create_simple_tx/) - Create a basic Bitcoin transaction.
- [Create TX With Inscription](./create_tx_with_inscription/) - Create a transaction with an Ordinal inscription.
- [Create TX With OP_RETURN](./create_tx_with_op_return/) - Create a transaction with an OP_RETURN output.
- [Fee Modeling](./fee_modeling/) - Examples of transaction fee calculation and modeling.
- [Validate SPV](./validate_spv/) - Validate a Simple Payment Verification (SPV) proof.
- [Verify Beef](./verify_beef/) - Verify a B.E.E.F (Bitcoin Extended Envelope Format) transaction.
- [Verify Transaction](./verify_transaction/) - Verify the validity of a Bitcoin transaction.

## Messaging and Authentication
- [Authenticated Messaging](./authenticated_messaging/) - Examples of authenticated messaging between parties.
- [ECIES Electrum Binary](./ecies_electrum_binary/) - ECIES encryption/decryption compatible with Electrum (binary format).
- [ECIES Shared](./ecies_shared/) - Elliptic Curve Integrated Encryption Scheme (ECIES) with a shared secret.
- [ECIES Single](./ecies_single/) - ECIES for single recipient encryption/decryption.
- [Encrypted Message](./encrypted_message/) - Send and receive encrypted messages.
- [Identity Client](./identity_client/) - Client for interacting with identity services.

## Registry
- [Registry Register](./registry_register/) - Register data with a distributed registry.
- [Registry Resolve](./registry_resolve/) - Resolve data from a distributed registry.

## Networking
- [Websocket Peer](./websocket_peer/) - Communicate with a Bitcoin node using WebSockets.

## Cryptography
- [AES](./aes/) - Advanced Encryption Standard (AES) examples.

## Wallet
- [Create Wallet](./create_wallet/) - Create a new wallet instance.
- [Encrypt Data](./encrypt_data/) - Encrypt data using the wallet.
- [Create Signature](./create_signature/) - Create a digital signature.
- [Create HMAC](./create_hmac/) - Create an HMAC.
- [Get Public Key](./get_public_key/) - Retrieve a public key from the wallet.
- [HTTP Wallet](./http_wallet/) - Interact with a wallet using JSON over HTTP.

## Additional Example Documents
- [Converting Transactions from go-bt](./GO_BT.md)

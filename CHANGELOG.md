# CHANGELOG

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Table of Contents

- [2.0.0 - 2025-06-08](#200---2025-06-08)
- [1.1.27 - 2025-05-15](#1127---2025-05-15)
- [1.1.26 - 2025-05-14](#1126---2025-05-14)
- [1.1.25 - 2025-05-09](#1125---2025-05-09)
- [1.1.24 - 2025-04-24](#1124---2025-04-24)
- [1.1.23 - 2025-04-23](#1123---2025-04-23)
- [1.1.22 - 2025-03-14](#1122---2025-03-14)
- [1.1.21 - 2025-03-12](#1121---2025-03-12)
- [1.1.20 - 2025-03-05](#1120---2025-03-05)
- [1.1.19 - 2025-03-04](#1119---2025-03-04)
- [1.1.18 - 2025-01-28](#1118---2025-01-28)
- [1.1.17 - 2024-12-24](#1117---2024-12-24)
- [1.1.16 - 2024-12-01](#1116---2024-12-01)
- [1.1.15 - 2024-11-26](#1115---2024-11-26)
- [1.1.14 - 2024-11-01](#1114---2024-11-01)
- [1.1.13 - 2024-11-01](#1113---2024-11-01)
- [1.1.12 - 2024-10-31](#1112---2024-10-31)
- [1.1.11 - 2024-10-23](#1111---2024-10-23)
- [1.1.10 - 2024-10-20](#1110---2024-10-20)
- [1.1.9 - 2024-10-01](#119---2024-10-01)
- [1.1.8 - 2024-09-17](#118---2024-09-17)
- [1.1.7 - 2024-09-10](#117---2024-09-10)
- [1.1.6 - 2024-09-09](#116---2024-09-09)
- [1.1.5 - 2024-09-06](#115---2024-09-06)
- [1.1.4 - 2024-09-05](#114---2024-09-05)
- [1.1.3 - 2024-09-04](#113---2024-09-04)
- [1.1.2 - 2024-09-02](#112---2024-09-02)
- [1.1.1 - 2024-08-28](#111---2024-08-28)
- [1.1.0 - 2024-08-19](#110---2024-08-19)
- [1.0.0 - 2024-06-06](#100---2024-06-06)

## [2.0.0] - 2025-06-08

This is a major release introducing comprehensive new modules for authentication, key-value storage, overlay services, registry management, decentralized storage, and advanced wallet functionality. This release represents a significant architectural evolution of the SDK, aligning with the TypeScript SDK's capabilities.

### Added

#### Auth Module (`auth/`)
- Complete authentication protocol implementation with peer-to-peer communication
- Certificate-based authentication system supporting verifiable and master certificates
- Session management with authenticated message exchange
- Transport interfaces supporting HTTP and WebSocket communications
- Comprehensive certificate validation with field encryption/decryption support
- Utilities for nonce generation, verification, and certificate operations

#### KVStore Module (`kvstore/`)
- Key-value storage backed by transaction outputs
- Local KVStore implementation with wallet integration
- Support for encrypted storage with automatic encryption/decryption
- Thread-safe operations with mutex protection
- Configurable retention periods and basket management
- Transaction-based persistence using PushDrop templates

#### Overlay Module (`overlay/`)
- Support for SHIP and SLAP protocols
- Topic-based message broadcasting and lookup
- Admin token management for service operations
- Network-aware configurations (Mainnet/Testnet/Local)
- Tagged BEEF and STEAK transaction handling
- Facilitator and resolver implementations for topic management

#### Registry Module (`registry/`)
- On-chain definition management for baskets, protocols, and certificates
- Registration and revocation of registry entries
- Query interfaces for resolving definitions by various criteria
- Support for certificate field descriptors with metadata
- Mock client for testing registry operations
- Integration with overlay lookup services

#### Storage Module (`storage/`)
- Decentralized file storage with UHRP URL support
- File upload with configurable retention periods
- File download with multi-host resolution
- File metadata retrieval and renewal operations
- Authenticated operations for file management
- Support for various MIME types and file formats

#### Wallet Module Enhancements (`wallet/`)
- ProtoWallet implementation for foundational cryptographic operations
- Comprehensive serializer framework for wallet wire protocol
- Support for 30+ wallet operations including:
  - Certificate management (acquire, prove, relinquish)
  - Action creation and management
  - Encryption/decryption operations
  - Signature creation and verification
  - HMAC operations
  - Key derivation and management
- HTTP and wire protocol substrates for wallet communication
- Cached key derivation for performance optimization

#### Identity Module (`identity/`)
- Client implementation for identity resolution services
- Support for identity key lookups and certificate discovery
- Integration with authentication protocols

#### Message Module Enhancements (`message/`)
- Enhanced verification with tampered message detection
- Support for specific recipient verification

### Changed

#### Breaking Changes
- ProtoWallet constructor now requires explicit type specification in ProtoWalletArgs
- Certificate validation now requires proper field validation
- Storage operations now require authenticated wallet for certain operations

#### Improvements
- Enhanced error handling across all new modules
- Consistent interface patterns following Go best practices
- Thread-safe implementations where applicable
- Comprehensive test coverage for new modules

### Fixed
- Certificate field validation to ensure field names are under 50 bytes (auth/certificates/master.go:149)
- ProtoWallet constructor now correctly uses passed KeyDeriver instead of creating new one (wallet/proto_wallet.go:42)
- Thread safety issues in KVStore Set method with proper mutex usage to prevent concurrent access/double spending
- Message verification to properly detect tampering
- Removed unused errors: `ErrNoKeyRing` in auth/certificates/verifiable.go
- Removed unused errors: `ErrNotConnected` and `ErrAlreadyConnected` in auth/transports/errors.go

### Security
- All certificate operations now validate field integrity
- Message signing includes SHA-256 hashing for improved security
- Encrypted storage in KVStore uses wallet-based encryption
- Authentication protocol prevents replay attacks with nonce verification

## [1.1.27] - 2025-05-15
  ### Fix
  - Fix BRC77 message signing to match ts-sdk

## [1.1.26] - 2025-05-14
  ### Updated
  - Support AtomicBeef in NewBeefFromBytes

## [1.1.25] - 2025-05-09
  ### Fix
  - nil pointer

## [1.1.24] - 2025-04-24
  ### Added
  - `transaction.NewBeef`

## [1.1.23] - 2025-04-23
  ### Added
  - `NewBeefFromAtomicBytes`
  - `ParseBeef`
  - `NewBeefFromTransaction`
  - `Beef.FindTransaction`
  ### Fixed
  - Missing nil checks in `beef.go`
  - Fix issues with handling of `TxidOnly` in `beef.go`

## [1.1.22] - 2025-03-14
  ### Updated
  - update package to use `github.com/bsv-blockchain/go-sdk` path

## [1.1.21] - 2025-03-12
  ### Changed
  - Add support for AtomicBEEF to `NewTransactionFromBEEF`

## [1.1.20] - 2025-03-05
  ### Fixed
  - Beef transaction ordering

## [1.1.19] - 2025-03-04
  ### Added
  - Dependabot
  - Mergify
  ### Changed
  - Parse Beef V1 into a Beef struct
  - Fix memory allocation in script interpreter
  - Fix Message encryption
  - Update golangci-lint configuration and bump version
  - Bump go and golangci-lint versions for github actions

## [1.1.18] - 2025-01-28
  ### Changed
  - Added support for BEEF v2 and AtomicBEEF
  - Update golang.org/x/crypto from v0.21.0 to v0.31.0
  - Update README to highlight examples and improve documentation
  - Update golangci-lint configuration to handle mixed receiver types
  - Update issue templates
  - Improved test coverage

## [1.1.17] - 2024-12-24
  ### Added
  - `ScriptNumber` type

## [1.1.16] - 2024-12-01
  ### Added
  - ArcBroadcaster Status

## [1.1.15] - 2024-11-26
  ### Changed
  - ensure BUMP ordering in BEEF
  - Fix arc broadcaster to handle script failures
  - support new headers in arc broadcaster

## [1.1.14] - 2024-11-01
  ### Changed
  - Update examples and documentation to reflect `tx.Sign` using script templates

## [1.1.13] - 2024-11-01
  ### Changed
  - Broadcaster examples

  ### Added
  - WOC Broadcaster
  - TAAL Broadcaster
  - Tests for woc, taal, and arc broadcasters

## [1.1.12] - 2024-10-31
  ### Fixed
  - fix `spv.Verify()` to work with source output (separate fix from 1.1.11)
  
## [1.1.11] - 2024-10-23
  ### Fixed
  - fix `spv.Verify()` to work with source output 
  
## [1.1.10] - 2024-10-20
  Big thanks for contributions from @wregulski

  ### Changed
  - `pubKey.ToDER()` now returns bytes
  - `pubKey.ToHash()` is now `pubKey.Hash()` 
  - `pubKey.SerializeCompressed()` is now `pubKey.Compressed()`
  - `pubKey.SerializeUncompressed()` is now `pubKey.Uncompressed()`
  - `pubKey.SerializeHybrid()` is now `pubKey.Hybrid()`
  - updated `merklepath.go` to use new helper functions from `transaction.merkletreeparent.go`
  
  ### Added
  - files `spv/verify.go`, `spv/verify_test.go` - chain tracker for whatsonchain.com
    - `spv.Verify()` ensures transaction scripts, merkle paths and fees are valid
    - `spv.VerifyScripts()` ensures transaction scripts are valid
  - file `docs/examples/verify_transaction/verify_transaction.go`
  - `publickey.ToDERHex()` returns a hex encoded public key
  - `script.Chunks()` helper method for `DecodeScript(scriptBytes)`
  - `script.PubKey()` returns a `*ec.PublicKey`
  - `script.PubKeyHex()` returns a hex string
  - `script.Address()` and `script.Addresses()` helpers
  - file `transaction.merkletreeparent.go` which contains helper functions
    - `transaction.MerkleTreeParentStr()`
    - `transaction.MerkleTreeParentBytes()`
    - `transaction.MerkleTreeParents()`
  - file `transaction/chaintracker/whatsonchain.go`, `whatsonchain_test.go` - chain tracker for whatsonchain.com
    - `chaintracker.NewWhatsOnChain` chaintracker

## [1.1.9] - 2024-10-01
  ### Changed
  - Updated readme
  - Improved test coverage
  - Update golangci-lint version in sonar workflow

## [1.1.8] - 2024-09-17
  ### Changed
  - Restore Transaction `Clone` to its previous state, and add `ShallowClone` as a more efficient alternative
  - Fix the version number bytes in `message`
  - Rename `merkleproof.ToHex()` to `Hex()`
  - Update golangci-lint version and rules

  ### Added
  - `transaction.ShallowClone`
  - `transaction.Hex`

## [1.1.7] - 2024-09-10
  - Rework `tx.Clone()` to be more efficient
  - Introduce SignUnsigned to sign only inputs that have not already been signed
  - Added tests
  - Other minor performance improvements.

  ### Added
  - New method `Transaction.SignUnsigned()`

  ### Changed
  - `Transaction.Clone()` does not reconstitute the source transaction from bytes. Creates a new transaction.

## [1.1.6] - 2024-09-09
  - Optimize handling of source transaction inputs. Avoid mocking up entire transaction when adding source inputs.
  - Minor alignment in ECIES helper function

### Added
  - New method `TransactionInput.SourceTxOutput()`
  
### Changed
  - `SetSourceTxFromOutput` changed to be `SetSourceTxOutput`
  - Default behavior of `EncryptSingle` uses ephemeral key. Updated test.

## [1.1.5] - 2024-09-06
  - Add test for ephemeral private key in electrum encrypt ecies
  - Add support for compression for backward compatibility and alignment with ts

  ### Added
  - `NewAddressFromPublicKeyWithCompression`, to `script/address.go` and `SignMessageWithCompression` to `bsm/sign.go`
  - Additional tests

## [1.1.4] - 2024-09-05

  - Update ECIES implementation to align with the typescript library

  ### Added
  - `primitives/aescbc` directory
    -  `AESCBCEncrypt`, `AESCBCDecrypt`, `PKCS7Padd`, `PKCS7Unpad`
  - `compat/ecies`
    - `EncryptSingle`, `DecryptSingle`, `EncryptShared` and `DecryptShared` convenience functions that deal with strings, uses Electrum ECIES and typical defaults
    - `ElectrumEncrypt`, `ElectrumDecrypt`, `BitcoreEncrypt`, `BitcoreDecrypt`
  - `docs/examples`
    - `ecies_shared`, `ecies_single`, `ecies_electrum_binary`
  - Tests for different ECIES encryption implementations

  ### Removed
  - Previous ecies implementation
  - Outdated ecies example
  - encryption.go for vanilla AES encryption (to align with typescript library)
  
  ### Changed
  - Renamed `message` example to `encrypt_message` for clarity
  - Change vanilla `aes` example to use existing encrypt/decrypt functions from `aesgcm` directory

## [1.1.3] - 2024-09-04

  - Add shamir key splitting
  - Added PublicKey.ToHash() - sha256 hash, then ripemd160 of the public key (matching ts implementation)`
  - Added new KeyShares and polynomial primitives, and polynomial operations to support key splitting
  - Tests for all new keyshare, private key, and polynomial operations
  - added recommended vscode plugin and extension settings for this repo in .vscode directory
  - handle base58 decode errors
  - additional tests for script/address.go

  ### Added
  - `PrivateKey.ToKeyShares`
  - `PrivateKey.ToPolynomial`
  - `PrivateKey.ToBackupShares`
  - `PrivateKeyFromKeyShares`
  - `PrivateKeyFromBackupShares`
  - `PublicKey.ToHash()`
  - New tests for the new `PrivateKey` methods
  - new primitive `keyshares`
  - `NewKeyShares` returns a new `KeyShares` struct
  - `NewKeySharesFromBackupFormat`
  - `KeyShares.ToBackupFormat`
  - `polonomial.go` and tests for core functionality used by `KeyShares` and `PrivateKey`
  - `util.Umod` in `util` package `big.go`
  - `util.NewRandomBigInt` in `util` package `big.go`

  ### Changed
  - `base58.Decode` now returns an error in the case of invalid characters

## [1.1.2] - 2024-09-02
  - Fix OP_BIN2NUM to copy bytes and prevent stack corruption & add corresponding test

### Changed
  - `opcodeBin2num` now copies value before minimally encoding

## [1.1.1] - 2024-08-28
 - Fix OP_RETURN data & add corresponding test
 - update release instructions

### Added
  - add additional test transaction
  - add additional script tests, fix test code

### Changed
  - `opcodeReturn` now includes any `parsedOp.Data` present after `OP_RETURN`
  - Changed RELEASE.md instructions

## [1.1.0] - 2024-08-19
- porting in all optimizations by Teranode team to their active go-bt fork
- introducing chainhash to remove type coercion on tx hashes through the project
- remove ByteStringLE (replaced by chainhash)
- update opRshift and opLshift modeled after C code in node software and tested against failing vectors
- add tests and vectors for txs using opRshift that were previously failing to verify
- update examples
- lint - change international spellings to match codebase standards, use require instead of assert, etc
- add additional test vectors from known failing transactions

### Added
- `MerkePath.ComputeRootHex`
- `MerklePath.VerifyHex`

### Changed
- `SourceTXID` on `TransactionInput` is now a `ChainHash` instead of `[]byte`
- `IsValidRootForHeight` on `ChainTracker` now takes a `ChainHash` instead of `[]byte`
- `MerklePath.ComputeRoot` now takes a `ChainHash` instead of a hex `string`.
- `MerklePath.Verify` now takes a `ChainHash` instead of hex `string`.
- `Transaction.TxID` now returns a `ChainHash` instead of a hex `string`
- `Transaction.PreviousOutHash` was renamed to `SourceOutHash`, and returns a `ChainHash` instead of `[]byte`
- The `TxID` field of the `UTXO` struct in the `transaction` package is now a `ChainHash` instead of `[]byte`
- Renamed `TransactionInput.SetPrevTxFromOutput` to `SetSourceTxFromOutput`

### Removed
- `TransactionInput.PreviousTxIDStr`
- `Transaction.TxIDBytes`
- `UTXO.TxIDStr` in favor of `UTXO.TxID.String()`

### Fixed
- `opcodeRShift` and `opcodeLShift` was fixed to match node logic and properly execute scripts using `OP_RSHIFT` and `OP_LSHIFT`.

---

## [1.0.0] - 2024-06-06

### Added
- Initial release

---

### Template for New Releases:

Replace `X.X.X` with the new version number and `YYYY-MM-DD` with the release date:

```
## [X.X.X] - YYYY-MM-DD

### Added
- 

### Changed
- 

### Deprecated
- 

### Removed
- 

### Fixed
- 

### Security
- 
```

Use this template as the starting point for each new version. Always update the "Unreleased" section with changes as they're implemented, and then move them under the new version header when that version is released.
# CHANGELOG

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Table of Contents

- [1.2.15 - 2026-01-27](#1215---2026-01-27)
- [1.2.14 - 2025-12-19](#1214---2025-12-19)
- [1.2.13 - 2025-12-05](#1213---2025-12-05)
- [1.2.12 - 2025-11-12](#1212---2025-11-12)
- [1.2.11 - 2025-10-27](#1211---2025-10-27)
- [1.2.10 - 2025-09-16](#1210---2025-09-16)
- [1.2.9 - 2025-09-07](#129---2025-09-07)
- [1.2.8 - 2025-08-07](#128---2025-08-07)
- [1.2.7 - 2025-08-05](#127---2025-08-05)
- [1.2.6 - 2025-07-21](#126---2025-07-21)
- [1.2.5 - 2025-07-16](#125---2025-07-16)
- [1.2.4 - 2025-06-30](#124---2025-06-30)
- [1.2.3 - 2025-06-30](#123---2025-06-30)
- [1.2.2 - 2025-06-27](#122---2025-06-27)
- [1.2.1 - 2025-06-12](#121---2025-06-12)
- [1.2.0 - 2025-06-10](#120---2025-06-10)
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

## [1.2.15] - 2026-01-27

### Fixed
- SPV fee validation now only validates fees on the root transaction, not ancestor transactions in the BEEF chain. Previously, historical ancestors with different fee rates could incorrectly fail validation.

### Added
- `VarInt.PutBytes()` method for direct buffer writing without allocation
- `Beef.MergeTransactionWithTxid()` and `Beef.MergeBeefTxWithTxid()` methods to merge transactions without recomputing TxID
- Test coverage for `VarInt.PutBytes()` method

### Changed
- Optimized `Transaction.Bytes()`, `Input.Bytes()`, and `Output.Bytes()` methods with pre-calculated size and pre-allocated buffers
- Optimized BEEF serialization with pre-allocated buffers
- `LookupFormula.History` now uses `*Beef` type instead of `[]byte`

## [1.2.14] - 2025-12-19

### Added
- `MerklePath.FindLeafByOffset()` method to find a PathElement at a given offset and level
- `MerklePath.AddLeaf()` method to add a PathElement to a specified level
- `MerklePath.ComputeMissingHashes()` method to compute parent hashes from sparse merkle path data

### Changed
- `Outpoint.Bytes()` now returns 36 bytes in little-endian format (consistent with transaction format)
- `Outpoint.TxBytes()` is now an alias for `Bytes()` for backward compatibility
- `NewOutpointFromBytes()` now accepts a `[]byte` slice instead of `[36]byte` array

## [1.2.13] - 2025-12-05

### Added
- `Header` type in block package for 80-byte Bitcoin block header parsing
- `MerklePath.Clone()` method for deep copying merkle paths

### Fixed
- `Beef.Clone()` now performs deep copy of all nested structures (BUMPs, transactions, input references)

## [1.2.12] - 2025-11-12

### Added
- `ArcBroadcast` method in Arc broadcaster for direct access to ARC response
- Missing ARC status constants: `MINED`, `CONFIRMED`, `DOUBLE_SPEND_ATTEMPTED`, `SEEN_IN_ORPHAN_MEMPOOL`
- Test coverage for fee calculation with `TestCalculateFee`

### Changed
- Arc broadcaster refactored with `ArcBroadcast` abstraction for better error handling

### Fixed
- Fee calculation formula to multiply in float space before casting to uint64, ensuring accurate fees for all satoshi rates

## [1.2.11] - 2025-10-27

### Added
- Webhook management methods in headers client (`RegisterWebhook`, `UnregisterWebhook`, `GetWebhook`)
- `GetMerkleRoots` method in headers client for bulk merkle root fetching with pagination
- Protocol ID support in overlay services with `ProtocolID` type and `ID()` method
- `OffChainValues` field to `TaggedBEEF` structure
- Anyone wallet support (nil private key handling in `NewWallet`)
- Comprehensive test coverage for headers client (450+ lines)

### Changed
- Session lookup now uses `YourNonce` instead of identity key for multi-device support
- Switched from `log` to `slog` for structured logging in overlay lookup resolver
- BEEF parsing changed from `NewTransactionFromBEEF` to `ParseBeef` with improved error handling
- Wallet serialization now deterministic with sorted keys in `DiscoverByAttributes` and `ListCertificates`
- Keyring serialization changed to proper base64 handling (`WriteIntFromBase64`/`ReadBase64Int`)

### Fixed
- Data race in auth peer callback management with proper mutex protection
- Authentication flow to properly validate session state before processing general messages
- Certificate validation logic in `handleInitialResponse` and `handleCertificateResponse`
- Channel closing in overlay lookup resolver goroutines
- Wallet serialization test vectors for `ListCertificates`

## [1.2.10] - 2025-09-16

### Added
- New error type `ErrHTTPServerFailedToAuthenticate` for authentication failures

### Changed
- Updated error return to include the new error type using `errors.Join()`
- Replaced string-based error checking with proper `errors.Is()` type checking

## [1.2.9] - 2025-09-07

### Added
- Codecov integration for automated code coverage reporting and analysis
- New `auth/authpayload` package with HTTP request/response serialization
- AuthFetch config options and methods
- BRC104 HTTP headers support (`auth/brc104/auth_http_headers.go`)

### Changed
- Added `auth/authpayload` package
- Updated dependencies
- Minor documentation corrections

### Fixed
- AuthFetch communication flow issues and hanging processes during handshake
- HTTP request payload preparation in auth client
- SPV verification now properly handles invalid merkle paths by returning error instead of fallback to input verification
- Headers client BlockByHeight now includes bounds check for empty headers array

## [1.2.8] - 2025-08-07

### Added
- Documented using SetSourceTxOutput to address (#218)
  - Added example `docs/examples/set_source_tx_output/` with `set_source_tx_output.go` and README
  - Added cross-implementation test vectors

### Changed
- Replaced `log.Logger` with `slog.Logger` in AuthFetch and Peer (#215)
  - Auth HTTP client now accepts an optional `*slog.Logger` in its constructor (`authhttp.New(..., logger...)`)
  - Prefer constructor injection over setters; `SetLogger` is deprecated
  - Structured logging for improved observability

### Fixed
- Shamir key split: enforce non-zero, unique x-coordinates in `ToKeyShares` and add tests to prevent regressions. Refactor Shamir logic into `primitives/ec/shamir.go` for clarity.

## [1.2.7] - 2025-08-05

### Added
- Implemented `RevealCounterpartyKeyLinkage` and `RevealSpecificKeyLinkage` methods in ProtoWallet (#219)
- Added Schnorr zero-knowledge proof primitive in `primitives/schnorr` package
- Added BRC-2 and BRC-3 compliance test vectors
- Added `TestWallet` implementation for testing with comprehensive certificate management
- Added `WalletKeys` interface and implementation for standardized key operations
- Added test certificate manager in `wallet/testcertificates` package
- Added `NewPrivateKeyFromInt` method to create private keys from integer values
- Added `Pad` method to SymmetricKey for zero-padding keys to 32 bytes

### Changed
- Updated `RevealSpecificSecret` in KeyDeriver to use compressed shared secret for HMAC computation
- Standardized proof serialization format to use compressed points (98 bytes total)
- Improved auth fetch process to prevent hanging and fix certificate exchange between peers (#217, #220)
- Refactored certificate validation logic with enhanced error handling
- Updated SonarQube scan action from v5.2.0 to v5.3.0 (#216)
- Enhanced `SimplifiedHTTPTransport` with better context handling and error management
- Improved peer authentication handshake process with better certificate handling

### Fixed
- Fixed auth fetch hanging process during initial handshake
- Fixed certificate exchange issues between peers
- Fixed certificate validation edge cases and improved test coverage
- Fixed session manager context cancellation handling

### Removed
- Removed `MockWallet` implementation in favor of `TestWallet`

## [1.2.6] - 2025-07-21

### Fixed
- Fixed BEEF validation stability issue where `IsValid` returned inconsistent results (#211)
- Fixed BEEF parsing panic when encountering transactions without merkle paths (#96)
- Fixed validation logic to properly check if transactions appear in BUMPs
- Fixed README installation instructions to use `go get` instead of `go install` (#202)

### Changed
- Renamed `SortTxs()` method to `ValidateTransactions()` for clarity
- Improved BEEF validation to handle transactions without source transactions gracefully
- Refactored BEEF implementation to use `chainhash.Hash` directly as map keys instead of string conversions for improved performance
- Added `*ByHash` versions of BEEF methods (`findTxidByHash`, `FindBumpByHash`, etc.) to avoid unnecessary hash/string conversions
- Updated `collectAncestors` to return `[]chainhash.Hash` instead of `[]string`

## [1.2.5] - 2025-07-16

### Changed
- Consolidated PushDrop implementation into single struct
- Merged CompletedProtoWallet implementations
- Renamed OverlayAdminTokenTemplate to use new API
- Optimized collectAncestors performance (3.17x faster, 78% less memory)
- Improved script parsing performance with two-pass approach
  - 28-49% performance improvement

### Added
- Optional sourceSatoshis and lockingScript parameters to Unlock method
- Pre-allocation for parsed opcodes in script parser

### Fixed
- Wire format fixes for 32 byte key padding
- Distinguish invalid signature errors from internal errors
- Script parsing performance regression


## [1.2.4] - 2025-06-30

### Changed
- Add context parameter to ChainTracker.IsValidRootForHeight for cancellation/timeout support
- Update all ChainTracker implementations to take context (WhatsOnChain, HeadersClient, GullibleHeadersClient)
- Update MerklePath.Verify and VerifyHex to take context
- Update BEEF.Verify to take context
- Update spv.Verify and VerifyScripts to take context

## [1.2.3] - 2025-06-30

### Added
- Enhanced peer authentication with proper message handling at receiver side
- Centralized certificate exchange logic with new `sendCertificates` method
- Added `SignCertificateWithWalletForTest` for wallet-based certificate signing in tests
- Implemented proper nonce creation/verification using `utils.CreateNonce` and `utils.VerifyNonce`

### Changed
- Updated `AUTH_PROTOCOL_ID` from "authrite message signature" to "auth message signature"
- Changed `AuthMessage` JSON marshaling to use `wallet.BytesList` for Payload and Signature fields
- Enhanced signature creation/verification to use wallet methods with explicit protocol details
- Improved mock wallet with `VerifyHMAC` implementation

### Fixed
- Fixed base64 concatenation bug in peer authentication nonce handling
- Fixed certificate signing bug in `certificate_debug.go`
- Fixed `TestPeerCertificateExchange` test to properly encrypt certificate fields
- Improved error handling consistency using `NewAuthError`
- Fixed variable naming consistency
- Enhanced session state management and error messages throughout auth flow

## [1.2.2] - 2025-06-27
### Added
- New `CurrentHeight` function on chaintracker interface

### Fixed
- Update type `wallet.Action.Satoshis` from `uint64` to `int64`

## [1.2.1] - 2025-06-12

### Added
- New `NewBeefFromHex` convenience function to create BEEF transactions directly from hex strings

### Fixed
- Fixed BEEF `IsValid` verification to properly handle transactions without MerklePath data
- Corrected validation logic in `verifyValid` to check for MerklePath existence before validating transaction inputs

## [1.2.0] - 2025-06-10

This is a major release introducing comprehensive new modules for authentication, key-value storage, overlay services, registry management, decentralized storage, and advanced wallet functionality. This release represents a significant architectural evolution of the SDK, aligning with the TypeScript SDK's capabilities.

### Updated
- golang.org/x/crypto from v0.29.0 to v0.31.0 (security fixes)
- golang.org/x/sync from v0.9.0 to v0.10.0
- golangci-lint from v2.1.1 to v2.1.6
- GitHub Actions: golangci-lint-action from v6 to v8
- GitHub Actions: sonarcloud-github-action to sonarqube-scan-action v5.0.0

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
# BSV BLOCKCHAIN | Software Development Kit for Go

Welcome to the BSV Blockchain Libraries Project, the comprehensive Go SDK designed to provide an updated and unified layer for developing scalable applications on the BSV Blockchain. This SDK addresses the limitations of previous tools by offering a fresh, peer-to-peer approach, adhering to SPV, and ensuring privacy and scalability.

# Status
[![CodeQL](https://github.com/bsv-blockchain/go-sdk/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/bsv-blockchain/go-sdk/actions/workflows/github-code-scanning/codeql)
[![Dependabot Updates](https://github.com/bsv-blockchain/go-sdk/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/bsv-blockchain/go-sdk/actions/workflows/dependabot/dependabot-updates)
[![golangci-lint](https://github.com/bsv-blockchain/go-sdk/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/bsv-blockchain/go-sdk/actions/workflows/golangci-lint.yaml)
[![pages-build-deployment](https://github.com/bsv-blockchain/go-sdk/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/bsv-blockchain/go-sdk/actions/workflows/pages/pages-build-deployment)
[![sonarcloud-analysis](https://github.com/bsv-blockchain/go-sdk/actions/workflows/sonar.yaml/badge.svg)](https://github.com/bsv-blockchain/go-sdk/actions/workflows/sonar.yaml)

## Table of Contents

- [BSV BLOCKCHAIN | Software Development Kit for Go](#bsv-blockchain--software-development-kit-for-go)
  - [Table of Contents](#table-of-contents)
  - [Objective](#objective)
  - [Getting Started](#getting-started)
    - [Installation](#installation)
    - [Basic Usage](#basic-usage)
    - [Examples](#examples)
  - [Features \& Deliverables](#features--deliverables)
  - [Documentation](#documentation)
  - [Contribution Guidelines](#contribution-guidelines)
  - [Support \& Contacts](#support--contacts)
  - [License](#license)

## Objective

The BSV Blockchain Libraries Project aims to structure and maintain a middleware layer of the BSV Blockchain technology stack. By facilitating the development and maintenance of core libraries, it serves as an essential toolkit for developers looking to build on the BSV Blockchain.

## Getting Started

### Installation

To add the SDK to your Go module:

```bash
go get github.com/bsv-blockchain/go-sdk
```

### Basic Usage

Here's a [simple example](https://goplay.tools/snippet/bnsS-pA56ob) of using the SDK to create and sign a transaction:

```go
package main

import (
	"context"
	"log"

	wif "github.com/bsv-blockchain/go-sdk/compat/wif"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/unlocker"
)

func main() {
	tx := transaction.NewTransaction()

	unlockingScriptTemplate, _ := p2pkh.Unlock(priv, nil)
   if err := tx.AddInputFrom(
		"11b476ad8e0a48fcd40807a111a050af51114877e09283bfa7f3505081a1819d",
		0,
		"76a9144bca0c466925b875875a8e1355698bdcc0b2d45d88ac",
		1500,
		unlockingScriptTemplate,
	); err!= nil {
      log.Fatal(err.Error())
   }

	_ = tx.PayToAddress("1AdZmoAQUw4XCsCihukoHMvNWXcsd8jDN6", 1000)

	priv, _ := ec.PrivateKeyFromWif("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")

	if err := tx.Sign(); err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("tx: %s\n", tx)
}

```

See the [Go Doc](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk) for a complete list of available modules and functions.

### Examples & Usage Guides

Our examples are organized by category to help you find what you need. Each example is self-contained and includes detailed comments.

### Transaction Management
- [Creating a Simple Transaction](./docs/examples/create_simple_tx/) - Basic transaction creation and signing
- [Adding OP_RETURN Data](./docs/examples/create_tx_with_op_return/) - How to embed data in transactions
- [Creating Inscriptions](./docs/examples/create_tx_with_inscription/) - Working with inscriptions
- [Transaction Verification](./docs/examples/verify_transaction/) - How to verify transactions
- [Fee Modeling](./docs/examples/fee_modeling/) - Understanding and calculating transaction fees
- [Broadcasting Transactions](./docs/examples/broadcaster/) - How to broadcast transactions to the network

### Key Management & Cryptography
- [HD Key Generation](./docs/examples/generate_hd_key/) - Creating hierarchical deterministic keys
- [HD Key from Extended Public Key](./docs/examples/hd_key_from_xpub/) - Working with xPubs
- [Child Key Derivation](./docs/examples/derive_child/) - Deriving child keys
- [Address from WIF](./docs/examples/address_from_wif/) - Converting WIF to addresses
- [AES Encryption](./docs/examples/aes/) - Symmetric encryption examples

### Advanced Cryptography
- [ECIES Single Key](./docs/examples/ecies_single/) - Elliptic Curve Integrated Encryption Scheme
- [ECIES Shared Keys](./docs/examples/ecies_shared/) - Working with shared ECIES keys
- [ECIES Electrum Binary](./docs/examples/ecies_electrum_binary/) - Electrum-compatible ECIES
- [Encrypted Messages](./docs/examples/encrypted_message/) - Working with encrypted messages

### Key Sharing & Backup
- [Key Shares to Backup](./docs/examples/keyshares_pk_to_backup/) - Backing up private keys using Shamir's Secret Sharing
- [Key Shares from Backup](./docs/examples/keyshares_pk_from_backup/) - Recovering private keys from shares

### Network & Verification
- [Headers Client](./docs/examples/headers_client/) - Working with blockchain headers
- [BEEF Verification](./docs/examples/verify_beef/) - Verifying BEEF proofs

### Migration Guides
- [Converting from go-bt](./docs/examples/GO_BT.md) - Guide for migrating from go-bt


Check out the [examples folder](https://github.com/bsv-blockchain/go-sdk/tree/master/docs/examples) for more examples.

## Features

- **Performance Oriented**: Designed to deliver performant functionality for large scale / high demand systems.
- **Cryptographic Primitives**: Secure key management, signature computations, and encryption protocols.
- **Script Level Constructs**: Network-compliant script interpreter with support for custom scripts and serialization formats.
- **Transaction Construction and Signing**: Comprehensive transaction builder API, ensuring versatile and secure transaction creation.
- **Transaction Broadcast Management**: Mechanisms to send transactions to both miners and overlays, ensuring extensibility and future-proofing.
- **Merkle Proof Verification**: Tools for representing and verifying merkle proofs, adhering to various serialization standards.
- **Serializable SPV Structures**: Structures and interfaces for full SPV verification.
- **Secure Encryption and Signed Messages**: Enhanced mechanisms for encryption and digital signatures, replacing outdated methods.
- **Shamir Key Splitting & Recombining**: Allows private keys to be split into N shares, and recombined by providing M of N shares.
- **Compatability Packages**: Supports additional / deprecated features like ECIES, Bitcoin Signed Message, and BIP32 style key derivation.

## Documentation

This SDK is supported by multiple layers of documentation:

### Core Documentation
- [Examples](./docs/examples/README.md) - Common usage examples and code samples
- [Concepts](./docs/concepts/README.md) - High-level concepts and architectural decisions
- [Low-Level Details](./docs/low-level/README.md) - Implementation details and technical specifications
- [Go Doc](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk) - Complete API reference

### Component-Specific Documentation
- [Script Interpreter](./script/interpreter/README.md) - Comprehensive documentation of the Bitcoin script interpreter
  - Includes extensive test suite
  - Based on the [Bitcoin Script specification](https://wiki.bitcoinsv.io/index.php/Script)

### Example Categories
1. Transaction Management
   - Basic transaction creation and signing
   - Converting transactions from go-bt
2. Cryptographic Operations
   - Standard Pay-to-pubkey-hash operations
   - Key management and derivation
3. Script Operations
   - Custom script creation
   - Script interpretation and validation

For hands-on examples, visit our [examples directory](./docs/examples/).

## Contribution Guidelines

We're always looking for contributors to help us improve the SDK. Whether it's bug reports, feature requests, or pull requests - all contributions are welcome.

1. **Fork & Clone**: Fork this repository and clone it to your local machine.
2. **Set Up**: Run `go get github.com/bsv-blockchain/go-sdk` to get all the modules.
3. **Make Changes**: Create a new branch and make your changes.
4. **Test**: Ensure all tests pass by running `go test ./...`.
5. **Commit**: Commit your changes and push to your fork.
6. **Pull Request**: Open a pull request from your fork to this repository.

For more details, check the [contribution guidelines](./CONTRIBUTING.md).

For information on past releases, check out the [changelog](./CHANGELOG.md). For future plans, check the [roadmap](./ROADMAP.md)!

## Support & Contacts

Project Owners: Thomas Giacomo and Darren Kellenschwiler

Development Team Lead: Luke Rohenaz

For questions, bug reports, or feature requests, please open an issue on GitHub or contact us directly.

## License

The license for the code in this repository is the Open BSV License. Refer to [LICENSE.txt](./LICENSE.txt) for the license text.

Thank you for being a part of the BSV Blockchain Libraries Project. Let's build the future of BSV Blockchain together!

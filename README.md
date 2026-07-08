> 📣 **Heads-up:** Consolidating this repository into the [go-stack monorepo](https://github.com/bsv-blockchain/go-stack) is under discussion — no archive decision has been made. Please weigh in on [roadmap discussion #70](https://github.com/bsv-blockchain/roadmap/discussions/70) before any change is made.

<div align="center">

# ⛓️&nbsp;&nbsp;BSV Blockchain | Go SDK

**A unified, peer-to-peer, SPV-first Software Development Kit for building scalable applications on the BSV Blockchain in Go.**

<br/>

<a href="https://github.com/bsv-blockchain/go-sdk/releases"><img src="https://img.shields.io/github/release-pre/bsv-blockchain/go-sdk?include_prereleases&style=flat-square&logo=github&color=black" alt="Release"></a>
<a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/bsv-blockchain/go-sdk?style=flat-square&logo=go&color=00ADD8" alt="Go Version"></a>
<a href="https://github.com/bsv-blockchain/go-sdk/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-OpenBSV-blue?style=flat-square" alt="License"></a>

<br/>

<table align="center" border="0">
  <tr>
    <td align="right">
       <code>CI / CD</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/bsv-blockchain/go-sdk/actions"><img src="https://img.shields.io/github/actions/workflow/status/bsv-blockchain/go-sdk/fortress.yml?branch=master&label=build&logo=github&style=flat-square" alt="Build"></a>
       <a href="https://github.com/bsv-blockchain/go-sdk/actions"><img src="https://img.shields.io/github/last-commit/bsv-blockchain/go-sdk?style=flat-square&logo=git&logoColor=white&label=last%20update" alt="Last Commit"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Quality</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://codecov.io/gh/bsv-blockchain/go-sdk"><img src="https://codecov.io/gh/bsv-blockchain/go-sdk/branch/master/graph/badge.svg?style=flat-square" alt="Coverage"></a>
    </td>
  </tr>

  <tr>
    <td align="right">
       <code>Security</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://scorecard.dev/viewer/?uri=github.com/bsv-blockchain/go-sdk"><img src="https://api.scorecard.dev/projects/github.com/bsv-blockchain/go-sdk/badge?style=flat-square" alt="Scorecard"></a>
       <a href=".github/SECURITY.md"><img src="https://img.shields.io/badge/policy-active-success?style=flat-square&logo=security&logoColor=white" alt="Security"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Community</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/bsv-blockchain/go-sdk/graphs/contributors"><img src="https://img.shields.io/github/contributors/bsv-blockchain/go-sdk?style=flat-square&color=orange" alt="Contributors"></a>
       <a href="https://deepwiki.com/bsv-blockchain/go-sdk"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
    </td>
  </tr>
</table>

</div>

<br/>
<br/>

<div align="center">

### <code>Project Navigation</code>

</div>

<table align="center">
  <tr>
    <td align="center" width="25%">
       📦&nbsp;<a href="#-installation"><code>Installation</code></a>
    </td>
    <td align="center" width="25%">
       🚀&nbsp;<a href="#-basic-usage"><code>Basic&nbsp;Usage</code></a>
    </td>
    <td align="center" width="25%">
       ✨&nbsp;<a href="#-features"><code>Features</code></a>
    </td>
    <td align="center" width="25%">
       🧪&nbsp;<a href="#-examples"><code>Examples</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       📚&nbsp;<a href="#-documentation"><code>Documentation</code></a>
    </td>
    <td align="center">
       🧰&nbsp;<a href="#-tests"><code>Tests</code></a>
    </td>
    <td align="center">
      🛠️&nbsp;<a href="#-code-standards"><code>Code&nbsp;Standards</code></a>
    </td>
    <td align="center">
      🤖&nbsp;<a href="#-ai-usage--assistant-guidelines"><code>AI&nbsp;Usage</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🤝&nbsp;<a href="#-contributing"><code>Contributing</code></a>
    </td>
    <td align="center">
       👥&nbsp;<a href="#-maintainers"><code>Maintainers</code></a>
    </td>
    <td align="center">
       ⚖️&nbsp;<a href="#-license"><code>License</code></a>
    </td>
    <td align="center">
       🔗&nbsp;<a href="https://pkg.go.dev/github.com/bsv-blockchain/go-sdk"><code>Go&nbsp;Docs</code></a>
    </td>
  </tr>
</table>
<br/>

## 🧩 What's Inside

The **BSV Blockchain Libraries Project** provides an updated and unified layer for developing scalable
applications on the BSV Blockchain. This SDK addresses the limitations of previous tools by offering a
fresh, peer-to-peer approach, adhering to SPV, and ensuring privacy and scalability.

It is a comprehensive toolkit for the full transaction lifecycle — constructing, signing, verifying, and
broadcasting transactions — alongside cryptographic primitives, a network-compliant script interpreter,
a BRC-100 wallet framework, peer authentication, overlay networks, identity, and on-chain storage.

<br/>

## 📦 Installation

**go-sdk** requires a [supported release of Go](https://golang.org/doc/devel/release.html#policy).

```shell script
go get github.com/bsv-blockchain/go-sdk
```

<br/>

## 🚀 Basic Usage

Here's a [simple example](https://goplay.tools/snippet/WotzYGbOSQ6) of using the SDK to create and sign a P2PKH transaction:

```go
package main

import (
    "log"

    ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
    "github.com/bsv-blockchain/go-sdk/transaction"
    "github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

func main() {
    // 1) Load a private key (WIF shown for example purposes)
    priv, _ := ec.PrivateKeyFromWif("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")

    // 2) Create a new transaction
    tx := transaction.NewTransaction()

    // 3) Build an unlocker for P2PKH
    unlocker, _ := p2pkh.Unlock(priv, nil)

    // 4) Add an input with its source output details
    //    If you don't have the source tx, fetch satoshis+lockingScript for the outpoint
    _ = tx.AddInputFrom(
        "11b476ad8e0a48fcd40807a111a050af51114877e09283bfa7f3505081a1819d", // prev txid
        0,                                                                  // vout
        "76a9144bca0c466925b875875a8e1355698bdcc0b2d45d88ac",              // source locking script
        1500,                                                               // source satoshis
        unlocker,                                                           // unlocking script template
    )

    // 5) Add an output
    _ = tx.PayToAddress("1AdZmoAQUw4XCsCihukoHMvNWXcsd8jDN6", 1000)

    // 6) Sign all inputs with attached templates
    if err := tx.Sign(); err != nil {
        log.Fatal(err)
    }
    log.Printf("tx hex: %s\n", tx.Hex())
}
```

See the [Go Doc](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk) for a complete list of available modules and functions.

<br/>

## ✨ Features

- **Transaction Construction & Signing** — a comprehensive, versatile transaction builder for secure creation, signing, and serialization.
- **BEEF & Atomic BEEF** — first-class support for the BEEF (`Background Evaluation Extended Format`) and Atomic BEEF transaction formats.
- **Script & Interpreter** — Bitcoin script types, BIP-276 serialization, and a full, network-compliant [script interpreter](./script/interpreter/README.md).
- **Script Templates** — reusable locking/unlocking templates including [`p2pkh`](./transaction/template/p2pkh) and [`pushdrop`](./transaction/template/pushdrop).
- **Fees, Broadcasters & Chain Trackers** — sats/kb fee modeling plus ready-made broadcasters (ARC, TAAL, WhatsOnChain) and chain trackers.
- **Cryptographic Primitives** — EC keys, ECDSA, Schnorr, hashing, AES (CBC/GCM), and DRBG for secure key management and signatures.
- **Type-42 Key Derivation** — private/public key derivation for shared, invoice-numbered key universes.
- **Shamir Key Splitting** — split a private key into N shares and recombine from any M of N.
- **SPV & Merkle Proofs** — serializable SPV structures and tools for representing and verifying merkle proofs.
- **Secure Messaging (BRC-77)** — sign, verify, and encrypt recipient-specific messages.
- **Wallet Framework** — a complete BRC-100 wallet `Interface`, `ProtoWallet`, wire-protocol serializer, and HTTP substrate.
- **Peer Authentication (BRC-103/104)** — mutual auth with master/verifiable certificates over HTTP and WebSocket transports.
- **Overlay Networks** — SHIP/SLAP topic broadcast and lookup/discovery for overlay services.
- **Identity, Registry & KV Store** — identity resolution, on-chain protocol/basket/certificate definitions, and on-chain key-value storage.
- **File Storage (UHRP)** — upload and download content addressed by UHRP URLs.
- **Compatibility Packages** — Base58, BIP32 (HD keys), BIP39 (mnemonics), Bitcoin Signed Message (BSM), and ECIES.

<br/>

## 🧪 Examples

Every example below is self-contained and thoroughly commented. Browse the full set in the
[examples directory](./docs/examples).

### Transactions
- [Broadcaster](./docs/examples/broadcaster/) — Broadcast a transaction to the network (ARC/GorillaPool & WhatsOnChain).
- [Create Simple TX](./docs/examples/create_simple_tx/) — Build and sign a basic P2PKH transaction.
- [Create TX With Inscription](./docs/examples/create_tx_with_inscription/) — Create a transaction with an Ordinal inscription.
- [Create TX With OP_RETURN](./docs/examples/create_tx_with_op_return/) — Embed data in a transaction with an OP_RETURN output.
- [Fee Modeling](./docs/examples/fee_modeling/) — Calculate and model transaction fees.
- [Set Source TX Output](./docs/examples/set_source_tx_output/) — Provide UTXO data (satoshis + locking script) to enable signing.
- [Validate SPV](./docs/examples/validate_spv/) — Validate SPV by decoding BEEF and checking merkle roots.
- [Verify BEEF](./docs/examples/verify_beef/) — Verify a BEEF structure.
- [Verify Transaction](./docs/examples/verify_transaction/) — Verify a transaction's scripts, merkle path, and fees.

### Keys & Addresses
- [Address From WIF](./docs/examples/address_from_wif/) — Derive an address from a WIF private key.
- [Derive Child Key](./docs/examples/derive_child/) — Derive a child key using the BRC-42 method.
- [Generate HD Key](./docs/examples/generate_hd_key/) — Generate a new hierarchical deterministic (HD) key.
- [HD Key From XPub](./docs/examples/hd_key_from_xpub/) — Create an HD key from an extended public key (xPub).
- [Key Shares To Backup](./docs/examples/keyshares_pk_to_backup/) — Split a private key into Shamir key-share backups.
- [Key Shares From Backup](./docs/examples/keyshares_pk_from_backup/) — Reconstruct a private key from key shares.

### Messaging & Authentication
- [Authenticated Messaging](./docs/examples/authenticated_messaging/) — Authenticated peer messaging over a transport.
- [ECIES Single](./docs/examples/ecies_single/) — ECIES encryption/decryption for a single recipient.
- [ECIES Shared](./docs/examples/ecies_shared/) — ECIES using a shared secret between two parties.
- [ECIES Electrum Binary](./docs/examples/ecies_electrum_binary/) — Electrum-compatible ECIES (binary format).
- [Encrypted Message](./docs/examples/encrypted_message/) — Encrypt/decrypt and sign/verify messages.
- [Identity Client](./docs/examples/identity_client/) — Create an identity client and reveal certificate attributes.

### Wallet
- [Create Wallet](./docs/examples/create_wallet/) — Generate entropy/mnemonic and create a new wallet.
- [Get Public Key](./docs/examples/get_public_key/) — Retrieve an identity public key from a wallet.
- [Create Signature](./docs/examples/create_signature/) — Create a digital signature with a wallet.
- [Create HMAC](./docs/examples/create_hmac/) — Create and verify an HMAC via a wallet.
- [Encrypt Data](./docs/examples/encrypt_data/) — Encrypt/decrypt data between wallets.
- [HTTP Wallet](./docs/examples/http_wallet/) — Interact with a wallet using JSON over HTTP.

### Registry
- [Registry Register](./docs/examples/registry_register/) — Register a basket definition with the registry.
- [Registry Resolve](./docs/examples/registry_resolve/) — Resolve a basket definition from the registry.

### Storage
- [Storage Uploader](./docs/examples/storage_uploader/) — Upload content to a storage service using a wallet.
- [Storage Downloader](./docs/examples/storage_downloader/) — Download a file via a UHRP URL.

### Networking
- [WebSocket Peer](./docs/examples/websocket_peer/) — Peer communication over WebSocket.

### Cryptography
- [AES](./docs/examples/aes/) — Symmetric AES encryption/decryption examples.

### Migration Guides
- [Converting from go-bt](./docs/examples/GO_BT.md) — Guide for migrating from go-bt.

<br/>

## 📚 Documentation

This SDK is supported by multiple layers of documentation:

- **API Reference** — the complete godocs at [pkg.go.dev/github.com/bsv-blockchain/go-sdk](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk).
- **Examples** — common usage patterns in the [examples directory](./docs/examples/README.md).
- **Concepts** — high-level concepts and architectural decisions in [docs/concepts](./docs/concepts/README.md).
- **Low-Level Details** — implementation details and specifications in [docs/low-level](./docs/low-level/README.md).
- **Script Interpreter** — deep-dive documentation of the [Bitcoin script interpreter](./script/interpreter/README.md), based on the [Bitcoin Script specification](https://wiki.bitcoinsv.io/index.php/Script).

<br/>

<details>
<summary><strong><code>Development Build Commands</code></strong></summary>
<br/>

Get the [MAGE-X](https://github.com/mrz1836/mage-x) build tool for development:
```shell script
go install github.com/mrz1836/mage-x/cmd/magex@latest
```

View all build commands:

```bash script
magex help
```

</details>

<details>
<summary><strong>Repository Features</strong></summary>
<br/>

This repository ships with a large set of built-in features covering CI/CD, security, code quality, developer experience, and community tooling.

**[View the full Repository Features list →](.github/docs/repository-features.md)**

</details>

<details>
<summary><strong>GitHub Workflows</strong></summary>
<br/>

All workflows are driven by modular configuration in [`.github/env/`](.github/env/README.md) — no YAML editing required.

**[View all workflows and the control center →](.github/docs/workflows.md)**

</details>

<details>
<summary><strong><code>Pre-commit Hooks</code></strong></summary>
<br/>

Set up the Go-Pre-commit System to run the same formatting, linting, and tests before every commit:

```bash
go install github.com/mrz1836/go-pre-commit/cmd/go-pre-commit@latest
go-pre-commit install
```

The system is configured via [modular env files](.github/env/README.md) and provides much faster execution than traditional Python-based pre-commit hooks. See the [complete documentation](https://github.com/mrz1836/go-pre-commit) for details.

</details>

<details>
<summary><strong><code>Library Deployment</code></strong></summary>
<br/>

This project uses [goreleaser](https://github.com/goreleaser/goreleaser) for streamlined library deployment to GitHub. Install it via:

```bash
brew install goreleaser
```

The release process is defined in the [.goreleaser.yml](.goreleaser.yml) configuration file. Create and push a new Git tag using:

```bash
magex version:bump push=true bump=patch branch=master
```

This ensures consistent, repeatable releases with properly versioned artifacts.

</details>

<details>
<summary><strong><code>Updating Dependencies</code></strong></summary>
<br/>

To update all dependencies (Go modules, linters, and related tools), run:

```bash
magex deps:update
```

This brings all dependencies up to date in a single step, keeping your development environment and CI in sync with the latest versions.

</details>

<br/>

## 🧰 Tests

All unit tests run via [GitHub Actions](https://github.com/bsv-blockchain/go-sdk/actions) using the
[GoFortress](.github/workflows/fortress.yml) workflow suite.

Run all tests (fast):

```bash script
magex test
```

Run all tests with the race detector (slower):

```bash script
magex test:race
```

<br/>

## 🛠️ Code Standards

Read more about this Go project's [code standards](.github/CODE_STANDARDS.md).

<br/>

## 🤖 AI Usage & Assistant Guidelines

Read the [AI Usage & Assistant Guidelines](.github/tech-conventions/ai-compliance.md) for details on how AI is used in this project and how to interact with AI assistants.

<br/>

## 👥 Maintainers

| [<img src="https://github.com/icellan.png" height="50" alt="Siggi" />](https://github.com/icellan) | [<img src="https://github.com/galt-tr.png" height="50" alt="Dylan" />](https://github.com/galt-tr) | [<img src="https://github.com/deggen.png" height="50" alt="Darren" />](https://github.com/deggen) | [<img src="https://github.com/rohenaz.png" height="50" alt="Luke" />](https://github.com/rohenaz) | [<img src="https://github.com/mrz1836.png" height="50" alt="MrZ" />](https://github.com/mrz1836) |
|:--------------------------------------------------------------------------------------------------:|:--------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------:|
|                                [Siggi](https://github.com/icellan)                                 |                                [Dylan](https://github.com/galt-tr)                                 |                                [Darren](https://github.com/deggen)                                |                                [Luke](https://github.com/rohenaz)                                 |                                [MrZ](https://github.com/mrz1836)                                 |

<br/>

## 🤝 Contributing

We're always looking for contributors to help us improve the SDK. Whether it's bug reports, feature requests, or pull requests — all contributions are welcome.

1. **Fork & Clone** — fork this repository and clone it to your local machine.
2. **Set Up** — run `go get github.com/bsv-blockchain/go-sdk` to get all the modules.
3. **Make Changes** — create a new branch and make your changes.
4. **Test** — ensure all tests pass by running `magex test` (or `go test ./...`).
5. **Commit** — commit your changes and push to your fork.
6. **Pull Request** — open a pull request from your fork to this repository.

View the [contributing guidelines](.github/CONTRIBUTING.md) and please follow the [code of conduct](.github/CODE_OF_CONDUCT.md). For information on past releases, check out the [changelog](./CHANGELOG.md).

### How can I help?

All kinds of contributions are welcome :raised_hands:! The most basic way to show your support is to star :star2: the project, or to raise issues :speech_balloon:.

[![Stars](https://img.shields.io/github/stars/bsv-blockchain/go-sdk?label=Please%20like%20us&style=social&v=1)](https://github.com/bsv-blockchain/go-sdk/stargazers)

<br/>

## 📝 License

The license for the code in this repository is the Open BSV License. Refer to [LICENSE](./LICENSE) for the license text.

[![License](https://img.shields.io/badge/license-OpenBSV-blue?style=flat&logo=springsecurity&logoColor=white)](LICENSE)

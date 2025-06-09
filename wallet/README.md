# Wallet Package

The wallet package provides a comprehensive interface for managing blockchain transactions, certificates, and cryptographic operations in the BSV Go SDK.

## Overview

The wallet package provides functionality for:
- Transaction creation and management
- Certificate handling and verification
- Cryptographic operations (encryption, signatures, HMAC)
- Output management
- Identity and authentication

## Package Structure

- `wallet.go` - Core wallet implementation
- `interfaces.go` - Interface definitions and types
- `error.go` - Error types and handling
- `key_deriver.go` - Key derivation functionality
- `proto_wallet.go` - Protocol-specific wallet implementation
- `mock.go` - Mock implementations for testing
- `cached_key_deriver.go` - Cached key derivation implementation

### Substrates

The `substrates/` directory contains lower-level implementations and utilities used by the wallet package.

### Serializer

The `serializer/` directory contains functionality for serializing and deserializing wallet data structures.

## Quick Start

```go
import (
    "context"
    "github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
    ctx := context.Background()

    // Create a new wallet client
    walletClient := wallet.NewWalletClient()

    // Create a transaction
    createArgs := wallet.CreateActionArgs{
        Description: "Example transaction",
        Outputs: []wallet.CreateActionOutput{
            {
                LockingScript:     "76a914...",
                Satoshis:         5000,
                OutputDescription: "Payment",
            },
        },
    }

    result, err := walletClient.CreateAction(ctx, createArgs, "example-app")
    if err != nil {
        // Handle error
    }

    // Use the result...
}
```

## Testing

The package includes comprehensive tests in `*_test.go` files. Run tests with:

```bash
go test ./...
```

## Core Interfaces

### Interface

The main `Interface` interface combines all wallet functionality:

```go
type Interface interface {
    KeyOperations
    CreateAction(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error)
    SignAction(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error)
    AbortAction(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error)
    ListActions(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error)
    InternalizeAction(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error)
    ListOutputs(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error)
    RelinquishOutput(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error)
    RevealCounterpartyKeyLinkage(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error)
    RevealSpecificKeyLinkage(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error)
    AcquireCertificate(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error)
    ListCertificates(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error)
    ProveCertificate(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error)
    RelinquishCertificate(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error)
    DiscoverByIdentityKey(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error)
    DiscoverByAttributes(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error)
    IsAuthenticated(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)
    WaitForAuthentication(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)
    GetHeight(ctx context.Context, args any, originator string) (*GetHeightResult, error)
    GetHeaderForHeight(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error)
    GetNetwork(ctx context.Context, args any, originator string) (*GetNetworkResult, error)
    GetVersion(ctx context.Context, args any, originator string) (*GetVersionResult, error)
}
```

### KeyOperations

The `KeyOperations` interface handles cryptographic operations:

```go
type KeyOperations interface {
    GetPublicKey(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)
    Encrypt(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error)
    Decrypt(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error)
    CreateHMAC(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error)
    VerifyHMAC(ctx context.Context, args VerifyHMACArgs, originator string) (*VerifyHMACResult, error)
    CreateSignature(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
    VerifySignature(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)
}
```

## Transaction Management

### Creating Transactions

To create a new transaction, use the `CreateAction` method with `CreateActionArgs`:

```go
type CreateActionArgs struct {
    Description string               // Human-readable description
    InputBEEF   []byte              // Optional BEEF-encoded input
    Inputs      []CreateActionInput  // Transaction inputs
    Outputs     []CreateActionOutput // Transaction outputs
    LockTime    uint32              // Optional lock time
    Version     uint32              // Transaction version
    Labels      []string            // Optional labels for organization
    Options     *CreateActionOptions // Optional configuration
}
```

Example:
```go
ctx := context.Background()

// Create transaction
createArgs := wallet.CreateActionArgs{
    Description: "Example transaction",
    Outputs: []wallet.CreateActionOutput{
        {
            LockingScript:     "76a914...",
            Satoshis:         5000,
            OutputDescription: "Payment",
        },
    },
}

result, err := walletClient.CreateAction(ctx, createArgs, "example-app")
if err != nil {
    log.Fatal(err)
}
```

### Signing Transactions

After creating a transaction, use `SignAction` to sign it:

```go
type SignActionArgs struct {
    Reference string                     // Base64-encoded reference
    Spends    map[uint32]SignActionSpend // Input index -> spending details
    Options   *SignActionOptions         // Optional configuration
}
```

Example:
```go
signArgs := wallet.SignActionArgs{
    Reference: result.Reference,
    Spends: map[uint32]wallet.SignActionSpend{
        0: {
            UnlockingScript: "...",
            SequenceNumber:  0xffffffff,
        },
    },
}

signResult, err := walletClient.SignAction(ctx, signArgs, "example-app")
if err != nil {
    log.Fatal(err)
}
```

## Certificate Management

### Certificate Structure

Certificates are represented by the `Certificate` type:

```go
type Certificate struct {
    Type               string            // Base64-encoded certificate type ID
    SerialNumber       string            // Base64-encoded unique serial number
    Subject            *ec.PublicKey     // Public key of the certificate subject
    Certifier          *ec.PublicKey     // Public key of the certificate issuer
    RevocationOutpoint string            // Format: "txid:outputIndex"
    Fields             map[string]string // Field name -> field value (encrypted)
    Signature          string            // Hex-encoded signature
}
```

### Acquiring Certificates

Use `AcquireCertificate` to obtain a new certificate:

```go
type AcquireCertificateArgs struct {
    Type                string              // Base64-encoded certificate type ID
    Certifier           string              // Certifier's public key
    AcquisitionProtocol AcquisitionProtocol // "direct" or "issuance"
    Fields              map[string]string   // Field name -> field value pairs
    SerialNumber        string              // Unique serial number
    RevocationOutpoint  string              // Optional: Format "txid:outputIndex"
    Signature           string              // Optional: Hex-encoded signature
    CertifierUrl        string              // Optional: URL of the certifier
    KeyringRevealer     string              // Optional: "certifier" or PubKeyHex
    KeyringForSubject   map[string]string   // Optional: Field name -> keyring mapping
    Privileged          *bool               // Optional: Whether this is a privileged operation
    PrivilegedReason    string              // Optional: Reason for privileged access
}
```

Example:
```go
// Acquire certificate
acquireArgs := wallet.AcquireCertificateArgs{
    Type:                "example-cert",
    Certifier:           "certifier-pubkey",
    AcquisitionProtocol: wallet.AcquisitionProtocolDirect,
    Fields: map[string]string{
        "name": "Example",
    },
}

cert, err := walletClient.AcquireCertificate(ctx, acquireArgs, "example-app")
if err != nil {
    log.Fatal(err)
}
```

### Managing Certificates

List and manage certificates using the provided methods:

```go
// List certificates
listArgs := wallet.ListCertificatesArgs{
    Types:  []string{"example-cert"},
    Limit:  10,
    Offset: 0,
}

certs, err := walletClient.ListCertificates(ctx, listArgs, "example-app")
if err != nil {
    log.Fatal(err)
}
```

## Output Management

### Listing Outputs

Use `ListOutputs` to query available outputs:

```go
type ListOutputsArgs struct {
    Basket                    string
    Tags                      []string
    TagQueryMode              QueryMode     // "any" or "all"
    Include                   OutputInclude // "locking scripts" or "entire transactions"
    IncludeCustomInstructions *bool
    IncludeTags               *bool
    IncludeLabels             *bool
    Limit                     uint32        // Default 10, max 10000
    Offset                    uint32
    SeekPermission            *bool         // Default true
}
```

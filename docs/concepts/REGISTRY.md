# Registry Package

The registry package provides functionality for managing on-chain registry definitions for baskets, protocols, and certificates.

## Overview

The BSV Blockchain registry subsystem manages on-chain definitions for three types of records:

1. **Basket** records (basket metadata)
2. **Protocol** records (protocol specifications)
3. **Certificate** records (certificate schemas)

The Go API exposes a `RegistryClient` with methods to register, resolve, list, and revoke registry entries.

## Registry Definition Types

The registry maintains three types of definitions, each with a specific structure:

### BasketDefinitionData

Contains metadata about basket types, including:
- `BasketID` - Unique identifier for the basket
- `Name` - Human-readable name
- `IconURL` - URL to an icon representing the basket
- `Description` - Human-readable description
- `DocumentationURL` - URL to documentation about the basket
- `RegistryOperator` - Public key of the registry operator

```go
type BasketDefinitionData struct {
    DefinitionType   DefinitionType
    BasketID         string
    Name             string
    IconURL          string
    Description      string
    DocumentationURL string
    RegistryOperator string
}
```

### ProtocolDefinitionData

Defines custom transaction protocols, including:
- `ProtocolID` - Unique identifier for the protocol
- `Name` - Human-readable name
- `IconURL` - URL to an icon representing the protocol
- `Description` - Human-readable description
- `DocumentationURL` - URL to documentation about the protocol
- `RegistryOperator` - Public key of the registry operator
- `ValidatorPublicKey` - Public key for identity validation
- `MajorVersion` - Major version number
- `MinorVersion` - Minor version number
- `PatchVersion` - Patch version number

```go
type ProtocolDefinitionData struct {
    DefinitionType     DefinitionType
    ProtocolID         string
    Name               string
    IconURL            string
    Description        string
    DocumentationURL   string
    RegistryOperator   string
    ValidatorPublicKey string
    MajorVersion       uint32
    MinorVersion       uint32
    PatchVersion       uint32
}
```

### CertificateDefinitionData

Defines certificate schemas, including:
- `CertificateID` - Unique identifier for the certificate
- `Name` - Human-readable name
- `IconURL` - URL to an icon representing the certificate
- `Description` - Human-readable description
- `DocumentationURL` - URL to documentation about the certificate
- `RegistryOperator` - Public key of the registry operator
- `AttestedAttributes` - List of attributes that will be attested in certificates
- `ValidatorPublicKey` - Public key for identity validation

```go
type CertificateDefinitionData struct {
    DefinitionType     DefinitionType
    CertificateID      string
    Name               string
    IconURL            string
    Description        string
    DocumentationURL   string
    RegistryOperator   string
    AttestedAttributes []string
    ValidatorPublicKey string
}
```

## Query Structures

When searching for registry definitions, specific query structures are used depending on the definition type:

### BasketQuery

```go
type BasketQuery struct {
    BasketID         *string
    RegistryOperators []string
    Name             *string
}
```

### ProtocolQuery

```go
type ProtocolQuery struct {
    Name             *string
    RegistryOperators []string
    ProtocolID       *string
}
```

### CertificateQuery

```go
type CertificateQuery struct {
    Type             *string
    Name             *string
    RegistryOperators []string
}
```

## Registry Record

A registry record combines the definition data with on-chain token data:

```go
type RegistryRecord struct {
    DefinitionData interface{} // BasketDefinitionData, ProtocolDefinitionData, or CertificateDefinitionData
    TokenData      TokenData
}

type TokenData struct {
    TxID          string
    OutputIndex   uint32
    Satoshis      uint64
    LockingScript string
    BEEF          []byte
}
```

## Storage Format

Registry definitions are stored on-chain using the PushDrop template:

```
<public_key> OP_CHECKSIG <field1> <field2> <field3> <field4> <field5> <field6> OP_2DROP OP_2DROP OP_2DROP
```

The specific fields stored depend on the definition type.

## RegistryClient Interface

The registry client manages on-chain registry definitions for all three types:

```go
type RegistryClientInterface interface {
    // RegisterDefinition publishes a new on-chain definition
    RegisterDefinition(ctx context.Context, data interface{}) (*RegisterDefinitionResult, error)
    
    // Resolve finds registry entries that match the query
    Resolve(ctx context.Context, definitionType DefinitionType, query interface{}) ([]interface{}, error)
    
    // ResolveBasket finds basket registry entries
    ResolveBasket(ctx context.Context, query BasketQuery) ([]*BasketDefinitionData, error)
    
    // ResolveProtocol finds protocol registry entries
    ResolveProtocol(ctx context.Context, query ProtocolQuery) ([]*ProtocolDefinitionData, error)
    
    // ResolveCertificate finds certificate registry entries
    ResolveCertificate(ctx context.Context, query CertificateQuery) ([]*CertificateDefinitionData, error)
    
    // ListOwnRegistryEntries lists the registry operator's published definitions
    ListOwnRegistryEntries(ctx context.Context, definitionType DefinitionType) ([]*RegistryRecord, error)
    
    // RevokeOwnRegistryEntry revokes a registry record by spending its UTXO
    RevokeOwnRegistryEntry(ctx context.Context, record *RegistryRecord) (*RevokeDefinitionResult, error)
}
```

## Basic Usage

### Creating a Registry Client

```go
// Create a new registry client with a wallet and originator
client := registry.NewRegistryClient(wallet, "my-app")
```

### Registering a Definition

```go
// Register a new basket definition
basketDef := &registry.BasketDefinitionData{
    DefinitionType:   registry.DefinitionTypeBasket,
    BasketID:         "my-basket",
    Name:             "My Basket",
    IconURL:          "https://example.com/icon.png",
    Description:      "My basket description",
    DocumentationURL: "https://example.com/docs",
}
result, err := client.RegisterDefinition(ctx, basketDef)
if err != nil {
    // handle error
}
```

### Resolving a Definition

```go
// Resolve a basket by ID
basketID := "my-basket"
query := registry.BasketQuery{BasketID: &basketID}
results, err := client.ResolveBasket(ctx, query)
if err != nil {
    // handle error
}
for _, basket := range results {
    fmt.Printf("Found basket: %s\n", basket.Name)
}
```

### Listing Own Registry Entries

```go
// List own registry entries
entries, err := client.ListOwnRegistryEntries(ctx, registry.DefinitionTypeBasket)
if err != nil {
    // handle error
}
for _, entry := range entries {
    basketData, ok := entry.DefinitionData.(*registry.BasketDefinitionData)
    if ok {
        fmt.Printf("Own basket: %s (%s)\n", basketData.Name, basketData.BasketID)
    }
}
```

### Revoking a Registry Entry

```go
// Revoke a registry entry
err := client.RevokeOwnRegistryEntry(ctx, registryRecord)
if err != nil {
    // handle error
}
```

## Implementation Details

The registry client uses several underlying mechanisms:

1. **PushDrop Template**: Registry entries are stored using the PushDrop transaction template, which allows for structured data to be stored on-chain.

2. **UHRP Lookup Protocol**: Registry entries are resolved using the UHRP lookup protocol, which queries registry entries from blockchain nodes.

3. **Wallet Interface**: The registry client relies on the wallet interface for signing transactions, retrieving outputs, and broadcasting transactions.

For more detailed examples, see the examples directory in the SDK.

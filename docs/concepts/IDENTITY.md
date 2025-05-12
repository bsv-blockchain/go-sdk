# Identity Concepts

## Overview

The identity system in the BSV Go SDK provides a robust framework for managing digital identities through certificates and selective attribute disclosure. It enables applications to:

1. **Verify user identities** through certificates issued by trusted certifiers
2. **Reveal identity attributes** publicly on the blockchain
3. **Resolve identities** by their keys or specific attributes

## Core Components

### IdentityClient

The `IdentityClient` provides a clean interface to work with identity certificates. It handles the complex operations of creating blockchain transactions for public attribute revelation and resolving identities through the wallet interface.

```go
// Initialize a client with default settings
client, err := identity.NewIdentityClient(nil, nil, "example.com")

// Initialize with custom options
options := &identity.IdentityClientOptions{
    ProtocolID:  wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "identity"},
    KeyID:       "1",
    TokenAmount: 1,
    OutputIndex: 0,
}
client, err := identity.NewIdentityClient(walletClient, options, "example.com")
```

### Certificates

Certificates are digital attestations about an identity, issued by a trusted certifier. They can contain various attributes or claims about the identity.

```go
// A simplified example of a certificate
certificate := &wallet.Certificate{
    Type:         identity.KnownIdentityTypes.XCert,
    SerialNumber: "12345",
    Subject:      publicKey,             // The identity the certificate is about
    Certifier:    certifierPublicKey,    // The entity issuing the certificate
    Fields: map[string]string{
        "userName":     "Alice",
        "profilePhoto": "https://example.com/alice.jpg",
        "email":        "alice@example.com",
        "age":          "30",
    },
    Signature:          "...",  // Certifier's signature
    RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000:0",
}
```

### DisplayableIdentity

When resolving identities, the SDK converts certificates into user-friendly `DisplayableIdentity` objects that can be easily presented in applications.

```go
type DisplayableIdentity struct {
    Name           string // User-friendly name
    AvatarURL      string // URL to profile image
    AbbreviatedKey string // Shortened version of identity key (first 10 chars)
    IdentityKey    string // Full identity key (public key)
    BadgeIconURL   string // URL to certifier badge icon
    BadgeLabel     string // Text describing the certification (e.g., "X account certified by CertifierX")
    BadgeClickURL  string // URL for more information about the certification
}
```

## Identity Types

The SDK supports various identity certificate types, each with a specific purpose:

```go
// Some of the supported identity types
KnownIdentityTypes = struct {
    XCert      string // X (Twitter) account verification
    DiscordCert string // Discord account verification
    EmailCert   string // Email verification
    PhoneCert   string // Phone number verification
    IdentiCert  string // Government ID verification
    Registrant  string // Entity certification
    Anyone      string // Public information
    Self        string // Self-attested information
}{
    XCert:      "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=",
    DiscordCert: "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=",
    EmailCert:   "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=",
    PhoneCert:   "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=",
    IdentiCert:  "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=",
    Registrant:  "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=",
    Anyone:      "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=",
    Self:        "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=",
}
```

## Key Functionality

### Selective Attribute Revelation

One of the most powerful features is the ability to selectively reveal attributes from a certificate. This maintains privacy by only disclosing the minimum information necessary.

```go
// Choose which fields to publicly reveal
fieldsToReveal := []identity.CertificateFieldNameUnder50Bytes{
    "userName",
    "profilePhoto",
}

// Create a public certificate with only those fields
success, failure, err := client.PubliclyRevealAttributes(
    context.Background(),
    certificate,
    fieldsToReveal,
)
```

### Identity Resolution

The SDK provides two main methods for resolving identities:

1. **By Identity Key**: Look up certificates issued to a specific identity key.

```go
identities, err := client.ResolveByIdentityKey(
    context.Background(),
    wallet.DiscoverByIdentityKeyArgs{
        IdentityKey: "exampleIdentityKey123",
    },
)
```

2. **By Attributes**: Find identities that have specific attributes.

```go
identities, err := client.ResolveByAttributes(
    context.Background(),
    wallet.DiscoverByAttributesArgs{
        Attributes: map[string]string{
            "email": "alice@example.com",
        },
    },
)
```

## Under the Hood

When revealing attributes publicly:

1. The client creates a keyring for verification through certificate proving
2. The certificate and keyring are serialized to JSON
3. A PushDrop template is used to create a locking script with the certificate data
4. A transaction is created with the certificate as an output
5. The transaction is broadcast to a federated overlay node

This process creates an on-chain record of the revealed attributes while maintaining the integrity and verifiability of the certificate.

## Use Cases

- **Social Media Verification**: Confirm that accounts belong to specific individuals or entities
- **Professional Credentials**: Verify professional qualifications or certifications
- **Age Verification**: Prove age without revealing exact date of birth
- **KYC/AML Compliance**: Satisfy regulatory requirements while minimizing data exposure
- **Organizational Membership**: Verify membership in organizations or groups

## Further Reading

- [Identity Client Example](../examples/identity_client/README.md) - Complete working example
- [API Documentation](../../identity/README.md) - Full API reference 
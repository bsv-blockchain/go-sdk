# IdentityClient

**Resolve who others are and let the world know who you are.**

## Overview

`IdentityClient` provides a straightforward interface for resolving and revealing identity certificates. It allows applications to verify user identities through certificates issued by trusted certifiers, reveal identity attributes publicly on the blockchain, and resolving identities associated with given attributes or identity keys.

## Features

- **Selective Attribute Revelation**: Create identity tokens which publicly reveal selective identity attributes and are tracked by overlay services.
- **Identity Resolution**: Easily resolve identity certificates based on identity keys or specific attributes.
- **Displayable Identities**: Parse identity certificates into user-friendly, displayable identities.

## Installation

```bash
go get github.com/bsv-blockchain/go-sdk
```

## Usage

### Initialization

```go
import (
	"github.com/bsv-blockchain/go-sdk/identity"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Initialize with default wallet and options
identityClient := identity.NewIdentityClient(nil, nil, "")

// Or with custom wallet and options
options := &identity.IdentityClientOptions{
	ProtocolID:  wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "identity"},
	KeyID:       "1",
	TokenAmount: 1,
	OutputIndex: 0,
}
identityClient := identity.NewIdentityClient(walletClient, options, "")
```

### Publicly Reveal Attributes

```go
success, failure, err := identityClient.PubliclyRevealAttributes(
	context.Background(),
	certificate,
	[]identity.CertificateFieldNameUnder50Bytes{"name", "email"},
)
```

### TypeScript-Compatible API

```go
// Simplified API that returns just the transaction ID like the TypeScript implementation
txid, err := identityClient.PubliclyRevealAttributesSimple(
	context.Background(), 
	certificate,
	[]identity.CertificateFieldNameUnder50Bytes{"name", "email"},
)
```

### Resolve Identity by Key

```go
identities, err := identityClient.ResolveByIdentityKey(
	context.Background(),
	wallet.DiscoverByIdentityKeyArgs{
		IdentityKey: "<identity-key-here>",
	},
)
```

### Resolve Identity by Attributes

```go
identities, err := identityClient.ResolveByAttributes(
	context.Background(),
	wallet.DiscoverByAttributesArgs{
		Attributes: map[string]string{"email": "user@example.com"},
	},
)
```

## Examples

For a complete working example of using the identity client, see:
- [Identity Client Example](../docs/examples/identity_client/README.md)

## Example in a Web Application

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/identity"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type IdentityResponse struct {
	Identities []identity.DisplayableIdentity `json:"identities"`
}

func handleIdentityRequest(w http.ResponseWriter, r *http.Request) {
	// Get identity key from query parameter
	identityKey := r.URL.Query().Get("identityKey")
	if identityKey == "" {
		http.Error(w, "Identity key is required", http.StatusBadRequest)
		return
	}

	// Create identity client
	identityClient := identity.NewIdentityClient(nil, nil, "")

	// Resolve identities
	identities, err := identityClient.ResolveByIdentityKey(
		r.Context(),
		wallet.DiscoverByIdentityKeyArgs{
			IdentityKey: identityKey,
		},
	)
	if err != nil {
		http.Error(w, "Failed to resolve identities: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return identities as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(IdentityResponse{
		Identities: identities,
	})
}

func main() {
	http.HandleFunc("/api/identity", handleIdentityRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## License

Open BSV License 
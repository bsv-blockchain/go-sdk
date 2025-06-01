package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bsv-blockchain/go-sdk/identity"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
	// EXAMPLE 1: Create an identity client
	client, err := identity.NewClient(nil, nil, "example.com")
	if err != nil {
		log.Fatalf("Failed to create identity client: %v", err)
	}

	// -------------------------------------------------------------------------
	// EXAMPLE 2: Publicly reveal attributes from an identity certificate
	// -------------------------------------------------------------------------
	// In a real application, you would obtain a certificate through wallet.acquireCertificate
	// or another mechanism. This is a simplified example.
	typeXCert, err := wallet.StringBase64(identity.KnownIdentityTypes.XCert).ToArray()
	if err != nil {
		log.Fatalf("Failed to get known identity type: %v", err)
	}
	certificate := &wallet.Certificate{
		// Certificate fields would be populated here
		Type:         typeXCert,
		SerialNumber: [32]byte{0x01, 0x02, 0x03},
		// Other fields...
		Fields: map[string]string{
			"userName":     "Alice",
			"profilePhoto": "https://example.com/alice.jpg",
			"age":          "30",
			"country":      "USA",
		},
	}

	// Choose which fields to publicly reveal (selective disclosure)
	fieldsToReveal := []identity.CertificateFieldNameUnder50Bytes{
		"userName",
		"profilePhoto",
	}

	// Publicly reveal the selected attributes
	// This creates a blockchain transaction with the publicly verifiable certificate
	success, failure, err := client.PubliclyRevealAttributes(
		context.Background(),
		certificate,
		fieldsToReveal,
	)

	if err != nil {
		log.Printf("Error revealing attributes: %v", err)
	} else if failure != nil {
		log.Printf("Broadcast failed: %s", failure.Description)
	} else {
		fmt.Printf("Successfully revealed attributes! Transaction ID: %s\n", success.Txid)
		fmt.Printf("Message: %s\n", success.Message)
	}

	// If you prefer a simplified API that matches the TypeScript implementation:
	txid, err := client.PubliclyRevealAttributesSimple(
		context.Background(),
		certificate,
		fieldsToReveal,
	)
	if err != nil {
		log.Printf("Error revealing attributes (simple API): %v", err)
	} else {
		fmt.Printf("Successfully revealed attributes! Transaction ID: %s\n", txid)
	}

	// -------------------------------------------------------------------------
	// EXAMPLE 3: Resolve identity by identity key
	// -------------------------------------------------------------------------
	identities, err := client.ResolveByIdentityKey(
		context.Background(),
		wallet.DiscoverByIdentityKeyArgs{
			IdentityKey: [33]byte{0x01, 0x02, 0x03},
		},
	)
	if err != nil {
		log.Printf("Error resolving identity by key: %v", err)
	} else {
		fmt.Printf("Found %d identities for the given key\n", len(identities))
		for i, identity := range identities {
			fmt.Printf("Identity %d:\n", i+1)
			fmt.Printf("  Name: %s\n", identity.Name)
			fmt.Printf("  Avatar URL: %s\n", identity.AvatarURL)
			fmt.Printf("  Identity Key: %s\n", identity.IdentityKey)
			fmt.Printf("  Badge: %s\n", identity.BadgeLabel)
		}
	}

	// -------------------------------------------------------------------------
	// EXAMPLE 4: Resolve identity by attributes
	// -------------------------------------------------------------------------
	identitiesByAttr, err := client.ResolveByAttributes(
		context.Background(),
		wallet.DiscoverByAttributesArgs{
			Attributes: map[string]string{
				"email": "alice@example.com",
			},
		},
	)
	if err != nil {
		log.Printf("Error resolving identity by attributes: %v", err)
	} else {
		fmt.Printf("Found %d identities with the given attributes\n", len(identitiesByAttr))
		for i, identity := range identitiesByAttr {
			fmt.Printf("Identity %d:\n", i+1)
			fmt.Printf("  Name: %s\n", identity.Name)
			fmt.Printf("  Identity Key: %s\n", identity.IdentityKey)
		}
	}

	typeEmailCert, err := wallet.StringBase64(identity.KnownIdentityTypes.EmailCert).ToArray()
	if err != nil {
		log.Fatalf("Failed to get known identity type: %v", err)
	}

	// -------------------------------------------------------------------------
	// EXAMPLE 5: Parse an identity certificate directly
	// -------------------------------------------------------------------------
	// This is useful when you have a certificate from another source and want to
	// convert it to a DisplayableIdentity
	certFromElsewhere := &wallet.IdentityCertificate{
		Certificate: wallet.Certificate{
			Type: typeEmailCert,
		},
		DecryptedFields: map[string]string{
			"email": "bob@example.com",
		},
		CertifierInfo: wallet.IdentityCertifier{
			Name:    "EmailCertifier",
			IconUrl: "https://example.com/certifier-icon.png",
		},
	}

	displayableIdentity := identity.ParseIdentity(certFromElsewhere)
	fmt.Printf("Parsed Identity:\n")
	fmt.Printf("  Name: %s\n", displayableIdentity.Name)
	fmt.Printf("  Badge: %s\n", displayableIdentity.BadgeLabel)
	fmt.Printf("  Badge Icon: %s\n", displayableIdentity.BadgeIconURL)
}

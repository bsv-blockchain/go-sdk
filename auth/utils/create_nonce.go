package utils

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// CreateNonce generates a cryptographic nonce derived from the wallet
// The nonce consists of random data combined with an HMAC calculated with the wallet
// Follows the same pattern as the TypeScript SDK's createNonce function
func CreateNonce(w wallet.Interface, counterparty wallet.CounterpartyType) (string, error) {
	// Generate 16 bytes of random data (matching TypeScript implementation)
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create encryption arguments for the wallet's CreateHmac function
	args := wallet.CreateHmacArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "server hmac",
			},
			KeyID: string(randomBytes),
			Counterparty: wallet.Counterparty{
				Type: counterparty,
			},
		},
		Data: randomBytes,
	}

	// Create an HMAC for the random data using the wallet's key
	hmac, err := w.CreateHmac(context.TODO(), args, "")
	if err != nil {
		return "", fmt.Errorf("failed to create HMAC: %w", err)
	}

	// Combine the random data and the HMAC
	combined := append(randomBytes, hmac.Hmac...)

	// Encode as base64
	nonce := base64.StdEncoding.EncodeToString(combined)
	return nonce, nil
}

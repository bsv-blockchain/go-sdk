package utils

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

// VerifyNonce verifies that a nonce was derived from the given wallet
// This is the Go equivalent of the TypeScript SDK's verifyNonce function
func VerifyNonce(
	ctx context.Context,
	nonce string,
	w wallet.KeyOperations,
	counterparty wallet.Counterparty,
) (bool, error) {
	// Convert nonce from base64 to binary
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return false, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Check nonce format
	if len(nonceBytes) <= 16 { // Need at least 16 bytes data + some HMAC
		return false, errors.New("invalid nonce format: too short")
	}

	// Split nonce into data and hmac parts (first 16 bytes are data)
	data := nonceBytes[:16]
	hmac := nonceBytes[16:]

	// Create args for wallet VerifyHMAC
	args := wallet.VerifyHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "server hmac", // Match TS SDK's protocol ID
			},
			KeyID:        string(data), // Use data as key ID
			Counterparty: counterparty,
		},
		Data: data,
		HMAC: hmac,
	}

	// Verify the hmac
	result, err := w.VerifyHMAC(ctx, args, "")
	if err != nil {
		return false, fmt.Errorf("failed to verify HMAC: %w", err)
	}

	return result.Valid, nil
}

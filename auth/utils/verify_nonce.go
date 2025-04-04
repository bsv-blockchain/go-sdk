package utils

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// VerifyNonce verifies that a nonce was derived from the given wallet
// This is the Go equivalent of the TypeScript SDK's verifyNonce function
func VerifyNonce(
	nonce string,
	w *wallet.Wallet,
	counterparty wallet.CounterpartyType,
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

	// Create args for wallet VerifyHmac
	args := wallet.VerifyHmacArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "server hmac", // Match TS SDK's protocol ID
			},
			KeyID: string(data), // Use data as key ID
			Counterparty: wallet.Counterparty{
				Type: counterparty,
			},
		},
		Data: data,
		Hmac: hmac,
	}

	// Verify the hmac
	result, err := w.VerifyHmac(args)
	if err != nil {
		return false, fmt.Errorf("failed to verify HMAC: %w", err)
	}

	return result.Valid, nil
}

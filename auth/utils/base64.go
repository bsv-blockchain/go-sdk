package utils

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// RandomBase64 generates a random byte sequence of specified length and returns it as base64 encoded string
func RandomBase64(length int) wallet.Base64String {
	randomBytes := make([]byte, length)
	_, _ = rand.Read(randomBytes)
	return wallet.Base64String(base64.StdEncoding.EncodeToString(randomBytes))
}

package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// base64NonceFormat matches the TS reference's verifyNonce.ts character-set
// check: a base64 string with no whitespace, in groups of 4, with proper
// padding.
var base64NonceFormat = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

// VerifyNonce verifies that a nonce was derived from the given wallet.
// This is the Go equivalent of the TypeScript SDK's verifyNonce function
// (auth/utils/verifyNonce.ts): a nonce that is not well-formed base64, does
// not decode to exactly 48 bytes, or does not round-trip back to the exact
// same base64 string is simply not valid, and VerifyNonce reports that as
// (false, nil) - it never treats a malformed nonce as an error. Only the
// underlying wallet's own VerifyHMAC call can return a non-nil error here,
// exactly as the TS reference lets wallet.verifyHmac's rejection propagate
// as a thrown exception instead of swallowing it into a `false` result.
func VerifyNonce(
	ctx context.Context,
	nonce string,
	w wallet.KeyOperations,
	counterparty wallet.Counterparty,
) (bool, error) {
	if !base64NonceFormat.MatchString(nonce) {
		return false, nil
	}

	// Convert nonce from base64 to binary. A decode failure here is not an
	// error condition - like the rest of this format validation, it just
	// means the nonce is not valid, matching the TS reference's verifyNonce.ts
	// (which also treats a decode failure as `false`, not a thrown error).
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return false, nil //nolint:nilerr // malformed nonce is reported as invalid, not as an error
	}

	// The TS reference requires exactly 48 bytes (16 bytes of data followed
	// by a 32-byte HMAC) and rejects any encoding of that buffer other than
	// the canonical one the nonce itself must equal.
	if len(nonceBytes) != 48 || base64.StdEncoding.EncodeToString(nonceBytes) != nonce {
		return false, nil
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
	}
	copy(args.HMAC[:], hmac)

	// Verify the hmac
	result, err := w.VerifyHMAC(ctx, args, "")
	if err != nil {
		return false, fmt.Errorf("failed to verify HMAC: %w", err)
	}

	return result.Valid, nil
}

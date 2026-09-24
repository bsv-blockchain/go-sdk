package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestCreateNonce(t *testing.T) {
	// Create a wallet with a random private key
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	completedWallet, err := wallet.NewCompletedProtoWallet(privateKey)
	if err != nil {
		t.Fatalf("Failed to create completed wallet: %v", err)
	}

	ctx := context.Background()

	// Test creating a nonce
	nonce, err := CreateNonce(ctx, completedWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	require.NoError(t, err, "Should not error when creating nonce")
	require.NotEmpty(t, nonce, "Nonce should not be empty")

	// Create another nonce to verify they're different
	nonce2, err := CreateNonce(ctx, completedWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	require.NoError(t, err, "Should not error when creating second nonce")
	require.NotEmpty(t, nonce2, "Second nonce should not be empty")
	require.NotEqual(t, nonce, nonce2, "Two nonces should be different")
}

func TestVerifyNonce(t *testing.T) {
	// Create a wallet with a random private key
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	completedWallet, err := wallet.NewCompletedProtoWallet(privateKey)
	if err != nil {
		t.Fatalf("Failed to create completed wallet: %v", err)
	}

	// Create a valid nonce
	counterparty := wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	}

	nonce, err := CreateNonce(t.Context(), completedWallet, counterparty)
	require.NoError(t, err, "Failed to create nonce")

	// Verify the valid nonce
	valid, err := VerifyNonce(t.Context(), nonce, completedWallet, counterparty)
	require.NoError(t, err, "Should not error when verifying a valid nonce")
	require.True(t, valid, "Valid nonce should verify successfully")

	// Test invalid nonce (wrong format/length). Matching the TS reference's
	// verifyNonce.ts, a malformed nonce is simply invalid - VerifyNonce
	// reports (false, nil) rather than an error, since no wallet call is ever
	// made for it.
	valid, err = VerifyNonce(t.Context(), "invalidnonce", completedWallet, counterparty)
	require.NoError(t, err, "A malformed nonce should not be treated as an error")
	require.False(t, valid, "Invalid nonce should not verify")

	// Test with different counterparty type (should fail). The underlying
	// wallet.VerifyHMAC (like the TS reference's wallet.verifyHmac) returns an
	// error rather than {Valid: false} for an HMAC that fails verification,
	// so a counterparty mismatch surfaces as an error here too.
	valid, err = VerifyNonce(t.Context(), nonce, completedWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeAnyone,
	})
	require.Error(t, err, "Should error with valid nonce format but invalid counterparty")
	require.False(t, valid, "Nonce with mismatched counterparty should not verify")
}

// TestVerifyNonceFormatEdgeCases pins the TS-reference-equivalent format
// checks (base64 charset/padding, exact 48-byte length, canonical
// round-trip) added to VerifyNonce: every case here is a plain (false, nil)
// result, never an error, since the wallet is never consulted for a
// malformed nonce.
func TestVerifyNonceFormatEdgeCases(t *testing.T) {
	privateKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	completedWallet, err := wallet.NewCompletedProtoWallet(privateKey)
	require.NoError(t, err)

	counterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

	validNonce, err := CreateNonce(t.Context(), completedWallet, counterparty)
	require.NoError(t, err)

	cases := map[string]string{
		"empty string":                   "",
		"not base64 at all":              "@@@not-base64@@@",
		"too short (well-formed base64)": "YWJjZA==",                               // decodes to 4 bytes, not 48
		"too long (well-formed base64)":  validNonce + "AAAA",                      // decodes to 51 bytes, not 48
		"padding in the middle":          validNonce[:60] + "==" + validNonce[62:], // fails the charset/padding regex
	}
	for name, nonce := range cases {
		t.Run(name, func(t *testing.T) {
			valid, err := VerifyNonce(t.Context(), nonce, completedWallet, counterparty)
			require.NoError(t, err)
			require.False(t, valid)
		})
	}
}

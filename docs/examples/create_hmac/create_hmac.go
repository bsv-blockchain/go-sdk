package main

import (
	"context"
	"fmt"
	"log"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
	ctx := context.Background()

	// --- 1. Setup Wallet ---
	fmt.Println("--- 1. Setting up Wallet ---")
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	myWallet, err := wallet.NewWallet(privateKey)
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}
	fmt.Println("Wallet created.")

	// Define ProtocolID and KeyID for HMAC operations
	// Protocol names must contain only letters, numbers, and spaces, and be >= 5 chars.
	// Key IDs can have spaces, must be >= 1 char.
	hmacProtocolID := wallet.Protocol{Protocol: "HMAC SelfSign", SecurityLevel: wallet.SecurityLevelSilent}
	hmacKeyID := "my hmac key v1"

	message := []byte("This is the data to be authenticated with HMAC.")
	fmt.Printf("Original Message: %s\n", string(message))

	// --- 2. Create HMAC (for Self) ---
	fmt.Println("\n--- 2. Creating HMAC for the message (for self) ---")
	createHmacArgs := wallet.CreateHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: hmacProtocolID,
			KeyID:      hmacKeyID,
			Counterparty: wallet.Counterparty{ // Explicitly set for self-operation
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		Data: wallet.JsonByteNoBase64(message),
	}
	createHmacResult, err := myWallet.CreateHMAC(ctx, createHmacArgs, "creator_originator")
	if err != nil {
		log.Fatalf("Failed to create HMAC: %v", err)
	}
	hmacBytes := createHmacResult.HMAC
	fmt.Printf("HMAC created: %x\n", hmacBytes)

	// --- 3. Verify HMAC (by Self) ---
	fmt.Println("\n--- 3. Verifying the HMAC (by self) ---")
	verifyHmacArgs := wallet.VerifyHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: hmacProtocolID, // Must match creation
			KeyID:      hmacKeyID,      // Must match creation
			Counterparty: wallet.Counterparty{ // Explicitly set for self-operation
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		Data: wallet.JsonByteNoBase64(message), // Original data
		HMAC: hmacBytes,                        // HMAC from step 2
	}
	verifyHmacResult, err := myWallet.VerifyHMAC(ctx, verifyHmacArgs, "verifier_originator")
	if err != nil {
		// This path should ideally not be hit if args are correct and HMAC was just created
		log.Fatalf("Error during HMAC verification call: %v", err)
	}
	if verifyHmacResult.Valid {
		fmt.Println("HMAC VERIFIED successfully!")
	} else {
		// This would be an unexpected failure for a valid HMAC
		log.Fatalf("HMAC verification FAILED (but should have succeeded).")
	}

	// --- 4. Verification Failure with Tampered Data ---
	fmt.Println("\n--- 4. Verifying with tampered data (expected failure) ---")
	tamperedDataArgs := verifyHmacArgs // Copy previous args
	tamperedDataArgs.Data = wallet.JsonByteNoBase64([]byte("This is tampered data!"))
	tamperedDataVerifyResult, err := myWallet.VerifyHMAC(ctx, tamperedDataArgs, "verifier_tampered_data")
	if err != nil {
		log.Fatalf("Error during tampered data HMAC verification call: %v", err)
	}
	if tamperedDataVerifyResult.Valid {
		fmt.Println("Tampered data HMAC verification unexpectedly SUCCEEDED (Error!).")
	} else {
		fmt.Println("Tampered data HMAC verification FAILED as expected.")
	}

	// --- 5. Verification Failure with Tampered HMAC ---
	fmt.Println("\n--- 5. Verifying with tampered HMAC (expected failure) ---")
	tamperedHmacArgs := verifyHmacArgs // Copy previous args
	// Create a slightly altered HMAC. Ensure it's different but same length if possible.
	corruptedHmac := make([]byte, len(hmacBytes))
	copy(corruptedHmac, hmacBytes)
	if len(corruptedHmac) > 0 {
		corruptedHmac[0] ^= 0xFF // Flip all bits of the first byte
	} else {
		corruptedHmac = append(corruptedHmac, 0x00) // Or handle if HMAC was empty (should not be)
	}
	tamperedHmacArgs.HMAC = wallet.JsonByteNoBase64(corruptedHmac)
	tamperedHmacVerifyResult, err := myWallet.VerifyHMAC(ctx, tamperedHmacArgs, "verifier_tampered_hmac")
	if err != nil {
		log.Fatalf("Error during tampered HMAC verification call: %v", err)
	}
	if tamperedHmacVerifyResult.Valid {
		fmt.Println("Tampered HMAC verification unexpectedly SUCCEEDED (Error!).")
	} else {
		fmt.Println("Tampered HMAC verification FAILED as expected.")
	}

	fmt.Println("\nCreate and verify HMAC example complete.")
}

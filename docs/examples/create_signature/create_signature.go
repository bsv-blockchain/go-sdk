package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
	ctx := context.Background()

	// --- 1. Setup Signer's Wallet ---
	fmt.Println("--- 1. Setting up Signer's wallet ---")
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}
	signerWallet, err := wallet.NewWallet(privateKey)
	if err != nil {
		log.Fatalf("Failed to create signer wallet: %v", err)
	}
	fmt.Println("Signer's wallet created.")

	// Define common protocol and key ID for self-operations
	// Protocol names must contain only letters, numbers, and spaces, and be >= 5 chars.
	selfProtocolID := wallet.Protocol{Protocol: "ECDSA SelfSign", SecurityLevel: wallet.SecurityLevelSilent}
	selfKeyID := "my signing key v1" // Key IDs can have spaces, must be >= 1 char.

	// --- 2. Define Data and Create Signature (for self) ---
	fmt.Println("\n--- 2. Creating signature for a message (for self) ---")
	message := []byte("This is the message to be signed by myself, for myself.")
	fmt.Printf("Original Message: %s\n", string(message))

	createSigArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: selfProtocolID,
			KeyID:      selfKeyID,
			Counterparty: wallet.Counterparty{ // Explicitly set for self-signing
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		Data: wallet.BytesList(message),
	}
	sigResult, err := signerWallet.CreateSignature(ctx, createSigArgs, "signer_createsig_self_originator")
	if err != nil {
		log.Fatalf("Failed to create signature for self: %v", err)
	}
	fmt.Printf("Signature created (%x)\n", sigResult.Signature)

	// --- 3. Verify Signature (by self) ---
	fmt.Println("\n--- 3. Verifying the signature (by self) ---")
	verifyArgs := wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: selfProtocolID, // Must match signing
			KeyID:      selfKeyID,      // Must match signing
			Counterparty: wallet.Counterparty{ // Explicitly set for self-verification
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		Data:      wallet.BytesList(message), // Original message
		Signature: sigResult.Signature,
		// ForSelf:   true, // DO NOT SET ForSelf for this type of self-verification, rely on Counterparty in EncryptionArgs
	}

	verifyResult, err := signerWallet.VerifySignature(ctx, verifyArgs, "verifier_verify_self_originator")
	if err != nil {
		log.Fatalf("Error during self-signature verification: %v", err)
	}
	if verifyResult.Valid {
		fmt.Println("Self-signature VERIFIED successfully using wallet.VerifySignature!")
	} else {
		fmt.Println("Self-signature verification FAILED using wallet.VerifySignature.")
	}

	// --- 4. Verification with Tampered Data (Failure Case) ---
	fmt.Println("\n--- 4. Verifying with tampered message (by self, expected failure) ---")
	tamperedMessage := []byte("This is NOT the message that was signed.")
	verifyArgsTampered := verifyArgs // Copy previous args, EncryptionArgs.Counterparty is already CounterpartyTypeSelf
	verifyArgsTampered.Data = wallet.BytesList(tamperedMessage)

	tamperedVerifyResult, err := signerWallet.VerifySignature(ctx, verifyArgsTampered, "verifier_tampered_self_originator")
	if err != nil {
		// This means the VerifySignature call itself encountered an issue (e.g., bad args, or it returns error on invalid sig)
		fmt.Printf("Tampered message self-signature verification FAILED as expected (due to error: %v)\n", err)
	} else {
		// VerifySignature call succeeded without error, now check the .Valid field
		if tamperedVerifyResult == nil {
			// This case should ideally not happen if err is nil, but good to guard.
			log.Fatalf("Tampered verification returned nil result and nil error, which is unexpected.")
		} else if tamperedVerifyResult.Valid {
			fmt.Println("Tampered message self-signature verification unexpectedly SUCCEEDED (Error!).")
		} else {
			fmt.Println("Tampered message self-signature verification FAILED as expected (result.Valid is false).")
		}
	}

	// --- 5. Signing a Pre-computed Hash (for self) ---
	fmt.Println("\n--- 5. Creating signature for a pre-computed hash (for self) ---")
	selfHashProtocolID := wallet.Protocol{Protocol: "ECDSA SelfSignHash", SecurityLevel: wallet.SecurityLevelSilent}
	selfHashKeyID := "my signing hash key v1"

	messageToHash := []byte("Another message, this time for hashing first, for self.")
	h := sha256.New()
	h.Write(messageToHash)
	messageHash := h.Sum(nil)
	fmt.Printf("Original Message for Hashing: %s\n", string(messageToHash))
	fmt.Printf("SHA256 Hash: %x\n", messageHash)

	createSigForHashArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: selfHashProtocolID,
			KeyID:      selfHashKeyID,
			Counterparty: wallet.Counterparty{ // Explicitly set for self-signing hash
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		HashToDirectlySign: wallet.BytesList(messageHash),
	}
	sigFromHashResult, err := signerWallet.CreateSignature(ctx, createSigForHashArgs, "signer_createsig_hash_self_originator")
	if err != nil {
		log.Fatalf("Failed to create signature for hash (for self): %v", err)
	}
	fmt.Printf("Signature for hash created (%x)\n", sigFromHashResult.Signature)

	// --- 6. Verify Signature of Pre-computed Hash (by self) ---
	fmt.Println("\n--- 6. Verifying signature of pre-computed hash (by self) ---")
	verifyHashArgs := wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: selfHashProtocolID, // Must match hash signing
			KeyID:      selfHashKeyID,      // Must match hash signing
			Counterparty: wallet.Counterparty{ // Explicitly set for self-verification of hash
				Type: wallet.CounterpartyTypeSelf,
			},
		},
		HashToDirectlyVerify: wallet.BytesList(messageHash),
		Signature:            sigFromHashResult.Signature,
		// ForSelf:              true, // DO NOT SET ForSelf for this type of self-verification
	}

	verifyHashResult, err := signerWallet.VerifySignature(ctx, verifyHashArgs, "verifier_verify_hash_self_originator")
	if err != nil {
		log.Fatalf("Error during self-signature (hash) verification: %v", err)
	}
	if verifyHashResult.Valid {
		fmt.Println("Self-signature (hash) VERIFIED successfully using wallet.VerifySignature!")
	} else {
		fmt.Println("Self-signature (hash) verification FAILED using wallet.VerifySignature.")
	}

	fmt.Println("\nCreate and verify signature example complete.")
}

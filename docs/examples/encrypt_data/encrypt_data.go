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

	// --- 1. Setup Wallets ---
	fmt.Println("--- 1. Setting up Alice's and Bob's wallets ---")
	// Create Alice's wallet
	// In a real application, load/derive this securely.
	alicePrivKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to create Alice's private key: %v", err)
	}
	aliceWallet, err := wallet.NewWallet(alicePrivKey)
	if err != nil {
		log.Fatalf("Failed to create Alice's wallet: %v", err)
	}
	fmt.Println("Alice's wallet created.")

	// Create Bob's wallet
	// In a real application, load/derive this securely.
	bobPrivKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to create Bob's private key: %v", err)
	}
	bobWallet, err := wallet.NewWallet(bobPrivKey)
	if err != nil {
		log.Fatalf("Failed to create Bob's wallet: %v", err)
	}
	fmt.Println("Bob's wallet created.")

	// --- 2. Alice Gets Bob's Public Key for Encryption ---
	fmt.Println("\n--- 2. Alice gets Bob's Public Key ---")
	// Alice needs Bob's public key to encrypt data for him.
	// In a real scenario, Bob would share his public key (e.g., IdentityKey) with Alice.
	bobIdentityKeyArgs := wallet.GetPublicKeyArgs{IdentityKey: true}
	bobPubKeyResult, err := bobWallet.GetPublicKey(ctx, bobIdentityKeyArgs, "bob_originator_get_pubkey")
	if err != nil {
		log.Fatalf("Bob failed to get his public key: %v", err)
	}
	bobECPubKey := bobPubKeyResult.PublicKey // This is already *ec.PublicKey
	if bobECPubKey == nil {
		log.Fatalf("Bob's public key is nil from GetPublicKey")
	}
	fmt.Printf("Alice obtained Bob's Public Key: %x\n", bobECPubKey.Compressed())

	// --- 3. Alice Encrypts Data for Bob ---
	fmt.Println("\n--- 3. Alice Encrypts Data for Bob ---")
	plaintextForBob := []byte("Hello Bob, this is a secret message from Alice!")
	fmt.Printf("Plaintext from Alice: %s\n", string(plaintextForBob))

	encryptArgsAliceToBob := wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: bobECPubKey, // Alice uses Bob's public key
			},
			ProtocolID: wallet.Protocol{
				Protocol:      "ECIES",
				SecurityLevel: wallet.SecurityLevelSilent,
			},
			KeyID: "AliceToBobECIES_Key1",
		},
		Plaintext: wallet.JsonByteNoBase64(plaintextForBob),
	}

	encryptedResultAliceToBob, err := aliceWallet.Encrypt(ctx, encryptArgsAliceToBob, "alice_encrypt_for_bob")
	if err != nil {
		log.Fatalf("Alice failed to encrypt data for Bob: %v", err)
	}
	fmt.Printf("Alice encrypted ciphertext for Bob (first 32 bytes): %x...\n", encryptedResultAliceToBob.Ciphertext[:32])

	// --- 4. Bob Decrypts Data from Alice ---
	fmt.Println("\n--- 4. Bob Decrypts Data from Alice ---")
	// Bob needs Alice's public key to know who the sender is for key derivation during decryption.
	aliceIdentityKeyArgs := wallet.GetPublicKeyArgs{IdentityKey: true}
	alicePubKeyResult, err := aliceWallet.GetPublicKey(ctx, aliceIdentityKeyArgs, "alice_originator_get_pubkey")
	if err != nil {
		log.Fatalf("Alice failed to get her public key: %v", err)
	}
	aliceECPubKey := alicePubKeyResult.PublicKey // This is already *ec.PublicKey
	if aliceECPubKey == nil {
		log.Fatalf("Alice's public key is nil from GetPublicKey")
	}

	decryptArgsBobFromAlice := wallet.DecryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: aliceECPubKey, // Bob specifies Alice's public key as the sender
			},
			ProtocolID: wallet.Protocol{
				Protocol:      "ECIES",
				SecurityLevel: wallet.SecurityLevelSilent,
			},
			KeyID: "AliceToBobECIES_Key1",
		},
		Ciphertext: encryptedResultAliceToBob.Ciphertext,
	}

	decryptedResultBobFromAlice, err := bobWallet.Decrypt(ctx, decryptArgsBobFromAlice, "bob_decrypt_from_alice")
	if err != nil {
		log.Fatalf("Bob failed to decrypt data from Alice: %v", err)
	}
	fmt.Printf("Bob decrypted message: %s\n", string(decryptedResultBobFromAlice.Plaintext))

	// --- 5. Alice Encrypts Data for Herself ---
	fmt.Println("\n--- 5. Alice Encrypts Data for Herself ---")
	plaintextForSelf := []byte("This is Alice's secret note to herself.")
	fmt.Printf("Plaintext from Alice for self: %s\n", string(plaintextForSelf))

	selfEncryptArgs := wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			ProtocolID: wallet.Protocol{
				Protocol:      "ECIES",
				SecurityLevel: wallet.SecurityLevelSilent,
			},
			KeyID: "AliceSelfECIES_Key1",
		},
		Plaintext: wallet.JsonByteNoBase64(plaintextForSelf),
	}
	selfEncryptedResult, err := aliceWallet.Encrypt(ctx, selfEncryptArgs, "alice_encrypt_for_self")
	if err != nil {
		log.Fatalf("Alice failed to encrypt data for herself: %v", err)
	}
	fmt.Printf("Alice encrypted ciphertext for self (first 32 bytes): %x...\n", selfEncryptedResult.Ciphertext[:32])

	// --- 6. Alice Decrypts Her Own Data ---
	fmt.Println("\n--- 6. Alice Decrypts Her Own Data ---")
	selfDecryptArgs := wallet.DecryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			ProtocolID: wallet.Protocol{
				Protocol:      "ECIES",
				SecurityLevel: wallet.SecurityLevelSilent,
			},
			KeyID: "AliceSelfECIES_Key1",
		},
		Ciphertext: selfEncryptedResult.Ciphertext,
	}
	selfDecryptedResult, err := aliceWallet.Decrypt(ctx, selfDecryptArgs, "alice_decrypt_for_self")
	if err != nil {
		log.Fatalf("Alice failed to decrypt her own data: %v", err)
	}
	fmt.Printf("Alice decrypted own message: %s\n", string(selfDecryptedResult.Plaintext))

	fmt.Println("\nEncryption and decryption example complete.")
}

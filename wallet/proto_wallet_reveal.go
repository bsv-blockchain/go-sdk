package wallet

import (
	"context"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/primitives/schnorr"
)

// RevealCounterpartyKeyLinkage reveals the key linkage between the wallet's identity and a counterparty.
// This creates a cryptographic proof that can be verified by a third party.
func (p *ProtoWallet) RevealCounterpartyKeyLinkage(
	ctx context.Context,
	args RevealCounterpartyKeyLinkageArgs,
	originator string,
) (*RevealCounterpartyKeyLinkageResult, error) {
	// Validate inputs
	if args.Counterparty == nil {
		return nil, fmt.Errorf("counterparty public key is required")
	}
	if args.Verifier == nil {
		return nil, fmt.Errorf("verifier public key is required")
	}

	// Get the identity key (root key)
	identityKey := p.keyDeriver.rootKey
	proverPublicKey := identityKey.PubKey()

	// Get the shared secret (linkage) as a point
	linkagePoint, err := p.keyDeriver.RevealCounterpartySecret(Counterparty{
		Type:         CounterpartyTypeOther,
		Counterparty: args.Counterparty,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to reveal counterparty secret: %v", err)
	}

	// Generate Schnorr proof
	s := schnorr.New()
	proof, err := s.GenerateProof(identityKey, proverPublicKey, args.Counterparty, linkagePoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// Serialize the proof components
	// Format: R compressed (33 bytes) || S' compressed (33 bytes) || z (32 bytes) = 98 bytes total
	proofBytes := make([]byte, 0, 98)

	// R point compressed
	proofBytes = append(proofBytes, proof.R.Compressed()...)

	// S' point compressed
	proofBytes = append(proofBytes, proof.SPrime.Compressed()...)

	// z value (32 bytes)
	proofBytes = append(proofBytes, padTo32Bytes(proof.Z.Bytes())...)

	// Create revelation time
	revelationTime := time.Now().UTC().Format(time.RFC3339Nano)

	// Convert linkage point to compressed bytes for encryption
	linkageBytes := linkagePoint.Compressed()

	// Encrypt the linkage for the verifier
	encryptArgs := EncryptArgs{
		Plaintext: linkageBytes,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "counterparty linkage revelation"},
			KeyID:        revelationTime,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: args.Verifier},
		},
	}
	encryptResult, err := p.Encrypt(ctx, encryptArgs, originator)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt linkage: %v", err)
	}

	// Encrypt the proof for the verifier
	encryptProofArgs := EncryptArgs{
		Plaintext: proofBytes,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   Protocol{SecurityLevel: 2, Protocol: "counterparty linkage revelation"},
			KeyID:        revelationTime,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: args.Verifier},
		},
	}
	encryptProofResult, err := p.Encrypt(ctx, encryptProofArgs, originator)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt proof: %v", err)
	}

	return &RevealCounterpartyKeyLinkageResult{
		Prover:                proverPublicKey,
		Counterparty:          args.Counterparty,
		Verifier:              args.Verifier,
		RevelationTime:        revelationTime,
		EncryptedLinkage:      encryptResult.Ciphertext,
		EncryptedLinkageProof: encryptProofResult.Ciphertext,
	}, nil
}

// RevealSpecificKeyLinkage reveals the key linkage for a specific protocol and key ID.
func (p *ProtoWallet) RevealSpecificKeyLinkage(
	ctx context.Context,
	args RevealSpecificKeyLinkageArgs,
	originator string,
) (*RevealSpecificKeyLinkageResult, error) {
	// Validate inputs
	if args.Verifier == nil {
		return nil, fmt.Errorf("verifier public key is required")
	}

	// Get the identity key (root key)
	identityKey := p.keyDeriver.rootKey
	proverPublicKey := identityKey.PubKey()

	// Validate counterparty
	counterpartyPubKey, err := getCounterpartyPublicKey(args.Counterparty)
	if err != nil {
		return nil, err
	}

	// Get the specific secret (linkage)
	linkage, err := p.keyDeriver.RevealSpecificSecret(args.Counterparty, args.ProtocolID, args.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to reveal specific secret: %v", err)
	}

	// For specific key linkage, we use proof type 0 (no proof)
	// Just a single byte array [0]
	proofBytes := []byte{0}

	// Create the special protocol ID for specific linkage revelation
	encryptProtocolID := Protocol{
		SecurityLevel: 2,
		Protocol:      fmt.Sprintf("specific linkage revelation %d %s", args.ProtocolID.SecurityLevel, args.ProtocolID.Protocol),
	}

	// Encrypt the linkage for the verifier
	encryptArgs := EncryptArgs{
		Plaintext: linkage,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   encryptProtocolID,
			KeyID:        args.KeyID,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: args.Verifier},
		},
	}
	encryptResult, err := p.Encrypt(ctx, encryptArgs, originator)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt linkage: %v", err)
	}

	// Encrypt the proof for the verifier
	encryptProofArgs := EncryptArgs{
		Plaintext: proofBytes,
		EncryptionArgs: EncryptionArgs{
			ProtocolID:   encryptProtocolID,
			KeyID:        args.KeyID,
			Counterparty: Counterparty{Type: CounterpartyTypeOther, Counterparty: args.Verifier},
		},
	}
	encryptProofResult, err := p.Encrypt(ctx, encryptProofArgs, originator)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt proof: %v", err)
	}

	return &RevealSpecificKeyLinkageResult{
		EncryptedLinkage:      encryptResult.Ciphertext,
		EncryptedLinkageProof: encryptProofResult.Ciphertext,
		Prover:                proverPublicKey,
		Verifier:              args.Verifier,
		Counterparty:          counterpartyPubKey,
		ProtocolID:            args.ProtocolID,
		KeyID:                 args.KeyID,
		ProofType:             0, // No proof for specific linkage
	}, nil
}

// padTo32Bytes pads a byte slice to 32 bytes with leading zeros
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// getCounterpartyPublicKey converts a Counterparty to a PublicKey
func getCounterpartyPublicKey(counterparty Counterparty) (*ec.PublicKey, error) {
	switch counterparty.Type {
	case CounterpartyTypeSelf:
		return nil, fmt.Errorf("cannot reveal specific key linkage for 'self'")
	case CounterpartyTypeAnyone:
		return nil, fmt.Errorf("cannot reveal specific key linkage for 'anyone'")
	case CounterpartyTypeOther:
		if counterparty.Counterparty == nil {
			return nil, fmt.Errorf("counterparty public key is required")
		}
		return counterparty.Counterparty, nil
	default:
		return nil, fmt.Errorf("invalid counterparty type: %v", counterparty.Type)
	}
}

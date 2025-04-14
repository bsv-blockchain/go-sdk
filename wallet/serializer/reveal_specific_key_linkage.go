package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRevealSpecificKeyLinkageArgs(args *wallet.RevealSpecificKeyLinkageArgs) ([]byte, error) {
	w := newWriter()

	// Encode key-related parameters (protocol, keyID, counterparty, privileged)
	params := KeyRelatedParams{
		ProtocolID:       args.ProtocolID,
		KeyID:            args.KeyID,
		Counterparty:     args.Counterparty,
		Privileged:       args.Privileged,
		PrivilegedReason: args.PrivilegedReason,
	}
	keyParams, err := encodeKeyRelatedParams(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding key params: %w", err)
	}
	w.writeBytes(keyParams)

	// Write verifier public key
	verifierBytes, err := hex.DecodeString(args.Verifier)
	if err != nil {
		return nil, fmt.Errorf("invalid verifier hex: %w", err)
	}
	w.writeBytes(verifierBytes)

	return w.buf, nil
}

func DeserializeRevealSpecificKeyLinkageArgs(data []byte) (*wallet.RevealSpecificKeyLinkageArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.RevealSpecificKeyLinkageArgs{}

	// Decode key-related parameters
	params, err := decodeKeyRelatedParams(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding key params: %w", err)
	}
	args.ProtocolID = params.ProtocolID
	args.KeyID = params.KeyID
	args.Counterparty = params.Counterparty
	args.Privileged = params.Privileged
	args.PrivilegedReason = params.PrivilegedReason

	// Read verifier public key
	args.Verifier = hex.EncodeToString(r.readRemaining())

	if r.err != nil {
		return nil, fmt.Errorf("error decoding args: %w", r.err)
	}

	return args, nil
}

func SerializeRevealSpecificKeyLinkageResult(result *wallet.RevealSpecificKeyLinkageResult) ([]byte, error) {
	w := newWriter()

	// Write prover, verifier, counterparty public keys
	w.writeIntBytes(result.Prover)
	w.writeIntBytes(result.Verifier)
	if err := encodeCounterparty(w, result.Counterparty); err != nil {
		return nil, fmt.Errorf("error encoding counterparty: %w", err)
	}

	// Write protocol ID (security level + protocol string)
	w.writeBytes(encodeProtocol(result.ProtocolID))

	// Write key ID, encrypted linkage and proof
	w.writeIntBytes([]byte(result.KeyID))
	w.writeIntBytes(result.EncryptedLinkage)
	w.writeIntBytes(result.EncryptedLinkageProof)

	// Write proof type
	w.writeByte(result.ProofType)

	return w.buf, nil
}

func DeserializeRevealSpecificKeyLinkageResult(data []byte) (*wallet.RevealSpecificKeyLinkageResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.RevealSpecificKeyLinkageResult{}

	// Read prover, verifier, counterparty public keys
	result.Prover = r.readIntBytes()
	result.Verifier = r.readIntBytes()
	counterparty, err := decodeCounterparty(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding counterparty: %w", err)
	}
	result.Counterparty = counterparty

	// Read protocol ID
	protocol, err := decodeProtocol(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding protocol: %w", err)
	}
	result.ProtocolID = protocol

	// Read key ID, encrypted linkage, and proof
	result.KeyID = string(r.readIntBytes())
	result.EncryptedLinkage = r.readIntBytes()
	result.EncryptedLinkageProof = r.readIntBytes()

	// Read proof type
	result.ProofType = r.readByte()

	if r.err != nil {
		return nil, fmt.Errorf("error reading result: %w", r.err)
	}

	return result, nil
}

func writePubKeyHex(w *writer, pubKey string) {
	bytes, _ := hex.DecodeString(pubKey)
	w.writeBytes(bytes)
}

func readPubKeyHex(r *readerHoldError) string {
	bytes := r.readBytes(33)
	return hex.EncodeToString(bytes)
}

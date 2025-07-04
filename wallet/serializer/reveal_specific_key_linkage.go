package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRevealSpecificKeyLinkageArgs(args *wallet.RevealSpecificKeyLinkageArgs) ([]byte, error) {
	w := util.NewWriter()

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
	w.WriteBytes(keyParams)

	// Write verifier public key
	if args.Verifier == nil {
		return nil, fmt.Errorf("verifier public key is required")
	}
	w.WriteBytes(args.Verifier.Compressed())

	return w.Buf, nil
}

func DeserializeRevealSpecificKeyLinkageArgs(data []byte) (*wallet.RevealSpecificKeyLinkageArgs, error) {
	r := util.NewReaderHoldError(data)
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
	parsedVerifier, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing verifier public key: %w", err)
	}
	args.Verifier = parsedVerifier

	if r.Err != nil {
		return nil, fmt.Errorf("error decoding args: %w", r.Err)
	}

	return args, nil
}

func SerializeRevealSpecificKeyLinkageResult(result *wallet.RevealSpecificKeyLinkageResult) ([]byte, error) {
	w := util.NewWriter()

	// Write prover, verifier, counterparty public keys
	if result.Prover == nil {
		return nil, fmt.Errorf("prover public key is required")
	}
	w.WriteBytes(result.Prover.Compressed())
	if result.Verifier == nil {
		return nil, fmt.Errorf("verifier public key is required")
	}
	w.WriteBytes(result.Verifier.Compressed())
	if result.Counterparty == nil {
		return nil, fmt.Errorf("counterparty public key is required")
	}
	w.WriteBytes(result.Counterparty.Compressed())

	// Write protocol ID (security level + protocol string)
	w.WriteBytes(encodeProtocol(result.ProtocolID))

	// Write key ID, encrypted linkage and proof
	w.WriteIntBytes([]byte(result.KeyID))
	w.WriteIntBytes(result.EncryptedLinkage)
	w.WriteIntBytes(result.EncryptedLinkageProof)

	// Write proof type
	w.WriteByte(result.ProofType)

	return w.Buf, nil
}

func DeserializeRevealSpecificKeyLinkageResult(data []byte) (*wallet.RevealSpecificKeyLinkageResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.RevealSpecificKeyLinkageResult{}

	// Read prover, verifier, counterparty public keys
	prover, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing prover public key: %w", err)
	}
	result.Prover = prover

	verifier, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing verifier public key: %w", err)
	}
	result.Verifier = verifier

	counterparty, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing counterparty public key: %w", err)
	}
	result.Counterparty = counterparty

	// Read protocol ID
	protocol, err := decodeProtocol(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding protocol: %w", err)
	}
	result.ProtocolID = protocol

	// Read key ID, encrypted linkage, and proof
	result.KeyID = string(r.ReadIntBytes())
	result.EncryptedLinkage = r.ReadIntBytes()
	result.EncryptedLinkageProof = r.ReadIntBytes()

	// Read proof type
	result.ProofType = r.ReadByte()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading result: %w", r.Err)
	}

	return result, nil
}

package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRevealCounterpartyKeyLinkageArgs(args *wallet.RevealCounterpartyKeyLinkageArgs) ([]byte, error) {
	w := newWriter()

	// Write privileged params
	w.writeBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	// Write counterparty public key
	if err := w.writeOptionalFromHex(args.Counterparty); err != nil {
		return nil, fmt.Errorf("invalid counterparty hex: %w", err)
	}

	// Write verifier public key
	if err := w.writeOptionalFromHex(args.Verifier); err != nil {
		return nil, fmt.Errorf("invalid verifier hex: %w", err)
	}

	return w.buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageArgs(data []byte) (*wallet.RevealCounterpartyKeyLinkageArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.RevealCounterpartyKeyLinkageArgs{}

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	// Read counterparty public key
	args.Counterparty = r.readOptionalToHex()

	// Read verifier public key
	args.Verifier = r.readOptionalToHex()

	if r.err != nil {
		return nil, fmt.Errorf("error decoding args: %w", r.err)
	}

	return args, nil
}

func SerializeRevealCounterpartyKeyLinkageResult(result *wallet.RevealCounterpartyKeyLinkageResult) ([]byte, error) {
	w := newWriter()

	// Write prover public key
	w.writeString(result.Prover)

	// Write verifier public key
	w.writeString(result.Verifier)

	// Write counterparty public key
	w.writeString(result.Counterparty)

	// Write revelation time
	w.writeString(result.RevelationTime)

	// Write encrypted linkage
	w.writeVarInt(uint64(len(result.EncryptedLinkage)))
	w.writeBytes(result.EncryptedLinkage)

	// Write encrypted linkage proof
	w.writeVarInt(uint64(len(result.EncryptedLinkageProof)))
	w.writeBytes(result.EncryptedLinkageProof)

	return w.buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageResult(data []byte) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.RevealCounterpartyKeyLinkageResult{}

	// Read prover public key
	result.Prover = r.readString()

	// Read verifier public key
	result.Verifier = r.readString()

	// Read counterparty public key
	result.Counterparty = r.readString()

	// Read revelation time
	result.RevelationTime = r.readString()

	// Read encrypted linkage
	linkageLen := r.readVarInt()
	result.EncryptedLinkage = r.readBytes(int(linkageLen))

	// Read encrypted linkage proof
	proofLen := r.readVarInt()
	result.EncryptedLinkageProof = r.readBytes(int(proofLen))

	if r.err != nil {
		return nil, fmt.Errorf("error decoding result: %w", r.err)
	}

	return result, nil
}

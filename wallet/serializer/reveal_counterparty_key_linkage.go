package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRevealCounterpartyKeyLinkageArgs(args *wallet.RevealCounterpartyKeyLinkageArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	// Write counterparty public key
	if err := w.WriteOptionalFromHex(args.Counterparty); err != nil {
		return nil, fmt.Errorf("invalid counterparty hex: %w", err)
	}

	// Write verifier public key
	if err := w.WriteOptionalFromHex(args.Verifier); err != nil {
		return nil, fmt.Errorf("invalid verifier hex: %w", err)
	}

	return w.Buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageArgs(data []byte) (*wallet.RevealCounterpartyKeyLinkageArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RevealCounterpartyKeyLinkageArgs{}

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	// Read counterparty public key
	args.Counterparty = r.ReadOptionalToHex()

	// Read verifier public key
	args.Verifier = r.ReadOptionalToHex()

	if r.Err != nil {
		return nil, fmt.Errorf("error decoding args: %w", r.Err)
	}

	return args, nil
}

func SerializeRevealCounterpartyKeyLinkageResult(result *wallet.RevealCounterpartyKeyLinkageResult) ([]byte, error) {
	w := util.NewWriter()

	// Write prover public key
	w.WriteString(result.Prover)

	// Write verifier public key
	w.WriteString(result.Verifier)

	// Write counterparty public key
	w.WriteString(result.Counterparty)

	// Write revelation time
	w.WriteString(result.RevelationTime)

	// Write encrypted linkage
	w.WriteVarInt(uint64(len(result.EncryptedLinkage)))
	w.WriteBytes(result.EncryptedLinkage)

	// Write encrypted linkage proof
	w.WriteVarInt(uint64(len(result.EncryptedLinkageProof)))
	w.WriteBytes(result.EncryptedLinkageProof)

	return w.Buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageResult(data []byte) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.RevealCounterpartyKeyLinkageResult{}

	// Read prover public key
	result.Prover = r.ReadString()

	// Read verifier public key
	result.Verifier = r.ReadString()

	// Read counterparty public key
	result.Counterparty = r.ReadString()

	// Read revelation time
	result.RevelationTime = r.ReadString()

	// Read encrypted linkage
	linkageLen := r.ReadVarInt()
	result.EncryptedLinkage = r.ReadBytes(int(linkageLen))

	// Read encrypted linkage proof
	proofLen := r.ReadVarInt()
	result.EncryptedLinkageProof = r.ReadBytes(int(proofLen))

	if r.Err != nil {
		return nil, fmt.Errorf("error decoding result: %w", r.Err)
	}

	return result, nil
}

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
	w.WriteBytes(args.Counterparty[:])

	// Write verifier public key
	w.WriteBytes(args.Verifier[:])

	return w.Buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageArgs(data []byte) (*wallet.RevealCounterpartyKeyLinkageArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RevealCounterpartyKeyLinkageArgs{}

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	// Read counterparty public key
	copy(args.Counterparty[:], r.ReadBytes(sizePubKey))

	// Read verifier public key
	copy(args.Verifier[:], r.ReadBytes(sizePubKey))

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error decoding args: %w", r.Err)
	}

	return args, nil
}

func SerializeRevealCounterpartyKeyLinkageResult(result *wallet.RevealCounterpartyKeyLinkageResult) ([]byte, error) {
	w := util.NewWriter()

	// Write prover public key
	w.WriteBytes(result.Prover[:])

	// Write verifier public key
	w.WriteBytes(result.Verifier[:])

	// Write counterparty public key
	w.WriteBytes(result.Counterparty[:])

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
	copy(result.Prover[:], r.ReadBytes(sizePubKey))

	// Read verifier public key
	copy(result.Verifier[:], r.ReadBytes(sizePubKey))

	// Read counterparty public key
	copy(result.Counterparty[:], r.ReadBytes(sizePubKey))

	// Read revelation time
	result.RevelationTime = r.ReadString()

	// Read encrypted linkage
	linkageLen := r.ReadVarInt()
	result.EncryptedLinkage = r.ReadBytes(int(linkageLen))

	// Read encrypted linkage proof
	proofLen := r.ReadVarInt()
	result.EncryptedLinkageProof = r.ReadBytes(int(proofLen))

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error decoding result: %w", r.Err)
	}

	return result, nil
}

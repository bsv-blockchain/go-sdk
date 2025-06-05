package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRevealCounterpartyKeyLinkageArgs(args *wallet.RevealCounterpartyKeyLinkageArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	// Write counterparty public key
	if args.Counterparty == nil {
		return nil, fmt.Errorf("counterparty public key is required")
	}
	w.WriteBytes(args.Counterparty.Compressed())

	// Write verifier public key
	if args.Verifier == nil {
		return nil, fmt.Errorf("verifier public key is required")
	}
	w.WriteBytes(args.Verifier.Compressed())

	return w.Buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageArgs(data []byte) (*wallet.RevealCounterpartyKeyLinkageArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RevealCounterpartyKeyLinkageArgs{}

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	// Read counterparty public key
	parsedCounterparty, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing counterparty public key: %w", err)
	}
	args.Counterparty = parsedCounterparty

	// Read verifier public key
	parsedVerifier, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing verifier public key: %w", err)
	}
	args.Verifier = parsedVerifier

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error decoding args: %w", r.Err)
	}

	return args, nil
}

func SerializeRevealCounterpartyKeyLinkageResult(result *wallet.RevealCounterpartyKeyLinkageResult) ([]byte, error) {
	w := util.NewWriter()

	// Write prover public key
	if result.Prover == nil {
		return nil, fmt.Errorf("prover public key is required")
	}
	w.WriteBytes(result.Prover.Compressed())

	// Write verifier public key
	if result.Verifier == nil {
		return nil, fmt.Errorf("verifier public key is required")
	}
	w.WriteBytes(result.Verifier.Compressed())

	// Write counterparty public key
	if result.Counterparty == nil {
		return nil, fmt.Errorf("counterparty public key is required")
	}
	w.WriteBytes(result.Counterparty.Compressed())

	// Write revelation time
	w.WriteString(result.RevelationTime)

	// Write encrypted linkage
	w.WriteIntBytes(result.EncryptedLinkage)

	// Write encrypted linkage proof
	w.WriteIntBytes(result.EncryptedLinkageProof)

	return w.Buf, nil
}

func DeserializeRevealCounterpartyKeyLinkageResult(data []byte) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.RevealCounterpartyKeyLinkageResult{}

	// Read prover public key
	parsedProver, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing prover public key: %w", err)
	}
	result.Prover = parsedProver

	// Read verifier public key
	parsedVerifier, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing verifier public key: %w", err)
	}
	result.Verifier = parsedVerifier

	// Read counterparty public key
	parsedCounterparty, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing counterparty public key: %w", err)
	}
	result.Counterparty = parsedCounterparty

	// Read revelation time
	result.RevelationTime = r.ReadString()

	// Read encrypted linkage
	result.EncryptedLinkage = r.ReadIntBytes()

	// Read encrypted linkage proof
	result.EncryptedLinkageProof = r.ReadIntBytes()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error decoding result: %w", r.Err)
	}

	return result, nil
}

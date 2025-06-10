package transaction

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
)

// newOutputFromBytes returns a transaction Output from the bytes provided
func newOutputFromBytes(bytes []byte) (*TransactionOutput, int, error) {
	if len(bytes) < 8 {
		return nil, 0, fmt.Errorf("%w < 8", ErrOutputTooShort)
	}

	offset := 8
	l, size := util.NewVarIntFromBytes(bytes[offset:])
	offset += size

	totalLength := offset + int(l)

	if len(bytes) < totalLength {
		return nil, 0, fmt.Errorf("%w < 8 + script", ErrInputTooShort)
	}

	s := script.Script(bytes[offset:totalLength])

	return &TransactionOutput{
		Satoshis:      binary.LittleEndian.Uint64(bytes[0:8]),
		LockingScript: &s,
	}, totalLength, nil
}

// TotalOutputSatoshis returns the total Satoshis outputted from the transaction.
func (tx *Transaction) TotalOutputSatoshis() (total uint64) {
	for _, o := range tx.Outputs {
		total += o.Satoshis
	}
	return
}

// AddHashPuzzleOutput makes an output to a hash puzzle + PKH with a value.
func (tx *Transaction) AddHashPuzzleOutput(secret, publicKeyHash string, satoshis uint64) error {
	publicKeyHashBytes, err := hex.DecodeString(publicKeyHash)
	if err != nil {
		return err
	}

	s := &script.Script{}

	_ = s.AppendOpcodes(script.OpHASH160)
	secretBytesHash := crypto.Hash160([]byte(secret))

	if err = s.AppendPushData(secretBytesHash); err != nil {
		return err
	}
	_ = s.AppendOpcodes(script.OpEQUALVERIFY, script.OpDUP, script.OpHASH160)

	if err = s.AppendPushData(publicKeyHashBytes); err != nil {
		return err
	}
	_ = s.AppendOpcodes(script.OpEQUALVERIFY, script.OpCHECKSIG)

	tx.AddOutput(&TransactionOutput{
		Satoshis:      satoshis,
		LockingScript: s,
	})
	return nil
}

// AddOpReturnOutput creates a new Output with OP_FALSE OP_RETURN and then the data
// passed in encoded as hex.
func (tx *Transaction) AddOpReturnOutput(data []byte) error {
	o, err := CreateOpReturnOutput([][]byte{data})
	if err != nil {
		return err
	}

	tx.AddOutput(o)
	return nil
}

// AddOpReturnPartsOutput creates a new Output with OP_FALSE OP_RETURN and then
// uses OP_PUSHDATA format to encode the multiple byte arrays passed in.
func (tx *Transaction) AddOpReturnPartsOutput(data [][]byte) error {
	o, err := CreateOpReturnOutput(data)
	if err != nil {
		return err
	}
	tx.AddOutput(o)
	return nil
}

// CreateOpReturnOutput creates a new Output with OP_FALSE OP_RETURN and then
// uses OP_PUSHDATA format to encode the multiple byte arrays passed in.
func CreateOpReturnOutput(data [][]byte) (*TransactionOutput, error) {
	s := &script.Script{}

	_ = s.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	if err := s.AppendPushDataArray(data); err != nil {
		return nil, err
	}

	return &TransactionOutput{LockingScript: s}, nil
}

// OutputCount returns the number of transaction Inputs.
func (tx *Transaction) OutputCount() int {
	return len(tx.Outputs)
}

// AddOutput adds a new output to the transaction.
func (tx *Transaction) AddOutput(output *TransactionOutput) {
	tx.Outputs = append(tx.Outputs, output)
}

// // PayToAddress creates a new P2PKH output from a BitCoin address (base58)
// // and the satoshis amount and adds that to the transaction.
func (tx *Transaction) PayToAddress(addr string, satoshis uint64) error {
	add, err := script.NewAddressFromString(addr)
	if err != nil {
		return err
	}
	b := make([]byte, 0, 25)
	b = append(b, script.OpDUP, script.OpHASH160, script.OpDATA20)
	b = append(b, add.PublicKeyHash...)
	b = append(b, script.OpEQUALVERIFY, script.OpCHECKSIG)
	s := script.Script(b)
	tx.AddOutput(&TransactionOutput{
		Satoshis:      satoshis,
		LockingScript: &s,
	})
	return nil
}

package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeInternalizeActionArgs(args *wallet.InternalizeActionArgs) ([]byte, error) {
	w := util.NewWriter()

	// Transaction BEEF - write length first
	w.WriteVarInt(uint64(len(args.Tx)))
	w.WriteBytes(args.Tx)

	// Outputs
	w.WriteVarInt(uint64(len(args.Outputs)))
	for _, output := range args.Outputs {
		w.WriteVarInt(uint64(output.OutputIndex))
		w.WriteString(output.Protocol)

		// Payment remittance
		if output.PaymentRemittance != nil {
			w.WriteByte(1) // present
			w.WriteString(output.PaymentRemittance.DerivationPrefix)
			w.WriteString(output.PaymentRemittance.DerivationSuffix)
			w.WriteString(output.PaymentRemittance.SenderIdentityKey)
		} else {
			w.WriteByte(0) // not present
		}

		// Insertion remittance
		if output.InsertionRemittance != nil {
			w.WriteByte(1) // present
			w.WriteString(output.InsertionRemittance.Basket)
			w.WriteOptionalString(output.InsertionRemittance.CustomInstructions)
			w.WriteStringSlice(output.InsertionRemittance.Tags)
		} else {
			w.WriteByte(0) // not present
		}
	}

	// Description, labels, and seek permission
	w.WriteString(args.Description)
	w.WriteStringSlice(args.Labels)
	w.WriteOptionalBool(args.SeekPermission)

	return w.Buf, nil
}

func DeserializeInternalizeActionArgs(data []byte) (*wallet.InternalizeActionArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.InternalizeActionArgs{}

	// Transaction BEEF - read length first
	txLen := r.ReadVarInt()
	args.Tx = r.ReadBytes(int(txLen))
	if r.Err != nil {
		return nil, fmt.Errorf("error reading tx bytes: %w", r.Err)
	}

	// Outputs
	outputCount := r.ReadVarInt()
	args.Outputs = make([]wallet.InternalizeOutput, 0, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		output := wallet.InternalizeOutput{
			OutputIndex: r.ReadVarInt32(),
			Protocol:    r.ReadString(),
		}

		// Payment remittance
		if r.ReadByte() == 1 {
			output.PaymentRemittance = &wallet.Payment{
				DerivationPrefix:  r.ReadString(),
				DerivationSuffix:  r.ReadString(),
				SenderIdentityKey: r.ReadString(),
			}
		}

		// Insertion remittance
		if r.ReadByte() == 1 {
			output.InsertionRemittance = &wallet.BasketInsertion{
				Basket:             r.ReadString(),
				CustomInstructions: r.ReadString(),
				Tags:               r.ReadStringSlice(),
			}
		}

		// Check error each loop
		if r.Err != nil {
			return nil, fmt.Errorf("error reading internalize output: %w", r.Err)
		}

		args.Outputs = append(args.Outputs, output)
	}

	// Description, labels, and seek permission
	args.Description = r.ReadString()
	args.Labels = r.ReadStringSlice()
	args.SeekPermission = r.ReadOptionalBool()

	if r.Err != nil {
		return nil, fmt.Errorf("error reading internalize action args: %w", r.Err)
	}

	return args, nil
}

func SerializeInternalizeActionResult(result *wallet.InternalizeActionResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(1) // accepted = true
	return w.Buf, nil
}

func DeserializeInternalizeActionResult(data []byte) (*wallet.InternalizeActionResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.InternalizeActionResult{}
	accepted := r.ReadByte()
	result.Accepted = accepted == 1
	if r.Err != nil {
		return nil, fmt.Errorf("error reading internalize action result: %w", r.Err)
	}
	return result, nil
}

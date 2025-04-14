package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeInternalizeActionArgs(args *wallet.InternalizeActionArgs) ([]byte, error) {
	w := newWriter()

	// Transaction BEEF - write length first
	w.writeVarInt(uint64(len(args.Tx)))
	w.writeBytes(args.Tx)

	// Outputs
	w.writeVarInt(uint64(len(args.Outputs)))
	for _, output := range args.Outputs {
		w.writeVarInt(uint64(output.OutputIndex))
		w.writeString(output.Protocol)

		// Payment remittance
		if output.PaymentRemittance != nil {
			w.writeByte(1) // present
			w.writeString(output.PaymentRemittance.DerivationPrefix)
			w.writeString(output.PaymentRemittance.DerivationSuffix)
			w.writeString(output.PaymentRemittance.SenderIdentityKey)
		} else {
			w.writeByte(0) // not present
		}

		// Insertion remittance
		if output.InsertionRemittance != nil {
			w.writeByte(1) // present
			w.writeString(output.InsertionRemittance.Basket)
			w.writeOptionalString(output.InsertionRemittance.CustomInstructions)
			w.writeStringSlice(output.InsertionRemittance.Tags)
		} else {
			w.writeByte(0) // not present
		}
	}

	// Description, labels, and seek permission
	w.writeString(args.Description)
	w.writeStringSlice(args.Labels)
	w.writeOptionalBool(args.SeekPermission)

	return w.buf, nil
}

func DeserializeInternalizeActionArgs(data []byte) (*wallet.InternalizeActionArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.InternalizeActionArgs{}

	// Transaction BEEF - read length first
	txLen := r.readVarInt()
	args.Tx = r.readBytes(int(txLen))
	if r.err != nil {
		return nil, fmt.Errorf("error reading tx bytes: %w", r.err)
	}

	// Outputs
	outputCount := r.readVarInt()
	args.Outputs = make([]wallet.InternalizeOutput, 0, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		output := wallet.InternalizeOutput{
			OutputIndex: r.readVarInt32(),
			Protocol:    r.readString(),
		}

		// Payment remittance
		if r.readByte() == 1 {
			output.PaymentRemittance = &wallet.Payment{
				DerivationPrefix:  r.readString(),
				DerivationSuffix:  r.readString(),
				SenderIdentityKey: r.readString(),
			}
		}

		// Insertion remittance
		if r.readByte() == 1 {
			output.InsertionRemittance = &wallet.BasketInsertion{
				Basket:             r.readString(),
				CustomInstructions: r.readString(),
				Tags:               r.readStringSlice(),
			}
		}

		// Check error each loop
		if r.err != nil {
			return nil, fmt.Errorf("error reading internalize output: %w", r.err)
		}

		args.Outputs = append(args.Outputs, output)
	}

	// Description, labels, and seek permission
	args.Description = r.readString()
	args.Labels = r.readStringSlice()
	args.SeekPermission = r.readOptionalBool()

	if r.err != nil {
		return nil, fmt.Errorf("error reading internalize action args: %w", r.err)
	}

	return args, nil
}

func SerializeInternalizeActionResult(result *wallet.InternalizeActionResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(1) // accepted = true
	return w.buf, nil
}

func DeserializeInternalizeActionResult(data []byte) (*wallet.InternalizeActionResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.InternalizeActionResult{}
	accepted := r.readByte()
	result.Accepted = accepted == 1
	if r.err != nil {
		return nil, fmt.Errorf("error reading internalize action result: %w", r.err)
	}
	return result, nil
}

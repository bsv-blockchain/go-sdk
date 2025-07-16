package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	internalizeActionProtocolWalletPayment   = 1
	internalizeActionProtocolBasketInsertion = 2
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
		if output.Protocol == wallet.InternalizeProtocolWalletPayment {
			// Payment remittance
			if output.PaymentRemittance == nil {
				return nil, fmt.Errorf("payment remittance is required for wallet payment protocol")
			}
			w.WriteByte(internalizeActionProtocolWalletPayment)
			w.WriteBytes(output.PaymentRemittance.SenderIdentityKey.Compressed())
			w.WriteIntBytes(output.PaymentRemittance.DerivationPrefix)
			w.WriteIntBytes(output.PaymentRemittance.DerivationSuffix)
		} else {
			// Basket insertion remittance
			if output.InsertionRemittance == nil {
				return nil, fmt.Errorf("insertion remittance is required for basket insertion protocol")
			}
			w.WriteByte(internalizeActionProtocolBasketInsertion)
			w.WriteString(output.InsertionRemittance.Basket)
			w.WriteOptionalString(output.InsertionRemittance.CustomInstructions)
			w.WriteStringSlice(output.InsertionRemittance.Tags)
		}
	}

	// Description, labels, and seek permission
	w.WriteStringSlice(args.Labels)
	w.WriteString(args.Description)
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
		}

		// Payment remittance
		switch r.ReadByte() {
		case internalizeActionProtocolWalletPayment:
			output.Protocol = wallet.InternalizeProtocolWalletPayment
			senderIdentityKey, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
			if err != nil {
				return nil, fmt.Errorf("error parsing sender identity key: %w", err)
			}
			output.PaymentRemittance = &wallet.Payment{
				SenderIdentityKey: senderIdentityKey,
				DerivationPrefix:  r.ReadIntBytes(),
				DerivationSuffix:  r.ReadIntBytes(),
			}
		case internalizeActionProtocolBasketInsertion:
			output.Protocol = wallet.InternalizeProtocolBasketInsertion
			output.InsertionRemittance = &wallet.BasketInsertion{
				Basket:             r.ReadString(),
				CustomInstructions: r.ReadString(),
				Tags:               r.ReadStringSlice(),
			}
		default:
			return nil, fmt.Errorf("invalid internalize action protocol: %d", r.Err)
		}

		// Check error each loop
		if r.Err != nil {
			return nil, fmt.Errorf("error reading internalize output: %w", r.Err)
		}

		args.Outputs = append(args.Outputs, output)
	}

	// Description, labels, and seek permission
	args.Labels = r.ReadStringSlice()
	args.Description = r.ReadString()
	args.SeekPermission = r.ReadOptionalBool()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading internalize action args: %w", r.Err)
	}

	return args, nil
}

func SerializeInternalizeActionResult(*wallet.InternalizeActionResult) ([]byte, error) {
	// Frame indicates error or not, no additional data
	return nil, nil
}

func DeserializeInternalizeActionResult([]byte) (*wallet.InternalizeActionResult, error) {
	// Accepted is implicit
	return &wallet.InternalizeActionResult{
		Accepted: true,
	}, nil
}

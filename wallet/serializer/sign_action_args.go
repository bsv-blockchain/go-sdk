package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

func SerializeSignActionArgs(args *wallet.SignActionArgs) ([]byte, error) {
	w := util.NewWriter()

	// Serialize spends map
	w.WriteVarInt(uint64(len(args.Spends)))
	for index, spend := range args.Spends {
		w.WriteVarInt(uint64(index))

		// Unlocking script
		w.WriteIntBytes(spend.UnlockingScript)

		// Sequence number
		w.WriteOptionalUint32(spend.SequenceNumber)
	}

	// Reference
	w.WriteIntBytes(args.Reference)

	// Options
	if args.Options != nil {
		w.WriteByte(1) // options present

		// AcceptDelayedBroadcast, ReturnTXIDOnly, NoSend
		w.WriteOptionalBool(args.Options.AcceptDelayedBroadcast)
		w.WriteOptionalBool(args.Options.ReturnTXIDOnly)
		w.WriteOptionalBool(args.Options.NoSend)

		// SendWith
		if err := w.WriteTxidSlice(args.Options.SendWith); err != nil {
			return nil, fmt.Errorf("error writing sendWith txids: %w", err)
		}
	} else {
		w.WriteByte(0) // options not present
	}

	return w.Buf, nil
}

func DeserializeSignActionArgs(data []byte) (*wallet.SignActionArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.SignActionArgs{}

	// Deserialize spends
	spendCount := r.ReadVarInt()
	args.Spends = make(map[uint32]wallet.SignActionSpend)
	for i := 0; i < int(spendCount); i++ {
		inputIndex := r.ReadVarInt32()
		spend := wallet.SignActionSpend{}

		// Unlocking script, sequence number
		spend.UnlockingScript = r.ReadIntBytes()
		spend.SequenceNumber = r.ReadOptionalUint32()

		args.Spends[inputIndex] = spend
		if r.Err != nil {
			return nil, fmt.Errorf("error reading spend %d: %w", inputIndex, r.Err)
		}
	}

	// Reference
	args.Reference = r.ReadIntBytes()

	// Options
	optionsPresent := r.ReadByte()
	if optionsPresent == 1 {
		args.Options = &wallet.SignActionOptions{}

		// AcceptDelayedBroadcast, ReturnTXIDOnly, NoSend
		args.Options.AcceptDelayedBroadcast = r.ReadOptionalBool()
		args.Options.ReturnTXIDOnly = r.ReadOptionalBool()
		args.Options.NoSend = r.ReadOptionalBool()

		// SendWith
		args.Options.SendWith = r.ReadTxidSlice()
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading sign action args: %w", r.Err)
	}

	return args, nil
}

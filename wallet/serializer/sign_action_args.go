package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionArgs(args *wallet.SignActionArgs) ([]byte, error) {
	w := util.NewWriter()

	// Serialize spends map
	w.WriteVarInt(uint64(len(args.Spends)))
	for index, spend := range args.Spends {
		w.WriteVarInt(uint64(index))

		// Unlocking script
		script, err := hex.DecodeString(spend.UnlockingScript)
		if err != nil {
			return nil, fmt.Errorf("invalid unlocking script hex: %w", err)
		}
		w.WriteVarInt(uint64(len(script)))
		w.WriteBytes(script)

		// Sequence number
		w.WriteVarInt(uint64(spend.SequenceNumber))
	}

	// Reference
	ref, err := base64.StdEncoding.DecodeString(args.Reference)
	if err != nil {
		return nil, fmt.Errorf("invalid reference base64: %w", err)
	}
	w.WriteVarInt(uint64(len(ref)))
	w.WriteBytes(ref)

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

		// Unlocking script
		scriptLen := r.ReadVarInt()
		unlockingScript := r.ReadBytes(int(scriptLen))
		spend.UnlockingScript = hex.EncodeToString(unlockingScript)

		// Sequence number
		spend.SequenceNumber = r.ReadVarInt32()

		args.Spends[inputIndex] = spend
		if r.Err != nil {
			return nil, fmt.Errorf("error reading spend %d: %w", inputIndex, r.Err)
		}
	}

	// Reference
	refLen := r.ReadVarInt()
	reference := r.ReadBytes(int(refLen))
	args.Reference = base64.StdEncoding.EncodeToString(reference)

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

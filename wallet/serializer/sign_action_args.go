package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeSignActionArgs(args *wallet.SignActionArgs) ([]byte, error) {
	w := newWriter()

	// Serialize spends map
	w.writeVarInt(uint64(len(args.Spends)))
	for index, spend := range args.Spends {
		w.writeVarInt(uint64(index))

		// Unlocking script
		script, err := hex.DecodeString(spend.UnlockingScript)
		if err != nil {
			return nil, fmt.Errorf("invalid unlocking script hex: %w", err)
		}
		w.writeVarInt(uint64(len(script)))
		w.writeBytes(script)

		// Sequence number
		w.writeVarInt(uint64(spend.SequenceNumber))
	}

	// Reference
	ref, err := base64.StdEncoding.DecodeString(args.Reference)
	if err != nil {
		return nil, fmt.Errorf("invalid reference base64: %w", err)
	}
	w.writeVarInt(uint64(len(ref)))
	w.writeBytes(ref)

	// Options
	if args.Options != nil {
		w.writeByte(1) // options present

		// AcceptDelayedBroadcast, ReturnTXIDOnly, NoSend
		w.writeOptionalBool(args.Options.AcceptDelayedBroadcast)
		w.writeOptionalBool(args.Options.ReturnTXIDOnly)
		w.writeOptionalBool(args.Options.NoSend)

		// SendWith
		if err := w.writeTxidSlice(args.Options.SendWith); err != nil {
			return nil, fmt.Errorf("error writing sendWith txids: %w", err)
		}
	} else {
		w.writeByte(0) // options not present
	}

	return w.buf, nil
}

func DeserializeSignActionArgs(data []byte) (*wallet.SignActionArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.SignActionArgs{}

	// Deserialize spends
	spendCount := r.readVarInt()
	args.Spends = make(map[uint32]wallet.SignActionSpend)
	for i := 0; i < int(spendCount); i++ {
		inputIndex := r.readVarInt32()
		spend := wallet.SignActionSpend{}

		// Unlocking script
		scriptLen := r.readVarInt()
		unlockingScript := r.readBytes(int(scriptLen))
		spend.UnlockingScript = hex.EncodeToString(unlockingScript)

		// Sequence number
		spend.SequenceNumber = r.readVarInt32()

		args.Spends[inputIndex] = spend
		if r.err != nil {
			return nil, fmt.Errorf("error reading spend %d: %w", inputIndex, r.err)
		}
	}

	// Reference
	refLen := r.readVarInt()
	reference := r.readBytes(int(refLen))
	args.Reference = base64.StdEncoding.EncodeToString(reference)

	// Options
	optionsPresent := r.readByte()
	if optionsPresent == 1 {
		args.Options = &wallet.SignActionOptions{}

		// AcceptDelayedBroadcast, ReturnTXIDOnly, NoSend
		args.Options.AcceptDelayedBroadcast = r.readOptionalBool()
		args.Options.ReturnTXIDOnly = r.readOptionalBool()
		args.Options.NoSend = r.readOptionalBool()

		// SendWith
		args.Options.SendWith = r.readTxidSlice()
	}

	if r.err != nil {
		return nil, fmt.Errorf("error reading sign action args: %w", r.err)
	}

	return args, nil
}

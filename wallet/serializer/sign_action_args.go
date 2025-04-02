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
	r := newReader(data)
	args := &wallet.SignActionArgs{}

	// Deserialize spends
	spendCount, err := r.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read spend count: %w", err)
	}
	args.Spends = make(map[uint32]wallet.SignActionSpend)
	for i := 0; i < int(spendCount); i++ {
		inputIndex, err := r.readVarInt32()
		if err != nil {
			return nil, fmt.Errorf("failed to read input index: %w", err)
		}
		spend := wallet.SignActionSpend{}

		// Unlocking script
		scriptLen, err := r.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("failed to read unlocking script length: %w", err)
		}
		unlockingScript, err := r.readBytes(int(scriptLen))
		if err != nil {
			return nil, fmt.Errorf("failed to read unlocking script: %w", err)
		}
		spend.UnlockingScript = hex.EncodeToString(unlockingScript)

		// Sequence number
		spend.SequenceNumber, err = r.readVarInt32()
		if err != nil {
			return nil, fmt.Errorf("failed to read sequence number: %w", err)
		}

		args.Spends[inputIndex] = spend
	}

	// Reference
	refLen, err := r.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read reference length: %w", err)
	}
	reference, err := r.readBytes(int(refLen))
	if err != nil {
		return nil, fmt.Errorf("failed to read reference: %w", err)
	}
	args.Reference = base64.StdEncoding.EncodeToString(reference)

	// Options
	optionsPresent, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read options presence: %w", err)
	}
	if optionsPresent == 1 {
		args.Options = &wallet.SignActionOptions{}

		// AcceptDelayedBroadcast, ReturnTXIDOnly, NoSend
		args.Options.AcceptDelayedBroadcast, err = r.readOptionalBool()
		if err != nil {
			return nil, fmt.Errorf("failed to read accept delayed broadcast flag: %w", err)
		}
		args.Options.ReturnTXIDOnly, err = r.readOptionalBool()
		if err != nil {
			return nil, fmt.Errorf("failed to read return txid only flag: %w", err)
		}
		args.Options.NoSend, err = r.readOptionalBool()
		if err != nil {
			return nil, fmt.Errorf("failed to read no send flag: %w", err)
		}

		// SendWith
		args.Options.SendWith, err = r.readTxidSlice()
		if err != nil {
			return nil, fmt.Errorf("failed to read sendWith txids: %w", err)
		}
	}

	return args, nil
}

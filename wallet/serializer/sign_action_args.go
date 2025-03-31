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

		// AcceptDelayedBroadcast
		if args.Options.AcceptDelayedBroadcast != nil {
			if *args.Options.AcceptDelayedBroadcast {
				w.writeByte(1)
			} else {
				w.writeByte(0)
			}
		} else {
			w.writeByte(0xFF) // nil
		}

		// ReturnTXIDOnly
		if args.Options.ReturnTXIDOnly != nil {
			if *args.Options.ReturnTXIDOnly {
				w.writeByte(1)
			} else {
				w.writeByte(0)
			}
		} else {
			w.writeByte(0xFF) // nil
		}

		// NoSend
		if args.Options.NoSend != nil {
			if *args.Options.NoSend {
				w.writeByte(1)
			} else {
				w.writeByte(0)
			}
		} else {
			w.writeByte(0xFF) // nil
		}

		// SendWith
		w.writeVarInt(uint64(len(args.Options.SendWith)))
		for _, txid := range args.Options.SendWith {
			txidBytes, err := hex.DecodeString(txid)
			if err != nil {
				return nil, fmt.Errorf("invalid txid hex: %w", err)
			}
			w.writeBytes(txidBytes)
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

		// AcceptDelayedBroadcast
		acceptFlag, err := r.readByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read accept delayed broadcast flag: %w", err)
		}
		if acceptFlag != 0xFF {
			val := acceptFlag == 1
			args.Options.AcceptDelayedBroadcast = &val
		}

		// ReturnTXIDOnly
		returnFlag, err := r.readByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read return txid only flag: %w", err)
		}
		if returnFlag != 0xFF {
			val := returnFlag == 1
			args.Options.ReturnTXIDOnly = &val
		}

		// NoSend
		noSendFlag, err := r.readByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read no send flag: %w", err)
		}
		if noSendFlag != 0xFF {
			val := noSendFlag == 1
			args.Options.NoSend = &val
		}

		// SendWith
		sendWithLen, err := r.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("failed to read sendWith length: %w", err)
		}
		args.Options.SendWith = make([]string, sendWithLen)
		for i := 0; i < int(sendWithLen); i++ {
			sendWith, err := r.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("failed to read sendWith bytes: %w", err)
			}
			args.Options.SendWith[i] = hex.EncodeToString(sendWith)
		}
	}

	return args, nil
}

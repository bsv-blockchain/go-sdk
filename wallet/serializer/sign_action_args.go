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

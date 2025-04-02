package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"math"
)

// SerializeCreateActionArgs serializes a wallet.CreateActionArgs object into a byte slice
func SerializeCreateActionArgs(args *wallet.CreateActionArgs) ([]byte, error) {
	paramWriter := newWriter()

	// Serialize description & input BEEF
	paramWriter.writeString(args.Description)
	paramWriter.writeOptionalBytes(args.InputBEEF)

	// Serialize inputs
	if err := serializeCreateActionInputs(paramWriter, args.Inputs); err != nil {
		return nil, fmt.Errorf("failed to serialize create action inputs: %w", err)
	}

	// Serialize outputs
	if err := serializeCreateActionOutputs(paramWriter, args.Outputs); err != nil {
		return nil, fmt.Errorf("failed to serialize create action outputs: %w", err)
	}

	// Serialize lockTime, version, and labels
	paramWriter.writeOptionalUint32(args.LockTime)
	paramWriter.writeOptionalUint32(args.Version)
	paramWriter.writeStringSlice(args.Labels)

	// Serialize options
	if err := serializeCreateActionOptions(paramWriter, args.Options); err != nil {
		return nil, fmt.Errorf("failed to serialize create action options: %w", err)
	}

	return paramWriter.buf, nil
}

func serializeCreateActionInputs(paramWriter *writer, inputs []wallet.CreateActionInput) error {
	if inputs == nil {
		paramWriter.writeVarInt(math.MaxUint64) // -1
		return nil
	}
	paramWriter.writeVarInt(uint64(len(inputs)))
	for _, input := range inputs {
		// Serialize outpoint
		outpoint, err := encodeOutpoint(input.Outpoint)
		if err != nil {
			return fmt.Errorf("error encode outpoint for input: %w", err)
		}
		paramWriter.writeBytes(outpoint)

		// Serialize unlocking script
		if input.UnlockingScript != "" {
			script, err := hex.DecodeString(input.UnlockingScript)
			if err != nil {
				return fmt.Errorf("error decoding unlocking script: %w", err)
			}
			paramWriter.writeVarInt(uint64(len(script)))
			paramWriter.writeBytes(script)
		} else {
			paramWriter.writeVarInt(math.MaxUint64) // -1
			paramWriter.writeVarInt(uint64(input.UnlockingScriptLength))
		}

		// Serialize input description and sequence number
		paramWriter.writeString(input.InputDescription)
		paramWriter.writeOptionalUint32(input.SequenceNumber)
	}
	return nil
}

func serializeCreateActionOutputs(paramWriter *writer, outputs []wallet.CreateActionOutput) error {
	if outputs == nil {
		paramWriter.writeVarInt(math.MaxUint64) // -1
		return nil
	}
	paramWriter.writeVarInt(uint64(len(outputs)))
	for _, output := range outputs {
		// Serialize locking script
		script, err := hex.DecodeString(output.LockingScript)
		if err != nil {
			return fmt.Errorf("error decoding locking script: %w", err)
		}
		paramWriter.writeVarInt(uint64(len(script)))
		paramWriter.writeBytes(script)

		// Serialize satoshis, output description, basket, custom instructions, and tags
		paramWriter.writeVarInt(output.Satoshis)
		paramWriter.writeString(output.OutputDescription)
		paramWriter.writeOptionalString(output.Basket)
		paramWriter.writeOptionalString(output.CustomInstructions)
		paramWriter.writeStringSlice(output.Tags)
	}
	return nil
}

func serializeCreateActionOptions(paramWriter *writer, options *wallet.CreateActionOptions) error {
	if options == nil {
		paramWriter.writeByte(0) // options not present
		return nil
	}
	paramWriter.writeByte(1) // options present

	// signAndProcess
	if options.SignAndProcess != nil {
		if *options.SignAndProcess {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0)
		}
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	// acceptDelayedBroadcast
	if options.AcceptDelayedBroadcast != nil {
		if *options.AcceptDelayedBroadcast {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0)
		}
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	// trustSelf
	if options.TrustSelf == "known" {
		paramWriter.writeByte(1)
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	// knownTxids
	if options.KnownTxids != nil {
		paramWriter.writeVarInt(uint64(len(options.KnownTxids)))
		for _, txid := range options.KnownTxids {
			txidBytes, err := hex.DecodeString(txid)
			if err != nil {
				return fmt.Errorf("error decoding known txid: %w", err)
			}
			paramWriter.writeBytes(txidBytes)
		}
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// returnTXIDOnly
	if options.ReturnTXIDOnly != nil {
		if *options.ReturnTXIDOnly {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0)
		}
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	// noSend
	if options.NoSend != nil {
		if *options.NoSend {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0)
		}
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	// noSendChange
	if options.NoSendChange != nil {
		paramWriter.writeVarInt(uint64(len(options.NoSendChange)))
		for _, outpoint := range options.NoSendChange {
			op, err := encodeOutpoint(outpoint)
			if err != nil {
				return fmt.Errorf("error encode outpoint for options no send change: %w", err)
			}
			paramWriter.writeBytes(op)
		}
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// sendWith
	if options.SendWith != nil {
		paramWriter.writeVarInt(uint64(len(options.SendWith)))
		for _, txid := range options.SendWith {
			txidBytes, err := hex.DecodeString(txid)
			if err != nil {
				return fmt.Errorf("error decoding send with txid: %w", err)
			}
			paramWriter.writeBytes(txidBytes)
		}
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// randomizeOutputs
	if options.RandomizeOutputs != nil {
		if *options.RandomizeOutputs {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0)
		}
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	return nil
}

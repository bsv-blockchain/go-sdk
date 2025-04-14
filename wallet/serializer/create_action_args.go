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
		if err = paramWriter.writeOptionalFromHex(input.UnlockingScript); err != nil {
			return fmt.Errorf("invalid unlocking script: %w", err)
		}
		if input.UnlockingScript == "" {
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

	// signAndProcess and acceptDelayedBroadcast
	paramWriter.writeOptionalBool(options.SignAndProcess)
	paramWriter.writeOptionalBool(options.AcceptDelayedBroadcast)

	// trustSelf
	if options.TrustSelf == "known" {
		paramWriter.writeByte(1)
	} else {
		paramWriter.writeByte(0xFF) // -1
	}

	// knownTxids
	if err := paramWriter.writeTxidSlice(options.KnownTxids); err != nil {
		return fmt.Errorf("error writing known txids: %w", err)
	}

	// returnTXIDOnly and noSend
	paramWriter.writeOptionalBool(options.ReturnTXIDOnly)
	paramWriter.writeOptionalBool(options.NoSend)

	// noSendChange
	noSendChangeData, err := encodeOutpoints(options.NoSendChange)
	if err != nil {
		return fmt.Errorf("error encoding noSendChange: %w", err)
	}
	paramWriter.writeOptionalBytes(noSendChangeData)

	// sendWith
	if err := paramWriter.writeTxidSlice(options.SendWith); err != nil {
		return fmt.Errorf("error writing send with txids: %w", err)
	}

	// randomizeOutputs
	paramWriter.writeOptionalBool(options.RandomizeOutputs)

	return nil
}

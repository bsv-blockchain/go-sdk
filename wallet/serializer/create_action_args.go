package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	trustSelfKnown = 1
)

// SerializeCreateActionArgs serializes a wallet.CreateActionArgs object into a byte slice
func SerializeCreateActionArgs(args *wallet.CreateActionArgs) ([]byte, error) {
	paramWriter := util.NewWriter()

	// Serialize description & input BEEF
	paramWriter.WriteString(args.Description)
	paramWriter.WriteOptionalBytes(args.InputBEEF)

	// Serialize inputs
	if err := serializeCreateActionInputs(paramWriter, args.Inputs); err != nil {
		return nil, fmt.Errorf("failed to serialize create action inputs: %w", err)
	}

	// Serialize outputs
	if err := serializeCreateActionOutputs(paramWriter, args.Outputs); err != nil {
		return nil, fmt.Errorf("failed to serialize create action outputs: %w", err)
	}

	// Serialize lockTime, version, and labels
	paramWriter.WriteOptionalUint32(args.LockTime)
	paramWriter.WriteOptionalUint32(args.Version)
	paramWriter.WriteStringSlice(args.Labels)

	// Serialize options
	if err := serializeCreateActionOptions(paramWriter, args.Options); err != nil {
		return nil, fmt.Errorf("failed to serialize create action options: %w", err)
	}

	return paramWriter.Buf, nil
}

func serializeCreateActionInputs(paramWriter *util.Writer, inputs []wallet.CreateActionInput) error {
	if inputs == nil {
		paramWriter.WriteNegativeOne()
		return nil
	}
	paramWriter.WriteVarInt(uint64(len(inputs)))
	for _, input := range inputs {
		// Serialize outpoint
		outpoint, err := encodeOutpoint(input.Outpoint)
		if err != nil {
			return fmt.Errorf("error encode outpoint for input: %w", err)
		}
		paramWriter.WriteBytes(outpoint)

		// Serialize unlocking script
		if len(input.UnlockingScript) > 0 {
			paramWriter.WriteIntBytes(input.UnlockingScript)
		} else {
			paramWriter.WriteNegativeOne()
			paramWriter.WriteVarInt(uint64(input.UnlockingScriptLength))
		}

		// Serialize input description and sequence number
		paramWriter.WriteString(input.InputDescription)
		paramWriter.WriteOptionalUint32(input.SequenceNumber)
	}
	return nil
}

func serializeCreateActionOutputs(paramWriter *util.Writer, outputs []wallet.CreateActionOutput) error {
	if outputs == nil {
		paramWriter.WriteNegativeOne()
		return nil
	}
	paramWriter.WriteVarInt(uint64(len(outputs)))
	for _, output := range outputs {
		// Serialize locking script, satoshis, output description, basket, custom instructions, and tags
		paramWriter.WriteIntBytes(output.LockingScript)
		paramWriter.WriteVarInt(output.Satoshis)
		paramWriter.WriteString(output.OutputDescription)
		paramWriter.WriteOptionalString(output.Basket)
		paramWriter.WriteOptionalString(output.CustomInstructions)
		paramWriter.WriteStringSlice(output.Tags)
	}
	return nil
}

func serializeCreateActionOptions(paramWriter *util.Writer, options *wallet.CreateActionOptions) error {
	if options == nil {
		paramWriter.WriteByte(0) // options not present
		return nil
	}
	paramWriter.WriteByte(1) // options present

	// signAndProcess and acceptDelayedBroadcast
	paramWriter.WriteOptionalBool(options.SignAndProcess)
	paramWriter.WriteOptionalBool(options.AcceptDelayedBroadcast)

	// trustSelf
	if options.TrustSelf == wallet.TrustSelfKnown {
		paramWriter.WriteByte(trustSelfKnown)
	} else {
		paramWriter.WriteNegativeOneByte()
	}

	// knownTxids
	if err := paramWriter.WriteTxidSlice(options.KnownTxids); err != nil {
		return fmt.Errorf("error writing known txids: %w", err)
	}

	// returnTXIDOnly and noSend
	paramWriter.WriteOptionalBool(options.ReturnTXIDOnly)
	paramWriter.WriteOptionalBool(options.NoSend)

	// noSendChange
	noSendChangeData, err := encodeOutpoints(options.NoSendChange)
	if err != nil {
		return fmt.Errorf("error encoding noSendChange: %w", err)
	}
	paramWriter.WriteOptionalBytes(noSendChangeData)

	// sendWith
	if err := paramWriter.WriteTxidSlice(options.SendWith); err != nil {
		return fmt.Errorf("error writing send with txids: %w", err)
	}

	// randomizeOutputs
	paramWriter.WriteOptionalBool(options.RandomizeOutputs)

	return nil
}

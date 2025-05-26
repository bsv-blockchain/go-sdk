package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// DeserializeCreateActionArgs deserializes a byte slice into a wallet.CreateActionArgs object
func DeserializeCreateActionArgs(data []byte) (*wallet.CreateActionArgs, error) {
	if len(data) == 0 {
		return nil, errors.New("empty message")
	}

	messageReader := util.NewReaderHoldError(data)
	args := &wallet.CreateActionArgs{}
	var err error

	// Read description and input BEEF
	args.Description = messageReader.ReadString()
	args.InputBEEF = messageReader.ReadOptionalBytes()

	// Read inputs
	inputs, err := deserializeCreateActionInputs(messageReader)
	if err != nil {
		return nil, fmt.Errorf("error deserializing inputs: %w", err)
	}
	args.Inputs = inputs

	// Read outputs
	outputs, err := deserializeCreateActionOutputs(messageReader)
	if err != nil {
		return nil, fmt.Errorf("error deserializing outputs: %w", err)
	}
	args.Outputs = outputs

	// Read lockTime, version, and labels
	args.LockTime = messageReader.ReadOptionalUint32()
	args.Version = messageReader.ReadOptionalUint32()
	args.Labels = messageReader.ReadStringSlice()

	// Read options
	options, err := deserializeCreateActionOptions(messageReader)
	if err != nil {
		return nil, fmt.Errorf("error deserializing options: %w", err)
	}
	args.Options = options

	messageReader.CheckComplete()
	if messageReader.Err != nil {
		return nil, fmt.Errorf("error deserializing create action args: %w", messageReader.Err)
	}

	return args, nil
}

// deserializeCreateActionInputs deserializes the inputs into a slice of wallet.CreateActionInput
func deserializeCreateActionInputs(messageReader *util.ReaderHoldError) ([]wallet.CreateActionInput, error) {
	inputsLen := messageReader.ReadVarInt()
	if util.IsNegativeOne(inputsLen) {
		return nil, nil
	}
	var inputs []wallet.CreateActionInput
	var err error
	for i := uint64(0); i < inputsLen; i++ {
		input := wallet.CreateActionInput{}

		// Read outpoint
		outpointBytes := messageReader.ReadBytes(outpointSize)
		input.Outpoint, err = decodeOutpoint(outpointBytes)
		if err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", err)
		}

		// Read unlocking script
		scriptBytes := messageReader.ReadOptionalBytes()
		if scriptBytes != nil {
			input.UnlockingScript = scriptBytes
			input.UnlockingScriptLength = uint32(len(scriptBytes))
		} else {
			// Read unlocking script length value
			length := messageReader.ReadVarInt32()
			input.UnlockingScriptLength = length
		}

		// Read input description
		input.InputDescription = messageReader.ReadString()

		// Read sequence number
		input.SequenceNumber = messageReader.ReadOptionalUint32()

		if messageReader.Err != nil {
			return nil, fmt.Errorf("error reading input %d: %w", i, messageReader.Err)
		}

		inputs = append(inputs, input)
	}

	return inputs, nil
}

// deserializeCreateActionOutputs deserializes the outputs into a slice of wallet.CreateActionOutput
func deserializeCreateActionOutputs(messageReader *util.ReaderHoldError) ([]wallet.CreateActionOutput, error) {
	outputsLen := messageReader.ReadVarInt()
	if util.IsNegativeOne(outputsLen) {
		return nil, nil
	}

	outputs := make([]wallet.CreateActionOutput, 0, outputsLen)
	for i := uint64(0); i < outputsLen; i++ {
		// Read locking script
		lockingScriptBytes := messageReader.ReadOptionalBytes()
		if lockingScriptBytes == nil {
			return nil, fmt.Errorf("locking script cannot be nil")
		}

		// Read satoshis, output description, basket, custom instructions, and tags
		output := wallet.CreateActionOutput{
			LockingScript:      hex.EncodeToString(lockingScriptBytes),
			Satoshis:           messageReader.ReadVarInt(),
			OutputDescription:  messageReader.ReadString(),
			Basket:             messageReader.ReadString(),
			CustomInstructions: messageReader.ReadString(),
			Tags:               messageReader.ReadStringSlice(),
		}

		if messageReader.Err != nil {
			return nil, fmt.Errorf("error reading output %d: %w", i, messageReader.Err)
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// deserializeCreateActionOptions decodes into wallet.CreateActionOptions
func deserializeCreateActionOptions(messageReader *util.ReaderHoldError) (*wallet.CreateActionOptions, error) {
	optionsPresent := messageReader.ReadByte()
	if optionsPresent != 1 {
		return nil, nil
	}

	options := &wallet.CreateActionOptions{}

	// Read signAndProcess and acceptDelayedBroadcast
	options.SignAndProcess = messageReader.ReadOptionalBool()
	options.AcceptDelayedBroadcast = messageReader.ReadOptionalBool()

	// Read trustSelf
	if messageReader.ReadByte() == trustSelfKnown {
		options.TrustSelf = wallet.TrustSelfKnown
	}

	// Read knownTxids, returnTXIDOnly, and noSend
	options.KnownTxids = messageReader.ReadTxidSlice()
	options.ReturnTXIDOnly = messageReader.ReadOptionalBool()
	options.NoSend = messageReader.ReadOptionalBool()

	// Read noSendChange
	noSendChangeData := messageReader.ReadOptionalBytes()
	noSendChange, err := decodeOutpoints(noSendChangeData)
	if err != nil {
		return nil, fmt.Errorf("error decoding noSendChange: %w", err)
	}
	options.NoSendChange = noSendChange

	// Read sendWith and randomizeOutputs
	options.SendWith = messageReader.ReadTxidSlice()
	options.RandomizeOutputs = messageReader.ReadOptionalBool()

	return options, nil
}

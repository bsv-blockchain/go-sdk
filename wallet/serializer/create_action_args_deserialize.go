package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"math"
)

// DeserializeCreateActionArgs deserializes a byte slice into a wallet.CreateActionArgs object
func DeserializeCreateActionArgs(data []byte) (*wallet.CreateActionArgs, error) {
	if len(data) == 0 {
		return nil, errors.New("empty message")
	}

	messageReader := newReaderHoldError(data)
	args := &wallet.CreateActionArgs{}
	var err error

	// Read description and input BEEF
	args.Description = messageReader.readString()
	args.InputBEEF = messageReader.readOptionalBytes()

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
	args.LockTime = messageReader.readOptionalUint32()
	args.Version = messageReader.readOptionalUint32()
	args.Labels = messageReader.readStringSlice()

	// Read options
	options, err := deserializeCreateActionOptions(messageReader)
	if err != nil {
		return nil, fmt.Errorf("error deserializing options: %w", err)
	}
	args.Options = options

	return args, nil
}

// deserializeCreateActionInputs deserializes the inputs into a slice of wallet.CreateActionInput
func deserializeCreateActionInputs(messageReader *readerHoldError) ([]wallet.CreateActionInput, error) {
	inputsLen := messageReader.readVarInt()
	if inputsLen == math.MaxUint64 { // -1 means nil
		return nil, nil
	}

	inputs := make([]wallet.CreateActionInput, 0, inputsLen)
	var err error
	for i := uint64(0); i < inputsLen; i++ {
		input := wallet.CreateActionInput{}

		// Read outpoint
		outpointBytes := messageReader.readBytes(36) // 32 txid + 4 index
		input.Outpoint, err = decodeOutpoint(outpointBytes)
		if err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", err)
		}

		// Read unlocking script
		scriptBytes := messageReader.readOptionalBytes()
		if scriptBytes != nil {
			input.UnlockingScript = hex.EncodeToString(scriptBytes)
			input.UnlockingScriptLength = uint32(len(scriptBytes))
		} else {
			// Read unlocking script length value
			length := messageReader.readVarInt32()
			input.UnlockingScriptLength = length
		}

		// Read input description
		input.InputDescription = messageReader.readString()

		// Read sequence number
		seqNum := messageReader.readVarInt()
		if seqNum != math.MaxUint64 { // -1 means nil
			input.SequenceNumber = uint32(seqNum)
		}

		if messageReader.err != nil {
			return nil, fmt.Errorf("error reading input %d: %w", i, messageReader.err)
		}

		inputs = append(inputs, input)
	}

	return inputs, nil
}

// deserializeCreateActionOutputs deserializes the outputs into a slice of wallet.CreateActionOutput
func deserializeCreateActionOutputs(messageReader *readerHoldError) ([]wallet.CreateActionOutput, error) {
	outputsLen := messageReader.readVarInt()
	if outputsLen == math.MaxUint64 { // -1 means nil
		return nil, nil
	}

	outputs := make([]wallet.CreateActionOutput, 0, outputsLen)
	for i := uint64(0); i < outputsLen; i++ {
		// Read locking script
		lockingScriptBytes := messageReader.readOptionalBytes()
		if lockingScriptBytes == nil {
			return nil, fmt.Errorf("locking script cannot be nil")
		}

		// Read satoshis, output description, basket, custom instructions, and tags
		output := wallet.CreateActionOutput{
			LockingScript:      hex.EncodeToString(lockingScriptBytes),
			Satoshis:           messageReader.readVarInt(),
			OutputDescription:  messageReader.readString(),
			Basket:             messageReader.readString(),
			CustomInstructions: messageReader.readString(),
			Tags:               messageReader.readStringSlice(),
		}

		if messageReader.err != nil {
			return nil, fmt.Errorf("error reading output %d: %w", i, messageReader.err)
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// deserializeCreateActionOptions decodes into wallet.CreateActionOptions
func deserializeCreateActionOptions(messageReader *readerHoldError) (*wallet.CreateActionOptions, error) {
	optionsPresent := messageReader.readByte()
	if optionsPresent != 1 {
		return nil, nil
	}

	options := &wallet.CreateActionOptions{}

	// Read signAndProcess and acceptDelayedBroadcast
	options.SignAndProcess = messageReader.readOptionalBool()
	options.AcceptDelayedBroadcast = messageReader.readOptionalBool()

	// Read trustSelf
	if messageReader.readByte() == 1 {
		options.TrustSelf = "known"
	}

	// Read knownTxids, returnTXIDOnly, and noSend
	options.KnownTxids = messageReader.readTxidSlice()
	options.ReturnTXIDOnly = messageReader.readOptionalBool()
	options.NoSend = messageReader.readOptionalBool()

	// Read noSendChange
	noSendChangeData := messageReader.readOptionalBytes()
	noSendChange, err := decodeOutpoints(noSendChangeData)
	if err != nil {
		return nil, fmt.Errorf("error decoding noSendChange: %w", err)
	}
	options.NoSendChange = noSendChange

	// Read sendWith and randomizeOutputs
	options.SendWith = messageReader.readTxidSlice()
	options.RandomizeOutputs = messageReader.readOptionalBool()

	return options, nil
}

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

	messageReader := newReader(data)
	args := &wallet.CreateActionArgs{}
	var err error

	// Read description
	args.Description, err = messageReader.readString()
	if err != nil {
		return nil, fmt.Errorf("error reading description: %w", err)
	}

	// Read input BEEF
	args.InputBEEF, err = messageReader.readOptionalBytes()
	if err != nil {
		return nil, fmt.Errorf("error reading input BEEF: %w", err)
	}

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

	// Read lockTime
	args.LockTime, err = messageReader.readOptionalUint32()
	if err != nil {
		return nil, fmt.Errorf("error reading lockTime: %w", err)
	}

	// Read version
	args.Version, err = messageReader.readOptionalUint32()
	if err != nil {
		return nil, fmt.Errorf("error reading version: %w", err)
	}

	// Read labels
	args.Labels, err = messageReader.readStringSlice()
	if err != nil {
		return nil, fmt.Errorf("error reading labels: %w", err)
	}

	// Read options
	options, err := deserializeCreateActionOptions(messageReader)
	if err != nil {
		return nil, fmt.Errorf("error deserializing options: %w", err)
	}
	args.Options = options

	return args, nil
}

// deserializeCreateActionInputs deserializes the inputs into a slice of wallet.CreateActionInput
func deserializeCreateActionInputs(messageReader *reader) ([]wallet.CreateActionInput, error) {
	inputsLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading inputs length: %w", err)
	}
	if inputsLen == math.MaxUint64 { // -1 means nil
		return nil, nil
	}

	inputs := make([]wallet.CreateActionInput, 0, inputsLen)
	for i := uint64(0); i < inputsLen; i++ {
		input := wallet.CreateActionInput{}

		// Read outpoint
		outpointBytes, err := messageReader.readBytes(36) // 32 txid + 4 index
		if err != nil {
			return nil, fmt.Errorf("error reading outpoint: %w", err)
		}
		input.Outpoint, err = decodeOutpoint(outpointBytes)
		if err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", err)
		}

		// Read unlocking script
		scriptBytes, err := messageReader.readOptionalBytes()
		if err != nil {
			return nil, fmt.Errorf("error reading unlocking script: %w", err)
		}
		if scriptBytes != nil {
			input.UnlockingScript = hex.EncodeToString(scriptBytes)
			input.UnlockingScriptLength = uint32(len(scriptBytes))
		} else {
			// Read unlocking script length value
			length, err := messageReader.readVarInt32()
			if err != nil {
				return nil, fmt.Errorf("error reading unlocking script length value: %w", err)
			}
			input.UnlockingScriptLength = length
		}

		// Read input description
		input.InputDescription, err = messageReader.readString()
		if err != nil {
			return nil, fmt.Errorf("error reading input description: %w", err)
		}

		// Read sequence number
		seqNum, err := messageReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading sequence number: %w", err)
		}
		if seqNum != math.MaxUint64 { // -1 means nil
			input.SequenceNumber = uint32(seqNum)
		}

		inputs = append(inputs, input)
	}

	return inputs, nil
}

// deserializeCreateActionOutputs deserializes the outputs into a slice of wallet.CreateActionOutput
func deserializeCreateActionOutputs(messageReader *reader) ([]wallet.CreateActionOutput, error) {
	outputsLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading outputs length: %w", err)
	}
	if outputsLen == math.MaxUint64 { // -1 means nil
		return nil, nil
	}

	outputs := make([]wallet.CreateActionOutput, 0, outputsLen)
	for i := uint64(0); i < outputsLen; i++ {
		output := wallet.CreateActionOutput{}

		// Read locking script
		lockingScriptBytes, err := messageReader.readOptionalBytes()
		if err != nil {
			return nil, fmt.Errorf("error reading locking script: %w", err)
		}
		if lockingScriptBytes == nil {
			return nil, fmt.Errorf("locking script cannot be nil")
		}
		output.LockingScript = hex.EncodeToString(lockingScriptBytes)

		// Read satoshis
		satoshis, err := messageReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading satoshis: %w", err)
		}
		output.Satoshis = satoshis

		// Read output description
		output.OutputDescription, err = messageReader.readString()
		if err != nil {
			return nil, fmt.Errorf("error reading output description: %w", err)
		}

		// Read basket
		output.Basket, err = messageReader.readString()
		if err != nil {
			return nil, fmt.Errorf("error reading basket: %w", err)
		}

		// Read custom instructions
		output.CustomInstructions, err = messageReader.readString()
		if err != nil {
			return nil, fmt.Errorf("error reading custom instructions: %w", err)
		}

		// Read tags
		output.Tags, err = messageReader.readStringSlice()
		if err != nil {
			return nil, fmt.Errorf("error reading tags: %w", err)
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// deserializeCreateActionOptions decodes into wallet.CreateActionOptions
func deserializeCreateActionOptions(messageReader *reader) (*wallet.CreateActionOptions, error) {
	optionsPresent, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading options present flag: %w", err)
	}
	if optionsPresent != 1 {
		return nil, nil
	}

	options := &wallet.CreateActionOptions{}

	// Read signAndProcess
	signAndProcessFlag, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading signAndProcess flag: %w", err)
	}
	if signAndProcessFlag != 0xFF { // -1 means nil
		options.SignAndProcess = new(bool)
		*options.SignAndProcess = signAndProcessFlag == 1
	}

	// Read acceptDelayedBroadcast
	acceptDelayedBroadcastFlag, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading acceptDelayedBroadcast flag: %w", err)
	}
	if acceptDelayedBroadcastFlag != 0xFF { // -1 means nil
		options.AcceptDelayedBroadcast = new(bool)
		*options.AcceptDelayedBroadcast = acceptDelayedBroadcastFlag == 1
	}

	// Read trustSelf
	trustSelfFlag, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading trustSelf flag: %w", err)
	}
	if trustSelfFlag == 1 {
		options.TrustSelf = "known"
	}

	// Read knownTxids
	knownTxidsLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading knownTxids length: %w", err)
	}
	if knownTxidsLen != math.MaxUint64 { // -1 means nil
		options.KnownTxids = make([]string, 0, knownTxidsLen)
		for i := uint64(0); i < knownTxidsLen; i++ {
			txidBytes, err := messageReader.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("error reading known txid: %w", err)
			}
			options.KnownTxids = append(options.KnownTxids, hex.EncodeToString(txidBytes))
		}
	}

	// Read returnTXIDOnly
	returnTXIDOnlyFlag, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading returnTXIDOnly flag: %w", err)
	}
	if returnTXIDOnlyFlag != 0xFF { // -1 means nil
		options.ReturnTXIDOnly = new(bool)
		*options.ReturnTXIDOnly = returnTXIDOnlyFlag == 1
	}

	// Read noSend
	noSendFlag, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading noSend flag: %w", err)
	}
	if noSendFlag != 0xFF { // -1 means nil
		options.NoSend = new(bool)
		*options.NoSend = noSendFlag == 1
	}

	// Read noSendChange
	noSendChangeData, err := messageReader.readOptionalBytes()
	if err != nil {
		return nil, fmt.Errorf("error reading noSendChange: %w", err)
	}
	options.NoSendChange, err = decodeOutpoints(noSendChangeData)
	if err != nil {
		return nil, fmt.Errorf("error decoding noSendChange: %w", err)
	}

	// Read sendWith
	sendWithLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading sendWith length: %w", err)
	}
	if sendWithLen != math.MaxUint64 { // -1 means nil
		options.SendWith = make([]string, 0, sendWithLen)
		for i := uint64(0); i < sendWithLen; i++ {
			txidBytes, err := messageReader.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("error reading sendWith txid: %w", err)
			}
			options.SendWith = append(options.SendWith, hex.EncodeToString(txidBytes))
		}
	}

	// Read randomizeOutputs
	randomizeOutputsFlag, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading randomizeOutputs flag: %w", err)
	}
	if randomizeOutputsFlag != 0xFF { // -1 means nil
		options.RandomizeOutputs = new(bool)
		*options.RandomizeOutputs = randomizeOutputsFlag == 1
	}

	return options, nil
}

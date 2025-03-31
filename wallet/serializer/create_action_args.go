package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"math"
)

// SerializeCreateActionArgs serializes a wallet.CreateActionArgs object into a byte slice
func SerializeCreateActionArgs(args *wallet.CreateActionArgs) ([]byte, error) {
	buf := make([]byte, 0)
	paramWriter := newWriter(&buf)

	// Serialize description
	descBytes := []byte(args.Description)
	paramWriter.writeVarInt(uint64(len(descBytes)))
	paramWriter.writeBytes(descBytes)

	// Serialize input BEEF
	if args.InputBEEF != nil {
		paramWriter.writeVarInt(uint64(len(args.InputBEEF)))
		paramWriter.writeBytes(args.InputBEEF)
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1 in varint
	}

	// Serialize inputs
	if args.Inputs != nil {
		paramWriter.writeVarInt(uint64(len(args.Inputs)))
		for _, input := range args.Inputs {
			// Serialize outpoint
			outpoint, err := encodeOutpoint(input.Outpoint)
			if err != nil {
				return nil, fmt.Errorf("error encode outpoint for input: %w", err)
			}
			paramWriter.writeBytes(outpoint)

			// Serialize unlocking script
			if input.UnlockingScript != "" {
				script, err := hex.DecodeString(input.UnlockingScript)
				if err != nil {
					return nil, fmt.Errorf("error decoding unlocking script: %w", err)
				}
				paramWriter.writeVarInt(uint64(len(script)))
				paramWriter.writeBytes(script)
			} else {
				paramWriter.writeVarInt(math.MaxUint64) // -1
				paramWriter.writeVarInt(uint64(input.UnlockingScriptLength))
			}

			// Serialize input description
			inputDesc := []byte(input.InputDescription)
			paramWriter.writeVarInt(uint64(len(inputDesc)))
			paramWriter.writeBytes(inputDesc)

			// Serialize sequence number
			if input.SequenceNumber > 0 {
				paramWriter.writeVarInt(uint64(input.SequenceNumber))
			} else {
				paramWriter.writeVarInt(math.MaxUint64) // -1
			}
		}
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// Serialize outputs
	if args.Outputs != nil {
		paramWriter.writeVarInt(uint64(len(args.Outputs)))
		for _, output := range args.Outputs {
			// Serialize locking script
			script, err := hex.DecodeString(output.LockingScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding locking script: %w", err)
			}
			paramWriter.writeVarInt(uint64(len(script)))
			paramWriter.writeBytes(script)

			// Serialize satoshis
			paramWriter.writeVarInt(output.Satoshis)

			// Serialize output description
			outputDesc := []byte(output.OutputDescription)
			paramWriter.writeVarInt(uint64(len(outputDesc)))
			paramWriter.writeBytes(outputDesc)

			// Serialize basket
			if output.Basket != "" {
				basket := []byte(output.Basket)
				paramWriter.writeVarInt(uint64(len(basket)))
				paramWriter.writeBytes(basket)
			} else {
				paramWriter.writeVarInt(math.MaxUint64) // -1
			}

			// Serialize custom instructions
			if output.CustomInstructions != "" {
				ci := []byte(output.CustomInstructions)
				paramWriter.writeVarInt(uint64(len(ci)))
				paramWriter.writeBytes(ci)
			} else {
				paramWriter.writeVarInt(math.MaxUint64) // -1
			}

			// Serialize tags
			if output.Tags != nil {
				paramWriter.writeVarInt(uint64(len(output.Tags)))
				for _, tag := range output.Tags {
					tagBytes := []byte(tag)
					paramWriter.writeVarInt(uint64(len(tagBytes)))
					paramWriter.writeBytes(tagBytes)
				}
			} else {
				paramWriter.writeVarInt(math.MaxUint64) // -1
			}
		}
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// Serialize lockTime
	if args.LockTime > 0 {
		paramWriter.writeVarInt(uint64(args.LockTime))
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// Serialize version
	if args.Version > 0 {
		paramWriter.writeVarInt(uint64(args.Version))
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// Serialize labels
	if args.Labels != nil {
		paramWriter.writeVarInt(uint64(len(args.Labels)))
		for _, label := range args.Labels {
			labelBytes := []byte(label)
			paramWriter.writeVarInt(uint64(len(labelBytes)))
			paramWriter.writeBytes(labelBytes)
		}
	} else {
		paramWriter.writeVarInt(math.MaxUint64) // -1
	}

	// Serialize options
	if args.Options != nil {
		paramWriter.writeByte(1) // options present

		// signAndProcess
		if args.Options.SignAndProcess != nil {
			if *args.Options.SignAndProcess {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// acceptDelayedBroadcast
		if args.Options.AcceptDelayedBroadcast != nil {
			if *args.Options.AcceptDelayedBroadcast {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// trustSelf
		if args.Options.TrustSelf == "known" {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// knownTxids
		if args.Options.KnownTxids != nil {
			paramWriter.writeVarInt(uint64(len(args.Options.KnownTxids)))
			for _, txid := range args.Options.KnownTxids {
				txidBytes, err := hex.DecodeString(txid)
				if err != nil {
					return nil, fmt.Errorf("error decoding known txid: %w", err)
				}
				paramWriter.writeBytes(txidBytes)
			}
		} else {
			paramWriter.writeVarInt(math.MaxUint64) // -1
		}

		// returnTXIDOnly
		if args.Options.ReturnTXIDOnly != nil {
			if *args.Options.ReturnTXIDOnly {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// noSend
		if args.Options.NoSend != nil {
			if *args.Options.NoSend {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// noSendChange
		if args.Options.NoSendChange != nil {
			paramWriter.writeVarInt(uint64(len(args.Options.NoSendChange)))
			for _, outpoint := range args.Options.NoSendChange {
				op, err := encodeOutpoint(outpoint)
				if err != nil {
					return nil, fmt.Errorf("error encode outpoint for options no send change: %w", err)
				}
				paramWriter.writeBytes(op)
			}
		} else {
			paramWriter.writeVarInt(math.MaxUint64) // -1
		}

		// sendWith
		if args.Options.SendWith != nil {
			paramWriter.writeVarInt(uint64(len(args.Options.SendWith)))
			for _, txid := range args.Options.SendWith {
				txidBytes, err := hex.DecodeString(txid)
				if err != nil {
					return nil, fmt.Errorf("error decoding send with txid: %w", err)
				}
				paramWriter.writeBytes(txidBytes)
			}
		} else {
			paramWriter.writeVarInt(math.MaxUint64) // -1
		}

		// randomizeOutputs
		if args.Options.RandomizeOutputs != nil {
			if *args.Options.RandomizeOutputs {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}
	} else {
		paramWriter.writeByte(0) // options not present
	}

	return buf, nil
}

// DeserializeCreateActionArgs deserializes a byte slice into a wallet.CreateActionArgs object
func DeserializeCreateActionArgs(data []byte) (*wallet.CreateActionArgs, error) {
	if len(data) == 0 {
		return nil, errors.New("empty message")
	}

	messageReader := newReader(data)
	args := &wallet.CreateActionArgs{}

	// Read description
	descLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading description length: %w", err)
	}
	descBytes, err := messageReader.readBytes(int(descLen))
	if err != nil {
		return nil, fmt.Errorf("error reading description: %w", err)
	}
	args.Description = string(descBytes)

	// Read input BEEF
	inputBeefLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading input BEEF length: %w", err)
	}
	if inputBeefLen != math.MaxUint64 { // -1 means nil
		args.InputBEEF, err = messageReader.readBytes(int(inputBeefLen))
		if err != nil {
			return nil, fmt.Errorf("error reading input BEEF: %w", err)
		}
	}

	// Read inputs
	inputsLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading inputs length: %w", err)
	}
	if inputsLen != math.MaxUint64 { // -1 means nil
		args.Inputs = make([]wallet.CreateActionInput, 0, inputsLen)
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
			unlockingScriptLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading unlocking script length: %w", err)
			}
			if unlockingScriptLen != math.MaxUint64 { // -1 means nil
				scriptBytes, err := messageReader.readBytes(int(unlockingScriptLen))
				if err != nil {
					return nil, fmt.Errorf("error reading unlocking script: %w", err)
				}
				input.UnlockingScript = hex.EncodeToString(scriptBytes)
				input.UnlockingScriptLength = uint32(len(scriptBytes))
			} else {
				// Read unlocking script length value
				length, err := messageReader.readVarInt()
				if err != nil {
					return nil, fmt.Errorf("error reading unlocking script length value: %w", err)
				}
				input.UnlockingScriptLength = uint32(length)
			}

			// Read input description
			inputDescLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading input description length: %w", err)
			}
			inputDescBytes, err := messageReader.readBytes(int(inputDescLen))
			if err != nil {
				return nil, fmt.Errorf("error reading input description: %w", err)
			}
			input.InputDescription = string(inputDescBytes)

			// Read sequence number
			seqNum, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading sequence number: %w", err)
			}
			if seqNum != math.MaxUint64 { // -1 means nil
				input.SequenceNumber = uint32(seqNum)
			}

			args.Inputs = append(args.Inputs, input)
		}
	}

	// Read outputs
	outputsLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading outputs length: %w", err)
	}
	if outputsLen != math.MaxUint64 { // -1 means nil
		args.Outputs = make([]wallet.CreateActionOutput, 0, outputsLen)
		for i := uint64(0); i < outputsLen; i++ {
			output := wallet.CreateActionOutput{}

			// Read locking script
			lockingScriptLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading locking script length: %w", err)
			}
			lockingScriptBytes, err := messageReader.readBytes(int(lockingScriptLen))
			if err != nil {
				return nil, fmt.Errorf("error reading locking script: %w", err)
			}
			output.LockingScript = hex.EncodeToString(lockingScriptBytes)

			// Read satoshis
			satoshis, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading satoshis: %w", err)
			}
			output.Satoshis = satoshis

			// Read output description
			outputDescLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading output description length: %w", err)
			}
			outputDescBytes, err := messageReader.readBytes(int(outputDescLen))
			if err != nil {
				return nil, fmt.Errorf("error reading output description: %w", err)
			}
			output.OutputDescription = string(outputDescBytes)

			// Read basket
			basketLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading basket length: %w", err)
			}
			if basketLen != math.MaxUint64 { // -1 means nil
				basketBytes, err := messageReader.readBytes(int(basketLen))
				if err != nil {
					return nil, fmt.Errorf("error reading basket: %w", err)
				}
				output.Basket = string(basketBytes)
			}

			// Read custom instructions
			customInstLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading custom instructions length: %w", err)
			}
			if customInstLen != math.MaxUint64 { // -1 means nil
				customInstBytes, err := messageReader.readBytes(int(customInstLen))
				if err != nil {
					return nil, fmt.Errorf("error reading custom instructions: %w", err)
				}
				output.CustomInstructions = string(customInstBytes)
			}

			// Read tags
			tagsLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading tags length: %w", err)
			}
			if tagsLen != math.MaxUint64 { // -1 means nil
				output.Tags = make([]string, 0, tagsLen)
				for j := uint64(0); j < tagsLen; j++ {
					tagLen, err := messageReader.readVarInt()
					if err != nil {
						return nil, fmt.Errorf("error reading tag length: %w", err)
					}
					tagBytes, err := messageReader.readBytes(int(tagLen))
					if err != nil {
						return nil, fmt.Errorf("error reading tag: %w", err)
					}
					output.Tags = append(output.Tags, string(tagBytes))
				}
			}

			args.Outputs = append(args.Outputs, output)
		}
	}

	// Read lockTime
	lockTime, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading lockTime: %w", err)
	}
	if lockTime != math.MaxUint64 { // -1 means nil
		args.LockTime = uint32(lockTime)
	}

	// Read version
	version, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading version: %w", err)
	}
	if version != math.MaxUint64 { // -1 means nil
		args.Version = uint32(version)
	}

	// Read labels
	labelsLen, err := messageReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading labels length: %w", err)
	}
	if labelsLen != math.MaxUint64 { // -1 means nil
		args.Labels = make([]string, 0, labelsLen)
		for i := uint64(0); i < labelsLen; i++ {
			labelLen, err := messageReader.readVarInt()
			if err != nil {
				return nil, fmt.Errorf("error reading label length: %w", err)
			}
			labelBytes, err := messageReader.readBytes(int(labelLen))
			if err != nil {
				return nil, fmt.Errorf("error reading label: %w", err)
			}
			args.Labels = append(args.Labels, string(labelBytes))
		}
	}

	// Read options
	optionsPresent, err := messageReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading options present flag: %w", err)
	}
	if optionsPresent == 1 {
		args.Options = &wallet.CreateActionOptions{}

		// Read signAndProcess
		signAndProcessFlag, err := messageReader.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading signAndProcess flag: %w", err)
		}
		if signAndProcessFlag != 0xFF { // -1 means nil
			args.Options.SignAndProcess = new(bool)
			*args.Options.SignAndProcess = signAndProcessFlag == 1
		}

		// Read acceptDelayedBroadcast
		acceptDelayedBroadcastFlag, err := messageReader.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading acceptDelayedBroadcast flag: %w", err)
		}
		if acceptDelayedBroadcastFlag != 0xFF { // -1 means nil
			args.Options.AcceptDelayedBroadcast = new(bool)
			*args.Options.AcceptDelayedBroadcast = acceptDelayedBroadcastFlag == 1
		}

		// Read trustSelf
		trustSelfFlag, err := messageReader.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading trustSelf flag: %w", err)
		}
		if trustSelfFlag == 1 {
			args.Options.TrustSelf = "known"
		}

		// Read knownTxids
		knownTxidsLen, err := messageReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading knownTxids length: %w", err)
		}
		if knownTxidsLen != math.MaxUint64 { // -1 means nil
			args.Options.KnownTxids = make([]string, 0, knownTxidsLen)
			for i := uint64(0); i < knownTxidsLen; i++ {
				txidBytes, err := messageReader.readBytes(32)
				if err != nil {
					return nil, fmt.Errorf("error reading known txid: %w", err)
				}
				args.Options.KnownTxids = append(args.Options.KnownTxids, hex.EncodeToString(txidBytes))
			}
		}

		// Read returnTXIDOnly
		returnTXIDOnlyFlag, err := messageReader.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading returnTXIDOnly flag: %w", err)
		}
		if returnTXIDOnlyFlag != 0xFF { // -1 means nil
			args.Options.ReturnTXIDOnly = new(bool)
			*args.Options.ReturnTXIDOnly = returnTXIDOnlyFlag == 1
		}

		// Read noSend
		noSendFlag, err := messageReader.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading noSend flag: %w", err)
		}
		if noSendFlag != 0xFF { // -1 means nil
			args.Options.NoSend = new(bool)
			*args.Options.NoSend = noSendFlag == 1
		}

		// Read noSendChange
		noSendChangeLen, err := messageReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading noSendChange length: %w", err)
		}
		if noSendChangeLen != math.MaxUint64 { // -1 means nil
			args.Options.NoSendChange = make([]string, 0, noSendChangeLen)
			for i := uint64(0); i < noSendChangeLen; i++ {
				outpointBytes, err := messageReader.readBytes(36) // 32 txid + 4 index
				if err != nil {
					return nil, fmt.Errorf("error reading noSendChange outpoint: %w", err)
				}
				outpoint, err := decodeOutpoint(outpointBytes)
				if err != nil {
					return nil, fmt.Errorf("error decoding noSendChange outpoint: %w", err)
				}
				args.Options.NoSendChange = append(args.Options.NoSendChange, outpoint)
			}
		}

		// Read sendWith
		sendWithLen, err := messageReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading sendWith length: %w", err)
		}
		if sendWithLen != math.MaxUint64 { // -1 means nil
			args.Options.SendWith = make([]string, 0, sendWithLen)
			for i := uint64(0); i < sendWithLen; i++ {
				txidBytes, err := messageReader.readBytes(32)
				if err != nil {
					return nil, fmt.Errorf("error reading sendWith txid: %w", err)
				}
				args.Options.SendWith = append(args.Options.SendWith, hex.EncodeToString(txidBytes))
			}
		}

		// Read randomizeOutputs
		randomizeOutputsFlag, err := messageReader.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading randomizeOutputs flag: %w", err)
		}
		if randomizeOutputsFlag != 0xFF { // -1 means nil
			args.Options.RandomizeOutputs = new(bool)
			*args.Options.RandomizeOutputs = randomizeOutputsFlag == 1
		}
	}

	return args, nil
}

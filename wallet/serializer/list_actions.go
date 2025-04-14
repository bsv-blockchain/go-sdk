package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeListActionsArgs(args *wallet.ListActionsArgs) ([]byte, error) {
	w := newWriter()

	// Serialize labels
	w.writeStringSlice(args.Labels)

	// Serialize labelQueryMode
	switch args.LabelQueryMode {
	case "any":
		w.writeByte(1)
	case "all":
		w.writeByte(2)
	case "":
		w.writeByte(0xFF) // -1
	default:
		return nil, fmt.Errorf("invalid label query mode: %s", args.LabelQueryMode)
	}

	// Serialize include options
	w.writeOptionalBool(args.IncludeLabels)
	w.writeOptionalBool(args.IncludeInputs)
	w.writeOptionalBool(args.IncludeInputSourceLockingScripts)
	w.writeOptionalBool(args.IncludeInputUnlockingScripts)
	w.writeOptionalBool(args.IncludeOutputs)
	w.writeOptionalBool(args.IncludeOutputLockingScripts)

	// Serialize limit, offset, and seekPermission
	w.writeOptionalUint32(args.Limit)
	w.writeOptionalUint32(args.Offset)
	w.writeOptionalBool(args.SeekPermission)

	return w.buf, nil
}

func DeserializeListActionsArgs(data []byte) (*wallet.ListActionsArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.ListActionsArgs{}

	// Deserialize labels
	args.Labels = r.readStringSlice()

	// Deserialize labelQueryMode
	switch r.readByte() {
	case 1:
		args.LabelQueryMode = "any"
	case 2:
		args.LabelQueryMode = "all"
	case 0xFF:
		args.LabelQueryMode = ""
	default:
		return nil, fmt.Errorf("invalid label query mode byte: %d", r.readByte())
	}

	// Deserialize include options
	args.IncludeLabels = r.readOptionalBool()
	args.IncludeInputs = r.readOptionalBool()
	args.IncludeInputSourceLockingScripts = r.readOptionalBool()
	args.IncludeInputUnlockingScripts = r.readOptionalBool()
	args.IncludeOutputs = r.readOptionalBool()
	args.IncludeOutputLockingScripts = r.readOptionalBool()

	// Deserialize limit, offset, and seekPermission
	args.Limit = r.readOptionalUint32()
	args.Offset = r.readOptionalUint32()
	args.SeekPermission = r.readOptionalBool()

	if r.err != nil {
		return nil, fmt.Errorf("error reading list action args: %w", r.err)
	}

	return args, nil
}

func SerializeListActionsResult(result *wallet.ListActionsResult) ([]byte, error) {
	w := newWriter()

	// Serialize totalActions
	w.writeVarInt(uint64(result.TotalActions))

	// Serialize actions
	w.writeVarInt(uint64(len(result.Actions)))
	for _, action := range result.Actions {
		// Serialize basic action fields
		txid, err := hex.DecodeString(action.Txid)
		if err != nil {
			return nil, fmt.Errorf("invalid txid hex: %w", err)
		}
		w.writeBytes(txid)
		w.writeVarInt(action.Satoshis)

		// Serialize status
		switch action.Status {
		case wallet.ActionStatusCompleted:
			w.writeByte(byte(wallet.ActionStatusCodeCompleted))
		case wallet.ActionStatusUnprocessed:
			w.writeByte(byte(wallet.ActionStatusCodeUnprocessed))
		case wallet.ActionStatusSending:
			w.writeByte(byte(wallet.ActionStatusCodeSending))
		case wallet.ActionStatusUnproven:
			w.writeByte(byte(wallet.ActionStatusCodeUnproven))
		case wallet.ActionStatusUnsigned:
			w.writeByte(byte(wallet.ActionStatusCodeUnsigned))
		case wallet.ActionStatusNoSend:
			w.writeByte(byte(wallet.ActionStatusCodeNoSend))
		case wallet.ActionStatusNonFinal:
			w.writeByte(byte(wallet.ActionStatusCodeNonFinal))
		default:
			return nil, fmt.Errorf("invalid action status: %s", action.Status)
		}

		// Serialize IsOutgoing, Description, Labels, Version, and LockTime
		w.writeOptionalBool(&action.IsOutgoing)
		w.writeString(action.Description)
		w.writeStringSlice(action.Labels)
		w.writeVarInt(uint64(action.Version))
		w.writeVarInt(uint64(action.LockTime))

		// Serialize inputs
		w.writeVarInt(uint64(len(action.Inputs)))
		for _, input := range action.Inputs {
			opBytes, err := encodeOutpoint(input.SourceOutpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid source outpoint: %w", err)
			}
			w.writeBytes(opBytes)
			w.writeVarInt(input.SourceSatoshis)

			// SourceLockingScript
			if err = w.writeOptionalFromHex(input.SourceLockingScript); err != nil {
				return nil, fmt.Errorf("invalid source locking script: %w", err)
			}

			// UnlockingScript
			if err = w.writeOptionalFromHex(input.UnlockingScript); err != nil {
				return nil, fmt.Errorf("invalid unlocking script: %w", err)
			}

			w.writeString(input.InputDescription)
			w.writeVarInt(uint64(input.SequenceNumber))
		}

		// Serialize outputs
		w.writeVarInt(uint64(len(action.Outputs)))
		for _, output := range action.Outputs {
			w.writeVarInt(uint64(output.OutputIndex))
			w.writeVarInt(output.Satoshis)

			// LockingScript
			if err = w.writeOptionalFromHex(output.LockingScript); err != nil {
				return nil, fmt.Errorf("invalid locking script: %w", err)
			}

			// Serialize Spendable, OutputDescription, Basket, Tags, and CustomInstructions
			w.writeOptionalBool(&output.Spendable)
			w.writeString(output.OutputDescription)
			w.writeString(output.Basket)
			w.writeStringSlice(output.Tags)
			w.writeOptionalString(output.CustomInstructions)
		}
	}

	return w.buf, nil
}

func DeserializeListActionsResult(data []byte) (*wallet.ListActionsResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.ListActionsResult{}

	// Deserialize totalActions
	result.TotalActions = r.readVarInt32()

	// Deserialize actions
	actionCount := r.readVarInt()
	result.Actions = make([]wallet.Action, 0, actionCount)
	for i := uint64(0); i < actionCount; i++ {
		action := wallet.Action{}

		// Deserialize basic action fields
		txid := r.readBytes(32)
		action.Txid = hex.EncodeToString(txid)
		action.Satoshis = r.readVarInt()

		// Deserialize status
		status := r.readByte()
		switch wallet.ActionStatusCode(status) {
		case wallet.ActionStatusCodeCompleted:
			action.Status = wallet.ActionStatusCompleted
		case wallet.ActionStatusCodeUnprocessed:
			action.Status = wallet.ActionStatusUnprocessed
		case wallet.ActionStatusCodeSending:
			action.Status = wallet.ActionStatusSending
		case wallet.ActionStatusCodeUnproven:
			action.Status = wallet.ActionStatusUnproven
		case wallet.ActionStatusCodeUnsigned:
			action.Status = wallet.ActionStatusUnsigned
		case wallet.ActionStatusCodeNoSend:
			action.Status = wallet.ActionStatusNoSend
		case wallet.ActionStatusCodeNonFinal:
			action.Status = wallet.ActionStatusNonFinal
		default:
			return nil, fmt.Errorf("invalid status byte %d", status)
		}

		// Deserialize IsOutgoing, Description, Labels, Version, and LockTime
		action.IsOutgoing = r.readByte() == 1
		action.Description = r.readString()
		action.Labels = r.readStringSlice()
		action.Version = r.readVarInt32()
		action.LockTime = r.readVarInt32()

		// Deserialize inputs
		inputCount := r.readVarInt()
		action.Inputs = make([]wallet.ActionInput, 0, inputCount)
		for j := uint64(0); j < inputCount; j++ {
			input := wallet.ActionInput{}

			opBytes := r.readBytes(36)
			input.SourceOutpoint, _ = decodeOutpoint(opBytes)

			// Serialize source satoshis, locking script, unlocking script, input description, and sequence number
			input.SourceSatoshis = r.readVarInt()
			input.SourceLockingScript = r.readOptionalToHex()
			input.UnlockingScript = r.readOptionalToHex()
			input.InputDescription = r.readString()
			input.SequenceNumber = r.readVarInt32()

			// Check for error each loop
			if r.err != nil {
				return nil, fmt.Errorf("error reading list action input %d: %w", j, r.err)
			}

			action.Inputs = append(action.Inputs, input)
		}

		// Deserialize outputs
		outputCount := r.readVarInt()
		action.Outputs = make([]wallet.ActionOutput, 0, outputCount)
		for k := uint64(0); k < outputCount; k++ {
			output := wallet.ActionOutput{}

			// Serialize output index, satoshis, locking script, spendable, output description, basket, tags,
			// and custom instructions
			output.OutputIndex = r.readVarInt32()
			output.Satoshis = r.readVarInt()
			output.LockingScript = r.readOptionalToHex()
			output.Spendable = r.readByte() == 1
			output.OutputDescription = r.readString()
			output.Basket = r.readString()
			output.Tags = r.readStringSlice()
			output.CustomInstructions = r.readString()

			// Check for error each loop
			if r.err != nil {
				return nil, fmt.Errorf("error reading list action output %d: %w", k, r.err)
			}

			action.Outputs = append(action.Outputs, output)
		}

		// Check for error each loop
		if r.err != nil {
			return nil, fmt.Errorf("error reading list action %d: %w", i, r.err)
		}

		result.Actions = append(result.Actions, action)
	}

	if r.err != nil {
		return nil, fmt.Errorf("error reading list action result: %w", r.err)
	}

	return result, nil
}

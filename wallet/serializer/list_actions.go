package serializer

import (
	"fmt"
	"math"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	labelQueryModeAnyCode uint8 = 1
	labelQueryModeAllCode uint8 = 2
)

func SerializeListActionsArgs(args *wallet.ListActionsArgs) ([]byte, error) {
	w := util.NewWriter()

	// Serialize labels
	w.WriteStringSlice(args.Labels)

	// Serialize labelQueryMode
	switch args.LabelQueryMode {
	case wallet.QueryModeAny:
		w.WriteByte(labelQueryModeAnyCode)
	case wallet.QueryModeAll:
		w.WriteByte(labelQueryModeAllCode)
	case "":
		w.WriteNegativeOneByte()
	default:
		return nil, fmt.Errorf("invalid label query mode: %s", args.LabelQueryMode)
	}

	// Serialize include options
	w.WriteOptionalBool(args.IncludeLabels)
	w.WriteOptionalBool(args.IncludeInputs)
	w.WriteOptionalBool(args.IncludeInputSourceLockingScripts)
	w.WriteOptionalBool(args.IncludeInputUnlockingScripts)
	w.WriteOptionalBool(args.IncludeOutputs)
	w.WriteOptionalBool(args.IncludeOutputLockingScripts)

	// Serialize limit, offset, and seekPermission
	if args.Limit != nil && *args.Limit > wallet.MaxActionsLimit {
		return nil, fmt.Errorf("limit exceeds maximum allowed value: %d", args.Limit)
	}
	w.WriteOptionalUint32(args.Limit)
	w.WriteOptionalUint32(args.Offset)
	w.WriteOptionalBool(args.SeekPermission)

	return w.Buf, nil
}

func DeserializeListActionsArgs(data []byte) (*wallet.ListActionsArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.ListActionsArgs{}

	// Deserialize labels
	args.Labels = r.ReadStringSlice()

	// Deserialize labelQueryMode
	switch r.ReadByte() {
	case labelQueryModeAnyCode:
		args.LabelQueryMode = wallet.QueryModeAny
	case labelQueryModeAllCode:
		args.LabelQueryMode = wallet.QueryModeAll
	case util.NegativeOneByte:
		args.LabelQueryMode = ""
	default:
		return nil, fmt.Errorf("invalid label query mode byte: %d", r.ReadByte())
	}

	// Deserialize include options
	args.IncludeLabels = r.ReadOptionalBool()
	args.IncludeInputs = r.ReadOptionalBool()
	args.IncludeInputSourceLockingScripts = r.ReadOptionalBool()
	args.IncludeInputUnlockingScripts = r.ReadOptionalBool()
	args.IncludeOutputs = r.ReadOptionalBool()
	args.IncludeOutputLockingScripts = r.ReadOptionalBool()

	// Deserialize limit, offset, and seekPermission
	args.Limit = r.ReadOptionalUint32()
	args.Offset = r.ReadOptionalUint32()
	args.SeekPermission = r.ReadOptionalBool()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading list action args: %w", r.Err)
	}

	return args, nil
}

// actionStatusCode is the numeric representation of ActionStatus.
type actionStatusCode uint8

const (
	actionStatusCodeCompleted   actionStatusCode = 1
	actionStatusCodeUnprocessed actionStatusCode = 2
	actionStatusCodeSending     actionStatusCode = 3
	actionStatusCodeUnproven    actionStatusCode = 4
	actionStatusCodeUnsigned    actionStatusCode = 5
	actionStatusCodeNoSend      actionStatusCode = 6
	actionStatusCodeNonFinal    actionStatusCode = 7
)

func SerializeListActionsResult(result *wallet.ListActionsResult) ([]byte, error) {
	w := util.NewWriter()

	if int(result.TotalActions) != len(result.Actions) {
		return nil, fmt.Errorf("totalActions %d does not match length of actions %d",
			result.TotalActions, len(result.Actions))
	}

	// Serialize totalActions
	w.WriteVarInt(uint64(result.TotalActions))

	// Serialize actions
	for _, action := range result.Actions {
		// Serialize basic action fields
		w.WriteBytesReverse(action.Txid[:])
		w.WriteVarInt(uint64(action.Satoshis))

		// Serialize status
		switch action.Status {
		case wallet.ActionStatusCompleted:
			w.WriteByte(byte(actionStatusCodeCompleted))
		case wallet.ActionStatusUnprocessed:
			w.WriteByte(byte(actionStatusCodeUnprocessed))
		case wallet.ActionStatusSending:
			w.WriteByte(byte(actionStatusCodeSending))
		case wallet.ActionStatusUnproven:
			w.WriteByte(byte(actionStatusCodeUnproven))
		case wallet.ActionStatusUnsigned:
			w.WriteByte(byte(actionStatusCodeUnsigned))
		case wallet.ActionStatusNoSend:
			w.WriteByte(byte(actionStatusCodeNoSend))
		case wallet.ActionStatusNonFinal:
			w.WriteByte(byte(actionStatusCodeNonFinal))
		default:
			return nil, fmt.Errorf("invalid action status: %s", action.Status)
		}

		// Serialize IsOutgoing, Description, Labels, Version, and LockTime
		w.WriteOptionalBool(&action.IsOutgoing)
		w.WriteString(action.Description)
		w.WriteStringSlice(action.Labels)
		w.WriteVarInt(uint64(action.Version))
		w.WriteVarInt(uint64(action.LockTime))

		// Serialize inputs
		if len(action.Inputs) == 0 {
			w.WriteNegativeOne()
		} else {
			w.WriteVarInt(uint64(len(action.Inputs)))
		}
		for _, input := range action.Inputs {
			w.WriteBytes(encodeOutpoint(&input.SourceOutpoint))
			w.WriteVarInt(input.SourceSatoshis)

			// SourceLockingScript
			w.WriteIntBytesOptional(input.SourceLockingScript)

			// UnlockingScript
			w.WriteIntBytesOptional(input.UnlockingScript)

			w.WriteString(input.InputDescription)
			w.WriteVarInt(uint64(input.SequenceNumber))
		}

		// Serialize outputs
		if len(action.Outputs) == 0 {
			w.WriteNegativeOne()
		} else {
			w.WriteVarInt(uint64(len(action.Outputs)))
		}
		for _, output := range action.Outputs {
			w.WriteVarInt(uint64(output.OutputIndex))
			w.WriteVarInt(output.Satoshis)
			w.WriteIntBytesOptional(output.LockingScript)

			// Serialize Spendable, OutputDescription, Basket, Tags, and CustomInstructions
			w.WriteOptionalBool(&output.Spendable)
			w.WriteString(output.OutputDescription)
			w.WriteString(output.Basket)
			w.WriteStringSlice(output.Tags)
			w.WriteOptionalString(output.CustomInstructions)
		}
	}

	return w.Buf, nil
}

func DeserializeListActionsResult(data []byte) (*wallet.ListActionsResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ListActionsResult{}

	// Deserialize totalActions
	result.TotalActions = r.ReadVarInt32()

	// Deserialize actions
	result.Actions = make([]wallet.Action, 0, result.TotalActions)
	for i := uint32(0); i < result.TotalActions; i++ {
		action := wallet.Action{}

		// Deserialize basic action fields
		copy(action.Txid[:], r.ReadBytesReverse(chainhash.HashSize))
		action.Satoshis = int64(r.ReadVarInt())

		// Deserialize status
		status := r.ReadByte()
		switch actionStatusCode(status) {
		case actionStatusCodeCompleted:
			action.Status = wallet.ActionStatusCompleted
		case actionStatusCodeUnprocessed:
			action.Status = wallet.ActionStatusUnprocessed
		case actionStatusCodeSending:
			action.Status = wallet.ActionStatusSending
		case actionStatusCodeUnproven:
			action.Status = wallet.ActionStatusUnproven
		case actionStatusCodeUnsigned:
			action.Status = wallet.ActionStatusUnsigned
		case actionStatusCodeNoSend:
			action.Status = wallet.ActionStatusNoSend
		case actionStatusCodeNonFinal:
			action.Status = wallet.ActionStatusNonFinal
		default:
			return nil, fmt.Errorf("invalid status byte %d", status)
		}

		// Deserialize IsOutgoing, Description, Labels, Version, and LockTime
		action.IsOutgoing = r.ReadByte() == 1
		action.Description = r.ReadString()
		action.Labels = r.ReadStringSlice()
		action.Version = r.ReadVarInt32()
		action.LockTime = r.ReadVarInt32()

		// Deserialize inputs
		inputCount := r.ReadVarInt()
		if inputCount == math.MaxUint64 {
			inputCount = 0
		} else {
			action.Inputs = make([]wallet.ActionInput, 0, inputCount)
		}
		for j := uint64(0); j < inputCount; j++ {
			input := wallet.ActionInput{}

			outpoint, err := decodeOutpoint(&r.Reader)
			if err != nil {
				return nil, fmt.Errorf("error decoding source outpoint for input %d: %w", j, err)
			}
			input.SourceOutpoint = *outpoint

			// Serialize source satoshis, locking script, unlocking script, input description, and sequence number
			input.SourceSatoshis = r.ReadVarInt()
			input.SourceLockingScript = r.ReadIntBytes()
			input.UnlockingScript = r.ReadIntBytes()
			input.InputDescription = r.ReadString()
			input.SequenceNumber = r.ReadVarInt32()

			// Check for error each loop
			if r.Err != nil {
				return nil, fmt.Errorf("error reading list action input %d: %w", j, r.Err)
			}

			action.Inputs = append(action.Inputs, input)
		}

		// Deserialize outputs
		outputCount := r.ReadVarInt()
		if outputCount == math.MaxUint64 {
			outputCount = 0
		} else {
			action.Outputs = make([]wallet.ActionOutput, 0, outputCount)
		}
		for k := uint64(0); k < outputCount; k++ {
			output := wallet.ActionOutput{}

			// Serialize output index, satoshis, locking script, spendable, output description, basket, tags,
			// and custom instructions
			output.OutputIndex = r.ReadVarInt32()
			output.Satoshis = r.ReadVarInt()
			output.LockingScript = r.ReadIntBytes()
			output.Spendable = r.ReadByte() == 1
			output.OutputDescription = r.ReadString()
			output.Basket = r.ReadString()
			output.Tags = r.ReadStringSlice()
			output.CustomInstructions = r.ReadString()

			// Check for error each loop
			if r.Err != nil {
				return nil, fmt.Errorf("error reading list action output %d: %w", k, r.Err)
			}

			action.Outputs = append(action.Outputs, output)
		}

		// Check for error each loop
		if r.Err != nil {
			return nil, fmt.Errorf("error reading list action %d: %w", i, r.Err)
		}

		result.Actions = append(result.Actions, action)
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading list action result: %w", r.Err)
	}

	return result, nil
}

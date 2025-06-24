package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	tagQueryModeAllCode uint8 = 1
	tagQueryModeAnyCode uint8 = 2

	outputIncludeLockingScriptsCode     uint8 = 1
	outputIncludeEntireTransactionsCode uint8 = 2
)

func SerializeListOutputsArgs(args *wallet.ListOutputsArgs) ([]byte, error) {
	w := util.NewWriter()

	// Basket is required
	w.WriteString(args.Basket)

	// Tags and query mode
	w.WriteStringSlice(args.Tags)
	switch args.TagQueryMode {
	case wallet.QueryModeAll:
		w.WriteByte(tagQueryModeAllCode)
	case wallet.QueryModeAny:
		w.WriteByte(tagQueryModeAnyCode)
	default:
		w.WriteNegativeOneByte()
	}

	// Include options
	switch args.Include {
	case wallet.OutputIncludeLockingScripts:
		w.WriteByte(outputIncludeLockingScriptsCode)
	case wallet.OutputIncludeEntireTransactions:
		w.WriteByte(outputIncludeEntireTransactionsCode)
	default:
		w.WriteNegativeOneByte()
	}

	w.WriteOptionalBool(args.IncludeCustomInstructions)
	w.WriteOptionalBool(args.IncludeTags)
	w.WriteOptionalBool(args.IncludeLabels)

	// Pagination
	w.WriteOptionalUint32(args.Limit)
	w.WriteOptionalUint32(args.Offset)
	w.WriteOptionalBool(args.SeekPermission)

	return w.Buf, nil
}

func DeserializeListOutputsArgs(data []byte) (*wallet.ListOutputsArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.ListOutputsArgs{}

	args.Basket = r.ReadString()
	args.Tags = r.ReadStringSlice()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading basket/tags: %w", r.Err)
	}

	switch r.ReadByte() {
	case tagQueryModeAllCode:
		args.TagQueryMode = wallet.QueryModeAll
	case tagQueryModeAnyCode:
		args.TagQueryMode = wallet.QueryModeAny
	}

	switch r.ReadByte() {
	case outputIncludeLockingScriptsCode:
		args.Include = wallet.OutputIncludeLockingScripts
	case outputIncludeEntireTransactionsCode:
		args.Include = wallet.OutputIncludeEntireTransactions
	}

	args.IncludeCustomInstructions = r.ReadOptionalBool()
	args.IncludeTags = r.ReadOptionalBool()
	args.IncludeLabels = r.ReadOptionalBool()
	args.Limit = r.ReadOptionalUint32()
	args.Offset = r.ReadOptionalUint32()
	args.SeekPermission = r.ReadOptionalBool()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading list outputs args: %w", r.Err)
	}

	return args, nil
}

func SerializeListOutputsResult(result *wallet.ListOutputsResult) ([]byte, error) {
	w := util.NewWriter()

	if uint32(len(result.Outputs)) != result.TotalOutputs {
		return nil, fmt.Errorf("total outputs %d does not match actual outputs %d", result.TotalOutputs, len(result.Outputs))
	}

	w.WriteVarInt(uint64(result.TotalOutputs))

	// Optional BEEF
	if result.BEEF != nil {
		w.WriteIntBytes(result.BEEF)
	} else {
		w.WriteNegativeOne()
	}

	// Outputs
	for _, output := range result.Outputs {
		// Serialize each output
		w.WriteBytes(encodeOutpoint(&output.Outpoint))
		w.WriteVarInt(output.Satoshis)
		if len(output.LockingScript) > 0 {
			w.WriteIntBytes(output.LockingScript)
		} else {
			w.WriteNegativeOne()
		}
		w.WriteOptionalString(output.CustomInstructions)
		w.WriteStringSlice(output.Tags)
		w.WriteStringSlice(output.Labels)
	}

	return w.Buf, nil
}

func DeserializeListOutputsResult(data []byte) (*wallet.ListOutputsResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ListOutputsResult{}

	result.TotalOutputs = r.ReadVarInt32()

	// Optional BEEF
	beefLen := r.ReadByte()
	if !util.IsNegativeOne(uint64(beefLen)) {
		result.BEEF = r.ReadBytes(int(beefLen))
	}

	// Outputs
	result.Outputs = make([]wallet.Output, 0, result.TotalOutputs)
	for i := uint32(0); i < result.TotalOutputs; i++ {
		outpoint, err := decodeOutpoint(&r.Reader)
		if err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", err)
		}
		sats := r.ReadVarInt()
		lockScriptByteLen := r.ReadVarInt()
		var lockingScript []byte
		if !util.IsNegativeOne(lockScriptByteLen) {
			lockingScript = r.ReadBytes(int(lockScriptByteLen))
		}
		output := wallet.Output{
			Outpoint:           *outpoint,
			Satoshis:           sats,
			LockingScript:      lockingScript,
			Spendable:          true, // Default to true, matches ts-sdk
			CustomInstructions: r.ReadString(),
			Tags:               r.ReadStringSlice(),
			Labels:             r.ReadStringSlice(),
		}
		// Check error each loop
		if r.Err != nil {
			return nil, fmt.Errorf("error reading output: %w", r.Err)
		}
		result.Outputs = append(result.Outputs, output)
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading list outputs result: %w", r.Err)
	}

	return result, nil
}

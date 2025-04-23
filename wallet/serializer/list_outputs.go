package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeListOutputsArgs(args *wallet.ListOutputsArgs) ([]byte, error) {
	w := util.NewWriter()

	// Basket is required
	w.WriteString(args.Basket)

	// Tags and query mode
	w.WriteStringSlice(args.Tags)
	w.WriteString(args.TagQueryMode)

	// Include options
	w.WriteString(args.Include)
	w.WriteOptionalBool(args.IncludeCustomInstructions)
	w.WriteOptionalBool(args.IncludeTags)
	w.WriteOptionalBool(args.IncludeLabels)

	// Pagination
	w.WriteVarInt(uint64(args.Limit))
	w.WriteVarInt(uint64(args.Offset))
	w.WriteOptionalBool(args.SeekPermission)

	return w.Buf, nil
}

func DeserializeListOutputsArgs(data []byte) (*wallet.ListOutputsArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.ListOutputsArgs{}

	args.Basket = r.ReadString()
	args.Tags = r.ReadStringSlice()
	args.TagQueryMode = r.ReadString()
	args.Include = r.ReadString()
	args.IncludeCustomInstructions = r.ReadOptionalBool()
	args.IncludeTags = r.ReadOptionalBool()
	args.IncludeLabels = r.ReadOptionalBool()
	args.Limit = r.ReadVarInt32()
	args.Offset = r.ReadVarInt32()
	args.SeekPermission = r.ReadOptionalBool()

	if r.Err != nil {
		return nil, fmt.Errorf("error reading list outputs args: %w", r.Err)
	}

	return args, nil
}

func SerializeListOutputsResult(result *wallet.ListOutputsResult) ([]byte, error) {
	w := util.NewWriter()

	w.WriteVarInt(uint64(result.TotalOutputs))

	// Optional BEEF
	if result.BEEF != nil {
		w.WriteByte(1)
		w.WriteVarInt(uint64(len(result.BEEF)))
		w.WriteBytes(result.BEEF)
	} else {
		w.WriteByte(0)
	}

	// Outputs
	w.WriteVarInt(uint64(len(result.Outputs)))
	for _, output := range result.Outputs {
		// Serialize each output
		w.WriteVarInt(output.Satoshis)
		w.WriteOptionalString(output.LockingScript)
		w.WriteOptionalBool(&output.Spendable)
		w.WriteOptionalString(output.CustomInstructions)
		w.WriteStringSlice(output.Tags)
		w.WriteString(output.Outpoint)
		w.WriteStringSlice(output.Labels)
	}

	return w.Buf, nil
}

func DeserializeListOutputsResult(data []byte) (*wallet.ListOutputsResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ListOutputsResult{}

	result.TotalOutputs = r.ReadVarInt32()

	// Optional BEEF
	if r.ReadByte() == 1 {
		beefLen := r.ReadVarInt()
		result.BEEF = r.ReadBytes(int(beefLen))
	}

	// Outputs
	outputCount := r.ReadVarInt()
	result.Outputs = make([]wallet.Output, 0, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		output := wallet.Output{
			Satoshis:           r.ReadVarInt(),
			LockingScript:      r.ReadString(),
			Spendable:          *r.ReadOptionalBool(),
			CustomInstructions: r.ReadString(),
			Tags:               r.ReadStringSlice(),
			Outpoint:           r.ReadString(),
			Labels:             r.ReadStringSlice(),
		}
		// Check error each loop
		if r.Err != nil {
			return nil, fmt.Errorf("error reading output: %w", r.Err)
		}
		result.Outputs = append(result.Outputs, output)
	}

	if r.Err != nil {
		return nil, fmt.Errorf("error reading list outputs result: %w", r.Err)
	}

	return result, nil
}

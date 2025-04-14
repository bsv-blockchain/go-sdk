package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeListOutputsArgs(args *wallet.ListOutputsArgs) ([]byte, error) {
	w := newWriter()

	// Basket is required
	w.writeString(args.Basket)

	// Tags and query mode
	w.writeStringSlice(args.Tags)
	w.writeString(args.TagQueryMode)

	// Include options
	w.writeString(args.Include)
	w.writeOptionalBool(args.IncludeCustomInstructions)
	w.writeOptionalBool(args.IncludeTags)
	w.writeOptionalBool(args.IncludeLabels)

	// Pagination
	w.writeVarInt(uint64(args.Limit))
	w.writeVarInt(uint64(args.Offset))
	w.writeOptionalBool(args.SeekPermission)

	return w.buf, nil
}

func DeserializeListOutputsArgs(data []byte) (*wallet.ListOutputsArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.ListOutputsArgs{}

	args.Basket = r.readString()
	args.Tags = r.readStringSlice()
	args.TagQueryMode = r.readString()
	args.Include = r.readString()
	args.IncludeCustomInstructions = r.readOptionalBool()
	args.IncludeTags = r.readOptionalBool()
	args.IncludeLabels = r.readOptionalBool()
	args.Limit = r.readVarInt32()
	args.Offset = r.readVarInt32()
	args.SeekPermission = r.readOptionalBool()

	if r.err != nil {
		return nil, fmt.Errorf("error reading list outputs args: %w", r.err)
	}

	return args, nil
}

func SerializeListOutputsResult(result *wallet.ListOutputsResult) ([]byte, error) {
	w := newWriter()

	w.writeVarInt(uint64(result.TotalOutputs))

	// Optional BEEF
	if result.BEEF != nil {
		w.writeByte(1)
		w.writeVarInt(uint64(len(result.BEEF)))
		w.writeBytes(result.BEEF)
	} else {
		w.writeByte(0)
	}

	// Outputs
	w.writeVarInt(uint64(len(result.Outputs)))
	for _, output := range result.Outputs {
		// Serialize each output
		w.writeVarInt(output.Satoshis)
		w.writeOptionalString(output.LockingScript)
		w.writeOptionalBool(&output.Spendable)
		w.writeOptionalString(output.CustomInstructions)
		w.writeStringSlice(output.Tags)
		w.writeString(output.Outpoint)
		w.writeStringSlice(output.Labels)
	}

	return w.buf, nil
}

func DeserializeListOutputsResult(data []byte) (*wallet.ListOutputsResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.ListOutputsResult{}

	result.TotalOutputs = r.readVarInt32()

	// Optional BEEF
	if r.readByte() == 1 {
		beefLen := r.readVarInt()
		result.BEEF = r.readBytes(int(beefLen))
	}

	// Outputs
	outputCount := r.readVarInt()
	result.Outputs = make([]wallet.Output, 0, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		output := wallet.Output{
			Satoshis:           r.readVarInt(),
			LockingScript:      r.readString(),
			Spendable:          *r.readOptionalBool(),
			CustomInstructions: r.readString(),
			Tags:               r.readStringSlice(),
			Outpoint:           r.readString(),
			Labels:             r.readStringSlice(),
		}
		// Check error each loop
		if r.err != nil {
			return nil, fmt.Errorf("error reading output: %w", r.err)
		}
		result.Outputs = append(result.Outputs, output)
	}

	if r.err != nil {
		return nil, fmt.Errorf("error reading list outputs result: %w", r.err)
	}

	return result, nil
}

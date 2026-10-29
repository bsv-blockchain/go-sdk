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

// listOutputsSpendableExtensionByte is the single trailing request byte that
// negotiates the "spendable" result encoding. It mirrors ts-stack's
// WalletWireTransceiver.#transmitListOutputs (params.writeUInt8(1)) and
// WalletWireProcessor ("Invalid listOutputs encoding extension: expected 1").
const listOutputsSpendableExtensionByte uint8 = 1

// SerializeListOutputsArgs serializes the listOutputs request args. When
// spendable is true, a single trailing 0x01 byte is appended to negotiate the
// opt-in "spendable" result encoding, matching current ts-stack
// (WalletWireTransceiver.#transmitListOutputs). Legacy peers omit the byte.
func SerializeListOutputsArgs(args *wallet.ListOutputsArgs, spendable bool) ([]byte, error) {
	w := util.NewWriter()

	// Basket is required
	w.WriteString(args.Basket)

	// Tags and query mode
	w.WriteStringSlice(args.Tags)
	switch args.TagQueryMode {
	case wallet.QueryModeAll:
		w.WriteByteValue(tagQueryModeAllCode)
	case wallet.QueryModeAny:
		w.WriteByteValue(tagQueryModeAnyCode)
	default:
		w.WriteNegativeOneByte()
	}

	// Include options
	switch args.Include {
	case wallet.OutputIncludeLockingScripts:
		w.WriteByteValue(outputIncludeLockingScriptsCode)
	case wallet.OutputIncludeEntireTransactions:
		w.WriteByteValue(outputIncludeEntireTransactionsCode)
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

	// Optional request extension selecting the spendable result layout.
	// Historical peers omit this byte; only request the extended layout
	// explicitly (mirrors ts-stack WalletWireTransceiver.#transmitListOutputs).
	if spendable {
		w.WriteByteValue(listOutputsSpendableExtensionByte)
	}

	return w.Buf, nil
}

// DeserializeListOutputsArgs deserializes the listOutputs request args. The
// returned bool reports whether the request negotiated the "spendable" result
// encoding via the optional trailing 0x01 byte. An unextended request leaves it
// false and keeps the deployed SDK 2/3 response bytes (mirrors ts-stack
// WalletWireProcessor: includeSpendable = !paramsReader.eof()).
func DeserializeListOutputsArgs(data []byte) (*wallet.ListOutputsArgs, bool, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.ListOutputsArgs{}

	args.Basket = r.ReadString()
	args.Tags = r.ReadStringSlice()
	if r.Err != nil {
		return nil, false, fmt.Errorf("error reading basket/tags: %w", r.Err)
	}

	switch r.ReadByteValue() {
	case tagQueryModeAllCode:
		args.TagQueryMode = wallet.QueryModeAll
	case tagQueryModeAnyCode:
		args.TagQueryMode = wallet.QueryModeAny
	}

	switch r.ReadByteValue() {
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
	if r.Err != nil {
		return nil, false, fmt.Errorf("error reading list outputs args: %w", r.Err)
	}

	// Optional request extension selecting the spendable result layout. The
	// deployed SDK 2/3 request stops here, so accept exactly zero or one
	// trailing byte rather than erroring on leftover data.
	spendable := false
	if !r.IsComplete() {
		b := r.ReadByteValue()
		if r.Err != nil {
			return nil, false, fmt.Errorf("error reading list outputs encoding extension: %w", r.Err)
		}
		if b != listOutputsSpendableExtensionByte {
			return nil, false, fmt.Errorf("invalid listOutputs encoding extension: expected 1, received %d", b)
		}
		spendable = true
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, false, fmt.Errorf("error reading list outputs args: %w", r.Err)
	}

	return args, spendable, nil
}

// SerializeListOutputsResult serializes the listOutputs result. When spendable
// is false the legacy SDK 2/3 layout is emitted unchanged. When spendable is
// true it mirrors ts-stack's WalletWireProcessor "spendable" layout: a leading
// -1 varint marker precedes totalOutputs, and each output carries an explicit
// Int8 spendable byte after its lockingScript. In legacy mode a non-spendable
// output is refused (matching ts-stack), since the legacy layout cannot carry
// spendability and must not silently read back as spendable.
func SerializeListOutputsResult(result *wallet.ListOutputsResult, spendable bool) ([]byte, error) {
	w := util.NewWriter()

	if uint32(len(result.Outputs)) != result.TotalOutputs { //nolint:gosec // G115 -- value is bounded by domain constraints
		return nil, fmt.Errorf("total outputs %d does not match actual outputs %d", result.TotalOutputs, len(result.Outputs))
	}

	if !spendable {
		for i := range result.Outputs {
			if !result.Outputs[i].Spendable {
				return nil, fmt.Errorf("non-spendable listOutputs records require the spendable encoding extension or JSON")
			}
		}
	}

	// A leading negative marker cannot be mistaken for a legacy output count,
	// so a spendable-aware reader can detect the extended layout.
	if spendable {
		w.WriteNegativeOne()
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
		// Spendability is explicit only on negotiated connections.
		if spendable {
			if output.Spendable {
				w.WriteByteValue(1)
			} else {
				w.WriteByteValue(0)
			}
		}
		w.WriteOptionalString(output.CustomInstructions)
		w.WriteStringSlice(output.Tags)
		w.WriteStringSlice(output.Labels)
	}

	return w.Buf, nil
}

// DeserializeListOutputsResult deserializes the listOutputs result. spendable
// must match the encoding negotiated by the request: when true the leading -1
// varint marker and the per-output Int8 spendable byte are read, mirroring
// ts-stack's WalletWireTransceiver spendable path. When false the legacy layout
// is read and every output defaults to spendable=true.
func DeserializeListOutputsResult(data []byte, spendable bool) (*wallet.ListOutputsResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ListOutputsResult{}

	// In spendable mode the result is prefixed with a -1 marker acknowledging
	// the negotiated encoding (ts-stack: "Missing listOutputs spendable
	// encoding acknowledgement").
	if spendable {
		marker := r.ReadVarInt()
		if r.Err != nil {
			return nil, fmt.Errorf("error reading list outputs spendable marker: %w", r.Err)
		}
		if !util.IsNegativeOne(marker) {
			return nil, fmt.Errorf("missing listOutputs spendable encoding acknowledgement")
		}
	}

	result.TotalOutputs = r.ReadVarInt32()

	// Optional BEEF
	beefLen := r.ReadVarInt()
	if !util.IsNegativeOne(beefLen) {
		result.BEEF = r.ReadBytes(int(beefLen)) //nolint:gosec // G115 -- value is bounded by domain constraints
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
			lockingScript = r.ReadBytes(int(lockScriptByteLen)) //nolint:gosec // G115 -- value is bounded by domain constraints
		}
		// Spendability is explicit only on negotiated connections; legacy
		// records default to spendable (matches ts-sdk).
		isSpendable := true
		if spendable {
			b := r.ReadByteValue()
			if r.Err != nil {
				return nil, fmt.Errorf("error reading output spendable flag: %w", r.Err)
			}
			if b != 0 && b != 1 {
				return nil, fmt.Errorf("invalid listOutputs spendable flag: expected 0 or 1, received %d", b)
			}
			isSpendable = b == 1
		}
		output := wallet.Output{
			Outpoint:           *outpoint,
			Satoshis:           sats,
			LockingScript:      lockingScript,
			Spendable:          isSpendable,
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

package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverByAttributesArgs(args *wallet.DiscoverByAttributesArgs) ([]byte, error) {
	w := newWriter()

	// Write attributes
	attributeKeys := make([]string, 0, len(args.Attributes))
	for k := range args.Attributes {
		attributeKeys = append(attributeKeys, k)
	}
	w.writeVarInt(uint64(len(attributeKeys)))
	for _, key := range attributeKeys {
		w.writeIntBytes([]byte(key))
		w.writeIntBytes([]byte(args.Attributes[key]))
	}

	// Write limit, offset, seek permission
	w.writeOptionalUint32(args.Limit)
	w.writeOptionalUint32(args.Offset)
	w.writeOptionalBool(args.SeekPermission)

	return w.buf, nil
}

func DeserializeDiscoverByAttributesArgs(data []byte) (*wallet.DiscoverByAttributesArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.DiscoverByAttributesArgs{
		Attributes: make(map[string]string),
	}

	// Read attributes
	attributesLength := r.readVarInt()
	for i := uint64(0); i < attributesLength; i++ {
		fieldKey := string(r.readIntBytes())
		fieldValue := string(r.readIntBytes())

		if r.err != nil {
			return nil, fmt.Errorf("error reading attribute %d: %w", i, r.err)
		}

		args.Attributes[fieldKey] = fieldValue
	}

	// Read limit, offset, seek permission
	args.Limit = r.readOptionalUint32()
	args.Offset = r.readOptionalUint32()
	args.SeekPermission = r.readOptionalBool()

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverByAttributes args: %w", r.err)
	}

	return args, nil
}

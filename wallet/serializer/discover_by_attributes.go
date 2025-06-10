package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

func SerializeDiscoverByAttributesArgs(args *wallet.DiscoverByAttributesArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write attributes
	attributeKeys := make([]string, 0, len(args.Attributes))
	for k := range args.Attributes {
		attributeKeys = append(attributeKeys, k)
	}
	w.WriteVarInt(uint64(len(attributeKeys)))
	for _, key := range attributeKeys {
		w.WriteIntBytes([]byte(key))
		w.WriteIntBytes([]byte(args.Attributes[key]))
	}

	// Write limit, offset, seek permission
	w.WriteOptionalUint32(args.Limit)
	w.WriteOptionalUint32(args.Offset)
	w.WriteOptionalBool(args.SeekPermission)

	return w.Buf, nil
}

func DeserializeDiscoverByAttributesArgs(data []byte) (*wallet.DiscoverByAttributesArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.DiscoverByAttributesArgs{
		Attributes: make(map[string]string),
	}

	// Read attributes
	attributesLength := r.ReadVarInt()
	for i := uint64(0); i < attributesLength; i++ {
		fieldKey := string(r.ReadIntBytes())
		fieldValue := string(r.ReadIntBytes())

		if r.Err != nil {
			return nil, fmt.Errorf("error reading attribute %d: %w", i, r.Err)
		}

		args.Attributes[fieldKey] = fieldValue
	}

	// Read limit, offset, seek permission
	args.Limit = r.ReadOptionalUint32()
	args.Offset = r.ReadOptionalUint32()
	args.SeekPermission = r.ReadOptionalBool()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverByAttributes args: %w", r.Err)
	}

	return args, nil
}

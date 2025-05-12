package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverByIdentityKeyArgs(args *wallet.DiscoverByIdentityKeyArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write identity key (33 bytes)
	if err := w.WriteSizeFromHex(args.IdentityKey, sizeIdentity); err != nil {
		return nil, fmt.Errorf("invalid identityKey hex: %w", err)
	}

	// Write limit, offset, seek permission
	w.WriteOptionalUint32(args.Limit)
	w.WriteOptionalUint32(args.Offset)
	w.WriteOptionalBool(args.SeekPermission)

	return w.Buf, nil
}

func DeserializeDiscoverByIdentityKeyArgs(data []byte) (*wallet.DiscoverByIdentityKeyArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.DiscoverByIdentityKeyArgs{}

	// Read identity key (33 bytes)
	args.IdentityKey = r.ReadHex(sizeIdentity)

	// Read limit
	args.Limit = r.ReadOptionalUint32()
	args.Offset = r.ReadOptionalUint32()
	args.SeekPermission = r.ReadOptionalBool()

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverByIdentityKey args: %w", r.Err)
	}

	return args, nil
}

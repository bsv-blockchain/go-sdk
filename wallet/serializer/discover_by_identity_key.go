package serializer

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverByIdentityKeyArgs(args *wallet.DiscoverByIdentityKeyArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write identity key (33 bytes)
	identityKeyBytes, err := hex.DecodeString(args.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identityKey hex: %w", err)
	}
	if len(identityKeyBytes) != 33 {
		return nil, fmt.Errorf("identityKey must be 33 bytes")
	}
	w.WriteBytes(identityKeyBytes)

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
	identityKeyBytes := r.ReadBytes(33)
	args.IdentityKey = hex.EncodeToString(identityKeyBytes)

	// Read limit (varint) or 9 bytes of 0xFF if undefined
	args.Limit = r.ReadOptionalUint32()
	args.Offset = r.ReadOptionalUint32()
	args.SeekPermission = r.ReadOptionalBool()

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverByIdentityKey args: %w", r.Err)
	}

	return args, nil
}

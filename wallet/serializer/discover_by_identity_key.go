package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverByIdentityKeyArgs(args *wallet.DiscoverByIdentityKeyArgs) ([]byte, error) {
	w := newWriter()

	// Write identity key (33 bytes)
	identityKeyBytes, err := hex.DecodeString(args.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identityKey hex: %w", err)
	}
	if len(identityKeyBytes) != 33 {
		return nil, fmt.Errorf("identityKey must be 33 bytes")
	}
	w.writeBytes(identityKeyBytes)

	// Write limit, offset, seek permission
	w.writeOptionalUint32(args.Limit)
	w.writeOptionalUint32(args.Offset)
	w.writeOptionalBool(args.SeekPermission)

	return w.buf, nil
}

func DeserializeDiscoverByIdentityKeyArgs(data []byte) (*wallet.DiscoverByIdentityKeyArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.DiscoverByIdentityKeyArgs{}

	// Read identity key (33 bytes)
	identityKeyBytes := r.readBytes(33)
	args.IdentityKey = hex.EncodeToString(identityKeyBytes)

	// Read limit (varint) or 9 bytes of 0xFF if undefined
	args.Limit = r.readOptionalUint32()
	args.Offset = r.readOptionalUint32()
	args.SeekPermission = r.readOptionalBool()

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverByIdentityKey args: %w", r.err)
	}

	return args, nil
}

package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeVerifyHMACArgs(args *wallet.VerifyHMACArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode key related params (protocol, key, counterparty, privileged)
	params := KeyRelatedParams{
		ProtocolID:       args.ProtocolID,
		KeyID:            args.KeyID,
		Counterparty:     args.Counterparty,
		Privileged:       &args.Privileged,
		PrivilegedReason: args.PrivilegedReason,
	}
	keyParams, err := encodeKeyRelatedParams(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding key params: %w", err)
	}
	w.WriteBytes(keyParams)

	// Write HMAC bytes (fixed 32 bytes)
	w.WriteBytes(args.HMAC[:])

	// Write data length + bytes
	w.WriteIntBytes(args.Data)

	// Write seekPermission flag
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeVerifyHMACArgs(data []byte) (*wallet.VerifyHMACArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.VerifyHMACArgs{}

	// Decode key related params
	params, err := decodeKeyRelatedParams(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding key params: %w", err)
	}
	args.ProtocolID = params.ProtocolID
	args.KeyID = params.KeyID
	args.Counterparty = params.Counterparty
	args.Privileged = util.ReadOptionalBoolAsBool(params.Privileged)
	args.PrivilegedReason = params.PrivilegedReason

	// Read HMAC (fixed 32 bytes)
	copy(args.HMAC[:], r.ReadBytes(32))

	// Read data
	args.Data = r.ReadIntBytes()

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing VerifyHMAC args: %w", r.Err)
	}

	return args, nil
}

func SerializeVerifyHMACResult(_ *wallet.VerifyHMACResult) ([]byte, error) {
	return nil, nil
}

func DeserializeVerifyHMACResult(_ []byte) (*wallet.VerifyHMACResult, error) {
	return &wallet.VerifyHMACResult{Valid: true}, nil
}

package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeVerifyHmacArgs(args *wallet.VerifyHmacArgs) ([]byte, error) {
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
	w.WriteBytes(args.Hmac)

	// Write data length + bytes
	w.WriteVarInt(uint64(len(args.Data)))
	w.WriteBytes(args.Data)

	// Write seekPermission flag
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeVerifyHmacArgs(data []byte) (*wallet.VerifyHmacArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.VerifyHmacArgs{}

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
	args.Hmac = r.ReadBytes(32)

	// Read data
	dataLen := r.ReadVarInt()
	args.Data = r.ReadBytes(int(dataLen))

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing VerifyHmac args: %w", r.Err)
	}

	return args, nil
}

func SerializeVerifyHmacResult(result *wallet.VerifyHmacResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	return w.Buf, nil
}

func DeserializeVerifyHmacResult(data []byte) (*wallet.VerifyHmacResult, error) {
	r := util.NewReaderHoldError(data)

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("verifyHmac failed with error byte %d", errorByte)
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing VerifyHmac result: %w", r.Err)
	}

	return &wallet.VerifyHmacResult{Valid: true}, nil
}

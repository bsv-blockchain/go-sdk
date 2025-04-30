package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeCreateHmacArgs(args *wallet.CreateHmacArgs) ([]byte, error) {
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

	// Write data length + bytes
	w.WriteVarInt(uint64(len(args.Data)))
	w.WriteBytes(args.Data)

	// Write seekPermission flag (-1 if undefined)
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeCreateHmacArgs(data []byte) (*wallet.CreateHmacArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.CreateHmacArgs{}

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

	// Read data
	dataLen := r.ReadVarInt()
	args.Data = r.ReadBytes(int(dataLen))

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing CreateHmac args: %w", r.Err)
	}

	return args, nil
}

func SerializeCreateHmacResult(result *wallet.CreateHmacResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	w.WriteBytes(result.Hmac)
	return w.Buf, nil
}

func DeserializeCreateHmacResult(data []byte) (*wallet.CreateHmacResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.CreateHmacResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("createHmac failed with error byte %d", errorByte)
	}

	// Read hmac (remaining bytes)
	result.Hmac = r.ReadRemaining()

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing CreateHmac result: %w", r.Err)
	}

	return result, nil
}

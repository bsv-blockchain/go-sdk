package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

func SerializeCreateHMACArgs(args *wallet.CreateHMACArgs) ([]byte, error) {
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

	// Write seekPermission flag
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeCreateHMACArgs(data []byte) (*wallet.CreateHMACArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.CreateHMACArgs{}

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
		return nil, fmt.Errorf("error deserializing CreateHMAC args: %w", r.Err)
	}

	return args, nil
}

func SerializeCreateHMACResult(result *wallet.CreateHMACResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	w.WriteBytes(result.HMAC)
	return w.Buf, nil
}

func DeserializeCreateHMACResult(data []byte) (*wallet.CreateHMACResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.CreateHMACResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("createHMAC failed with error byte %d", errorByte)
	}

	// Read hmac (remaining bytes)
	result.HMAC = r.ReadRemaining()

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing CreateHMAC result: %w", r.Err)
	}

	return result, nil
}

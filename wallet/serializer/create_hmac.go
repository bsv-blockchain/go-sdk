package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeCreateHmacArgs(args *wallet.CreateHmacArgs) ([]byte, error) {
	w := newWriter()

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
	w.writeBytes(keyParams)

	// Write data length + bytes
	w.writeVarInt(uint64(len(args.Data)))
	w.writeBytes(args.Data)

	// Write seekPermission flag (-1 if undefined)
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

func DeserializeCreateHmacArgs(data []byte) (*wallet.CreateHmacArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.CreateHmacArgs{}

	// Decode key related params
	params, err := decodeKeyRelatedParams(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding key params: %w", err)
	}
	args.ProtocolID = params.ProtocolID
	args.KeyID = params.KeyID
	args.Counterparty = params.Counterparty
	args.Privileged = readOptionalBoolAsBool(params.Privileged)
	args.PrivilegedReason = params.PrivilegedReason

	// Read data
	dataLen := r.readVarInt()
	args.Data = r.readBytes(int(dataLen))

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing CreateHmac args: %w", r.err)
	}

	return args, nil
}

func SerializeCreateHmacResult(result *wallet.CreateHmacResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	w.writeBytes(result.Hmac)
	return w.buf, nil
}

func DeserializeCreateHmacResult(data []byte) (*wallet.CreateHmacResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.CreateHmacResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("createHmac failed with error byte %d", errorByte)
	}

	// Read hmac (remaining bytes)
	result.Hmac = r.readRemaining()

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing CreateHmac result: %w", r.err)
	}

	return result, nil
}

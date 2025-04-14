package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeVerifyHmacArgs(args *wallet.VerifyHmacArgs) ([]byte, error) {
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

	// Write HMAC bytes (fixed 32 bytes)
	w.writeBytes(args.Hmac)

	// Write data length + bytes
	w.writeVarInt(uint64(len(args.Data)))
	w.writeBytes(args.Data)

	// Write seekPermission flag (-1 if undefined)
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

func DeserializeVerifyHmacArgs(data []byte) (*wallet.VerifyHmacArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.VerifyHmacArgs{}

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

	// Read HMAC (fixed 32 bytes)
	args.Hmac = r.readBytes(32)

	// Read data
	dataLen := r.readVarInt()
	args.Data = r.readBytes(int(dataLen))

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing VerifyHmac args: %w", r.err)
	}

	return args, nil
}

func SerializeVerifyHmacResult(result *wallet.VerifyHmacResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	return w.buf, nil
}

func DeserializeVerifyHmacResult(data []byte) (*wallet.VerifyHmacResult, error) {
	r := newReaderHoldError(data)

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("verifyHmac failed with error byte %d", errorByte)
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing VerifyHmac result: %w", r.err)
	}

	return &wallet.VerifyHmacResult{Valid: true}, nil
}

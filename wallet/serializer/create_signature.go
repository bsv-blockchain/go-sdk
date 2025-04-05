package serializer

import (
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeCreateSignatureArgs(args *wallet.CreateSignatureArgs) ([]byte, error) {
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

	// Write data or hash flag and content
	if args.Data != nil {
		w.writeByte(1)
		w.writeVarInt(uint64(len(args.Data)))
		w.writeBytes(args.Data)
	} else {
		w.writeByte(2)
		w.writeBytes(args.HashToDirectlySign)
	}

	// Write seekPermission flag (-1 if undefined)
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

func DeserializeCreateSignatureArgs(data []byte) (*wallet.CreateSignatureArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.CreateSignatureArgs{}

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

	// Read data or hash
	dataTypeFlag := r.readByte()
	if dataTypeFlag == 1 {
		dataLen := r.readVarInt()
		args.Data = r.readBytes(int(dataLen))
	} else if dataTypeFlag == 2 {
		args.HashToDirectlySign = r.readBytes(32)
	} else {
		return nil, fmt.Errorf("invalid data type flag: %d", dataTypeFlag)
	}

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing CreateSignature args: %w", r.err)
	}

	return args, nil
}

func SerializeCreateSignatureResult(result *wallet.CreateSignatureResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	w.writeBytes(result.Signature.Serialize())
	return w.buf, nil
}

func DeserializeCreateSignatureResult(data []byte) (*wallet.CreateSignatureResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.CreateSignatureResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("createSignature failed with error byte %d", errorByte)
	}

	// Read signature (remaining bytes)
	sig, err := ec.FromDER(r.readRemaining())
	if err != nil {
		return nil, fmt.Errorf("error deserializing signature: %w", err)
	}
	result.Signature = *sig

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing CreateSignature result: %w", r.err)
	}

	return result, nil
}

package serializer

import (
	"crypto/sha256"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeVerifySignatureArgs(args *wallet.VerifySignatureArgs) ([]byte, error) {
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

	// Write forSelf flag
	w.writeOptionalBool(&args.ForSelf)

	// Write signature length + bytes
	w.writeIntBytes(args.Signature.Serialize())

	// Write data or hash flag and content
	if len(args.Data) > 0 {
		w.writeByte(1)
		w.writeIntBytes(args.Data)
	} else if len(args.HashToDirectlyVerify) == sha256.Size {
		w.writeByte(2)
		w.writeBytes(args.HashToDirectlyVerify)
	} else {
		return nil, fmt.Errorf("invalid data or hash to directly verify")
	}

	// Write seekPermission flag (-1 if undefined)
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

func DeserializeVerifySignatureArgs(data []byte) (*wallet.VerifySignatureArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.VerifySignatureArgs{}

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

	// Read forSelf flag
	args.ForSelf = readOptionalBoolAsBool(r.readOptionalBool())

	// Read signature
	sig, err := ec.FromDER(r.readIntBytes())
	if err != nil {
		return nil, fmt.Errorf("error reading signature: %w", err)
	}
	args.Signature = *sig

	// Read data or hash
	dataTypeFlag := r.readByte()
	if dataTypeFlag == 1 {
		args.Data = r.readIntBytes()
	} else if dataTypeFlag == 2 {
		args.HashToDirectlyVerify = r.readBytes(sha256.Size)
	} else {
		return nil, fmt.Errorf("invalid data type flag: %d", dataTypeFlag)
	}

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing VerifySignature args: %w", r.err)
	}

	return args, nil
}

func SerializeVerifySignatureResult(result *wallet.VerifySignatureResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	if result.Valid {
		w.writeByte(1) // valid = true
	} else {
		w.writeByte(0) // valid = false
	}
	return w.buf, nil
}

func DeserializeVerifySignatureResult(data []byte) (*wallet.VerifySignatureResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.VerifySignatureResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("verifySignature failed with error byte %d", errorByte)
	}

	// Read valid flag
	valid := r.readByte()
	result.Valid = valid == 1

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing VerifySignature result: %w", r.err)
	}

	return result, nil
}

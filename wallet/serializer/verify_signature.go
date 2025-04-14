package serializer

import (
	"crypto/sha256"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeVerifySignatureArgs(args *wallet.VerifySignatureArgs) ([]byte, error) {
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

	// Write forSelf flag
	w.WriteOptionalBool(&args.ForSelf)

	// Write signature length + bytes
	w.WriteIntBytes(args.Signature.Serialize())

	// Write data or hash flag and content
	if len(args.Data) > 0 {
		w.WriteByte(1)
		w.WriteIntBytes(args.Data)
	} else if len(args.HashToDirectlyVerify) == sha256.Size {
		w.WriteByte(2)
		w.WriteBytes(args.HashToDirectlyVerify)
	} else {
		return nil, fmt.Errorf("invalid data or hash to directly verify")
	}

	// Write seekPermission flag (-1 if undefined)
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeVerifySignatureArgs(data []byte) (*wallet.VerifySignatureArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.VerifySignatureArgs{}

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

	// Read forSelf flag
	args.ForSelf = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	// Read signature
	sig, err := ec.FromDER(r.ReadIntBytes())
	if err != nil {
		return nil, fmt.Errorf("error reading signature: %w", err)
	}
	args.Signature = *sig

	// Read data or hash
	dataTypeFlag := r.ReadByte()
	if dataTypeFlag == 1 {
		args.Data = r.ReadIntBytes()
	} else if dataTypeFlag == 2 {
		args.HashToDirectlyVerify = r.ReadBytes(sha256.Size)
	} else {
		return nil, fmt.Errorf("invalid data type flag: %d", dataTypeFlag)
	}

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing VerifySignature args: %w", r.Err)
	}

	return args, nil
}

func SerializeVerifySignatureResult(result *wallet.VerifySignatureResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	if result.Valid {
		w.WriteByte(1) // valid = true
	} else {
		w.WriteByte(0) // valid = false
	}
	return w.Buf, nil
}

func DeserializeVerifySignatureResult(data []byte) (*wallet.VerifySignatureResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.VerifySignatureResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("verifySignature failed with error byte %d", errorByte)
	}

	// Read valid flag
	valid := r.ReadByte()
	result.Valid = valid == 1

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing VerifySignature result: %w", r.Err)
	}

	return result, nil
}

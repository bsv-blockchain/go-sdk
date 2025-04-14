package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeEncryptArgs(args *wallet.EncryptArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode key related params (protocol, key, counterparty, privileged)
	params := KeyRelatedParams{
		ProtocolID:       args.ProtocolID,
		KeyID:            args.KeyID,
		Counterparty:     args.Counterparty,
		Privileged:       &args.Privileged,
		PrivilegedReason: args.PrivilegedReason,
	}
	paramBytes, err := encodeKeyRelatedParams(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding key params: %w", err)
	}
	w.WriteBytes(paramBytes)

	// Write plaintext length and data
	w.WriteVarInt(uint64(len(args.Plaintext)))
	w.WriteBytes(args.Plaintext)

	// Write seekPermission flag (-1 for undefined, 0 for false, 1 for true)
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeEncryptArgs(data []byte) (*wallet.EncryptArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.EncryptArgs{}

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

	// Read plaintext
	plaintextLen := r.ReadVarInt()
	args.Plaintext = r.ReadBytes(int(plaintextLen))

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	if r.Err != nil {
		return nil, fmt.Errorf("error decrypting encrypt args: %w", r.Err)
	}

	return args, nil
}

func SerializeEncryptResult(result *wallet.EncryptResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	w.WriteBytes(result.Ciphertext)
	return w.Buf, nil
}

func DeserializeEncryptResult(data []byte) (*wallet.EncryptResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.EncryptResult{}

	// Read error byte (0 = success)
	if errByte := r.ReadByte(); errByte != 0 {
		return nil, fmt.Errorf("encrypt failed with error byte %d", errByte)
	}

	// Read ciphertext (remaining bytes)
	result.Ciphertext = r.ReadRemaining()

	if r.Err != nil {
		return nil, fmt.Errorf("error decrypting encrypt result: %w", r.Err)
	}

	return result, nil
}

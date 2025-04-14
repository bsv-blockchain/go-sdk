package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeEncryptArgs(args *wallet.EncryptArgs) ([]byte, error) {
	w := newWriter()

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
	w.writeBytes(paramBytes)

	// Write plaintext length and data
	w.writeVarInt(uint64(len(args.Plaintext)))
	w.writeBytes(args.Plaintext)

	// Write seekPermission flag (-1 for undefined, 0 for false, 1 for true)
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

func DeserializeEncryptArgs(data []byte) (*wallet.EncryptArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.EncryptArgs{}

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

	// Read plaintext
	plaintextLen := r.readVarInt()
	args.Plaintext = r.readBytes(int(plaintextLen))

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error decrypting encrypt args: %w", r.err)
	}

	return args, nil
}

func SerializeEncryptResult(result *wallet.EncryptResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	w.writeBytes(result.Ciphertext)
	return w.buf, nil
}

func DeserializeEncryptResult(data []byte) (*wallet.EncryptResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.EncryptResult{}

	// Read error byte (0 = success)
	if errByte := r.readByte(); errByte != 0 {
		return nil, fmt.Errorf("encrypt failed with error byte %d", errByte)
	}

	// Read ciphertext (remaining bytes)
	result.Ciphertext = r.readRemaining()

	if r.err != nil {
		return nil, fmt.Errorf("error decrypting encrypt result: %w", r.err)
	}

	return result, nil
}

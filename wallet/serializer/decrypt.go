package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDecryptArgs(args *wallet.DecryptArgs) ([]byte, error) {
	w := newWriter()

	// Encode key related params (protocol, key, counterparty, privileged)
	params := KeyRelatedParams{
		ProtocolID:       args.ProtocolID,
		KeyID:           args.KeyID,
		Counterparty:     args.Counterparty,
		Privileged:       &args.Privileged,
		PrivilegedReason: args.PrivilegedReason,
	}
	keyParams, err := encodeKeyRelatedParams(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding key params: %w", err)
	}
	w.writeBytes(keyParams)

	// Write ciphertext length + bytes
	w.writeVarInt(uint64(len(args.Ciphertext)))
	w.writeBytes(args.Ciphertext)

	// Write seekPermission flag (-1 if undefined)
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

func DeserializeDecryptArgs(data []byte) (*wallet.DecryptArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.DecryptArgs{}

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

	// Read ciphertext
	ciphertextLen := r.readVarInt()
	args.Ciphertext = r.readBytes(int(ciphertextLen))

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error decrypting args: %w", r.err)
	}

	return args, nil
}

func SerializeDecryptResult(result *wallet.DecryptResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	w.writeBytes(result.Plaintext)
	return w.buf, nil
}

func DeserializeDecryptResult(data []byte) (*wallet.DecryptResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.DecryptResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("decrypt failed with error byte %d", errorByte)
	}

	// Read plaintext (remaining bytes)
	result.Plaintext = r.readRemaining()

	if r.err != nil {
		return nil, fmt.Errorf("error decrypting result: %w", r.err)
	}

	return result, nil
}

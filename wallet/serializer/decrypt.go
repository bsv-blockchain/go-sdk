package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDecryptArgs(args *wallet.DecryptArgs) ([]byte, error) {
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

	// Write ciphertext length + bytes
	w.WriteVarInt(uint64(len(args.Ciphertext)))
	w.WriteBytes(args.Ciphertext)

	// Write seekPermission flag (-1 if undefined)
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

func DeserializeDecryptArgs(data []byte) (*wallet.DecryptArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.DecryptArgs{}

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

	// Read ciphertext
	ciphertextLen := r.ReadVarInt()
	args.Ciphertext = r.ReadBytes(int(ciphertextLen))

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error decrypting args: %w", r.Err)
	}

	return args, nil
}

func SerializeDecryptResult(result *wallet.DecryptResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	w.WriteBytes(result.Plaintext)
	return w.Buf, nil
}

func DeserializeDecryptResult(data []byte) (*wallet.DecryptResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.DecryptResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("decrypt failed with error byte %d", errorByte)
	}

	// Read plaintext (remaining bytes)
	result.Plaintext = r.ReadRemaining()

	if r.Err != nil {
		return nil, fmt.Errorf("error decrypting result: %w", r.Err)
	}

	return result, nil
}

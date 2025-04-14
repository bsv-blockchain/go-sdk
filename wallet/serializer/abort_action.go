package serializer

import (
	"encoding/base64"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeAbortActionArgs(args *wallet.AbortActionArgs) ([]byte, error) {
	w := newWriter()

	// Serialize reference
	ref, err := base64.StdEncoding.DecodeString(args.Reference)
	if err != nil {
		return nil, fmt.Errorf("invalid reference base64: %w", err)
	}
	w.writeVarInt(uint64(len(ref)))
	w.writeBytes(ref)

	return w.buf, nil
}

func DeserializeAbortActionArgs(data []byte) (*wallet.AbortActionArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.AbortActionArgs{}

	// Read reference
	refLen := r.readVarInt()
	reference := r.readBytes(int(refLen))
	args.Reference = base64.StdEncoding.EncodeToString(reference)

	if r.err != nil {
		return nil, fmt.Errorf("error reading abort action args: %w", r.err)
	}

	return args, nil
}

func SerializeAbortActionResult(result *wallet.AbortActionResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	return w.buf, nil
}

func DeserializeAbortActionResult(data []byte) (*wallet.AbortActionResult, error) {
	r := newReaderHoldError(data)

	// Read error byte
	errorByte := r.readByte()
	if errorByte != 0 {
		// Read error message if present
		msgLen := r.readVarInt()
		msg := r.readBytes(int(msgLen))
		return nil, fmt.Errorf("abort action failed: %s", string(msg))
	}

	return &wallet.AbortActionResult{
		Aborted: true,
	}, nil
}

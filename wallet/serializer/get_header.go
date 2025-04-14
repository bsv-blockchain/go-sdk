package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetHeaderArgs(args *wallet.GetHeaderArgs) ([]byte, error) {
	w := newWriter()
	w.writeVarInt(uint64(args.Height))
	return w.buf, nil
}

func DeserializeGetHeaderArgs(data []byte) (*wallet.GetHeaderArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.GetHeaderArgs{
		Height: r.readVarInt32(),
	}
	if r.err != nil {
		return nil, fmt.Errorf("error deserializing GetHeaderArgs: %w", r.err)
	}
	return args, nil
}

func SerializeGetHeaderResult(result *wallet.GetHeaderResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0
	headerBytes, err := hex.DecodeString(result.Header)
	if err != nil {
		return nil, fmt.Errorf("invalid header hex: %w", err)
	}
	w.writeBytes(headerBytes)
	return w.buf, nil
}

func DeserializeGetHeaderResult(data []byte) (*wallet.GetHeaderResult, error) {
	r := newReaderHoldError(data)

	// Read error byte (must be 0 for success)
	if errByte := r.readByte(); errByte != 0 {
		return nil, fmt.Errorf("error byte indicates failure: %d", errByte)
	}

	// Read remaining bytes as header
	headerBytes := r.readRemaining()
	if r.err != nil {
		return nil, fmt.Errorf("error reading header bytes: %w", r.err)
	}

	return &wallet.GetHeaderResult{
		Header: hex.EncodeToString(headerBytes),
	}, nil
}

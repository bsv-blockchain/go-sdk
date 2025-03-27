package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// WriteRequestFrame writes a call frame with call type, originator and params
func WriteRequestFrame(call byte, originator string, params []byte) []byte {
	frame := make([]byte, 0)
	frameWriter := newWriter(&frame)

	// Write call type byte
	frameWriter.writeByte(call)

	// Write originator length and bytes
	originatorBytes := []byte(originator)
	frameWriter.writeByte(byte(len(originatorBytes)))
	frameWriter.writeBytes(originatorBytes)

	// Write params if present
	if len(params) > 0 {
		frameWriter.writeBytes(params)
	}

	return frame
}

// ReadResultFrame reads a response frame and returns either the result or error
func ReadResultFrame(data []byte) ([]byte, error) {
	frameReader := newReader(data)

	// Check error byte
	errorByte, err := frameReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %v", err)
	}

	if errorByte != 0 {
		// Read error message
		errorMsgLen, err := frameReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading error message length: %v", err)
		}
		errorMsgBytes, err := frameReader.readBytes(int(errorMsgLen))
		if err != nil {
			return nil, fmt.Errorf("error reading error message: %v", err)
		}
		errorMsg := string(errorMsgBytes)

		// Read stack trace
		stackTraceLen, err := frameReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace length: %v", err)
		}
		stackTraceBytes, err := frameReader.readBytes(int(stackTraceLen))
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace: %v", err)
		}
		stackTrace := string(stackTraceBytes)

		return nil, &wallet.Error{
			Code:    errorByte,
			Message: errorMsg,
			Stack:   stackTrace,
		}
	}

	// Return result frame
	return frameReader.readRemaining(), nil
}

package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type RequestFrame struct {
	Call       byte
	Originator string
	Params     []byte
}

// WriteRequestFrame writes a call frame with call type, originator and params
func WriteRequestFrame(requestFrame RequestFrame) []byte {
	frame := make([]byte, 0)
	frameWriter := newWriter(&frame)

	// Write call type byte
	frameWriter.writeByte(requestFrame.Call)

	// Write originator length and bytes
	originatorBytes := []byte(requestFrame.Originator)
	frameWriter.writeByte(byte(len(originatorBytes)))
	frameWriter.writeBytes(originatorBytes)

	// Write params if present
	if len(requestFrame.Params) > 0 {
		frameWriter.writeBytes(requestFrame.Params)
	}

	return frame
}

// ReadRequestFrame reads a request frame and returns call type, originator and params
func ReadRequestFrame(data []byte) (*RequestFrame, error) {
	frameReader := newReader(data)

	// Read call type byte
	call, err := frameReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading call byte: %v", err)
	}

	// Read originator length and bytes
	originatorLen, err := frameReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading originator length: %v", err)
	}
	originatorBytes, err := frameReader.readBytes(int(originatorLen))
	if err != nil {
		return nil, fmt.Errorf("error reading originator: %v", err)
	}
	originator := string(originatorBytes)

	// Remaining bytes are params
	params := frameReader.readRemaining()

	return &RequestFrame{
		Call:       call,
		Originator: originator,
		Params:     params,
	}, nil
}

// WriteResultFrame writes a result frame with either success data or an error
func WriteResultFrame(result []byte, err *wallet.Error) []byte {
	frame := make([]byte, 0)
	frameWriter := newWriter(&frame)

	if err != nil {
		// Write error byte
		frameWriter.writeByte(err.Code)

		// Write error message
		errorMsgBytes := []byte(err.Message)
		frameWriter.writeVarInt(uint64(len(errorMsgBytes)))
		frameWriter.writeBytes(errorMsgBytes)

		// Write stack trace
		stackBytes := []byte(err.Stack)
		frameWriter.writeVarInt(uint64(len(stackBytes)))
		frameWriter.writeBytes(stackBytes)
	} else {
		// Write success byte (0)
		frameWriter.writeByte(0)

		// Write result data if present
		if len(result) > 0 {
			frameWriter.writeBytes(result)
		}
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

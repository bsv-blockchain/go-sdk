package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type RequestFrame struct {
	Call       byte
	Originator string
	Params     []byte
}

// WriteRequestFrame writes a call frame with call type, originator and params
func WriteRequestFrame(requestFrame RequestFrame) []byte {
	frameWriter := util.NewWriter()

	// Write call type byte
	frameWriter.WriteByte(requestFrame.Call)

	// Write originator length and bytes
	originatorBytes := []byte(requestFrame.Originator)
	frameWriter.WriteByte(byte(len(originatorBytes)))
	frameWriter.WriteBytes(originatorBytes)

	// Write params if present
	if len(requestFrame.Params) > 0 {
		frameWriter.WriteBytes(requestFrame.Params)
	}

	return frameWriter.Buf
}

// ReadRequestFrame reads a request frame and returns call type, originator and params
func ReadRequestFrame(data []byte) (*RequestFrame, error) {
	frameReader := util.NewReader(data)

	// Read call type byte
	call, err := frameReader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading call byte: %w", err)
	}

	// Read originator length and bytes
	originatorLen, err := frameReader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading originator length: %w", err)
	}
	originatorBytes, err := frameReader.ReadBytes(int(originatorLen))
	if err != nil {
		return nil, fmt.Errorf("error reading originator: %w", err)
	}
	originator := string(originatorBytes)

	// Remaining bytes are params
	params := frameReader.ReadRemaining()

	return &RequestFrame{
		Call:       call,
		Originator: originator,
		Params:     params,
	}, nil
}

// WriteResultFrame writes a result frame with either success data or an error
func WriteResultFrame(result []byte, err *wallet.Error) []byte {
	frameWriter := util.NewWriter()

	if err != nil {
		// Write error byte
		frameWriter.WriteByte(err.Code)

		// Write error message
		errorMsgBytes := []byte(err.Message)
		frameWriter.WriteVarInt(uint64(len(errorMsgBytes)))
		frameWriter.WriteBytes(errorMsgBytes)

		// Write stack trace
		stackBytes := []byte(err.Stack)
		frameWriter.WriteVarInt(uint64(len(stackBytes)))
		frameWriter.WriteBytes(stackBytes)
	} else {
		// Write success byte (0)
		frameWriter.WriteByte(0)

		// Write result data if present
		if len(result) > 0 {
			frameWriter.WriteBytes(result)
		}
	}

	return frameWriter.Buf
}

// ReadResultFrame reads a response frame and returns either the result or error
func ReadResultFrame(data []byte) ([]byte, error) {
	frameReader := util.NewReader(data)

	// Check error byte
	errorByte, err := frameReader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %w", err)
	}

	if errorByte != 0 {
		// Read error message
		errorMsgLen, err := frameReader.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading error message length: %w", err)
		}
		errorMsgBytes, err := frameReader.ReadBytes(int(errorMsgLen))
		if err != nil {
			return nil, fmt.Errorf("error reading error message: %w", err)
		}
		errorMsg := string(errorMsgBytes)

		// Read stack trace
		stackTraceLen, err := frameReader.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace length: %w", err)
		}
		stackTraceBytes, err := frameReader.ReadBytes(int(stackTraceLen))
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace: %w", err)
		}
		stackTrace := string(stackTraceBytes)

		return nil, &wallet.Error{
			Code:    errorByte,
			Message: errorMsg,
			Stack:   stackTrace,
		}
	}

	// Return result frame
	return frameReader.ReadRemaining(), nil
}

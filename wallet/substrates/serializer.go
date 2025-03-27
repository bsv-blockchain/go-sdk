package substrates

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"strings"
)

// writer is a helper for building binary messages
type writer struct {
	buf *[]byte
}

func newWriter(buf *[]byte) *writer {
	return &writer{buf: buf}
}

func (w *writer) writeByte(b byte) {
	*w.buf = append(*w.buf, b)
}

func (w *writer) writeBytes(b []byte) {
	*w.buf = append(*w.buf, b...)
}

func (w *writer) writeVarInt(n uint64) {
	var buf [binary.MaxVarintLen64]byte
	size := binary.PutUvarint(buf[:], n)
	w.writeBytes(buf[:size])
}

type reader struct {
	data []byte
	pos  int
}

func newReader(data []byte) *reader {
	return &reader{data: data}
}

func (r *reader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("read past end of data")
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) readBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, errors.New("read past end of data")
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *reader) readVarInt() (uint64, error) {
	return binary.ReadUvarint(r)
}

func (r *reader) ReadByte() (byte, error) {
	return r.readByte()
}

// encodeOutpoint converts outpoint string "txid.index" to binary format
func encodeOutpoint(outpoint string) ([]byte, error) {
	parts := strings.Split(outpoint, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid outpoint format")
	}

	txid, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid txid: %v", err)
	}

	var index uint32
	if _, err := fmt.Sscanf(parts[1], "%d", &index); err != nil {
		return nil, fmt.Errorf("invalid index: %v", err)
	}

	buf := make([]byte, 36)
	copy(buf[:32], txid)
	binary.BigEndian.PutUint32(buf[32:36], index)

	return buf, nil
}

// decodeOutpoint converts binary outpoint data to string format "txid.index"
func decodeOutpoint(data []byte) (string, error) {
	if len(data) < 32 {
		return "", errors.New("invalid outpoint data length")
	}

	txid := hex.EncodeToString(data[:32])
	index := binary.BigEndian.Uint32(data[32:36])
	return fmt.Sprintf("%s.%d", txid, index), nil
}

func SerializeCreateActionArgs(args *wallet.CreateActionArgs) ([]byte, error) {
	buf := make([]byte, 0)
	paramWriter := newWriter(&buf)

	// Serialize description
	descBytes := []byte(args.Description)
	paramWriter.writeVarInt(uint64(len(descBytes)))
	paramWriter.writeBytes(descBytes)

	// Serialize input BEEF
	if args.InputBEEF != nil {
		paramWriter.writeVarInt(uint64(len(args.InputBEEF)))
		paramWriter.writeBytes(args.InputBEEF)
	} else {
		paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1 in varint
	}

	// Serialize inputs
	if args.Inputs != nil {
		paramWriter.writeVarInt(uint64(len(args.Inputs)))
		for _, input := range args.Inputs {
			// Serialize outpoint
			outpoint, err := encodeOutpoint(input.Outpoint)
			if err != nil {
				return nil, err
			}
			paramWriter.writeBytes(outpoint)

			// Serialize unlocking script
			if input.UnlockingScript != "" {
				script, err := hex.DecodeString(input.UnlockingScript)
				if err != nil {
					return nil, fmt.Errorf("error decoding unlocking script: %v", err)
				}
				paramWriter.writeVarInt(uint64(len(script)))
				paramWriter.writeBytes(script)
			} else {
				paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
				paramWriter.writeVarInt(uint64(input.UnlockingScriptLength))
			}

			// Serialize input description
			inputDesc := []byte(input.InputDescription)
			paramWriter.writeVarInt(uint64(len(inputDesc)))
			paramWriter.writeBytes(inputDesc)

			// Serialize sequence number
			if input.SequenceNumber > 0 {
				paramWriter.writeVarInt(uint64(input.SequenceNumber))
			} else {
				paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
			}
		}
	} else {
		paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
	}

	// Serialize outputs
	if args.Outputs != nil {
		paramWriter.writeVarInt(uint64(len(args.Outputs)))
		for _, output := range args.Outputs {
			// Serialize locking script
			script, err := hex.DecodeString(output.LockingScript)
			if err != nil {
				return nil, fmt.Errorf("error decoding locking script: %v", err)
			}
			paramWriter.writeVarInt(uint64(len(script)))
			paramWriter.writeBytes(script)

			// Serialize satoshis
			paramWriter.writeVarInt(output.Satoshis)

			// Serialize output description
			outputDesc := []byte(output.OutputDescription)
			paramWriter.writeVarInt(uint64(len(outputDesc)))
			paramWriter.writeBytes(outputDesc)

			// Serialize basket
			if output.Basket != "" {
				basket := []byte(output.Basket)
				paramWriter.writeVarInt(uint64(len(basket)))
				paramWriter.writeBytes(basket)
			} else {
				paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
			}

			// Serialize custom instructions
			if output.CustomInstructions != "" {
				ci := []byte(output.CustomInstructions)
				paramWriter.writeVarInt(uint64(len(ci)))
				paramWriter.writeBytes(ci)
			} else {
				paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
			}

			// Serialize tags
			if output.Tags != nil {
				paramWriter.writeVarInt(uint64(len(output.Tags)))
				for _, tag := range output.Tags {
					tagBytes := []byte(tag)
					paramWriter.writeVarInt(uint64(len(tagBytes)))
					paramWriter.writeBytes(tagBytes)
				}
			} else {
				paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
			}
		}
	} else {
		paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
	}

	// Serialize lockTime
	if args.LockTime > 0 {
		paramWriter.writeVarInt(uint64(args.LockTime))
	} else {
		paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
	}

	// Serialize version
	if args.Version > 0 {
		paramWriter.writeVarInt(uint64(args.Version))
	} else {
		paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
	}

	// Serialize labels
	if args.Labels != nil {
		paramWriter.writeVarInt(uint64(len(args.Labels)))
		for _, label := range args.Labels {
			labelBytes := []byte(label)
			paramWriter.writeVarInt(uint64(len(labelBytes)))
			paramWriter.writeBytes(labelBytes)
		}
	} else {
		paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
	}

	// Serialize options
	if args.Options != nil {
		paramWriter.writeByte(1) // options present

		// signAndProcess
		if args.Options.SignAndProcess != nil {
			if *args.Options.SignAndProcess {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// acceptDelayedBroadcast
		if args.Options.AcceptDelayedBroadcast != nil {
			if *args.Options.AcceptDelayedBroadcast {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// trustSelf
		if args.Options.TrustSelf == "known" {
			paramWriter.writeByte(1)
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// knownTxids
		if args.Options.KnownTxids != nil {
			paramWriter.writeVarInt(uint64(len(args.Options.KnownTxids)))
			for _, txid := range args.Options.KnownTxids {
				txidBytes, err := hex.DecodeString(txid)
				if err != nil {
					return nil, fmt.Errorf("error decoding known txid: %v", err)
				}
				paramWriter.writeBytes(txidBytes)
			}
		} else {
			paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
		}

		// returnTXIDOnly
		if args.Options.ReturnTXIDOnly != nil {
			if *args.Options.ReturnTXIDOnly {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// noSend
		if args.Options.NoSend != nil {
			if *args.Options.NoSend {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}

		// noSendChange
		if args.Options.NoSendChange != nil {
			paramWriter.writeVarInt(uint64(len(args.Options.NoSendChange)))
			for _, outpoint := range args.Options.NoSendChange {
				op, err := encodeOutpoint(outpoint)
				if err != nil {
					return nil, err
				}
				paramWriter.writeBytes(op)
			}
		} else {
			paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
		}

		// sendWith
		if args.Options.SendWith != nil {
			paramWriter.writeVarInt(uint64(len(args.Options.SendWith)))
			for _, txid := range args.Options.SendWith {
				txidBytes, err := hex.DecodeString(txid)
				if err != nil {
					return nil, fmt.Errorf("error decoding send with txid: %v", err)
				}
				paramWriter.writeBytes(txidBytes)
			}
		} else {
			paramWriter.writeVarInt(0xFFFFFFFFFFFFFFFF) // -1
		}

		// randomizeOutputs
		if args.Options.RandomizeOutputs != nil {
			if *args.Options.RandomizeOutputs {
				paramWriter.writeByte(1)
			} else {
				paramWriter.writeByte(0)
			}
		} else {
			paramWriter.writeByte(0xFF) // -1
		}
	} else {
		paramWriter.writeByte(0) // options not present
	}

	return buf, nil
}

func DeserializeCreateActionArgs(data []byte) (*wallet.CreateActionArgs, error) {
	// TODO: Implement args deserialization matching TS format
	return &wallet.CreateActionArgs{}, nil
}

func SerializeCreateActionResult(result *wallet.CreateActionResult) ([]byte, error) {
	// TODO: Implement result serialization matching TS format
	return nil, nil
}

func DeserializeCreateActionResult(data []byte) (*wallet.CreateActionResult, error) {
	if len(data) == 0 {
		return nil, errors.New("empty response data")
	}

	resultReader := newReader(data)
	result := &wallet.CreateActionResult{}

	// Read error byte (first byte indicates success/failure)
	errorByte, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %v", err)
	}

	if errorByte != 0 {
		// Handle error case
		errorMsgLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading error message length: %v", err)
		}
		errorMsgBytes, err := resultReader.readBytes(int(errorMsgLen))
		if err != nil {
			return nil, fmt.Errorf("error reading error message: %v", err)
		}
		errorMsg := string(errorMsgBytes)

		stackTraceLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace length: %v", err)
		}
		stackTraceBytes, err := resultReader.readBytes(int(stackTraceLen))
		if err != nil {
			return nil, fmt.Errorf("error reading stack trace: %v", err)
		}
		stackTrace := string(stackTraceBytes)

		return nil, fmt.Errorf("wallet error %d: %s\n%s", errorByte, errorMsg, stackTrace)
	}

	// Parse txid
	txidFlag, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading txid flag: %v", err)
	}
	if txidFlag == 1 {
		txidBytes, err := resultReader.readBytes(32)
		if err != nil {
			return nil, fmt.Errorf("error reading txid: %v", err)
		}
		result.Txid = hex.EncodeToString(txidBytes)
	}

	// Parse tx
	txFlag, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading tx flag: %v", err)
	}
	if txFlag == 1 {
		txLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading tx length: %v", err)
		}
		txBytes, err := resultReader.readBytes(int(txLen))
		if err != nil {
			return nil, fmt.Errorf("error reading tx: %v", err)
		}
		result.Tx = txBytes
	}

	// Parse noSendChange
	noSendChangeLen, err := resultReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading noSendChange length: %v", err)
	}
	if noSendChangeLen >= 0 {
		result.NoSendChange = make([]string, 0, noSendChangeLen)
		for i := uint64(0); i < noSendChangeLen; i++ {
			outpointBytes, err := resultReader.readBytes(36) // 32 txid + 4 index
			if err != nil {
				return nil, fmt.Errorf("error reading outpoint: %v", err)
			}
			outpoint, err := decodeOutpoint(outpointBytes)
			if err != nil {
				return nil, fmt.Errorf("error decoding outpoint: %v", err)
			}
			result.NoSendChange = append(result.NoSendChange, outpoint)
		}
	}

	// Parse sendWithResults
	sendWithResultsLen, err := resultReader.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading sendWithResults length: %v", err)
	}
	if sendWithResultsLen >= 0 {
		result.SendWithResults = make([]wallet.SendWithResult, 0, sendWithResultsLen)
		for i := uint64(0); i < sendWithResultsLen; i++ {
			txidBytes, err := resultReader.readBytes(32)
			if err != nil {
				return nil, fmt.Errorf("error reading sendWith txid: %v", err)
			}
			txid := hex.EncodeToString(txidBytes)

			statusCode, err := resultReader.readByte()
			if err != nil {
				return nil, fmt.Errorf("error reading status code: %v", err)
			}

			var status string
			switch statusCode {
			case 1:
				status = "unproven"
			case 2:
				status = "sending"
			case 3:
				status = "failed"
			default:
				return nil, fmt.Errorf("invalid status code: %d", statusCode)
			}

			result.SendWithResults = append(result.SendWithResults, wallet.SendWithResult{
				Txid:   txid,
				Status: status,
			})
		}
	}

	// Parse signableTransaction
	signableTxFlag, err := resultReader.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading signable tx flag: %v", err)
	}
	if signableTxFlag == 1 {
		txLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading signable tx length: %v", err)
		}
		txBytes, err := resultReader.readBytes(int(txLen))
		if err != nil {
			return nil, fmt.Errorf("error reading signable tx: %v", err)
		}

		refLen, err := resultReader.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading reference length: %v", err)
		}
		refBytes, err := resultReader.readBytes(int(refLen))
		if err != nil {
			return nil, fmt.Errorf("error reading reference: %v", err)
		}

		result.SignableTransaction = &wallet.SignableTransaction{
			Tx:        txBytes,
			Reference: string(refBytes),
		}
	}

	return result, nil
}

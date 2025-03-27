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
	// TODO: Implement result deserialization matching TS format
	return &wallet.CreateActionResult{}, nil
}

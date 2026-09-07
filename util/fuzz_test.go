package util_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
)

// varIntSeeds cover each VarInt length prefix boundary (1, 3, 5, and 9 byte
// encodings) plus a couple of truncated forms.
var varIntSeeds = [][]byte{
	{},
	{0x00},                         // 0
	{0xfc},                         // 252 (largest single-byte)
	{0xfd, 0xfd, 0x00},             // 253 via 3-byte form
	{0xfe, 0xff, 0xff, 0xff, 0xff}, // 5-byte form
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 9-byte form
	{0xfd},                         // truncated 3-byte prefix
	{0xfe, 0x01},                   // truncated 5-byte prefix
	{0xff, 0x01, 0x02, 0x03, 0x04}, // truncated 9-byte prefix
}

// FuzzReadVarInt fuzzes VarInt length-prefix decoding, a common panic source in
// length-prefixed binary formats. The invariant is that no input panics.
func FuzzReadVarInt(f *testing.F) {
	for _, s := range varIntSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := util.NewReader(data)
		// Drain repeated varints until the reader is exhausted or errors; this
		// must never panic regardless of the bytes.
		for range 64 {
			if _, err := r.ReadVarInt(); err != nil {
				break
			}
		}
	})
}

// FuzzReader drives a mix of Reader operations off the fuzz input, stressing the
// length-parsing helpers (ReadVarInt, ReadIntBytes, ReadBytes) that back
// transaction and BEEF deserialization. The invariant is no panic.
func FuzzReader(f *testing.F) {
	for _, s := range varIntSeeds {
		f.Add(s)
	}
	f.Add([]byte{0x04, 0xde, 0xad, 0xbe, 0xef})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := util.NewReader(data)
		for range 64 {
			if r.IsComplete() {
				break
			}
			// The first byte of the remaining stream selects the next read so
			// the fuzzer explores every reader path.
			sel, err := r.ReadByte()
			if err != nil {
				break
			}
			switch sel % 4 {
			case 0:
				_, err = r.ReadVarInt()
			case 1:
				_, err = r.ReadIntBytes()
			case 2:
				_, err = r.ReadBytes(int(sel))
			case 3:
				_, err = r.ReadVarInt32()
			}
			if err != nil {
				break
			}
		}
	})
}

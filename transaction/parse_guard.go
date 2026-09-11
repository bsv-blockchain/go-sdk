package transaction

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// byteLenReader is implemented by the in-memory readers the binary parsers are
// actually driven by (*bytes.Reader, *bytes.Buffer, *strings.Reader): it reports
// the number of unread bytes remaining.
type byteLenReader interface {
	Len() int
}

// guardParseCount protects a slice preallocation against an attacker-controlled
// element count read from untrusted binary. When the reader can report its
// remaining bytes — which is the case for every entry point that parses a byte
// slice (NewTransactionFromBytes, NewTransactionFromBEEF, NewMerklePathFromBinary
// all wrap the input in a *bytes.Reader) — a count that could not possibly be
// satisfied by the bytes that remain is rejected before make() is handed an
// oversized length. This turns a "makeslice: len out of range" panic on
// malformed input into an ordinary error.
//
// minBytesPerElem is the minimum number of input bytes each element consumes
// while parsing (1 for a byte slice). For pointer-element slices this keeps the
// bound tight — an N-byte message cannot describe more than N/minBytesPerElem
// elements — so a small message cannot force a large (count * pointer-size)
// allocation. It must never exceed the true per-element minimum, or valid input
// would be rejected.
//
// Valid transactions are unaffected regardless of size. Streaming readers that
// cannot report a length are left unguarded — they are not the untrusted-binary
// entry points, and bounding them could reject legitimate streamed data.
// maxParseAllocBytes caps the allocation a single count/length may request from
// a reader that cannot report its remaining bytes (a streaming io.Reader). It is
// far larger than any legitimate transaction field or element count, but small
// enough that the resulting make() cannot exceed the runtime's maximum slice
// size and panic with "makeslice: len out of range".
const maxParseAllocBytes uint64 = 1 << 32 // 4 GiB

const (
	// minInputParseBytes is the smallest number of bytes a serialized transaction
	// input can occupy: 32-byte previous txid + 4-byte output index + 1-byte
	// empty-script varint + 4-byte sequence. It bounds input-count pre-sizing and
	// must never exceed the true per-element minimum, or a valid count would be
	// rejected (extended-format inputs are larger, so this remains a safe lower
	// bound for them too).
	minInputParseBytes = 41
	// minOutputParseBytes is the smallest number of bytes a serialized transaction
	// output can occupy: 8-byte value + 1-byte empty-script varint. It bounds
	// output-count pre-sizing.
	minOutputParseBytes = 9
)

func guardParseCount(r io.Reader, count uint64, minBytesPerElem int, what string) error {
	if minBytesPerElem < 1 {
		minBytesPerElem = 1
	}
	m := uint64(minBytesPerElem)

	if lr, ok := r.(byteLenReader); ok {
		// The bytes are already in memory, so the remaining length is an exact
		// upper bound on how many elements can possibly follow.
		remaining := lr.Len()
		if maxCount := uint64(remaining) / m; count > maxCount { //nolint:gosec // G115 -- Len() is non-negative
			return fmt.Errorf("%s count %d exceeds capacity of %d remaining bytes", what, count, remaining)
		}
		return nil
	}

	// A streaming reader cannot report its remaining bytes, so fall back to a
	// generous absolute ceiling. Clamp it to the platform's maximum int as well,
	// so the subsequent make([]T, count) cannot overflow the length on 32-bit
	// builds and panic with "makeslice: len out of range".
	maxCount := maxParseAllocBytes / m
	if maxInt := uint64(^uint(0) >> 1); maxCount > maxInt {
		maxCount = maxInt
	}
	if count > maxCount {
		return fmt.Errorf("%s count %d exceeds the maximum for a streamed reader", what, count)
	}
	return nil
}

// readGuardedBytes reads exactly l bytes from r into a freshly allocated slice,
// first rejecting (via guardParseCount) a length larger than r's remaining bytes
// so a malformed length cannot trigger a makeslice panic. It returns the bytes
// read alongside the buffer so callers can account for the read and wrap errors
// with their own context.
func readGuardedBytes(r io.Reader, l uint64, what string) ([]byte, int, error) {
	if err := guardParseCount(r, l, 1, what); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, l)
	n, err := io.ReadFull(r, buf)
	return buf, n, err
}

// readVarInt reads a CompactSize varint from r into scratch (len >= 8) and
// returns its value together with the number of bytes read. It is the
// allocation-free counterpart of util.VarInt.ReadFrom for the parse hot path: the
// caller's reusable scratch removes the per-call make([]byte, ...) that
// VarInt.ReadFrom performs on every invocation. The decoding — including
// acceptance of non-minimal encodings and the 1/3/5/9 byte counts returned
// (including on a short read) — is identical to util.VarInt.ReadFrom.
func readVarInt(r io.Reader, scratch []byte) (uint64, int64, error) {
	if _, err := io.ReadFull(r, scratch[:1]); err != nil {
		return 0, 0, errors.Wrap(err, "could not read varint type")
	}

	switch scratch[0] {
	case 0xff:
		if n, err := io.ReadFull(r, scratch[:8]); err != nil {
			return 0, 9, errors.Wrapf(err, "varint(8): got %d bytes", n)
		}
		return binary.LittleEndian.Uint64(scratch[:8]), 9, nil

	case 0xfe:
		if n, err := io.ReadFull(r, scratch[:4]); err != nil {
			return 0, 5, errors.Wrapf(err, "varint(4): got %d bytes", n)
		}
		return uint64(binary.LittleEndian.Uint32(scratch[:4])), 5, nil

	case 0xfd:
		if n, err := io.ReadFull(r, scratch[:2]); err != nil {
			return 0, 3, errors.Wrapf(err, "varint(2): got %d bytes", n)
		}
		return uint64(binary.LittleEndian.Uint16(scratch[:2])), 3, nil

	default:
		return uint64(scratch[0]), 1, nil
	}
}

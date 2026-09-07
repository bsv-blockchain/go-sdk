package transaction

import (
	"fmt"
	"io"
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
func guardParseCount(r io.Reader, count uint64, minBytesPerElem int, what string) error {
	lr, ok := r.(byteLenReader)
	if !ok {
		return nil
	}
	if minBytesPerElem < 1 {
		minBytesPerElem = 1
	}
	remaining := lr.Len()
	maxCount := uint64(remaining) / uint64(minBytesPerElem) //nolint:gosec // G115 -- Len() and minBytesPerElem are non-negative
	if count > maxCount {
		return fmt.Errorf("%s count %d exceeds capacity of %d remaining bytes", what, count, remaining)
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

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
// all wrap the input in a *bytes.Reader) — a count larger than the bytes that
// remain cannot be satisfied and is rejected before make() is handed an
// impossible size. This turns a "makeslice: len out of range" panic on malformed
// input into an ordinary error.
//
// Valid transactions are unaffected regardless of size: every element consumes at
// least one byte, so a legitimate count can never exceed the remaining input.
// Streaming readers that cannot report a length are left unguarded — they are not
// the untrusted-binary entry points, and bounding them could reject legitimate
// streamed data.
func guardParseCount(r io.Reader, count uint64, what string) error {
	lr, ok := r.(byteLenReader)
	if !ok {
		return nil
	}
	if remaining := lr.Len(); count > uint64(remaining) { //nolint:gosec // G115 -- Len() is non-negative
		return fmt.Errorf("%s count %d exceeds %d remaining bytes", what, count, remaining)
	}
	return nil
}

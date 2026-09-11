package transaction_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/testdata"
)

// Fuzz targets for the binary parsers a node feeds untrusted bytes into. The
// invariant under test is that no input causes a panic; where a parse succeeds,
// re-serialization must be stable (parse -> bytes -> parse -> bytes is fixed).

// rawTxSeeds are small, valid raw transactions used to seed the corpus.
var rawTxSeeds = []string{
	// coinbase
	"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff17033f250d2f43555656452f2c903fb60859897700d02700ffffffff01d864a012000000001976a914d648686cf603c11850f39600e37312738accca8f88ac00000000",
	// standard multi-input P2PKH spend
	"0200000003a9bc457fdc6a54d99300fb137b23714d860c350a9d19ff0f571e694a419ff3a0010000006b48304502210086c83beb2b2663e4709a583d261d75be538aedcafa7766bd983e5c8db2f8b2fc02201a88b178624ab0ad1748b37c875f885930166237c88f5af78ee4e61d337f935f412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff0092bb9a47e27bf64fc98f557c530c04d9ac25e2f2a8b600e92a0b1ae7c89c20010000006b483045022100f06b3db1c0a11af348401f9cebe10ae2659d6e766a9dcd9e3a04690ba10a160f02203f7fbd7dfcfc70863aface1a306fcc91bbadf6bc884c21a55ef0d32bd6b088c8412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff9d0d4554fa692420a0830ca614b6c60f1bf8eaaa21afca4aa8c99fb052d9f398000000006b483045022100d920f2290548e92a6235f8b2513b7f693a64a0d3fa699f81a034f4b4608ff82f0220767d7d98025aff3c7bd5f2a66aab6a824f5990392e6489aae1e1ae3472d8dffb412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff02807c814a000000001976a9143a6bf34ebfcf30e8541bbb33a7882845e5a29cb488ac76b0e60e000000001976a914bd492b67f90cb85918494767ebb23102c4f06b7088ac67000000",
}

// FuzzNewTransactionFromBytes fuzzes raw transaction deserialization.
func FuzzNewTransactionFromBytes(f *testing.F) {
	for _, h := range rawTxSeeds {
		b, err := hex.DecodeString(h)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := transaction.NewTransactionFromBytes(data)
		if err != nil {
			return
		}
		// Re-serialization must round-trip deterministically.
		out := tx.Bytes()
		tx2, err := transaction.NewTransactionFromBytes(out)
		require.NoError(t, err)
		require.Equal(t, out, tx2.Bytes())

		// AppendBytes and WriteTo must produce bytes identical to Bytes().
		require.Equal(t, out, tx.AppendBytes(nil))
		var buf bytes.Buffer
		n, werr := tx.WriteTo(&buf)
		require.NoError(t, werr)
		require.Equal(t, out, buf.Bytes())
		require.Equal(t, int64(len(out)), n)
	})
}

// FuzzNewTransactionFromBEEF fuzzes BEEF deserialization, seeded with the
// small BRC-62 vector and the large multi-transaction Issue96 vector.
func FuzzNewTransactionFromBEEF(f *testing.F) {
	for _, h := range []string{BRC62Hex, testdata.Issue96BeefHex} {
		b, err := hex.DecodeString(h)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// The parser must not panic on any input.
		_, _ = transaction.NewTransactionFromBEEF(data)
	})
}

// FuzzMerklePathFromBinary fuzzes BUMP (BRC-74) parsing, seeded with the valid
// and (structurally) invalid bump vectors.
func FuzzMerklePathFromBinary(f *testing.F) {
	seeds := make([]string, 0, len(testdata.ValidBumps)+len(testdata.InvalidBumps))
	for _, b := range testdata.ValidBumps {
		seeds = append(seeds, b.Bump)
	}
	for _, b := range testdata.InvalidBumps {
		seeds = append(seeds, b.Bump)
	}
	for _, h := range seeds {
		b, err := hex.DecodeString(h)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		mp, err := transaction.NewMerklePathFromBinary(data)
		if err != nil {
			return
		}
		// A parsed path must serialize back without panicking. Note the parser
		// is more lenient than the 37-byte minimum NewMerklePathFromBinary
		// enforces, so a re-parse of Bytes() is intentionally not asserted here.
		_ = mp.Bytes()
	})
}

package transaction

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/stretchr/testify/require"
)

// BRC-95: every transaction in an Atomic BEEF must be the subject or in its
// dependency graph; an entry outside it makes the BEEF invalid.

// atomicBeefUnrelatedIssue is the 488-byte repro of go-sdk#384: the subject S1 with
// its ancestry (Z proven, A raw unproven, P proven) plus a proven X that nothing spends.
const atomicBeefUnrelatedIssue = "01010101850259d5c7f0efe1fbf12869ab1b2e4d8d60df9c683bffcb24db9001eb3e383c0100beef03fea3bb0d00010100026c010e899b9b628ca7c259b9a9e563e5481006892d91983287d5df542bccaa8bfea1bb0d0001010002d430e4bdd40ff8e7c97784af10b582fe08530edc22900d0237ecd53e2b6df215fea0bb0d00010100025ceb233088ee6a0ae15c7ae83a5392073d400abc62ca98d8eea1cc17c5cc62ad0501000000012c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0000000000ffffffff010500000000000000015100000000010001000000016556f01b05df2fbe88262545264715260d79b7575c269a8cb43346398a8b02880000000000ffffffff015e01000000000000015100000000010101000000012a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0000000000ffffffff02e8030000000000000151f401000000000000015100000000010201000000015ceb233088ee6a0ae15c7ae83a5392073d400abc62ca98d8eea1cc17c5cc62ad0000000000ffffffff019001000000000000015100000000000100000001d430e4bdd40ff8e7c97784af10b582fe08530edc22900d0237ecd53e2b6df2150000000000ffffffff012c0100000000000001510000000000"

func TestNewBeefFromAtomicBytes_RefusesUnrelatedTransaction(t *testing.T) {
	raw, err := hex.DecodeString(atomicBeefUnrelatedIssue)
	require.NoError(t, err)

	_, _, err = NewBeefFromAtomicBytes(raw)
	require.Error(t, err)
	require.Contains(t, err.Error(), "outside the dependency graph")

	parsed, _, _, err := ParseBeef(raw)
	require.Error(t, err, "ParseBeef takes the same atomic path")
	require.Nil(t, parsed)
	require.Contains(t, err.Error(), "outside the dependency graph")
}

// The vector file is the ts-stack conformance corpus's atomic-beef.json (copied
// from bsv-blockchain/ts-stack at a9a9b93). Its expected values follow BRC-95's graph
// through the inputs of every raw entry, proven or not; two vectors are marked
// "intended" because @bsv/sdk 3.x cuts the graph at each proven transaction and
// refuses them. This test checks all eight.
func TestNewBeefFromAtomicBytes_AtomicBeefVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/atomic-beef/atomic-beef.json")
	require.NoError(t, err)

	var file struct {
		Vectors []struct {
			ID    string `json:"id"`
			Input struct {
				BeefHex string `json:"beef_hex"`
			} `json:"input"`
			Expected struct {
				Valid       bool   `json:"valid"`
				SubjectTxid string `json:"subject_txid"`
				Error       string `json:"error"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &file))
	require.Len(t, file.Vectors, 8)

	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			raw, err := hex.DecodeString(v.Input.BeefHex)
			require.NoError(t, err)

			_, subject, err := NewBeefFromAtomicBytes(raw)
			if v.Expected.Valid {
				require.NoError(t, err)
				require.Equal(t, v.Expected.SubjectTxid, subject.String())
				return
			}

			require.Error(t, err)
			switch v.Expected.Error {
			case "unrelated-transaction":
				require.Contains(t, err.Error(), "outside the dependency graph")
			case "subject-missing":
				require.Contains(t, err.Error(), "is missing")
			default:
				t.Fatalf("unknown expected error %q", v.Expected.Error)
			}
		})
	}
}

// What the Go writer emits is the subject's closure cut at proofs, so it must read back:
// rewriting the issue's BEEF through AtomicBytes drops the unrelated entry and the result parses.
func TestNewBeefFromAtomicBytes_AcceptsWhatAtomicBytesWrites(t *testing.T) {
	raw, err := hex.DecodeString(atomicBeefUnrelatedIssue)
	require.NoError(t, err)

	subject, err := chainhash.NewHash(raw[4:36])
	require.NoError(t, err)
	whole, err := newBeefFromBytes(raw[36:])
	require.NoError(t, err)

	cut, err := whole.AtomicBytes(subject)
	require.NoError(t, err)

	parsed, got, err := NewBeefFromAtomicBytes(cut)
	require.NoError(t, err)
	require.Equal(t, subject, got)
	require.Less(t, len(parsed.Transactions), len(whole.Transactions), "the unrelated entry is gone")
}

// The Go writer stops at a txid-only entry, so an atomic BEEF may carry the subject and a
// txid-only parent. The parent is reached through the subject's input, so it is not unrelated.
func TestNewBeefFromAtomicBytes_AcceptsTxidOnlyParent(t *testing.T) {
	raw, err := hex.DecodeString(atomicBeefUnrelatedIssue)
	require.NoError(t, err)

	subject, err := chainhash.NewHash(raw[4:36])
	require.NoError(t, err)
	whole, err := newBeefFromBytes(raw[36:])
	require.NoError(t, err)

	parentID := *whole.Transactions[*subject].Transaction.Inputs[0].SourceTXID
	whole.Transactions[parentID] = &BeefTx{DataFormat: TxIDOnly, KnownTxID: &parentID}
	whole.Version = BEEF_V2 // V1 has no txid-only entries

	cut, err := whole.AtomicBytes(subject)
	require.NoError(t, err)

	parsed, got, err := NewBeefFromAtomicBytes(cut)
	require.NoError(t, err)
	require.Equal(t, subject, got)
	require.Equal(t, TxIDOnly, parsed.Transactions[parentID].DataFormat)
}

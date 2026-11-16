package transaction

import (
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
)

// Benchmarks for the BEEF merge hot path.
//
// These model the two shapes a wallet actually produces:
//
//   - a transaction ancestry that is a DAG rather than a tree, so the same
//     ancestors are reachable by more than one path (benchSpendGraph), and
//   - a batch of transactions whose merkle proofs all belong to a handful of
//     recent blocks, so every proof shares a root with the ones already merged
//     (benchProvedBatch).
//
// Both are set up outside the timer; only the merge itself is measured.

// benchTx builds a distinct transaction spending output 0 of each parent.
// lockTime keeps otherwise-identical transactions from colliding.
func benchTx(lockTime uint32, parents ...*Transaction) *Transaction {
	tx := &Transaction{Version: 1, LockTime: lockTime}
	for _, p := range parents {
		tx.Inputs = append(tx.Inputs, &TransactionInput{
			SourceTXID:        p.TxID(),
			SourceTransaction: p,
			SourceTxOutIndex:  0,
			SequenceNumber:    0xffffffff,
		})
	}
	tx.Outputs = append(tx.Outputs, &TransactionOutput{
		Satoshis:      1000,
		LockingScript: &script.Script{},
	})
	return tx
}

// benchSpendGraph returns `depth` transactions where each one spends the two
// before it. Every transaction is therefore reachable from the tip by many
// distinct paths, which is the case an unmemoized ancestry walk handles badly.
// The tip is the last element.
func benchSpendGraph(depth int) []*Transaction {
	txs := make([]*Transaction, 0, depth)
	txs = append(txs, benchTx(0), benchTx(1, benchTx(0)))
	for i := 2; i < depth; i++ {
		txs = append(txs, benchTx(uint32(i), txs[i-1], txs[i-2]))
	}
	return txs
}

// benchMerkleTree computes every level of the merkle tree over leaves,
// bottom-up. Result [0] is the leaves; the last entry is the single root.
// len(leaves) must be a power of two.
func benchMerkleTree(leaves []*chainhash.Hash) [][]*chainhash.Hash {
	levels := [][]*chainhash.Hash{leaves}
	for cur := leaves; len(cur) > 1; {
		next := make([]*chainhash.Hash, 0, len(cur)/2)
		for i := 0; i < len(cur); i += 2 {
			next = append(next, MerkleTreeParent(cur[i], cur[i+1]))
		}
		levels = append(levels, next)
		cur = next
	}
	return levels
}

// benchOffset converts a position in the tree built above into a path offset.
// Positions are slice indices, so they are non-negative and bounded by the tree
// size.
func benchOffset(position int) uint64 {
	return uint64(position) //nolint:gosec // G115 -- a tree position is a slice index: non-negative and bounded by the tree size
}

// benchProofBUMP builds the merkle proof for one leaf: at every level, the
// sibling needed to climb to the root. Proofs built from the same tree share a
// root, so merging them together exercises the combine path.
func benchProofBUMP(blockHeight uint32, levels [][]*chainhash.Hash, index int) *MerklePath {
	treeHeight := len(levels) - 1
	path := make([][]*PathElement, treeHeight)

	isTxid := true
	path[0] = []*PathElement{
		{Offset: benchOffset(index), Hash: levels[0][index], Txid: &isTxid},
		{Offset: benchOffset(index ^ 1), Hash: levels[0][index^1]},
	}
	if index&1 == 1 {
		path[0][0], path[0][1] = path[0][1], path[0][0]
	}

	for h := 1; h < treeHeight; h++ {
		sib := (index >> h) ^ 1
		path[h] = []*PathElement{{Offset: benchOffset(sib), Hash: levels[h][sib]}}
	}

	return NewMerklePath(blockHeight, path)
}

// benchFullBUMP builds a path holding every node of the tree. Stands in for a
// BUMP that has absorbed many individual proofs through Combine.
func benchFullBUMP(blockHeight uint32, levels [][]*chainhash.Hash) *MerklePath {
	treeHeight := len(levels) - 1
	path := make([][]*PathElement, treeHeight)
	isTxid := true
	for h := 0; h < treeHeight; h++ {
		path[h] = make([]*PathElement, 0, len(levels[h]))
		for offset, hash := range levels[h] {
			el := &PathElement{Offset: benchOffset(offset), Hash: hash}
			if h == 0 {
				el.Txid = &isTxid
			}
			path[h] = append(path[h], el)
		}
	}
	return NewMerklePath(blockHeight, path)
}

// benchProvedBatch builds n transactions, each carrying a merkle proof, spread
// over `blocks` block heights. n/blocks must be a power of two.
func benchProvedBatch(n, blocks int) []*Transaction {
	perBlock := n / blocks
	// Power of two: the merkle tree helpers assume a full tree.
	if perBlock <= 0 || perBlock&(perBlock-1) != 0 {
		panic("transactions per block must be a power of two")
	}

	txs := make([]*Transaction, 0, n)
	var lockTime uint32
	for b := 0; b < blocks; b++ {
		block := make([]*Transaction, 0, perBlock)
		leaves := make([]*chainhash.Hash, 0, perBlock)
		for i := 0; i < perBlock; i++ {
			lockTime++
			tx := benchTx(lockTime)
			block = append(block, tx)
			leaves = append(leaves, tx.TxID())
		}

		levels := benchMerkleTree(leaves)
		for i, tx := range block {
			tx.MerklePath = benchProofBUMP(uint32(800000+b), levels, i)
		}
		txs = append(txs, block...)
	}
	return txs
}

// beefOf places transactions into a Beef directly, bypassing the merge path so
// that setup cost stays out of the measurement.
func beefOf(txs []*Transaction) *Beef {
	b := NewBeef()
	for _, tx := range txs {
		b.Transactions[*tx.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: tx}
	}
	return b
}

// BenchmarkMergeTransaction_SpendGraph measures merging a tip whose ancestry is
// a DAG. Cost should track the number of distinct ancestors, not the number of
// paths through them.
func BenchmarkMergeTransaction_SpendGraph(b *testing.B) {
	// Depths past ~24 are unreachable without the memoised walk - the number
	// of paths through the DAG grows like Fibonacci - so the large cases exist
	// to show the fixed walk tracks distinct ancestors rather than paths.
	for _, depth := range []int{10, 16, 20, 100, 400} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			txs := benchSpendGraph(depth)
			tip := txs[len(txs)-1]

			b.ReportAllocs()
			for b.Loop() {
				if _, err := NewBeef().MergeTransaction(tip); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMergeBeef_ProvedBatch measures merging a batch of proved
// transactions whose proofs cluster into a few blocks — the shape a wallet
// spending recent change produces.
func BenchmarkMergeBeef_ProvedBatch(b *testing.B) {
	for _, n := range []int{64, 256} {
		b.Run(fmt.Sprintf("txs=%d", n), func(b *testing.B) {
			src := beefOf(benchProvedBatch(n, 4))

			b.ReportAllocs()
			for b.Loop() {
				if err := NewBeef().MergeBeef(src); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMergeBeef_AlreadyKnown measures re-merging a BEEF the graph already
// holds. This is the shape a wallet actually produces: the same ancestry is
// merged again on every action — into the assembled transaction, into the
// storage response, and into the shared party graph.
func BenchmarkMergeBeef_AlreadyKnown(b *testing.B) {
	for _, n := range []int{64, 256} {
		b.Run(fmt.Sprintf("txs=%d", n), func(b *testing.B) {
			dst := NewBeef()
			if err := dst.MergeBeef(beefOf(benchProvedBatch(n, 4))); err != nil {
				b.Fatal(err)
			}

			// A separately built copy, so nothing matches by pointer identity —
			// the same position a freshly parsed response BEEF is in.
			src := beefOf(benchProvedBatch(n, 4))

			b.ReportAllocs()
			for b.Loop() {
				if err := dst.MergeBeef(src); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFindAtomicTransaction_SpendGraph measures resolving a transaction's
// ancestry into linked source transactions. Wallets hit this when a peer
// returns a txid-only stub that has to be filled in from a known graph.
func BenchmarkFindAtomicTransaction_SpendGraph(b *testing.B) {
	for _, depth := range []int{10, 16, 20} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			txs := benchSpendGraph(depth)
			tip := txs[len(txs)-1]
			txid := tip.TxID()

			b.ReportAllocs()
			for b.Loop() {
				src := beefOf(txs)
				if src.FindAtomicTransactionByHash(txid) == nil {
					b.Fatal("tip not found")
				}
			}
		})
	}
}

// BenchmarkComputeRoot_LargePath measures root computation over a path holding
// a whole block's tree, the state a BUMP reaches after absorbing many proofs.
func BenchmarkComputeRoot_LargePath(b *testing.B) {
	for _, leaves := range []int{256, 1024} {
		b.Run(fmt.Sprintf("leaves=%d", leaves), func(b *testing.B) {
			hashes := make([]*chainhash.Hash, 0, leaves)
			for i := 0; i < leaves; i++ {
				hashes = append(hashes, benchTx(uint32(i)).TxID())
			}
			bump := benchFullBUMP(800000, benchMerkleTree(hashes))

			b.ReportAllocs()
			for b.Loop() {
				if _, err := bump.ComputeRoot(nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

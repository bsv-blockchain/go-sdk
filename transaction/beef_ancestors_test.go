package transaction

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	script "github.com/bsv-blockchain/go-sdk/script"
)

// legacyCollectAncestors is the original, non-memoized implementation, kept
// here to assert the memoized walk produces an identical ordering.
func legacyCollectAncestors(t *Transaction, txid *chainhash.Hash, txns map[chainhash.Hash]*Transaction, allowPartial bool) ([]chainhash.Hash, error) {
	if txid == nil {
		txid = t.TxID()
	}
	if t.MerklePath != nil {
		return []chainhash.Hash{*txid}, nil
	}
	ancestors := make([]chainhash.Hash, 0)
	for _, input := range t.Inputs {
		if input.SourceTransaction == nil {
			if allowPartial {
				continue
			}
			return nil, fmt.Errorf("missing previous transaction for %s", txid)
		}
		txns[*input.SourceTXID] = input.SourceTransaction
		grands, err := legacyCollectAncestors(input.SourceTransaction, input.SourceTXID, txns, allowPartial)
		if err != nil {
			return nil, err
		}
		ancestors = append(grands, ancestors...)
	}
	ancestors = append(ancestors, *txid)

	found := make(map[chainhash.Hash]struct{})
	results := make([]chainhash.Hash, 0, len(ancestors))
	for _, ancestor := range ancestors {
		if _, ok := found[ancestor]; !ok {
			results = append(results, ancestor)
			found[ancestor] = struct{}{}
		}
	}
	return results, nil
}

func newTestTx(id uint32, nOutputs int, parents ...*Transaction) *Transaction {
	tx := &Transaction{Version: 1, LockTime: id}
	for i := 0; i < nOutputs; i++ {
		tx.Outputs = append(tx.Outputs, &TransactionOutput{Satoshis: 1, LockingScript: &script.Script{script.OpTRUE}})
	}
	for i, p := range parents {
		tx.Inputs = append(tx.Inputs, &TransactionInput{
			SourceTXID:        p.TxID(),
			SourceTxOutIndex:  uint32(i % len(p.Outputs)), //nolint:gosec // test index
			SourceTransaction: p,
		})
	}
	return tx
}

// TestCollectAncestorsDiamondChain builds a chain where every tx spends two
// outputs of its parent. The legacy walk revisited the parent once per input,
// i.e. 2^depth visits; the memoized walk must finish immediately.
func TestCollectAncestorsDiamondChain(t *testing.T) {
	const depth = 64
	root := newTestTx(0, 2)
	root.MerklePath = &MerklePath{BlockHeight: 1}
	tip := root
	for i := uint32(1); i <= depth; i++ {
		tip = newTestTx(i, 2, tip, tip)
	}

	done := make(chan struct{})
	var ancestors []chainhash.Hash
	var err error
	go func() {
		ancestors, err = tip.collectAncestors(nil, map[chainhash.Hash]*Transaction{}, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("collectAncestors did not finish; ancestor walk is not memoized")
	}
	require.NoError(t, err)
	require.Len(t, ancestors, depth+1)
	require.Equal(t, *root.TxID(), ancestors[0])
	require.Equal(t, *tip.TxID(), ancestors[depth])

	_, err = NewBeefFromTransaction(tip)
	require.NoError(t, err)
}

// TestCollectAncestorsMatchesLegacyOrder checks the memoized walk against the
// legacy implementation on random DAGs with mined, unmined and missing parents.
func TestCollectAncestorsMatchesLegacyOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test data
	for trial := 0; trial < 200; trial++ {
		tip := randomTestDAG(rng, uint32(trial*100)) //nolint:gosec // test id
		requireSameAncestors(t, tip, false, "trial %d allowPartial=false", trial)
		requireSameAncestors(t, tip, true, "trial %d allowPartial=true", trial)
	}
}

// randomTestDAG builds a random DAG of 2-15 transactions with mined roots,
// occasionally mined interior nodes, and sometimes a missing source on the tip.
func randomTestDAG(rng *rand.Rand, idBase uint32) *Transaction {
	n := 2 + rng.Intn(14)
	txs := make([]*Transaction, 0, n)
	for i := 0; i < n; i++ {
		var parents []*Transaction
		for k := rng.Intn(4); i > 0 && k > 0; k-- {
			parents = append(parents, txs[rng.Intn(i)])
		}
		tx := newTestTx(idBase+uint32(i), 1+rng.Intn(3), parents...) //nolint:gosec // test id
		if len(parents) == 0 || rng.Intn(5) == 0 {
			tx.MerklePath = &MerklePath{BlockHeight: uint32(rng.Intn(3))} //nolint:gosec // test height
		}
		txs = append(txs, tx)
	}
	tip := txs[n-1]
	if rng.Intn(4) == 0 && len(tip.Inputs) > 0 {
		tip.Inputs[rng.Intn(len(tip.Inputs))].SourceTransaction = nil
	}
	return tip
}

func requireSameAncestors(t *testing.T, tip *Transaction, allowPartial bool, msgAndArgs ...interface{}) {
	t.Helper()
	wantTxns := map[chainhash.Hash]*Transaction{}
	want, wantErr := legacyCollectAncestors(tip, nil, wantTxns, allowPartial)
	gotTxns := map[chainhash.Hash]*Transaction{}
	got, gotErr := tip.collectAncestors(nil, gotTxns, allowPartial)
	if wantErr != nil {
		require.Error(t, gotErr, msgAndArgs...)
		return
	}
	require.NoError(t, gotErr, msgAndArgs...)
	require.Equal(t, want, got, msgAndArgs...)
	require.Equal(t, wantTxns, gotTxns, msgAndArgs...)
}

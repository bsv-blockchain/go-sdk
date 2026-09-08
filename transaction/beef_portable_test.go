package transaction

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/stretchr/testify/require"
)

type portableBeefRecord struct {
	Hex     string `json:"beefHex"`
	Version uint32 `json:"version"`
	Bumps   []struct {
		Hex   string   `json:"hex"`
		Roots []string `json:"roots"`
	} `json:"bumps"`
	Transactions []struct {
		TxID string `json:"txid"`
		Raw  string `json:"rawTxHex"`
		Only bool   `json:"isTxidOnly"`
		Bump *int   `json:"bumpIndex"`
	} `json:"transactions"`
}

func portableBeefSnapshot(b *Beef) ([]byte, error) {
	type txSnap struct {
		TxID string `json:"txid"`
		Raw  string `json:"raw"`
		Only bool   `json:"only"`
		Bump int    `json:"bump"`
	}
	txs := make([]txSnap, 0, len(b.Transactions))
	for id, entry := range b.Transactions {
		item := txSnap{TxID: id.String(), Bump: entry.BumpIndex, Only: entry.DataFormat == TxIDOnly}
		if entry.Transaction != nil {
			item.Raw = entry.Transaction.Hex()
		}
		txs = append(txs, item)
	}
	sort.Slice(txs, func(i, j int) bool { return txs[i].TxID < txs[j].TxID })
	bumps := make([]string, 0, len(b.BUMPs))
	for _, proof := range b.BUMPs {
		bumps = append(bumps, proof.Hex())
	}
	newest := ""
	if b.NewestTxID != nil {
		newest = b.NewestTxID.String()
	}
	return json.Marshal(struct {
		Version      uint32   `json:"version"`
		Newest       string   `json:"newest"`
		Bumps        []string `json:"bumps"`
		Transactions []txSnap `json:"transactions"`
	}{b.Version, newest, bumps, txs})
}

func assertPortableBeef(t *testing.T, actual *Beef, expected portableBeefRecord) {
	t.Helper()
	require.Equal(t, expected.Version, actual.Version)
	require.Len(t, actual.Transactions, len(expected.Transactions))
	for _, want := range expected.Transactions {
		id, err := chainhash.NewHashFromHex(want.TxID)
		require.NoError(t, err)
		entry := actual.Transactions[*id]
		require.NotNil(t, entry)
		if want.Only {
			require.Equal(t, TxIDOnly, entry.DataFormat)
			require.Nil(t, entry.Transaction)
			require.Equal(t, id, entry.KnownTxID)
			continue
		}
		require.NotNil(t, entry.Transaction)
		require.Equal(t, want.Raw, entry.Transaction.Hex())
		require.Equal(t, id, entry.Transaction.TxID())
		if want.Bump == nil {
			require.Equal(t, RawTx, entry.DataFormat)
			continue
		}
		require.Equal(t, RawTxAndBumpIndex, entry.DataFormat)
		require.GreaterOrEqual(t, entry.BumpIndex, 0)
		require.Less(t, entry.BumpIndex, len(actual.BUMPs))
		proof := actual.BUMPs[entry.BumpIndex]
		expectedProof := expected.Bumps[*want.Bump]
		require.Equal(t, expectedProof.Hex, proof.Hex())
		root, err := proof.ComputeRoot(id)
		require.NoError(t, err)
		require.Contains(t, expectedProof.Roots, root.String())
	}
}

// These vectors were emitted by the actual pinned TS SDK. This verifies wire
// identity and proof references, not script validity, header trust or unspentness.
func TestPortableTSBeefRoundTrips(t *testing.T) {
	data, err := os.ReadFile("testdata/beef-compatibility/ts-interop-fixtures.json")
	require.NoError(t, err)
	var matrix struct {
		Fixtures []struct {
			Name      string             `json:"name"`
			Target    string             `json:"targetTxid"`
			Beef      portableBeefRecord `json:"beef"`
			Atomic    portableBeefRecord `json:"atomic"`
			AtomicHex string             `json:"atomicHex"`
		} `json:"fixtures"`
	}
	require.NoError(t, json.Unmarshal(data, &matrix))
	require.Len(t, matrix.Fixtures, 17)
	for _, fixture := range matrix.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(fixture.Beef.Hex)
			require.NoError(t, err)
			b, err := NewBeefFromBytes(raw)
			require.NoError(t, err)
			before, err := portableBeefSnapshot(b)
			require.NoError(t, err)
			assertPortableBeef(t, b, fixture.Beef)
			encoded, err := b.Bytes()
			require.NoError(t, err)
			parsed, err := NewBeefFromBytes(encoded)
			require.NoError(t, err)
			assertPortableBeef(t, parsed, fixture.Beef)
			id, err := chainhash.NewHashFromHex(fixture.Target)
			require.NoError(t, err)
			atomic, err := b.AtomicBytes(id)
			require.NoError(t, err)
			selected, target, err := NewBeefFromAtomicBytes(atomic)
			require.NoError(t, err)
			require.Equal(t, id, target)
			require.Equal(t, id, selected.NewestTxID)
			assertPortableBeef(t, selected, fixture.Atomic)
			tsAtomic, err := hex.DecodeString(fixture.AtomicHex)
			require.NoError(t, err)
			fromTS, tsTarget, err := NewBeefFromAtomicBytes(tsAtomic)
			require.NoError(t, err)
			require.Equal(t, id, tsTarget)
			assertPortableBeef(t, fromTS, fixture.Atomic)
			after, err := portableBeefSnapshot(b)
			require.NoError(t, err)
			require.Equal(t, before, after, "serialization must preserve caller entries, version, subject and proof state")
		})
	}
}

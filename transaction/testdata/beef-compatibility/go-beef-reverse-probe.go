// Run from the Go SDK module with the portable TS matrix path as its argument.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type fixture struct {
	Name   string `json:"name"`
	Target string `json:"targetTxid"`
	Beef   struct {
		Bumps []struct {
			Hex string `json:"hex"`
		} `json:"bumps"`
		Txs []struct {
			TxID string `json:"txid"`
			Raw  string `json:"rawTxHex"`
			Only bool   `json:"isTxidOnly"`
			Bump *int   `json:"bumpIndex"`
		} `json:"transactions"`
	} `json:"beef"`
}

type output struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Target    string `json:"targetTxid"`
	Version   uint32 `json:"version"`
	BeefHex   string `json:"beefHex"`
	AtomicHex string `json:"atomicHex"`
	SHA256    string `json:"sha256"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	if len(os.Args) != 2 {
		panic("usage: go-beef-reverse-probe.go matrix.json")
	}
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	var matrix struct {
		Fixtures []fixture `json:"fixtures"`
	}
	must(json.Unmarshal(raw, &matrix))
	results := []output{}
	for _, f := range matrix.Fixtures {
		id, err := chainhash.NewHashFromHex(f.Target)
		must(err)
		for _, version := range []uint32{transaction.BEEF_V1, transaction.BEEF_V2} {
			b := transaction.NewBeefV2()
			b.Version = version
			b.NewestTxID = id
			for _, proof := range f.Beef.Bumps {
				p, err := transaction.NewMerklePathFromHex(proof.Hex)
				must(err)
				b.BUMPs = append(b.BUMPs, p)
			}
			hasTxidOnly := false
			for _, entry := range f.Beef.Txs {
				if entry.Only {
					h, err := chainhash.NewHashFromHex(entry.TxID)
					must(err)
					b.MergeTxidOnly(h)
					hasTxidOnly = true
				} else {
					tx, err := transaction.NewTransactionFromHex(entry.Raw)
					must(err)
					if tx.TxID().String() != entry.TxID {
						panic("raw txid mismatch")
					}
					_, err = b.MergeRawTx(tx.Bytes(), entry.Bump)
					must(err)
				}
			}
			body, err := b.Bytes()
			if version == transaction.BEEF_V1 && hasTxidOnly {
				if err == nil {
					panic("V1 accepted txid-only")
				}
				continue
			}
			must(err)
			atomic, err := b.AtomicBytes(id)
			must(err)
			kind := "go-created-v1"
			if version == transaction.BEEF_V2 {
				kind = "go-created-v2"
			}
			results = append(results, output{f.Name, kind, f.Target, version, hex.EncodeToString(body), hex.EncodeToString(atomic), digest(body)})
		}
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	must(err)
	fmt.Println(string(encoded))
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

type fixtureFile struct {
	Fixtures []struct {
		Name       string `json:"name"`
		TargetTxID string `json:"targetTxid"`
		BEEF       struct {
			Hex string `json:"beefHex"`
		} `json:"beef"`
		AtomicHex string `json:"atomicHex"`
	} `json:"fixtures"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type txRecord struct {
	TxID       string                 `json:"txid"`
	DataFormat transaction.DataFormat `json:"dataFormat"`
	BumpIndex  int                    `json:"bumpIndex"`
	HasTx      bool                   `json:"hasTransaction"`
}
type beefRecord struct {
	Version uint32     `json:"version"`
	SHA256  string     `json:"sha256"`
	Hex     string     `json:"beefHex"`
	Bumps   []string   `json:"bumpRoots"`
	Txs     []txRecord `json:"transactions"`
}
type fixtureRecord struct {
	Name              string     `json:"name"`
	TargetTxID        string     `json:"targetTxid"`
	InputBeefSHA256   string     `json:"inputBeefSha256"`
	InputAtomicSHA256 string     `json:"inputAtomicSha256"`
	Beef              beefRecord `json:"beef"`
	Atomic            beefRecord `json:"atomic"`
	AtomicTxID        string     `json:"atomicTxid"`
	AtomicHex         string     `json:"atomicHex"`
}

func record(b *transaction.Beef, bytes []byte) beefRecord {
	txs := make([]txRecord, 0, len(b.Transactions))
	for id, item := range b.Transactions {
		txs = append(txs, txRecord{TxID: id.String(), DataFormat: item.DataFormat, BumpIndex: item.BumpIndex, HasTx: item.Transaction != nil})
	}
	roots := make([]string, 0, len(b.BUMPs))
	for _, bump := range b.BUMPs {
		root, err := bump.ComputeRoot(nil)
		if err != nil {
			panic(err)
		}
		roots = append(roots, root.String())
	}
	return beefRecord{Version: b.Version, SHA256: digest(bytes), Hex: hex.EncodeToString(bytes), Bumps: roots, Txs: txs}
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go-beef-probe.go /path/to/ts-interop-fixtures.json")
	}
	contents, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var file fixtureFile
	if err := json.Unmarshal(contents, &file); err != nil {
		panic(err)
	}
	results := make([]fixtureRecord, 0, len(file.Fixtures))
	for _, fixture := range file.Fixtures {
		inputBeef, err := hex.DecodeString(fixture.BEEF.Hex)
		if err != nil {
			panic(err)
		}
		inputAtomic, err := hex.DecodeString(fixture.AtomicHex)
		if err != nil {
			panic(err)
		}
		beef, err := transaction.NewBeefFromBytes(inputBeef)
		if err != nil {
			panic(fmt.Errorf("%s BEEF: %w", fixture.Name, err))
		}
		_, subject, err := transaction.NewBeefFromAtomicBytes(inputAtomic)
		if err != nil {
			panic(fmt.Errorf("%s AtomicBEEF: %w", fixture.Name, err))
		}
		// Exercise Go serialization APIs. These are fresh bytes, not input echoes.
		beefBytes, err := beef.Bytes()
		if err != nil {
			panic(fmt.Errorf("%s Beef.Bytes: %w", fixture.Name, err))
		}
		atomicBytes, err := beef.AtomicBytes(subject)
		if err != nil {
			panic(fmt.Errorf("%s Beef.AtomicBytes: %w", fixture.Name, err))
		}
		atomic, _, err := transaction.NewBeefFromAtomicBytes(atomicBytes)
		if err != nil {
			panic(err)
		}
		results = append(results, fixtureRecord{
			Name: fixture.Name, TargetTxID: fixture.TargetTxID,
			InputBeefSHA256: digest(inputBeef), InputAtomicSHA256: digest(inputAtomic),
			Beef: record(beef, beefBytes), Atomic: record(atomic, atomicBytes),
			AtomicTxID: subject.String(), AtomicHex: hex.EncodeToString(atomicBytes),
		})
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(encoded))
}

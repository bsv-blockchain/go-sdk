package main

import (
	"log"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
)

func main() {
	expectedWif := "KxPEP4DCP2a4g3YU5amfXjFH4kWmz8EHWrTugXocGWgWBbhGsX7a"

	// Restore a key from 3 of 5 key shares
	shares := []string{
		"89Gtabj94hosNkJtAtSeJTBKrrZ2BpoVYr2Kmt5UFzjR.69DcY9ngWU7afbj1Na84BahFUMPb6qkBa1hmzDkDcp18.3.bbc45478",
		"CsA3JhDRqBb1z58FxoixZmdsLTvHuehfwZzPgqJVA3Yv.4PP6QQcmFxikiX38yYUCqE2LFmht2MjXkf4nRjMqYBgw.3.bbc45478",
		"BVk1tcvJEbhUfZagStg15rFRxQDeLzgSN15rWkGhNf19.CUB7p6zK3JPBkBriRRGdWj4y3Z3qCfsaCYutmMWKv1VJ.3.bbc45478",
	}

	pk, _ := ec.PrivateKeyFromBackupShares(shares)

	if pk.Wif() == expectedWif {
		log.Println("Private key:", pk.Wif())
	}

	// Prints The Original Private key
	// KxPEP4DCP2a4g3YU5amfXjFH4kWmz8EHWrTugXocGWgWBbhGsX7a
}

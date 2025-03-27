package main

import (
	"encoding/hex"
	"log"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func main() {
	pk, _ := ec.PrivateKeyFromWif("KxPEP4DCP2a4g3YU5amfXjFH4kWmz8EHWrTugXocGWgWBbhGsX7a")
	log.Println("Private key:", hex.EncodeToString(pk.PubKey().Hash())[:8])
	totalShares := 5
	threshold := 3
	shares, _ := pk.ToBackupShares(threshold, totalShares)

	for i, share := range shares {
		log.Printf("Share %d: %s", i+1, share)
	}

	// Prints
	// Share 1: <share1-x>.<share1-y>.3.bbc45478
	// Share 2: <share1-x>.<share1-y>.3.bbc45478
	// Share 3: <share1-x>.<share1-y>.3.bbc45478
	// Share 4: <share1-x>.<share1-y>.3.bbc45478
	// Share 5: <share1-x>.<share1-y>.3.bbc45478
}

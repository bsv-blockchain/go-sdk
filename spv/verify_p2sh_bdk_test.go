//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package spv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/transaction/bdk"
)

// TestSPVVerifyEFInputP2SHAgainstBDK checks that bitcoin-sv reaches the
// verdict Verify does for an Extended Format input spending a P2SH-shaped
// output, at the pre-Genesis height p2shCoinHeight forces such a coin to: a
// real chain can never actually put a P2SH-shaped, non-coinbase
// output after Genesis (CheckRegularTransaction, validation.cpp:610-623), so
// this is the height the node itself would use if it could see this coin.
//
// The height 100 passed to the validator below is that same forced
// assumption, not an independent fact about a real chain: this checks that
// node and Verify agree on the script verdict once both are told the coin
// is pre-Genesis, i.e. the consequence of p2shCoinHeight's clamp, not its
// premise (that no other height is possible for such a coin), which is a
// property of validation.cpp:610-623 itself, not something a single
// verdict comparison at one height can establish.
func TestSPVVerifyEFInputP2SHAgainstBDK(t *testing.T) {
	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)
	for _, signed := range []bool{false, true} {
		tx := efP2SHSpend(t, signed)
		verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
		require.Equal(t, signed, verified, "SDK: %v", err)

		nodeErr := validator.ValidateTransaction(tx, []int32{100}, nextBlockHeight, true)
		require.Equal(t, signed, nodeErr == nil, "node: %v", nodeErr)
	}
}

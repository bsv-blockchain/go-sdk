package admintoken_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestDecodeTooFewFields covers the branch where a pushdrop script decodes but
// has fewer than the four fields an admin token requires.
func TestDecodeTooFewFields(t *testing.T) {
	testWallet := createTestWallet(t)
	pushDrop := &pushdrop.PushDrop{
		Wallet:     testWallet,
		Originator: testOriginator,
	}
	ctx := context.Background()

	protocolID := wallet.Protocol{SecurityLevel: 2, Protocol: "service host interconnect"}
	lockingScript, err := pushDrop.Lock(
		ctx,
		[][]byte{
			[]byte(overlay.ProtocolSHIP),
			[]byte("only-two-fields"),
		},
		protocolID,
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false,
		true,
		pushdrop.LockBefore,
	)
	require.NoError(t, err)

	assert.Nil(t, admintoken.Decode(lockingScript))
}

// TestLockGetPublicKeyError covers the branch where fetching the identity key
// fails before the token is locked.
func TestLockGetPublicKeyError(t *testing.T) {
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockWallet.OnGetPublicKey().ReturnError(errors.New("no identity key"))

	template := admintoken.NewOverlayAdminToken(mockWallet, testOriginator)
	_, err := template.Lock(context.Background(), overlay.ProtocolSHIP, "example.com", "tm_tests")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no identity key")
}

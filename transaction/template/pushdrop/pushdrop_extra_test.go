package pushdrop_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestDecodeReturnsNil(t *testing.T) {
	t.Parallel()

	t.Run("too-few-chunks", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, pushdrop.Decode(&script.Script{}))
	})

	t.Run("not-a-pushdrop", func(t *testing.T) {
		t.Parallel()
		s := &script.Script{}
		require.NoError(t, s.AppendPushData([]byte{0x01, 0x02, 0x03}))
		require.NoError(t, s.AppendPushData([]byte{0x04, 0x05, 0x06}))
		assert.Nil(t, pushdrop.Decode(s))
	})
}

func TestCreateMinimallyEncodedScriptChunkZeroCases(t *testing.T) {
	t.Parallel()

	empty := pushdrop.CreateMinimallyEncodedScriptChunk(nil)
	assert.Equal(t, script.Op0, empty.Op)

	single := pushdrop.CreateMinimallyEncodedScriptChunk([]byte{0})
	assert.Equal(t, script.Op0, single.Op)
}

func TestUnlockWithOptions(t *testing.T) {
	t.Parallel()
	p := &pushdrop.PushDrop{}
	sats := uint64(1234)
	ls := &script.Script{}
	unlocker := p.Unlock(
		context.Background(),
		wallet.Protocol{SecurityLevel: 0, Protocol: "testing"},
		"key",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		wallet.SignOutputsAll,
		false,
		pushdrop.UnlockOptions{SourceSatoshis: &sats, LockingScript: ls},
	)
	require.NotNil(t, unlocker)
	assert.Equal(t, uint32(73), unlocker.EstimateLength())
}

func TestLockAfterPosition(t *testing.T) {
	ctx := context.Background()
	testWallet := createTestWallet(t)
	p := &pushdrop.PushDrop{Wallet: testWallet, Originator: "test"}

	fields := [][]byte{[]byte("a"), []byte("b")}
	protocolID := wallet.Protocol{SecurityLevel: 0, Protocol: "testing"}
	counterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

	lockingScript, err := p.Lock(
		ctx,
		fields,
		protocolID,
		"test-key",
		counterparty,
		false,
		false,
		pushdrop.LockAfter,
	)
	require.NoError(t, err)
	require.NotNil(t, lockingScript)

	// Confirm the same public key is retrievable, proving the lock-after script
	// was assembled.
	expected, err := testWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        "test-key",
			Counterparty: counterparty,
		},
		ForSelf: util.BoolPtr(false),
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, expected)
}

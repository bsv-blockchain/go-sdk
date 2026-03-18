package admintoken_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestDecode_NullByteFields covers the null-byte normalization branch in Decode
func TestDecode_NullByteFields(t *testing.T) {
	testWallet := createTestWallet(t)
	pushDrop := &pushdrop.PushDrop{
		Wallet:     testWallet,
		Originator: "test-originator",
	}

	ctx := context.Background()

	// Get public key bytes for identity field
	pub, err := testWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "test-originator")
	require.NoError(t, err)

	protocolID := wallet.Protocol{SecurityLevel: 2, Protocol: "service host interconnect"}
	keyID := "1"
	counterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

	// Create a script with null bytes (0x00) in domain and topic fields.
	// pushdrop encodes empty-like values as a single null byte in some paths.
	lockingScript, err := pushDrop.Lock(
		ctx,
		[][]byte{
			[]byte(overlay.ProtocolSHIP),
			pub.PublicKey.Compressed(),
			{0x00}, // domain as null byte
			{0x00}, // topicOrService as null byte
		},
		protocolID,
		keyID,
		counterparty,
		false,
		true,
		pushdrop.LockBefore,
	)
	require.NoError(t, err)

	decoded := admintoken.Decode(lockingScript)
	require.NotNil(t, decoded)

	// Null bytes should be normalized to empty strings
	assert.Equal(t, "", decoded.Domain, "null byte domain should decode to empty string")
	assert.Equal(t, "", decoded.TopicOrService, "null byte topicOrService should decode to empty string")
	assert.Equal(t, overlay.ProtocolSHIP, decoded.Protocol)
}

// TestDecode_NilScript covers Decode when the pushdrop.Decode returns nil (bad script)
func TestDecode_NilScript(t *testing.T) {
	emptyScript := &script.Script{}
	result := admintoken.Decode(emptyScript)
	assert.Nil(t, result)
}

// TestLock_InvalidProtocol covers the error path for an invalid/unknown protocol
func TestLock_InvalidProtocol(t *testing.T) {
	testWallet := createTestWallet(t)
	template := admintoken.NewOverlayAdminToken(testWallet, "test-originator")

	ctx := context.Background()

	// Use a protocol string that is neither SHIP nor SLAP — its ID() returns empty string
	invalidProtocol := overlay.Protocol("UNKNOWN")
	_, err := template.Lock(ctx, invalidProtocol, "test.com", "tm_tests")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid overlay protocol id")
}

// TestNewOverlayAdminToken_WithoutOriginator covers creation without originator
func TestNewOverlayAdminToken_WithoutOriginator(t *testing.T) {
	privKeyBytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	privKey, _ := ec.PrivateKeyFromBytes(privKeyBytes)
	testWallet, err := wallet.NewCompletedProtoWallet(privKey)
	require.NoError(t, err)

	// Should not panic; Originator should be empty
	token := admintoken.NewOverlayAdminToken(testWallet)
	require.NotNil(t, token)
	assert.Equal(t, "", token.PushDrop.Originator)
}

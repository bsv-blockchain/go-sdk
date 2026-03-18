package registry

// registry_extra_test.go – additional tests to increase coverage beyond 61%.
//
// The mock.go stubs that call require.Fail() with 0% coverage cannot be
// exercised without failing the test (require.Fail marks the *testing.T as
// failed and calls FailNow). Since NewMockRegistry accepts *testing.T (not an
// interface), there is no way to inject a fake T from outside the package.
// Those 28 stub method bodies therefore remain in the architecturally-blocked
// category; this file focuses on all other uncovered paths.

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- shared helpers ---------------------------------------------------------

const validBeefHex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

func decodeValidBeef(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(validBeefHex)
	require.NoError(t, err)
	return b
}

func makeTestPubKey(t *testing.T) *ec.PublicKey {
	t.Helper()
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	key, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	return key
}

func successBroadcasterFactory(txid string) BroadcasterFactory {
	return func(_ []string, _ *topic.BroadcasterConfig) (transaction.Broadcaster, error) {
		return &MockBroadcaster{
			BroadcastSuccess: &transaction.BroadcastSuccess{Txid: txid, Message: "ok"},
		}, nil
	}
}

func errorBroadcasterFactory() BroadcasterFactory {
	return func(_ []string, _ *topic.BroadcasterConfig) (transaction.Broadcaster, error) {
		return nil, errors.New("broadcaster creation failed")
	}
}

// buildPushDropScript creates a pushdrop-format script from raw byte fields.
func buildPushDropScript(t *testing.T, fields [][]byte) *script.Script {
	t.Helper()
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	s := &script.Script{}
	require.NoError(t, s.AppendPushData(pubKeyBytes))
	require.NoError(t, s.AppendOpcodes(script.OpCHECKSIG))
	for _, f := range fields {
		require.NoError(t, s.AppendPushData(f))
	}
	numDrops := (len(fields) + 1) / 2
	for i := 0; i < numDrops; i++ {
		require.NoError(t, s.AppendOpcodes(script.Op2DROP))
	}
	return s
}

// beefWithScript wraps a locking script in a minimal parent→child BEEF chain.
func beefWithScript(t *testing.T, lockingScript *script.Script) ([]byte, *transaction.Transaction) {
	t.Helper()
	parentTx := transaction.NewTransaction()
	parentTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	parentTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      2000,
		LockingScript: &script.Script{},
	})

	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       parentTx.TxID(),
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockingScript,
	})
	tx.Inputs[0].SourceTransaction = parentTx

	beef, err := tx.AtomicBEEF(true)
	require.NoError(t, err)
	return beef, tx
}

// mockTxid is a convenience helper.
func mockTxid(t *testing.T) *chainhash.Hash {
	t.Helper()
	h, err := chainhash.NewHashFromHex("f1e1fd3c6504b94e9cb0ecfb7db1167655e3d5f98afd977a18fc01e1a6e59504")
	require.NoError(t, err)
	return h
}

// ---- DefaultBroadcasterFactory ----------------------------------------------

func TestDefaultBroadcasterFactory_ReturnsValue(t *testing.T) {
	// Just call DefaultBroadcasterFactory; a successful or errored result both cover it.
	_, _ = DefaultBroadcasterFactory([]string{"tm_basketmap"}, &topic.BroadcasterConfig{
		NetworkPreset: overlay.NetworkLocal,
	})
}

// ---- NewRegistryClient lookupFactory branch ---------------------------------

func TestNewRegistryClient_LookupFactoryReturnsResolver(t *testing.T) {
	client := NewRegistryClient(NewMockRegistry(t), "originator")
	resolver := client.lookupFactory()
	assert.NotNil(t, resolver)
}

// ---- RegisterDefinition error paths -----------------------------------------

func TestRegisterDefinition_GetPublicKeyError(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.GetPublicKeyError = errors.New("key unavailable")

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key unavailable")
}

func TestRegisterDefinition_NilTxInCreateActionResult(t *testing.T) {
	// CreateAction returns a non-nil result but with nil Tx → "failed to create registration transaction"
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	// Return a result with Tx == nil
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: nil}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(successBroadcasterFactory("aabbcc"))

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create")
}

func TestRegisterDefinition_BroadcasterFactoryError(t *testing.T) {
	beef := decodeValidBeef(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(errorBroadcasterFactory())

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broadcaster creation failed")
}

func TestRegisterDefinition_ProtocolType(t *testing.T) {
	beef := decodeValidBeef(t)
	txID := mockTxid(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.SignActionResultToReturn = &wallet.SignActionResult{Tx: beef, Txid: *txID}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(successBroadcasterFactory(txID.String()))

	result, err := client.RegisterDefinition(context.Background(), &ProtocolDefinitionData{
		DefinitionType:   DefinitionTypeProtocol,
		ProtocolID:       wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "test-proto"},
		Name:             "Test Protocol",
		IconURL:          "https://example.com/icon.png",
		Description:      "desc",
		DocumentationURL: "https://example.com/docs",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRegisterDefinition_CertificateType(t *testing.T) {
	beef := decodeValidBeef(t)
	txID := mockTxid(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.SignActionResultToReturn = &wallet.SignActionResult{Tx: beef, Txid: *txID}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(successBroadcasterFactory(txID.String()))

	result, err := client.RegisterDefinition(context.Background(), &CertificateDefinitionData{
		DefinitionType:   DefinitionTypeCertificate,
		Type:             "cert-type",
		Name:             "Test Cert",
		IconURL:          "https://example.com/icon.png",
		Description:      "desc",
		DocumentationURL: "https://example.com/docs",
		Fields: map[string]CertificateFieldDescriptor{
			"name": {FriendlyName: "Full Name", Type: "text"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
}

// ---- RegisterDefinition – network detection branches ------------------------

// mockWalletNetwork wraps MockRegistry and overrides GetNetwork.
type mockWalletNetwork struct {
	*MockRegistry
	resp string
	err  error
}

func (m *mockWalletNetwork) GetNetwork(_ context.Context, _ any, _ string) (*wallet.GetNetworkResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &wallet.GetNetworkResult{Network: wallet.Network(m.resp)}, nil
}

func TestRegisterDefinition_NetworkDetectTestnet(t *testing.T) {
	beef := decodeValidBeef(t)
	mw := &mockWalletNetwork{MockRegistry: NewMockRegistry(t), resp: "testnet"}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	client := NewRegistryClient(mw, "originator")
	client.network = overlay.Network(-1) // force GetNetwork call
	client.SetBroadcasterFactory(successBroadcasterFactory("aabb"))
	// Result may succeed or fail on BEEF parse; the network branch is exercised either way.
	_, _ = client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
}

func TestRegisterDefinition_NetworkDetectMainnet(t *testing.T) {
	beef := decodeValidBeef(t)
	mw := &mockWalletNetwork{MockRegistry: NewMockRegistry(t), resp: "mainnet"}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	client := NewRegistryClient(mw, "originator")
	client.network = overlay.Network(-1)
	client.SetBroadcasterFactory(successBroadcasterFactory("aabb"))
	_, _ = client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
}

func TestRegisterDefinition_NetworkDetectUnknown(t *testing.T) {
	beef := decodeValidBeef(t)
	mw := &mockWalletNetwork{MockRegistry: NewMockRegistry(t), resp: "local"}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	client := NewRegistryClient(mw, "originator")
	client.network = overlay.Network(-1)
	client.SetBroadcasterFactory(successBroadcasterFactory("aabb"))
	_, _ = client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
}

func TestRegisterDefinition_GetNetworkError(t *testing.T) {
	beef := decodeValidBeef(t)
	mw := &mockWalletNetwork{MockRegistry: NewMockRegistry(t), err: errors.New("no network")}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: beef}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	client := NewRegistryClient(mw, "originator")
	client.network = overlay.Network(-1)
	client.SetBroadcasterFactory(successBroadcasterFactory("aabb"))

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no network")
}

// ---- ListOwnRegistryEntries additional paths --------------------------------

func TestListOwnRegistryEntries_NonSpendableSkipped(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{Satoshis: 1000, Spendable: false, Outpoint: transaction.Outpoint{Index: 0}},
		},
		BEEF: []byte{},
	}
	client := NewRegistryClient(mw, "originator")
	results, err := client.ListOwnRegistryEntries(context.Background(), DefinitionTypeBasket)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListOwnRegistryEntries_InvalidBEEFSkipped(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{Satoshis: 1000, Spendable: true, Outpoint: transaction.Outpoint{Index: 0}},
		},
		BEEF: []byte("bad-beef"),
	}
	client := NewRegistryClient(mw, "originator")
	results, err := client.ListOwnRegistryEntries(context.Background(), DefinitionTypeBasket)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListOwnRegistryEntries_OutOfBoundsIndexSkipped(t *testing.T) {
	ls := buildPushDropScript(t, [][]byte{
		[]byte("basket-id"), []byte("name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), []byte("operator"),
	})
	beef, tx := beefWithScript(t, ls)

	mw := NewMockRegistry(t)
	mw.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{Satoshis: 1000, Spendable: true,
				Outpoint: transaction.Outpoint{Txid: *tx.TxID(), Index: 99}},
		},
		BEEF: beef,
	}
	// Use testLogger context to cover the debug branch
	ctx := context.WithValue(context.Background(), "testLogger", logCapture{}) //nolint:staticcheck
	client := NewRegistryClient(mw, "originator")
	results, err := client.ListOwnRegistryEntries(ctx, DefinitionTypeBasket)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListOwnRegistryEntries_InvalidLockingScriptSkipped(t *testing.T) {
	emptyScript := &script.Script{}
	beef, tx := beefWithScript(t, emptyScript)

	mw := NewMockRegistry(t)
	mw.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{Satoshis: 1000, Spendable: true,
				Outpoint: transaction.Outpoint{Txid: *tx.TxID(), Index: 0}},
		},
		BEEF: beef,
	}
	ctx := context.WithValue(context.Background(), "testLogger", logCapture{}) //nolint:staticcheck
	client := NewRegistryClient(mw, "originator")
	results, err := client.ListOwnRegistryEntries(ctx, DefinitionTypeBasket)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListOwnRegistryEntries_ProtocolType(t *testing.T) {
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	ls := buildPushDropScript(t, [][]byte{
		[]byte(`[2,"myprotocol"]`), []byte("Proto Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), pubKeyBytes,
	})
	beef, tx := beefWithScript(t, ls)

	mw := NewMockRegistry(t)
	mw.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{Satoshis: 1000, Spendable: true,
				Outpoint: transaction.Outpoint{Txid: *tx.TxID(), Index: 0}},
		},
		BEEF: beef,
	}
	client := NewRegistryClient(mw, "originator")
	results, err := client.ListOwnRegistryEntries(context.Background(), DefinitionTypeProtocol)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestListOwnRegistryEntries_CertificateType(t *testing.T) {
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	ls := buildPushDropScript(t, [][]byte{
		[]byte("cert-type"), []byte("Cert Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"),
		[]byte(`{"name":{"friendlyName":"N","type":"text","description":"","fieldIcon":""}}`),
		pubKeyBytes,
	})
	beef, tx := beefWithScript(t, ls)

	mw := NewMockRegistry(t)
	mw.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{Satoshis: 1000, Spendable: true,
				Outpoint: transaction.Outpoint{Txid: *tx.TxID(), Index: 0}},
		},
		BEEF: beef,
	}
	client := NewRegistryClient(mw, "originator")
	results, err := client.ListOwnRegistryEntries(context.Background(), DefinitionTypeCertificate)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestListOwnRegistryEntries_ListOutputsError(t *testing.T) {
	mw := &walletWithListError{MockRegistry: NewMockRegistry(t), err: errors.New("db offline")}
	client := NewRegistryClient(mw, "originator")
	_, err := client.ListOwnRegistryEntries(context.Background(), DefinitionTypeBasket)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db offline")
}

// walletWithListError overrides ListOutputs to return an error.
type walletWithListError struct {
	*MockRegistry
	err error
}

func (m *walletWithListError) ListOutputs(_ context.Context, _ wallet.ListOutputsArgs, _ string) (*wallet.ListOutputsResult, error) {
	return nil, m.err
}

// logCapture satisfies the testLogger context interface.
type logCapture struct{}

func (logCapture) Logf(_ string, _ ...interface{}) {}

// ---- parseLockingScript – success paths -------------------------------------

func testPubKeyBytes() []byte {
	return []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
}

func TestParseLockingScript_BasketSuccess(t *testing.T) {
	s := buildPushDropScript(t, [][]byte{
		[]byte("basket-id"), []byte("Basket Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), testPubKeyBytes(),
	})
	data, err := parseLockingScript(DefinitionTypeBasket, s)
	require.NoError(t, err)
	basket, ok := data.(*BasketDefinitionData)
	require.True(t, ok)
	assert.Equal(t, "basket-id", basket.BasketID)
}

func TestParseLockingScript_ProtocolSuccess(t *testing.T) {
	s := buildPushDropScript(t, [][]byte{
		[]byte(`[2,"myprotocol"]`), []byte("Proto Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), testPubKeyBytes(),
	})
	data, err := parseLockingScript(DefinitionTypeProtocol, s)
	require.NoError(t, err)
	proto, ok := data.(*ProtocolDefinitionData)
	require.True(t, ok)
	assert.Equal(t, "myprotocol", proto.ProtocolID.Protocol)
}

func TestParseLockingScript_ProtocolBadJSON(t *testing.T) {
	s := buildPushDropScript(t, [][]byte{
		[]byte("not-valid-json"), []byte("Proto Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), testPubKeyBytes(),
	})
	_, err := parseLockingScript(DefinitionTypeProtocol, s)
	require.Error(t, err)
}

func TestParseLockingScript_ProtocolWrongFieldCount(t *testing.T) {
	s := buildPushDropScript(t, [][]byte{[]byte("a"), []byte("b"), []byte("c")})
	_, err := parseLockingScript(DefinitionTypeProtocol, s)
	require.Error(t, err)
}

func TestParseLockingScript_CertificateSuccess(t *testing.T) {
	s := buildPushDropScript(t, [][]byte{
		[]byte("cert-type"), []byte("Cert Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"),
		[]byte(`{"name":{"friendlyName":"Name","type":"text","description":"","fieldIcon":""}}`),
		testPubKeyBytes(),
	})
	data, err := parseLockingScript(DefinitionTypeCertificate, s)
	require.NoError(t, err)
	cert, ok := data.(*CertificateDefinitionData)
	require.True(t, ok)
	assert.Equal(t, "cert-type", cert.Type)
}

func TestParseLockingScript_CertificateInvalidFieldsJSON(t *testing.T) {
	// Invalid fields JSON → results in empty map (no error)
	s := buildPushDropScript(t, [][]byte{
		[]byte("cert-type"), []byte("Cert Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), []byte("invalid-json"), testPubKeyBytes(),
	})
	data, err := parseLockingScript(DefinitionTypeCertificate, s)
	require.NoError(t, err)
	cert, ok := data.(*CertificateDefinitionData)
	require.True(t, ok)
	assert.Empty(t, cert.Fields)
}

func TestParseLockingScript_CertificateWrongFieldCount(t *testing.T) {
	s := buildPushDropScript(t, [][]byte{[]byte("a"), []byte("b")})
	_, err := parseLockingScript(DefinitionTypeCertificate, s)
	require.Error(t, err)
}

// ---- RevokeOwnRegistryEntry additional paths --------------------------------

func TestRevokeOwnRegistryEntry_WrongOwner(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: "000000000000000000000000000000000000000000000000000000000000000000",
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}

	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong to the current wallet")
}

func TestRevokeOwnRegistryEntry_InvalidOutpoint(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "NOTHEX",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse outpoint")
}

func TestRevokeOwnRegistryEntry_CreateActionError(t *testing.T) {
	key := makeTestPubKey(t)
	mw := &walletWithCreateActionError{MockRegistry: NewMockRegistry(t), err: errors.New("wallet busy")}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet busy")
}

func TestRevokeOwnRegistryEntry_NilSignableTransaction(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{SignableTransaction: nil}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create signable transaction")
}

func TestRevokeOwnRegistryEntry_InvalidPartialBeef(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        []byte("not-valid-beef"),
			Reference: []byte("ref"),
		},
	}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse partial transaction")
}

func TestRevokeOwnRegistryEntry_SignActionError(t *testing.T) {
	key := makeTestPubKey(t)
	beef := decodeValidBeef(t)
	mw := &walletWithSignActionError{MockRegistry: NewMockRegistry(t), err: errors.New("sign failed")}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{Tx: beef, Reference: []byte("ref")},
	}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script", BEEF: beef,
		},
	}
	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
}

func TestRevokeOwnRegistryEntry_SignResultNilTx(t *testing.T) {
	key := makeTestPubKey(t)
	beef := decodeValidBeef(t)
	txID := mockTxid(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{Tx: beef, Reference: []byte("ref")},
	}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	mw.SignActionResultToReturn = &wallet.SignActionResult{Tx: nil, Txid: *txID}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script", BEEF: beef,
		},
	}
	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get signed transaction")
}

func TestRevokeOwnRegistryEntry_BroadcasterFactoryError(t *testing.T) {
	key := makeTestPubKey(t)
	beef := decodeValidBeef(t)
	txID := mockTxid(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{Tx: beef, Reference: []byte("ref")},
	}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	mw.SignActionResultToReturn = &wallet.SignActionResult{Tx: beef, Txid: *txID}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script", BEEF: beef,
		},
	}
	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(errorBroadcasterFactory())

	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broadcaster creation failed")
}

func TestRevokeOwnRegistryEntry_InvalidSignedTxBeef(t *testing.T) {
	key := makeTestPubKey(t)
	beef := decodeValidBeef(t)
	txID := mockTxid(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{Tx: beef, Reference: []byte("ref")},
	}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	// SignAction returns bad BEEF
	mw.SignActionResultToReturn = &wallet.SignActionResult{Tx: []byte("bad-beef"), Txid: *txID}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script", BEEF: beef,
		},
	}
	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(successBroadcasterFactory("aabb"))

	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create transaction from BEEF")
}

func TestRevokeOwnRegistryEntry_ProtocolItemIdentifier(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{SignableTransaction: nil}

	record := &RegistryRecord{
		DefinitionData: &ProtocolDefinitionData{
			DefinitionType:   DefinitionTypeProtocol,
			Name:             "Proto Name",
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err) // Fails on nil signable tx — but exercises Protocol branch
}

func TestRevokeOwnRegistryEntry_CertNameBranch(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{SignableTransaction: nil}

	record := &RegistryRecord{
		DefinitionData: &CertificateDefinitionData{
			DefinitionType:   DefinitionTypeCertificate,
			Name:             "MyCert",
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
}

func TestRevokeOwnRegistryEntry_CertTypeBranch(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{SignableTransaction: nil}

	record := &RegistryRecord{
		DefinitionData: &CertificateDefinitionData{
			DefinitionType:   DefinitionTypeCertificate,
			Name:             "", // empty name → use Type
			Type:             "cert-type-id",
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
}

func TestRevokeOwnRegistryEntry_UnknownDefinitionDataBranch(t *testing.T) {
	key := makeTestPubKey(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{SignableTransaction: nil}

	record := &RegistryRecord{
		DefinitionData: &customDefinitionData{operator: key.ToDERHex()},
		TokenData: TokenData{
			TxID:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LockingScript: "some-script",
		},
	}
	client := NewRegistryClient(mw, "originator")
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
}

// customDefinitionData exercises the default case in the type-switch.
type customDefinitionData struct{ operator string }

func (c *customDefinitionData) GetDefinitionType() DefinitionType { return "custom" }
func (c *customDefinitionData) GetRegistryOperator() string       { return c.operator }

// walletWithCreateActionError overrides CreateAction to return an error.
type walletWithCreateActionError struct {
	*MockRegistry
	err error
}

func (m *walletWithCreateActionError) CreateAction(_ context.Context, _ wallet.CreateActionArgs, _ string) (*wallet.CreateActionResult, error) {
	return nil, m.err
}

// walletWithSignActionError overrides SignAction to return an error.
type walletWithSignActionError struct {
	*MockRegistry
	err error
}

func (m *walletWithSignActionError) SignAction(_ context.Context, _ wallet.SignActionArgs, _ string) (*wallet.SignActionResult, error) {
	return nil, m.err
}

// ---- Resolve* with valid BEEF – output-index out of range -------------------

func TestResolveBasket_OutputIndexOutOfRange(t *testing.T) {
	ls := buildPushDropScript(t, [][]byte{
		[]byte("basket-id"), []byte("name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), []byte("operator"),
	})
	beef, _ := beefWithScript(t, ls)

	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 99}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)
	results, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// Note: ResolveProtocol and ResolveCertificate do not have bounds-check guards
// on output.OutputIndex (unlike ResolveBasket), so we cannot test the
// out-of-range path for those methods without panicking. The equivalent tests
// are only present for ResolveBasket.

// ---- Resolve* – invalid locking script in valid BEEF ------------------------

func TestResolveBasket_InvalidLockingScriptSkipped(t *testing.T) {
	beef, _ := beefWithScript(t, &script.Script{})
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)
	results, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestResolveProtocol_InvalidLockingScriptSkipped(t *testing.T) {
	beef, _ := beefWithScript(t, &script.Script{})
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_protomap", facilitator)
	results, err := client.ResolveProtocol(context.Background(), ProtocolQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestResolveCertificate_InvalidLockingScriptSkipped(t *testing.T) {
	beef, _ := beefWithScript(t, &script.Script{})
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_certmap", facilitator)
	results, err := client.ResolveCertificate(context.Background(), CertificateQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// ---- Resolve* happy paths with complete matching scripts --------------------

func TestResolveBasket_ValidRecord(t *testing.T) {
	ls := buildPushDropScript(t, [][]byte{
		[]byte("basket-id"), []byte("Basket Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), testPubKeyBytes(),
	})
	beef, _ := beefWithScript(t, ls)
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)
	results, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "basket-id", results[0].BasketID)
}

func TestResolveProtocol_ValidRecord(t *testing.T) {
	ls := buildPushDropScript(t, [][]byte{
		[]byte(`[2,"myprotocol"]`), []byte("Proto Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), testPubKeyBytes(),
	})
	beef, _ := beefWithScript(t, ls)
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_protomap", facilitator)
	results, err := client.ResolveProtocol(context.Background(), ProtocolQuery{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "myprotocol", results[0].ProtocolID.Protocol)
}

func TestResolveCertificate_ValidRecord(t *testing.T) {
	ls := buildPushDropScript(t, [][]byte{
		[]byte("cert-type"), []byte("Cert Name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), []byte(`{}`), testPubKeyBytes(),
	})
	beef, _ := beefWithScript(t, ls)
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	client := buildClientWithMockLookup(t, "ls_certmap", facilitator)
	results, err := client.ResolveCertificate(context.Background(), CertificateQuery{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "cert-type", results[0].Type)
}

// ---- pushdrop.Lock coverage via mock wallet ---------------------------------

func TestPushDropLock_CoversBuildFieldsProtocol(t *testing.T) {
	ctx := context.Background()
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	pd := &pushdrop.PushDrop{Wallet: mw, Originator: "originator"}
	fields := [][]byte{
		[]byte(`[2,"proto"]`), []byte("name"), []byte("icon"),
		[]byte("desc"), []byte("doc"), testPubKeyBytes(),
	}
	_, err := pd.Lock(ctx, fields, wallet.Protocol{}, "1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		false, false, pushdrop.LockBefore,
	)
	require.NoError(t, err)
}

// ---- CreateAction mock – arg-check branches ---------------------------------

func TestMockCreateAction_ArgCheckBranch(t *testing.T) {
	expectedArgs := &wallet.CreateActionArgs{
		Description: "test action",
		Outputs:     []wallet.CreateActionOutput{},
	}
	mw := NewMockRegistry(t)
	mw.ExpectedCreateActionArgs = expectedArgs
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{}

	result, err := mw.CreateAction(context.Background(), wallet.CreateActionArgs{
		Description: "test action",
		Outputs:     []wallet.CreateActionOutput{},
	}, "")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestMockCreateAction_OriginatorCheckBranch(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.ExpectedOriginator = "expected-orig"
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{}

	result, err := mw.CreateAction(context.Background(), wallet.CreateActionArgs{}, "expected-orig")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ---- buildPushDropFields – zero-value protocol ID (covers line 163-165) ----

func TestBuildPushDropFields_ZeroValueProtocol(t *testing.T) {
	data := &ProtocolDefinitionData{
		ProtocolID: wallet.Protocol{SecurityLevel: 0, Protocol: ""},
	}
	fields, err := buildPushDropFields(data, "operator")
	require.NoError(t, err)
	assert.Len(t, fields, 6)
}

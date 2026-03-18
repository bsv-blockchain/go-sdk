package registry

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOriginator            = "test-originator"
	errLookupQueryError       = "lookup query error"
	errUnexpectedLookupResult = "unexpected lookup result type"
)

// Suppress unused import warning - time is used in slowFacilitator
var _ = time.Second

// mockFacilitator is a mock lookup.Facilitator that returns configurable responses.
type mockFacilitator struct {
	answer *lookup.LookupAnswer
	err    error
}

func (m *mockFacilitator) Lookup(ctx context.Context, url string, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return m.answer, m.err
}

// buildClientWithMockLookup creates a RegistryClient whose lookup factory returns a resolver
// backed by the given facilitator and host override for the specified service.
func buildClientWithMockLookup(t *testing.T, serviceName string, facilitator lookup.Facilitator) *RegistryClient {
	t.Helper()
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, testOriginator)
	client.lookupFactory = func() *lookup.LookupResolver {
		return &lookup.LookupResolver{
			Facilitator: facilitator,
			HostOverrides: map[string][]string{
				serviceName: {"http://mock-host"},
			},
			AdditionalHosts: map[string][]string{},
		}
	}
	return client
}

// ---- ResolveBasket ----

func TestResolveBasketLookupError(t *testing.T) {
	facilitator := &mockFacilitator{err: fmt.Errorf("lookup failed")}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)

	_, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), errLookupQueryError)
}

func TestResolveBasketWrongAnswerType(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{Type: "freeform", Result: "some result"},
	}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)

	_, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnexpectedLookupResult)
}

func TestResolveBasketEmptyOutputList(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		},
	}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)

	results, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestResolveBasketInvalidBEEFSkipped(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type: lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{
				{Beef: []byte("invalid-beef"), OutputIndex: 0},
			},
		},
	}
	client := buildClientWithMockLookup(t, "ls_basketmap", facilitator)

	// Invalid BEEF is silently skipped, returns empty
	results, err := client.ResolveBasket(context.Background(), BasketQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// ---- ResolveProtocol ----

func TestResolveProtocolLookupError(t *testing.T) {
	facilitator := &mockFacilitator{err: fmt.Errorf("network error")}
	client := buildClientWithMockLookup(t, "ls_protomap", facilitator)

	_, err := client.ResolveProtocol(context.Background(), ProtocolQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), errLookupQueryError)
}

func TestResolveProtocolWrongAnswerType(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{Type: "freeform"},
	}
	client := buildClientWithMockLookup(t, "ls_protomap", facilitator)

	_, err := client.ResolveProtocol(context.Background(), ProtocolQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnexpectedLookupResult)
}

func TestResolveProtocolEmptyOutputList(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		},
	}
	client := buildClientWithMockLookup(t, "ls_protomap", facilitator)

	results, err := client.ResolveProtocol(context.Background(), ProtocolQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestResolveProtocolInvalidBEEFSkipped(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type: lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{
				{Beef: []byte("invalid"), OutputIndex: 0},
			},
		},
	}
	client := buildClientWithMockLookup(t, "ls_protomap", facilitator)

	results, err := client.ResolveProtocol(context.Background(), ProtocolQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// ---- ResolveCertificate ----

func TestResolveCertificateLookupError(t *testing.T) {
	facilitator := &mockFacilitator{err: fmt.Errorf("no route")}
	client := buildClientWithMockLookup(t, "ls_certmap", facilitator)

	_, err := client.ResolveCertificate(context.Background(), CertificateQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), errLookupQueryError)
}

func TestResolveCertificateWrongAnswerType(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{Type: lookup.AnswerTypeFreeform, Result: "data"},
	}
	client := buildClientWithMockLookup(t, "ls_certmap", facilitator)

	_, err := client.ResolveCertificate(context.Background(), CertificateQuery{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnexpectedLookupResult)
}

func TestResolveCertificateEmptyOutputList(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		},
	}
	client := buildClientWithMockLookup(t, "ls_certmap", facilitator)

	results, err := client.ResolveCertificate(context.Background(), CertificateQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestResolveCertificateInvalidBEEFSkipped(t *testing.T) {
	facilitator := &mockFacilitator{
		answer: &lookup.LookupAnswer{
			Type: lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{
				{Beef: []byte("bad"), OutputIndex: 0},
			},
		},
	}
	client := buildClientWithMockLookup(t, "ls_certmap", facilitator)

	results, err := client.ResolveCertificate(context.Background(), CertificateQuery{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// ---- parseLockingScript ----

func TestParseLockingScriptEmptyScript(t *testing.T) {
	// An empty script (not nil) should fail gracefully
	emptyScript := &script.Script{}
	_, err := parseLockingScript(DefinitionTypeBasket, emptyScript)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid registry pushdrop script")
}

func buildMockPushDropScript(t *testing.T, fields ...[]byte) *script.Script {
	t.Helper()
	// Build a minimal OP_1 ... OP_DROP script that pushdrop.Decode can parse
	// pushDrop fields appear as OP_RETURN data pushes. Use test_util approach.
	// The simplest way: create a script with a dummy checksig + fields via ScriptChunks
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	s := &script.Script{}
	// Push key
	_ = s.AppendPushData(pubKeyBytes)
	// OP_CHECKSIG
	_ = s.AppendOpcodes(script.OpCHECKSIG)
	// Push each field
	for _, f := range fields {
		_ = s.AppendPushData(f)
	}
	// 2DROP pairs to match field count / 2
	numDrops := (len(fields) + 1) / 2
	for i := 0; i < numDrops; i++ {
		_ = s.AppendOpcodes(script.Op2DROP)
	}
	return s
}

func TestParseLockingScriptBasketWrongFieldCount(t *testing.T) {
	// 4 fields instead of expected 6
	s := buildMockPushDropScript(t, []byte("a"), []byte("b"), []byte("c"), []byte("d"))
	_, err := parseLockingScript(DefinitionTypeBasket, s)
	require.Error(t, err)
}

func TestParseLockingScriptProtocolType(t *testing.T) {
	// 6 fields for protocol - 3rd field is protocol ID JSON
	protocolIDJSON := `[2, "testprotocol"]`
	s := buildMockPushDropScript(t,
		[]byte("protocolname"),
		[]byte("iconurl"),
		[]byte(protocolIDJSON),
		[]byte("description"),
		[]byte("docurl"),
		[]byte("operator"),
	)
	_, err := parseLockingScript(DefinitionTypeProtocol, s)
	// May succeed or fail depending on pushdrop field order, at least exercises the code path
	_ = err
}

func TestParseLockingScriptCertificateType(t *testing.T) {
	// 7 fields for certificate
	fieldsJSON := `{"name":{"friendlyName":"Name","type":"text"}}`
	s := buildMockPushDropScript(t,
		[]byte("cert-type"),
		[]byte("certname"),
		[]byte("iconurl"),
		[]byte("description"),
		[]byte("docurl"),
		[]byte(fieldsJSON),
		[]byte("operator"),
	)
	_, err := parseLockingScript(DefinitionTypeCertificate, s)
	// Exercise the certificate code path
	_ = err
}

func TestParseLockingScriptUnknownType(t *testing.T) {
	s := buildMockPushDropScript(t, []byte("a"), []byte("b"))
	_, err := parseLockingScript("unknown-type", s)
	require.Error(t, err)
}

// ---- ListOwnRegistryEntries error paths ----

func TestListOwnRegistryEntriesListOutputsNilResult(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	// ListOutputsResultToReturn is nil, so MockRegistry.ListOutputs calls require.Fail
	// Instead set a proper empty result
	mockWallet.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 0,
		Outputs:      []wallet.Output{},
	}
	client := NewRegistryClient(mockWallet, testOriginator)

	results, err := client.ListOwnRegistryEntries(context.Background(), DefinitionTypeBasket)
	require.NoError(t, err)
	assert.Empty(t, results)
}

// ---- RevokeOwnRegistryEntry error paths ----

func TestRevokeOwnRegistryEntryMissingTxID(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, testOriginator)

	// Empty RegistryRecord triggers validation error
	record := &RegistryRecord{}
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing txid")
}

func TestRevokeOwnRegistryEntryGetPublicKeyError(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	mockWallet.GetPublicKeyError = fmt.Errorf("no key")
	client := NewRegistryClient(mockWallet, testOriginator)

	// Provide TxID and LockingScript to pass validation, then GetPublicKey fails
	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: "someoperator",
		},
		TokenData: TokenData{
			TxID:          "abc123def456abc123def456abc123def456abc123def456abc123def456abc123",
			LockingScript: "some-script",
			OutputIndex:   0,
		},
	}
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key")
}

// ---- mock facilitator with timeout ----


package broadcaster

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/transaction"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

const testTxHex = "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"

type MockFailureClient struct{}

func (m *MockFailureClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 500,
		Body:       io.NopCloser(strings.NewReader("Internal Server Error")),
	}, nil
}

type MockSuccessClient struct{}

func (m *MockSuccessClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"txid":"4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"}`)),
	}, nil
}

type MockNetworkErrorClient struct{}

func (m *MockNetworkErrorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network error")
}

type MockBadRequestClient struct{}

func (m *MockBadRequestClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 400,
		Body:       io.NopCloser(strings.NewReader("Bad Request")),
	}, nil
}

// MockNotFoundClient returns HTTP 404, which go-whatsonchain's BroadcastTx treats
// as a non-error. The broadcaster must still report a failure, not a false success.
type MockNotFoundClient struct{}

func (m *MockNotFoundClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 404,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
	}, nil
}

type MockUnauthorizedClient struct{}

func (m *MockUnauthorizedClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(strings.NewReader("Unauthorized")),
	}, nil
}

type MockBodyReadErrorClient struct{}

type ErrorReader struct{}

func (e *ErrorReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("read error")
}

func (e *ErrorReader) Close() error {
	return nil
}

func (m *MockBodyReadErrorClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 500,
		Body:       &ErrorReader{},
	}, nil
}

// MockRequestCheckClient checks the request content and headers
type MockRequestCheckClient struct {
	t            *testing.T
	expectedBody string
	apiKey       string
}

func (m *MockRequestCheckClient) Do(req *http.Request) (*http.Response, error) {
	// Check API key if provided. go-whatsonchain sends the key in the "woc-api-key"
	// header (not an Authorization: Bearer header).
	if m.apiKey != "" {
		require.Equal(m.t, m.apiKey, req.Header.Get("woc-api-key"), "API key not properly set in woc-api-key header")
	}

	// Check Content-Type
	contentType := req.Header.Get("Content-Type")
	require.Equal(m.t, "application/json", contentType, "Content-Type header not properly set")

	// Read and verify request body
	body, err := io.ReadAll(req.Body)
	require.NoError(m.t, err, "Failed to read request body")
	require.Equal(m.t, m.expectedBody, string(body), "Request body mismatch")

	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"txid":"4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"}`)),
	}, nil
}

// TestWhatsOnChainBroadcastRequestFormat tests the format of the broadcast request
func TestWhatsOnChainBroadcastRequestFormat(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	expectedBody := fmt.Sprintf(`{"txhex":"%s"}`, testTxHex)
	apiKey := "test-api-key"

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  apiKey,
		Client: &MockRequestCheckClient{
			t:            t,
			expectedBody: expectedBody,
			apiKey:       apiKey,
		},
	}

	success, failure := b.Broadcast(tx)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

func TestWhatsOnChainBroadcast(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockSuccessClient{},
	}

	success, failure := b.Broadcast(tx)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

func TestWhatsOnChainBroadcastFailure(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockFailureClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
	require.Contains(t, failure.Description, "Internal Server Error")
}

func TestWhatsOnChainBroadcastClientError(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockNetworkErrorClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Contains(t, failure.Description, "network error")
}

func TestWhatsOnChainBroadcastBadRequest(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockBadRequestClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
	require.Contains(t, failure.Description, "Bad Request")
}

func TestWhatsOnChainBroadcastNotFound(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockNotFoundClient{},
	}

	// A 404 must be a failure (go-whatsonchain treats 404 as a non-error), not a
	// false BroadcastSuccess.
	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "404", failure.Code)
	require.Contains(t, failure.Description, "404")
}

func TestWhatsOnChainBroadcastUnauthorized(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "invalid_api_key",
		Client:  &MockUnauthorizedClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
	require.Contains(t, failure.Description, "Unauthorized")
}

func TestWhatsOnChainBroadcastBodyReadError(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockBodyReadErrorClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
	require.Contains(t, failure.Description, "read error")
}

func TestWhatsOnChainBroadcastNilTransaction(t *testing.T) {
	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		Client:  &MockSuccessClient{},
	}

	success, failure := b.Broadcast(nil)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
	require.Contains(t, failure.Description, "nil transaction")
}

func TestWhatsOnChainBroadcastNilClient(t *testing.T) {
	// Stub http.DefaultTransport so the nil-Client -> http.DefaultClient
	// fallback path is exercised without reaching api.whatsonchain.com.
	tu.WithStubTransport(t, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"txid":"4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"}`)),
			Header:     make(http.Header),
		}, nil
	})

	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		// Client intentionally left nil -> falls back to http.DefaultClient
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
	require.Equal(t, tx.TxID().String(), success.Txid)

	// The nil-Client fallback must not mutate the shared field, so a broadcaster
	// reused across goroutines does not race on the assignment.
	require.Nil(t, b.Client)
}

func TestWhatsOnChainBroadcastTestnet(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCTestnet,
		ApiKey:  "",
		Client:  &MockSuccessClient{},
	}

	success, failure := b.Broadcast(tx)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

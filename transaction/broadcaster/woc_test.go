package broadcaster

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/stretchr/testify/require"
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
	// Check API key if provided
	if m.apiKey != "" {
		auth := req.Header.Get("Authorization")
		expected := "Bearer " + m.apiKey
		require.Equal(m.t, expected, auth, "API key not properly set in Authorization header")
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
	require.Equal(t, "Internal Server Error", failure.Description)
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
	require.Equal(t, "400", failure.Code)
	require.Equal(t, "Bad Request", failure.Description)
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
	require.Equal(t, "401", failure.Code)
	require.Equal(t, "Unauthorized", failure.Description)
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
	require.Equal(t, "unknown error", failure.Description)
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
	tx, err := transaction.NewTransactionFromHex(testTxHex)
	require.NoError(t, err)

	b := &WhatsOnChain{
		Network: WOCMainnet,
		ApiKey:  "",
		// Client intentionally left nil
	}

	// This will use http.DefaultClient
	// We expect a failure since we're not actually making HTTP calls
	_, failure := b.Broadcast(tx)
	require.NotNil(t, failure)
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

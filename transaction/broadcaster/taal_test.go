// taal_test.go

package broadcaster

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/require"
)

// MockTAALFailureClient simulates a failed API response.
type MockTAALFailureClient struct{}

// Do implements the HTTPClient interface for failure scenarios.
func (m *MockTAALFailureClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 500,
		Body:       io.NopCloser(strings.NewReader(`{"txid":"","status":0,"error":"Internal Server Error"}`)),
	}, nil
}

// MockTAALSuccessClient simulates a successful API response.
type MockTAALSuccessClient struct{}

// Do implements the HTTPClient interface for success scenarios.
func (m *MockTAALSuccessClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"txid":"4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a","status":1,"error":""}`)),
	}, nil
}

// Mock client that simulates network error
type MockTAALNetworkErrorClient struct{}

func (m *MockTAALNetworkErrorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network error")
}

// Mock client that returns invalid JSON
type MockTAALInvalidJSONClient struct{}

func (m *MockTAALInvalidJSONClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`invalid json`)),
	}, nil
}

// Mock client that returns a non-200 status code and specific error message
type MockTAALErrorClient struct{}

func (m *MockTAALErrorClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 400,
		Body:       io.NopCloser(strings.NewReader(`{"txid":"","status":0,"error":"Some error message"}`)),
	}, nil
}

// Test for error during HTTP client's Do method
func TestTAALBroadcastDoError(t *testing.T) {
	tx := &transaction.Transaction{
		// Populate with valid data
	}

	b := &TAALBroadcast{
		ApiKey: "",
		Client: &MockTAALNetworkErrorClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
	require.Contains(t, failure.Description, "network error")
}

// Test for error decoding the response body
func TestTAALBroadcastDecodeError(t *testing.T) {
	tx := &transaction.Transaction{
		// Populate with valid data
	}

	b := &TAALBroadcast{
		ApiKey: "",
		Client: &MockTAALInvalidJSONClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, strconv.Itoa(200), failure.Code)
	require.Equal(t, "unknown error", failure.Description)
}

// Test for error response with non-200 status code
func TestTAALBroadcastErrorResponse(t *testing.T) {
	tx := &transaction.Transaction{
		// Populate with valid data
	}

	b := &TAALBroadcast{
		ApiKey: "",
		Client: &MockTAALErrorClient{},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, strconv.Itoa(400), failure.Code)
	require.Equal(t, "Some error message", failure.Description)
}

// TestTAALBroadcast tests the Broadcast method of TAALBroadcast.
func TestTAALBroadcast(t *testing.T) {
	// Create a real transaction with a known TxID.
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err, "Failed to create transaction from hex")

	// Initialize TAALBroadcast with a failure client.
	b := &TAALBroadcast{
		ApiKey: "",
		Client: &MockTAALFailureClient{},
	}

	// Broadcast with failure client.
	success, failure := b.Broadcast(tx)
	require.Nil(t, success, "Expected no success when client fails")
	require.NotNil(t, failure, "Expected failure when client fails")
	require.Equal(t, "500", failure.Code, "Failure code mismatch")
	require.Equal(t, "Internal Server Error", failure.Description, "Failure description mismatch")

	// Initialize TAALBroadcast with a success client.
	b.Client = &MockTAALSuccessClient{}

	// Broadcast with success client.
	success, failure = b.Broadcast(tx)
	require.NotNil(t, success, "Expected success when client succeeds")
	require.Nil(t, failure, "Expected no failure when client succeeds")
	require.Equal(t, tx.TxID().String(), success.Txid, "Txid mismatch")
}

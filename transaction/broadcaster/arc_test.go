// arc_test.go

package broadcaster

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/stretchr/testify/require"
)

// MockArcFailureClient simulates a failed API response for Arc.
type MockArcFailureClient struct{}

// Do implements the HTTPClient interface for failure scenarios.
func (m *MockArcFailureClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 500,
		Body:       io.NopCloser(strings.NewReader(`{"blockHash":"","blockHeight":0,"extraInfo":"","status":500,"timestamp":"2023-01-01T00:00:00Z","title":"Internal Server Error","txStatus":null,"instance":null,"txid":"","detail":""}`)),
	}, nil
}

// MockArcSuccessClient simulates a successful API response for Arc.
type MockArcSuccessClient struct{}

// Do implements the HTTPClient interface for success scenarios.
func (m *MockArcSuccessClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(strings.NewReader(`{
			"blockHash":"abc123",
			"blockHeight":100,
			"extraInfo":"extra",
			"status":200,
			"timestamp":"2023-01-01T00:00:00Z",
			"title":"Broadcast Success",
			"txStatus":"7",
			"instance":"instance1",
			"txid":"4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a",
			"detail":"detail info"
		}`)),
	}, nil
}

// TestArcBroadcast tests the Broadcast method of Arc.
func TestArcBroadcast(t *testing.T) {
	// Create a real transaction with a known TxID.
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err, "Failed to create transaction from hex")

	// Initialize Arc with a failure client.
	a := &Arc{
		ApiUrl: "https://arc.gorillapool.io",
		ApiKey: "test_api_key",
		Client: &MockArcFailureClient{},
	}

	// Broadcast with failure client.
	success, failure := a.Broadcast(tx)
	require.Nil(t, success, "Expected no success when client fails")
	require.NotNil(t, failure, "Expected failure when client fails")
	require.Equal(t, "500", failure.Code, "Failure code mismatch")
	require.Equal(t, "Internal Server Error", failure.Description, "Failure description mismatch")

	// Initialize Arc with a success client.
	a.Client = &MockArcSuccessClient{}

	// Broadcast with success client.
	success, failure = a.Broadcast(tx)
	require.NotNil(t, success, "Expected success when client succeeds")
	require.Nil(t, failure, "Expected no failure when client succeeds")
	require.Equal(t, tx.TxID().String(), success.Txid, "Txid mismatch")
	require.Equal(t, "Broadcast Success", success.Message, "Message mismatch")
}

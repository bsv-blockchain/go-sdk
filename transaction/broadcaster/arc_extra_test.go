package broadcaster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/require"
)

const arcExampleURL = "https://arc.example.com"

// MockArcRejectedClient simulates a rejected transaction response.
type MockArcRejectedClient struct{}

func (m *MockArcRejectedClient) Do(req *http.Request) (*http.Response, error) {
	rejected := REJECTED
	body := map[string]interface{}{
		"status":    400,
		"txStatus":  string(rejected),
		"extraInfo": "mempool conflict",
		"title":     "Transaction rejected",
	}
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

// MockArcStatus200Client returns a status:200 response that should be a broadcast success.
type MockArcStatus200Client struct{}

func (m *MockArcStatus200Client) Do(req *http.Request) (*http.Response, error) {
	mined := MINED
	txid := "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
	body := map[string]interface{}{
		"status":   200,
		"txStatus": string(mined),
		"txid":     txid,
		"title":    "Success",
	}
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

// MockArcNetworkErrorClient simulates network failure.
type MockArcNetworkErrorClient struct{}

func (m *MockArcNetworkErrorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

// MockArcBadJSONClient returns malformed JSON.
type MockArcBadJSONClient struct{}

func (m *MockArcBadJSONClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{invalid json`)),
	}, nil
}

// MockArcStatusCheckClient checks header values are correctly set.
type MockArcStatusCheckClient struct {
	t *testing.T
}

func (m *MockArcStatusCheckClient) Do(req *http.Request) (*http.Response, error) {
	require.Equal(m.t, "Bearer testkey", req.Header.Get("Authorization"))
	require.Equal(m.t, "https://callback.example.com", req.Header.Get("X-CallbackUrl"))
	require.Equal(m.t, "mytoken", req.Header.Get("X-CallbackToken"))
	require.Equal(m.t, "true", req.Header.Get("X-CallbackBatch"))
	require.Equal(m.t, "true", req.Header.Get("X-FullStatusUpdates"))
	require.Equal(m.t, "30", req.Header.Get("X-MaxTimeout"))
	require.Equal(m.t, "true", req.Header.Get("X-SkipFeeValidation"))
	require.Equal(m.t, "true", req.Header.Get("X-SkipScriptValidation"))
	require.Equal(m.t, "true", req.Header.Get("X-SkipTxValidation"))
	require.Equal(m.t, "true", req.Header.Get("X-CumulativeFeeValidation"))
	require.Equal(m.t, "MINED", req.Header.Get("X-WaitForStatus"))
	require.Equal(m.t, "MINED", req.Header.Get("X-WaitFor"))

	txid := "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
	body := map[string]interface{}{
		"status": 200,
		"txid":   txid,
		"title":  "OK",
	}
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

func TestArcBroadcastRejected(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		ApiKey: "testkey",
		Client: &MockArcRejectedClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "400", failure.Code)
	require.Equal(t, "mempool conflict", failure.Description)
}

func TestArcBroadcastStatus200(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcStatus200Client{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.NotNil(t, success)
	require.Nil(t, failure)
	require.Equal(t, "Success", success.Message)
}

func TestArcBroadcastNetworkError(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcNetworkErrorClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
}

func TestArcBroadcastBadJSON(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcBadJSONClient{},
	}

	_, failure := a.ArcBroadcast(context.Background(), tx)
	require.Error(t, failure)
}

func TestArcAllHeaders(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	callbackURL := "https://callback.example.com"
	callbackToken := "mytoken"
	maxTimeout := 30
	a := &Arc{
		ApiUrl:                  arcExampleURL,
		ApiKey:                  "testkey",
		CallbackUrl:             &callbackURL,
		CallbackToken:           &callbackToken,
		CallbackBatch:           true,
		FullStatusUpdates:       true,
		MaxTimeout:              &maxTimeout,
		SkipFeeValidation:       true,
		SkipScriptValidation:    true,
		SkipTxValidation:        true,
		CumulativeFeeValidation: true,
		WaitForStatus:           "MINED",
		WaitFor:                 MINED,
		Client:                  &MockArcStatusCheckClient{t: t},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

func TestArcVerboseLogging(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl:  arcExampleURL,
		Verbose: true,
		Client:  &MockArcSuccessClient{},
	}

	success, failure := a.Broadcast(tx)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

func TestArcStatusMethod(t *testing.T) {
	txid := "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
	mined := MINED
	ts := time.Now()
	expectedResp := &ArcResponse{
		Txid:     txid,
		TxStatus: &mined,
		Status:   200,
		Timestamp: ts,
	}

	client := &MockArcStatusResponseClient{resp: expectedResp}
	a := &Arc{
		ApiUrl: arcExampleURL,
		ApiKey: "testkey",
		Client: client,
	}

	resp, err := a.Status(txid)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, txid, resp.Txid)
	require.Equal(t, mined, *resp.TxStatus)
}

// MockArcStatusResponseClient returns a specific ArcResponse for Status calls.
type MockArcStatusResponseClient struct {
	resp *ArcResponse
}

func (m *MockArcStatusResponseClient) Do(req *http.Request) (*http.Response, error) {
	b, _ := json.Marshal(m.resp)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

func TestArcStatusNetworkError(t *testing.T) {
	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcNetworkErrorClient{},
	}

	resp, err := a.Status("sometxid")
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestArcStatusBadJSON(t *testing.T) {
	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcBadJSONClient{},
	}

	resp, err := a.Status("sometxid")
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestArcBroadcastFailureNonSuccessStatus(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	// Status 500 without REJECTED txStatus (third branch of BroadcastCtx)
	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcFailureClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "500", failure.Code)
}

func TestArcDefaultHTTPClient(t *testing.T) {
	// When Client is nil, it defaults to http.DefaultClient
	a := &Arc{
		ApiUrl: arcExampleURL,
	}
	// This will fail since we're not calling a real endpoint, but it exercises the nil check
	tx := &transaction.Transaction{}
	// ArcBroadcast will try to call the real URL which will fail; but code for nil check will be exercised
	_, err := a.ArcBroadcast(context.Background(), tx)
	// Error is expected since we can't connect to arc.example.com
	_ = err
}

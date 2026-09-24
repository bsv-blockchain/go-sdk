package broadcaster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/transaction"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
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
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
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
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
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

	received := RECEIVED
	txid := "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
	body := map[string]interface{}{
		"status":   200,
		"txid":     txid,
		"txStatus": string(received),
		"title":    "OK",
	}
	b, err := json.Marshal(body)
	require.NoError(m.t, err)
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
	// The mock's outer HTTP status is 200 (ARC's real transport for this
	// endpoint never answers with a 4xx for a REJECTED txStatus — see
	// ArcTxResponse in specs/broadcast/arc.yaml); the body's own "status":400
	// is just mock-fixture noise from before BroadcastCtx looked at the real
	// HTTP status. A REJECTED txStatus is a ts-sdk ARC_ERROR_STATUS, so the
	// failure code must be the txStatus string itself, not an HTTP code.
	require.Equal(t, "REJECTED", failure.Code)
	// ts-sdk's description is `${txStatus} ${extraInfo}`.trim(), so the
	// txStatus prefix must be present, not just the bare extraInfo.
	require.Equal(t, "REJECTED mempool conflict", failure.Description)
}

// MockArcRejectedLowercaseClient returns a REJECTED txStatus in lowercase, to
// verify BroadcastCtx classifies it as a failure regardless of case (ts-sdk
// compares against ARC_ERROR_STATUSES after uppercasing txStatus).
type MockArcRejectedLowercaseClient struct{}

func (m *MockArcRejectedLowercaseClient) Do(req *http.Request) (*http.Response, error) {
	body := map[string]interface{}{
		"txStatus":  "rejected",
		"extraInfo": "mempool conflict",
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

func TestArcBroadcastRejectedCaseInsensitive(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcRejectedLowercaseClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	// Code/Description keep the original casing txStatus was sent in (ts-sdk
	// does the same: it only uppercases for the ARC_ERROR_STATUSES lookup,
	// not for the code/description it returns).
	require.Equal(t, "rejected", failure.Code)
	require.Equal(t, "rejected mempool conflict", failure.Description)
}

// MockArcMissingTxStatusClient returns HTTP 200 with no txStatus field at
// all, which ts-sdk's successfulArcResponse rejects as an invalid response
// rather than treating as success.
type MockArcMissingTxStatusClient struct{}

func (m *MockArcMissingTxStatusClient) Do(req *http.Request) (*http.Response, error) {
	txid := "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
	body := map[string]interface{}{
		"txid": txid,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

func TestArcBroadcastMissingTxStatusIsFailure(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcMissingTxStatusClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_INVALID_RESPONSE", failure.Code)
}

// MockArcEmptyTxStatusClient returns HTTP 200 with an explicit empty-string
// txStatus, which must also be rejected as invalid (not success).
type MockArcEmptyTxStatusClient struct{}

func (m *MockArcEmptyTxStatusClient) Do(req *http.Request) (*http.Response, error) {
	txid := "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
	body := map[string]interface{}{
		"txid":     txid,
		"txStatus": "",
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
}

func TestArcBroadcastEmptyTxStatusIsFailure(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcEmptyTxStatusClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_INVALID_RESPONSE", failure.Code)
}

// TestArcBroadcastDefaultErrorDescription pins the "no detail field" default
// to ts-sdk's literal "Unknown error", never the response's "title".
func TestArcBroadcastDefaultErrorDescription(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	a := &Arc{
		ApiUrl: arcExampleURL,
		Client: &MockArcTitleOnlyErrorClient{},
	}

	success, failure := a.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "503", failure.Code)
	require.Equal(t, "Unknown error", failure.Description)
}

// MockArcTitleOnlyErrorClient returns a non-2xx error body carrying only a
// "title" (no "detail"), matching ARC's ArcErrorResponse shape.
type MockArcTitleOnlyErrorClient struct{}

func (m *MockArcTitleOnlyErrorClient) Do(req *http.Request) (*http.Response, error) {
	body := map[string]interface{}{
		"status": 503,
		"title":  "Service Unavailable",
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 503,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}, nil
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
	require.Equal(t, "MINED", success.Message)
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
		Txid:      txid,
		TxStatus:  &mined,
		Status:    200,
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
	b, err := json.Marshal(m.resp)
	if err != nil {
		return nil, err
	}
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
	// Stub http.DefaultTransport so the nil-Client -> http.DefaultClient
	// fallback path is exercised without reaching arc.example.com.
	tu.WithStubTransport(t, func(_ *http.Request) (*http.Response, error) {
		seen := SEEN_ON_NETWORK
		body, err := json.Marshal(ArcResponse{
			Status:   200,
			TxStatus: &seen,
			Txid:     "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a",
		})
		require.NoError(t, err)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	})

	// When Client is nil, it defaults to http.DefaultClient.
	a := &Arc{
		ApiUrl: arcExampleURL,
	}
	tx := &transaction.Transaction{}
	resp, err := a.ArcBroadcast(context.Background(), tx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 200, resp.Status)
}

// arcStatusTestTxHex is a real transaction, so ARC responses can echo its txid.
const arcStatusTestTxHex = "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"

// mockArcJSONClient answers every request with a fixed status and JSON body.
type mockArcJSONClient struct {
	status int
	body   map[string]interface{}
}

func (m *mockArcJSONClient) Do(*http.Request) (*http.Response, error) {
	b, err := json.Marshal(m.body)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: m.status, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
}

func TestArcBroadcastTxidAndStatusChecks(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex(arcStatusTestTxHex)
	require.NoError(t, err)
	ownTxid := tx.TxID().String()
	otherTxid := strings.Repeat("ab", 32)

	tests := []struct {
		name        string
		status      int
		body        map[string]interface{}
		wantCode    string // empty means success
		wantMessage string
	}{
		{"accepted status echoing own txid", 200, map[string]interface{}{"txid": ownTxid, "txStatus": "SEEN_ON_NETWORK"}, "", "SEEN_ON_NETWORK"},
		{"accepted status is case-insensitive", 200, map[string]interface{}{"txid": strings.ToUpper(ownTxid), "txStatus": "mined"}, "", "mined"},
		{"queued is accepted", 200, map[string]interface{}{"txid": ownTxid, "txStatus": "QUEUED"}, "", "QUEUED"},
		{"unknown status is invalid", 200, map[string]interface{}{"txid": ownTxid, "txStatus": "7"}, "ERR_INVALID_RESPONSE", ""},
		{"success for another txid", 200, map[string]interface{}{"txid": otherTxid, "txStatus": "MINED"}, "ERR_TXID_MISMATCH", ""},
		{"success without txid", 200, map[string]interface{}{"txStatus": "MINED"}, "ERR_TXID_MISMATCH", ""},
		{"failure status for another txid", 200, map[string]interface{}{"txid": otherTxid, "txStatus": "REJECTED"}, "ERR_TXID_MISMATCH", ""},
		{"failure status for own txid", 200, map[string]interface{}{"txid": ownTxid, "txStatus": "REJECTED", "extraInfo": "bad"}, "REJECTED", ""},
		{"http error for another txid", 422, map[string]interface{}{"txid": otherTxid, "detail": "nope"}, "ERR_TXID_MISMATCH", ""},
		{"http error for own txid", 422, map[string]interface{}{"txid": ownTxid, "detail": "nope"}, "422", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Arc{ApiUrl: arcExampleURL, Client: &mockArcJSONClient{status: tc.status, body: tc.body}}
			success, failure := a.BroadcastCtx(context.Background(), tx)
			if tc.wantCode == "" {
				require.Nil(t, failure)
				require.NotNil(t, success)
				require.Equal(t, ownTxid, success.Txid)
				require.Equal(t, tc.wantMessage, success.Message)
				return
			}
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, tc.wantCode, failure.Code)
		})
	}
}

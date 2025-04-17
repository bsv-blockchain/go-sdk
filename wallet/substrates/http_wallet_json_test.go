package substrates

import (
	"encoding/json"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPWalletJSON(t *testing.T) {
	tests := []struct {
		name       string
		originator string
		baseURL    string
		client     *http.Client
		wantURL    string
	}{
		{
			name:       "default values",
			originator: TestOriginator,
			baseURL:    "",
			client:     nil,
			wantURL:    "http://localhost:3321",
		},
		{
			name:       "custom values",
			originator: "app.test",
			baseURL:    "https://wallet.example.com",
			client:     &http.Client{},
			wantURL:    "https://wallet.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHTTPWalletJSON(tt.originator, tt.baseURL, tt.client)
			require.Equal(t, tt.wantURL, client.baseURL, "baseURL mismatch")
			require.Equal(t, tt.originator, client.originator, "originator mismatch")
			if tt.client == nil {
				require.Same(t, http.DefaultClient, client.httpClient, "expected default HTTP client")
			} else {
				require.Same(t, tt.client, client.httpClient, "expected custom HTTP client")
			}
		})
	}
}

func TestHTTPWalletJSON_API(t *testing.T) {
	// Test server that validates requests and returns mock responses
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate headers
		require.Equal(t, r.Header.Get("Accept"), "application/json")
		require.Equal(t, r.Header.Get("Content-Type"), "application/json")
		require.Equal(t, r.Header.Get("Originator"), TestOriginator)
		require.Equal(t, r.URL.Path, "/testEndpoint")

		// Validate body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req map[string]interface{}
		err = json.Unmarshal(body, &req)
		require.NoError(t, err)
		require.Equal(t, "testValue", req["testKey"])

		// Return test response
		resp := map[string]string{"result": "success"}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON(TestOriginator, ts.URL, nil)

	// Test successful API call
	args := map[string]string{"testKey": "testValue"}
	data, err := client.api(t.Context(), "testEndpoint", args)
	require.NoError(t, err, "api call failed")

	var result map[string]string
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	require.Equal(t, "success", result["result"])
}

func TestHTTPWalletJSON_API_Errors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    string
	}{
		{
			name:       "HTTP error",
			statusCode: http.StatusInternalServerError,
			response:   `{"message": "server error"}`,
			wantErr:    "HTTP request failed with status 500",
		},
		{
			name:       "invalid JSON request",
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid request"}`,
			wantErr:    "HTTP request failed with status 400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, err := w.Write([]byte(tt.response))
				require.NoError(t, err)
			}))
			defer ts.Close()

			client := NewHTTPWalletJSON(TestOriginator, ts.URL, nil)
			_, err := client.api(t.Context(), "testEndpoint", map[string]string{"key": "value"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestHTTPWalletJSON_ErrorCases(t *testing.T) {
	ctx := t.Context()
	// Test JSON marshaling error
	t.Run("marshal error", func(t *testing.T) {
		client := NewHTTPWalletJSON("", "", nil)
		// Pass a channel which can't be marshaled to JSON
		_, err := client.api(ctx, "test", make(chan int))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal request")
	})

	// Test HTTP request error
	t.Run("HTTP error", func(t *testing.T) {
		client := NewHTTPWalletJSON("", "http://invalid-url", nil)
		_, err := client.api(ctx, "test", map[string]string{"key": "value"})
		require.Error(t, err)
	})

	// Test invalid JSON response
	t.Run("invalid JSON response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte("invalid json"))
			require.NoError(t, err)
		}))
		defer ts.Close()

		client := NewHTTPWalletJSON("", ts.URL, nil)
		_, err := client.CreateAction(ctx, wallet.CreateActionArgs{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func writeJSONResponse(t *testing.T, w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	require.NoError(t, err)
}

func TestHTTPWalletJSON_CreateAction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/createAction", r.URL.Path)

		var args wallet.CreateActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test desc", args.Description)

		writeJSONResponse(t, w, wallet.CreateActionResult{Txid: "test-txid"})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.CreateAction(t.Context(), wallet.CreateActionArgs{
		Description: "test desc",
	})
	require.NoError(t, err)
	require.Equal(t, "test-txid", result.Txid)
}

func TestHTTPWalletJSON_SignAction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/signAction", r.URL.Path)

		var args wallet.SignActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test-ref", args.Reference)
		require.Len(t, args.Spends, 1)
		require.Equal(t, "test-script", args.Spends[0].UnlockingScript)

		writeJSONResponse(t, w, wallet.SignActionResult{Txid: "signed-txid"})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.SignAction(t.Context(), wallet.SignActionArgs{
		Reference: "test-ref",
		Spends: map[uint32]wallet.SignActionSpend{
			0: {UnlockingScript: "test-script"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "signed-txid", result.Txid)
}

func TestHTTPWalletJSON_AbortAction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/abortAction", r.URL.Path)

		var args wallet.AbortActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test-ref", args.Reference)

		writeJSONResponse(t, w, wallet.AbortActionResult{Aborted: true})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.AbortAction(t.Context(), wallet.AbortActionArgs{
		Reference: "test-ref",
	})
	require.NoError(t, err)
	require.True(t, result.Aborted)
}

func TestHTTPWalletJSON_ListActions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/listActions", r.URL.Path)

		var args wallet.ListActionsArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, []string{"test-label"}, args.Labels)
		require.Equal(t, uint32(10), args.Limit)

		writeJSONResponse(t, w, wallet.ListActionsResult{
			TotalActions: 1,
			Actions: []wallet.Action{
				{
					Txid:        "test-txid",
					Description: "test-action",
				},
			},
		})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.ListActions(t.Context(), wallet.ListActionsArgs{
		Labels: []string{"test-label"},
		Limit:  10,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), result.TotalActions)
	require.Len(t, result.Actions, 1)
	require.Equal(t, "test-txid", result.Actions[0].Txid)
}

func TestHTTPWalletJSON_InternalizeAction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/internalizeAction", r.URL.Path)

		var args wallet.InternalizeActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test-desc", args.Description)
		require.Len(t, args.Outputs, 1)
		require.Equal(t, uint32(0), args.Outputs[0].OutputIndex)

		writeJSONResponse(t, w, wallet.InternalizeActionResult{Accepted: true})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.InternalizeAction(t.Context(), wallet.InternalizeActionArgs{
		Description: "test-desc",
		Outputs: []wallet.InternalizeOutput{
			{
				OutputIndex: 0,
				Protocol:    "wallet payment",
			},
		},
	})
	require.NoError(t, err)
	require.True(t, result.Accepted)
}

func TestHTTPWalletJSON_EncryptDecrypt(t *testing.T) {
	testData := []byte("test data")
	encryptedData := []byte("encrypted-data")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/encrypt", r.URL.Path)

		var args wallet.EncryptArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, testData, args.Plaintext)

		resp := wallet.EncryptResult{Ciphertext: encryptedData}
		writeJSONResponse(t, w, resp)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	encryptResult, err := client.Encrypt(t.Context(), wallet.EncryptArgs{
		Plaintext: testData,
	})
	require.NoError(t, err)
	require.Equal(t, encryptedData, encryptResult.Ciphertext)

	// Test decrypt
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/decrypt", r.URL.Path)

		var args wallet.DecryptArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, encryptedData, args.Ciphertext)

		resp := wallet.DecryptResult{Plaintext: testData}
		writeJSONResponse(t, w, resp)
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	decryptResult, err := client.Decrypt(t.Context(), wallet.DecryptArgs{
		Ciphertext: encryptedData,
	})
	require.NoError(t, err)
	require.Equal(t, testData, decryptResult.Plaintext)
}

func TestHTTPWalletJSON_HmacOperations(t *testing.T) {
	testData := []byte("test data")
	testHmac := []byte("test-hmac")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/createHmac" {
			var args wallet.CreateHmacArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, args.Data)

			resp := wallet.CreateHmacResult{Hmac: testHmac}
			writeJSONResponse(t, w, resp)
		} else {
			var args wallet.VerifyHmacArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, args.Data)
			require.Equal(t, testHmac, args.Hmac)

			resp := wallet.VerifyHmacResult{Valid: true}
			writeJSONResponse(t, w, resp)
		}
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)

	// Test create HMAC
	hmacResult, err := client.CreateHmac(t.Context(), wallet.CreateHmacArgs{
		Data: testData,
	})
	require.NoError(t, err)
	require.Equal(t, testHmac, hmacResult.Hmac)

	// Test verify HMAC
	verifyResult, err := client.VerifyHmac(t.Context(), wallet.VerifyHmacArgs{
		Data: testData,
		Hmac: testHmac,
	})
	require.NoError(t, err)
	require.True(t, verifyResult.Valid)
}

func TestHTTPWalletJSON_SignatureOperations(t *testing.T) {
	testData := []byte("test data")
	testSig := ec.Signature{
		R: big.NewInt(1),
		S: big.NewInt(2),
	} // Sample signature

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/createSignature" {
			var args wallet.CreateSignatureArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, args.Data)

			resp := wallet.CreateSignatureResult{Signature: testSig}
			writeJSONResponse(t, w, resp)
		} else {
			var args wallet.VerifySignatureArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, args.Data)
			require.Equal(t, testSig, args.Signature)

			resp := wallet.VerifySignatureResult{Valid: true}
			writeJSONResponse(t, w, resp)
		}
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)

	// Test create signature
	sigResult, err := client.CreateSignature(t.Context(), wallet.CreateSignatureArgs{
		Data: testData,
	})
	require.NoError(t, err)
	require.Equal(t, testSig, sigResult.Signature)

	// Test verify signature
	verifyResult, err := client.VerifySignature(t.Context(), wallet.VerifySignatureArgs{
		Data:      testData,
		Signature: testSig,
	})
	require.NoError(t, err)
	require.True(t, verifyResult.Valid)
}

package substrates

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
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
		var req map[string]any
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
		client := NewHTTPWalletJSON("", "htp://invalid-url", nil)
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
	txId := tu.GetByte32FromString("test-txid")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/createAction", r.URL.Path)

		var args wallet.CreateActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test desc", args.Description)

		writeJSONResponse(t, w, &wallet.CreateActionResult{Txid: txId})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.CreateAction(t.Context(), wallet.CreateActionArgs{
		Description: "test desc",
	})
	require.NoError(t, err)
	require.Equal(t, txId, [32]byte(result.Txid))
}

func TestHTTPWalletJSON_SignAction(t *testing.T) {
	var testRef = []byte("test-ref")
	var testScript = []byte("test-script")
	testTxId := tu.GetByte32FromString("signed-txid")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/signAction", r.URL.Path)

		var args wallet.SignActionArgs
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &args), "Body: %s", string(body))
		require.Equal(t, testRef, args.Reference)
		require.Len(t, args.Spends, 1)
		require.Equal(t, testScript, args.Spends[0].UnlockingScript)

		writeJSONResponse(t, w, &wallet.SignActionResult{Txid: testTxId})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.SignAction(t.Context(), &wallet.SignActionArgs{
		Reference: testRef,
		Spends: map[uint32]wallet.SignActionSpend{
			0: {UnlockingScript: testScript},
		},
	})
	require.NoError(t, err)
	require.Equal(t, testTxId, [32]byte(result.Txid))
}

func TestHTTPWalletJSON_AbortAction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/abortAction", r.URL.Path)

		var args wallet.AbortActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, []byte{1, 2, 3, 4}, args.Reference)

		writeJSONResponse(t, w, wallet.AbortActionResult{Aborted: true})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.AbortAction(t.Context(), wallet.AbortActionArgs{
		Reference: []byte{1, 2, 3, 4},
	})
	require.NoError(t, err)
	require.True(t, result.Aborted)
}

func TestHTTPWalletJSON_ListActions(t *testing.T) {
	testTxID := tu.GetByte32FromString("test-txid")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/listActions", r.URL.Path)

		var args wallet.ListActionsArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, []string{"test-label"}, args.Labels)
		require.Equal(t, util.Uint32Ptr(uint32(10)), args.Limit)

		writeJSONResponse(t, w, wallet.ListActionsResult{
			TotalActions: 1,
			Actions: []wallet.Action{
				{
					Txid:        testTxID,
					Description: "test-action",
				},
			},
		})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.ListActions(t.Context(), wallet.ListActionsArgs{
		Labels: []string{"test-label"},
		Limit:  util.Uint32Ptr(10),
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), result.TotalActions)
	require.Len(t, result.Actions, 1)
	require.Equal(t, testTxID, [32]byte(result.Actions[0].Txid))
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
				Protocol:    wallet.InternalizeProtocolWalletPayment,
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
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &args))
		require.Equal(t, testData, []byte(args.Plaintext))

		resp := wallet.EncryptResult{Ciphertext: encryptedData}
		writeJSONResponse(t, w, &resp)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	encryptResult, err := client.Encrypt(t.Context(), wallet.EncryptArgs{
		Plaintext: testData,
	})
	require.NoError(t, err)
	require.Equal(t, encryptedData, []byte(encryptResult.Ciphertext))

	// Test decrypt
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/decrypt", r.URL.Path)

		var args wallet.DecryptArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, encryptedData, []byte(args.Ciphertext))

		resp := wallet.DecryptResult{Plaintext: testData}
		writeJSONResponse(t, w, &resp)
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	decryptResult, err := client.Decrypt(t.Context(), wallet.DecryptArgs{
		Ciphertext: encryptedData,
	})
	require.NoError(t, err)
	require.Equal(t, testData, []byte(decryptResult.Plaintext))
}

func TestHTTPWalletJSON_HMACOperations(t *testing.T) {
	testData := []byte("test data")
	testHMAC := tu.GetByte32FromString("test-hmac")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/createHmac" {
			var args wallet.CreateHMACArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, []byte(args.Data))

			resp := wallet.CreateHMACResult{HMAC: testHMAC}
			writeJSONResponse(t, w, &resp)
		} else {
			var args wallet.VerifyHMACArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, []byte(args.Data))
			require.Equal(t, testHMAC, args.HMAC)

			resp := wallet.VerifyHMACResult{Valid: true}
			writeJSONResponse(t, w, &resp)
		}
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)

	// Test create HMAC
	hmacResult, err := client.CreateHMAC(t.Context(), wallet.CreateHMACArgs{
		Data: testData,
	})
	require.NoError(t, err)
	require.Equal(t, testHMAC, hmacResult.HMAC)

	// Test verify HMAC
	verifyResult, err := client.VerifyHMAC(t.Context(), wallet.VerifyHMACArgs{
		Data: testData,
		HMAC: testHMAC,
	})
	require.NoError(t, err)
	require.True(t, verifyResult.Valid)
}

func TestHTTPWalletJSON_SignatureOperations(t *testing.T) {
	testData := []byte("test data")
	// Use a valid DER-encoded signature
	testSig := tu.GetSigFromHex(t, "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020101")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/createSignature" {
			var args wallet.CreateSignatureArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, []byte(args.Data))

			resp := wallet.CreateSignatureResult{Signature: testSig}
			writeJSONResponse(t, w, &resp)
		} else {
			var args wallet.VerifySignatureArgs
			err := json.NewDecoder(r.Body).Decode(&args)
			require.NoError(t, err)
			require.Equal(t, testData, []byte(args.Data))
			require.Equal(t, testSig.Serialize(), args.Signature.Serialize())

			resp := wallet.VerifySignatureResult{Valid: true}
			writeJSONResponse(t, w, &resp)
		}
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)

	// Test create signature
	sigResult, err := client.CreateSignature(t.Context(), wallet.CreateSignatureArgs{
		Data: testData,
	})
	require.NoError(t, err)
	require.Equal(t, testSig.Serialize(), sigResult.Signature.Serialize())

	// Test verify signature
	verifyResult, err := client.VerifySignature(t.Context(), wallet.VerifySignatureArgs{
		Data:      testData,
		Signature: testSig,
	})
	require.NoError(t, err)
	require.True(t, verifyResult.Valid)
}

func TestHTTPWalletJSON_CertificateOperations(t *testing.T) {
	typeTest := wallet.CertificateType(tu.GetByte32FromString("test-type"))
	serialNumber := wallet.SerialNumber(tu.GetByte32FromString("12345"))
	certifier := tu.GetPKFromHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	verifier := tu.GetPKFromHex(t, "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	// Test AcquireCertificate
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/acquireCertificate", r.URL.Path)

		var args wallet.AcquireCertificateArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, typeTest, args.Type)
		require.Equal(t, certifier, args.Certifier)

		cert := wallet.Certificate{
			SerialNumber: serialNumber,
			Type:         typeTest,
		}
		writeJSONResponse(t, w, &cert)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	cert, err := client.AcquireCertificate(t.Context(), &wallet.AcquireCertificateArgs{
		Type:      typeTest,
		Certifier: certifier,
	})
	require.NoError(t, err)
	require.Equal(t, typeTest, cert.Type)
	require.Equal(t, serialNumber, cert.SerialNumber)

	// Test ListCertificates
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/listCertificates", r.URL.Path)

		var args wallet.ListCertificatesArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, []*ec.PublicKey{certifier}, args.Certifiers)

		result := wallet.ListCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.CertificateResult{
				{
					Certificate: wallet.Certificate{
						Type: typeTest,
					},
				},
			},
		}
		writeJSONResponse(t, w, result)
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	listResult, err := client.ListCertificates(t.Context(), wallet.ListCertificatesArgs{
		Certifiers: []*ec.PublicKey{tu.GetPKFromHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), listResult.TotalCertificates)
	require.Len(t, listResult.Certificates, 1)
	require.Equal(t, typeTest, listResult.Certificates[0].Type)

	// Test ProveCertificate
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/proveCertificate", r.URL.Path)

		var args wallet.ProveCertificateArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, verifier.Compressed(), args.Verifier.Compressed())

		result := wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"field": "key"},
		}
		writeJSONResponse(t, w, result)
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	proveResult, err := client.ProveCertificate(t.Context(), &wallet.ProveCertificateArgs{
		Certificate: wallet.Certificate{Type: typeTest},
		Verifier:    verifier,
	})
	require.NoError(t, err)
	require.Equal(t, "key", proveResult.KeyringForVerifier["field"])

	// Test RelinquishCertificate
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/relinquishCertificate", r.URL.Path)

		var args wallet.RelinquishCertificateArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, typeTest, args.Type)

		writeJSONResponse(t, w, wallet.RelinquishCertificateResult{Relinquished: true})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	relinquishResult, err := client.RelinquishCertificate(t.Context(), &wallet.RelinquishCertificateArgs{
		Type: typeTest,
	})
	require.NoError(t, err)
	require.True(t, relinquishResult.Relinquished)
}

func TestHTTPWalletJSON_DiscoveryOperations(t *testing.T) {
	typeDiscovered := wallet.CertificateType(tu.GetByte32FromString("discovered-type"))
	testKey := tu.GetPKFromHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	// Test DiscoverByIdentityKey
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/discoverByIdentityKey", r.URL.Path)

		var args wallet.DiscoverByIdentityKeyArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, testKey, args.IdentityKey)

		result := wallet.DiscoverCertificatesResult{
			TotalCertificates: 1,
			Certificates: []wallet.IdentityCertificate{{
				Certificate: wallet.Certificate{
					Type: typeDiscovered,
				}},
			},
		}
		writeJSONResponse(t, w, result)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	discoverResult, err := client.DiscoverByIdentityKey(t.Context(), &wallet.DiscoverByIdentityKeyArgs{
		IdentityKey: testKey,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), discoverResult.TotalCertificates)
	require.Equal(t, typeDiscovered, discoverResult.Certificates[0].Type)

	// Test DiscoverByAttributes
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/discoverByAttributes", r.URL.Path)

		var args wallet.DiscoverByAttributesArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "value", args.Attributes["key"])

		writeJSONResponse(t, w, wallet.DiscoverCertificatesResult{
			TotalCertificates: 1,
		})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	_, err = client.DiscoverByAttributes(t.Context(), wallet.DiscoverByAttributesArgs{
		Attributes: map[string]string{"key": "value"},
	})
	require.NoError(t, err)
}

func TestHTTPWalletJSON_OutputOperations(t *testing.T) {
	// Test ListOutputs
	outpoint := *tu.OutpointFromString(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/listOutputs", r.URL.Path)

		var args wallet.ListOutputsArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test-basket", args.Basket)
		require.Equal(t, []string{"tag1"}, args.Tags)

		result := wallet.ListOutputsResult{
			TotalOutputs: 1,
			Outputs: []wallet.Output{
				{
					Outpoint: outpoint,
					Satoshis: 1000,
				},
			},
		}
		writeJSONResponse(t, w, result)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	listResult, err := client.ListOutputs(t.Context(), wallet.ListOutputsArgs{
		Basket: "test-basket",
		Tags:   []string{"tag1"},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), listResult.TotalOutputs)
	require.Len(t, listResult.Outputs, 1)
	require.Equal(t, outpoint, listResult.Outputs[0].Outpoint)

	// Test RelinquishOutput
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/relinquishOutput", r.URL.Path)

		var args wallet.RelinquishOutputArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test-basket", args.Basket)
		require.Equal(t, outpoint, args.Output)

		writeJSONResponse(t, w, wallet.RelinquishOutputResult{Relinquished: true})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	relinquishResult, err := client.RelinquishOutput(t.Context(), &wallet.RelinquishOutputArgs{
		Basket: "test-basket",
		Output: outpoint,
	})
	require.NoError(t, err)
	require.True(t, relinquishResult.Relinquished)
}

func TestHTTPWalletJSON_KeyLinkageOperations(t *testing.T) {
	counterParty := tu.GetPKFromHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	verifier := tu.GetPKFromHex(t, "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	// Test RevealCounterpartyKeyLinkage
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/revealCounterpartyKeyLinkage", r.URL.Path)

		var args wallet.RevealCounterpartyKeyLinkageArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, counterParty, args.Counterparty)
		require.Equal(t, verifier, args.Verifier)

		result := wallet.RevealCounterpartyKeyLinkageResult{
			EncryptedLinkage: []byte("encrypted-data"),
		}
		writeJSONResponse(t, w, &result)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	linkageResult, err := client.RevealCounterpartyKeyLinkage(t.Context(), wallet.RevealCounterpartyKeyLinkageArgs{
		Counterparty: counterParty,
		Verifier:     verifier,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("encrypted-data"), linkageResult.EncryptedLinkage)

	// Test RevealSpecificKeyLinkage
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/revealSpecificKeyLinkage", r.URL.Path)

		var args wallet.RevealSpecificKeyLinkageArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test-protocol", args.ProtocolID.Protocol)
		require.Equal(t, "test-key", args.KeyID)

		result := wallet.RevealSpecificKeyLinkageResult{
			EncryptedLinkage: []byte("specific-encrypted"),
		}
		writeJSONResponse(t, w, &result)
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	specificResult, err := client.RevealSpecificKeyLinkage(t.Context(), wallet.RevealSpecificKeyLinkageArgs{
		ProtocolID: wallet.Protocol{
			Protocol: "test-protocol",
		},
		KeyID: "test-key",
	})
	require.NoError(t, err)
	require.Equal(t, []byte("specific-encrypted"), specificResult.EncryptedLinkage)
}

func TestHTTPWalletJSON_AuthOperations(t *testing.T) {
	// Test IsAuthenticated
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/isAuthenticated", r.URL.Path)
		writeJSONResponse(t, w, wallet.AuthenticatedResult{Authenticated: true})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	authResult, err := client.IsAuthenticated(t.Context(), nil)
	require.NoError(t, err)
	require.True(t, authResult.Authenticated)

	// Test WaitForAuthentication
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/waitForAuthentication", r.URL.Path)
		writeJSONResponse(t, w, wallet.AuthenticatedResult{Authenticated: true})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	waitResult, err := client.WaitForAuthentication(t.Context(), nil)
	require.NoError(t, err)
	require.True(t, waitResult.Authenticated)
}

func TestHTTPWalletJSON_NetworkOperations(t *testing.T) {
	// Test GetHeight
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/getHeight", r.URL.Path)
		writeJSONResponse(t, w, wallet.GetHeightResult{Height: 12345})
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	heightResult, err := client.GetHeight(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, uint32(12345), heightResult.Height)

	// Test GetHeaderForHeight
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/getHeaderForHeight", r.URL.Path)

		var args wallet.GetHeaderArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, uint32(12345), args.Height)

		writeJSONResponse(t, w, wallet.GetHeaderResult{Header: []byte("test-header")})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	headerResult, err := client.GetHeaderForHeight(t.Context(), wallet.GetHeaderArgs{
		Height: 12345,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("test-header"), headerResult.Header)

	// Test GetNetwork
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/getNetwork", r.URL.Path)
		writeJSONResponse(t, w, wallet.GetNetworkResult{Network: wallet.NetworkMainnet})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	networkResult, err := client.GetNetwork(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, wallet.NetworkMainnet, networkResult.Network)

	// Test GetVersion
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/getVersion", r.URL.Path)
		writeJSONResponse(t, w, wallet.GetVersionResult{Version: "1.0.0"})
	}))
	defer ts.Close()

	client = NewHTTPWalletJSON("", ts.URL, nil)
	versionResult, err := client.GetVersion(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, "1.0.0", versionResult.Version)
}

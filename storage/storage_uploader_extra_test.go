package storage

// storage_uploader_extra_test.go – tests for uploader methods that bypass the BSV
// mutual-auth barrier.
//
// The AuthFetch.Fetch method normally requires a full BSV mutual-auth handshake.
// When the peers sync.Map already holds an entry with SupportsMutualAuth = &false
// for a given base URL, Fetch routes through handleFetchAndValidate which makes a
// plain HTTP request with NO BSV auth headers.
//
// We use reflect + unsafe to write directly into the unexported peers sync.Map field
// of AuthFetch, enabling us to test all the post-auth code paths in getUploadInfo,
// FindFile, ListUploads, and RenewFile using httptest servers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"
)

// bypassAuthForUploader injects a non-mutual-auth peer entry into the AuthFetch peers
// map for the given base URL, causing subsequent Fetch calls to use plain HTTP.
func bypassAuthForUploader(t *testing.T, uploader *Uploader, baseURL string) {
	t.Helper()

	notSupported := false
	peer := &authhttp.AuthPeer{
		SupportsMutualAuth: &notSupported,
	}

	// Access the unexported peers sync.Map field of AuthFetch via unsafe pointer.
	af := uploader.authFetch
	rv := reflect.ValueOf(af).Elem()
	peersField := rv.FieldByName("peers")
	require.True(t, peersField.IsValid(), "peers field not found on AuthFetch")

	peersPtr := (*sync.Map)(unsafe.Pointer(peersField.UnsafeAddr()))
	peersPtr.Store(baseURL, peer)
}

// newBypassedUploader creates an Uploader whose AuthFetch is pre-configured to skip
// BSV mutual auth for requests to the given httptest server.
func newBypassedUploader(t *testing.T, ts *httptest.Server) *Uploader {
	t.Helper()
	w := wallet.NewTestWalletForRandomKey(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: ts.URL,
		Wallet:     w,
	})
	require.NoError(t, err)

	// baseURL is scheme://host (no path)
	parsed := fmt.Sprintf("%s://%s", "http", ts.Listener.Addr().String())
	bypassAuthForUploader(t, uploader, parsed)
	return uploader
}

// ---- getUploadInfo ----

func TestGetUploadInfoNonOKStatus(t *testing.T) {
	// handleFetchAndValidate returns (resp, nil) for 2xx statuses.
	// getUploadInfo checks resp.StatusCode != 200, so use 201 to trigger line 102.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated) // 201 - passes handleFetchAndValidate but not getUploadInfo check
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload info request failed: HTTP 201")
}

func TestGetUploadInfoInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode upload info response")
}

func TestGetUploadInfoErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": StatusError})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload route returned an error")
}

func TestGetUploadInfoSuccess(t *testing.T) {
	uploadURL := "https://s3.example.com/upload"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"status":    StatusSuccess,
			"uploadURL": uploadURL,
			"requiredHeaders": map[string]string{
				"x-amz-acl": "public-read",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	info, err := uploader.getUploadInfo(context.Background(), 1024, 30)
	require.NoError(t, err)
	assert.Equal(t, uploadURL, info.UploadURL)
	assert.Equal(t, StatusSuccess, info.Status)
	assert.Equal(t, "public-read", info.RequiredHeaders["x-amz-acl"])
}

// ---- FindFile ----

func TestFindFileNonOKStatus(t *testing.T) {
	// Use 202 Accepted (2xx but not 200) to bypass handleFetchAndValidate's error check
	// while triggering FindFile's internal status != 200 check.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/find", r.URL.Path)
		w.WriteHeader(http.StatusAccepted) // 202
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "findFile request failed: HTTP 202")
}

func TestFindFileInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid}"))
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode findFile response")
}

func TestFindFileErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      StatusError,
			"code":        "FILE_NOT_FOUND",
			"description": "file does not exist",
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FILE_NOT_FOUND")
}

func TestFindFileSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, testUHRPURL, r.URL.Query().Get("uhrpUrl"))
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": StatusSuccess,
			"data": map[string]interface{}{
				"name":       "test.txt",
				"size":       "100 bytes",
				"mimeType":   testMimeTypeTextPlain,
				"expiryTime": 9999999999,
			},
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	data, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.NoError(t, err)
	assert.Equal(t, "test.txt", data.Name)
	assert.Equal(t, testMimeTypeTextPlain, data.MimeType)
}

// ---- ListUploads ----

func TestListUploadsNonOKStatus(t *testing.T) {
	// Use 202 Accepted (2xx but not 200) to bypass handleFetchAndValidate's error check
	// while triggering ListUploads' internal status != 200 check.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/list", r.URL.Path)
		w.WriteHeader(http.StatusAccepted) // 202
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listUploads request failed: HTTP 202")
}

func TestListUploadsInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("bad json"))
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode listUploads response")
}

func TestListUploadsErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      StatusError,
			"code":        "ACCESS_DENIED",
			"description": "not authorized",
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCESS_DENIED")
}

func TestListUploadsSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  StatusSuccess,
			"uploads": []interface{}{"file1", "file2"},
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	result, err := uploader.ListUploads(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ---- RenewFile ----

func TestRenewFileNonOKStatus(t *testing.T) {
	// Use 202 Accepted (2xx but not 200) to bypass handleFetchAndValidate's error check
	// while triggering RenewFile's internal status != 200 check.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/renew", r.URL.Path)
		w.WriteHeader(http.StatusAccepted) // 202
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.RenewFile(context.Background(), testUHRPURL, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "renewFile request failed: HTTP 202")
}

func TestRenewFileInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json}"))
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.RenewFile(context.Background(), testUHRPURL, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode renewFile response")
}

func TestRenewFileErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      StatusError,
			"code":        "UHRP_NOT_FOUND",
			"description": "UHRP URL not found",
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	_, err := uploader.RenewFile(context.Background(), testUHRPURL, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UHRP_NOT_FOUND")
}

func TestRenewFileSuccess(t *testing.T) {
	prevExpiry := int64(1000000)
	newExpiry := int64(2000000)
	amount := int64(500)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request body contains uhrpUrl and additionalMinutes
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "uhrp://myfile", body["uhrpUrl"])
		assert.Equal(t, float64(120), body["additionalMinutes"])

		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         StatusSuccess,
			"prevExpiryTime": prevExpiry,
			"newExpiryTime":  newExpiry,
			"amount":         amount,
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	result, err := uploader.RenewFile(context.Background(), "uhrp://myfile", 120)
	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)
	assert.Equal(t, prevExpiry, result.PrevExpiryTime)
	assert.Equal(t, newExpiry, result.NewExpiryTime)
	assert.Equal(t, amount, result.Amount)
}

// ---- uploadFile – client.Do error path ----

// TestUploadFileConnectionRefused exercises the client.Do error path (line 136-138)
// by using a URL that refuses connections.
func TestUploadFileConnectionRefused(t *testing.T) {
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "http://localhost:9",
		Wallet:     mockWallet,
	})
	require.NoError(t, err)

	// Port 9 (discard protocol) is typically blocked or connection-refused.
	// We use a TCP address guaranteed to refuse connections.
	_, err = uploader.uploadFile(context.Background(), "http://127.0.0.1:1/upload", UploadableFile{
		Data: []byte("test data"),
		Type: testMimeTypeTextPlain,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file upload failed")
}

// ---- PublishFile – full success path ----

// TestPublishFileFullSuccess tests the complete PublishFile flow (getUploadInfo → uploadFile)
// using the auth bypass and a httptest server that handles both endpoints.
func TestPublishFileFullSuccess(t *testing.T) {
	fileData := []byte("test file for publish")

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/upload":
			// getUploadInfo: return a presigned URL pointing to this same server
			w.Header().Set(headerContentType, contentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          StatusSuccess,
				"uploadURL":       ts.URL + "/put-target",
				"requiredHeaders": map[string]string{},
			})
		case r.Method == "PUT" && r.URL.Path == "/put-target":
			// uploadFile: accept the PUT
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	result, err := uploader.PublishFile(context.Background(), UploadableFile{
		Data: fileData,
		Type: testMimeTypeTextPlain,
	}, 60)
	require.NoError(t, err)
	assert.True(t, result.Published)
	assert.NotEmpty(t, result.UhrpURL)
}

func TestRenewFileSuccessNilOptionals(t *testing.T) {
	// When PrevExpiryTime, NewExpiryTime, Amount are omitted, they default to 0.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": StatusSuccess,
			// omit all optional fields
		})
	}))
	defer ts.Close()

	uploader := newBypassedUploader(t, ts)
	result, err := uploader.RenewFile(context.Background(), testUHRPURL, 30)
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.PrevExpiryTime)
	assert.Equal(t, int64(0), result.NewExpiryTime)
	assert.Equal(t, int64(0), result.Amount)
}

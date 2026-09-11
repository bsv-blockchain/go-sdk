package storage

// storage_uploader_extra_test.go – socket-free tests for the authenticated
// uploader endpoints (getUploadInfo, FindFile, ListUploads, RenewFile) and the
// presigned-URL PUT path.
//
// Instead of standing up a local test server and reaching through a real BSV
// mutual-auth handshake, we inject a mockAuthFetcher (via WithAuthFetcher) that
// returns canned *http.Response values, and a *tu.MockHTTPClient (via
// WithUploaderClient) for the PUT upload. This exercises every post-fetch code
// path – JSON decode, checkAPIError, HTTP-status and pointer-field branches –
// with no network I/O, so the tests are safe to run with t.Parallel().

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const testStorageURL = "https://storage.test"

// mockAuthFetcher is a socket-free AuthFetcher that returns whatever fetchFunc
// produces. *authhttp.AuthFetch satisfies the same interface, but this stand-in
// performs no mutual-auth handshake and no I/O. Tests assert on the outgoing URL,
// method, and body directly inside fetchFunc.
type mockAuthFetcher struct {
	fetchFunc func(ctx context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error)
}

// Fetch delegates to fetchFunc. It satisfies AuthFetcher.
func (m *mockAuthFetcher) Fetch(ctx context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
	return m.fetchFunc(ctx, url, config)
}

// stringFetcher builds a mockAuthFetcher whose every Fetch call returns a fresh
// response with the given status and body (and no error).
func stringFetcher(status int, body string) *mockAuthFetcher {
	return &mockAuthFetcher{
		fetchFunc: func(context.Context, string, *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.StringResponse(status, body), nil
		},
	}
}

// erroringFetcher builds a mockAuthFetcher whose every Fetch call fails with err,
// standing in for a transport-level failure without any real network.
func erroringFetcher(err error) *mockAuthFetcher {
	return &mockAuthFetcher{
		fetchFunc: func(context.Context, string, *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return nil, err
		},
	}
}

// newMockUploader builds an Uploader against a fixed fake base URL with the given
// options applied (typically WithAuthFetcher and/or WithUploaderClient).
func newMockUploader(t *testing.T, opts ...func(*UploaderOptions)) *Uploader {
	t.Helper()
	w := wallet.NewTestWalletForRandomKey(t)
	u, err := NewUploader(UploaderConfig{StorageURL: testStorageURL, Wallet: w}, opts...)
	require.NoError(t, err)
	return u
}

// ---- getUploadInfo ----------------------------------------------------------

func TestGetUploadInfoNonOKStatus(t *testing.T) {
	t.Parallel()
	// A 2xx status other than 200 must trigger the status-check error branch.
	af := stringFetcher(http.StatusCreated, "")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload info request failed: HTTP 201")
}

func TestGetUploadInfoInvalidJSON(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusOK, "not valid json")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode upload info response")
}

func TestGetUploadInfoErrorStatus(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, _ string, _ *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, map[string]string{"status": StatusError}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload route returned an error")
}

func TestGetUploadInfoSuccess(t *testing.T) {
	t.Parallel()
	uploadURL := "https://s3.example.com/upload"
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			assert.Equal(t, testStorageURL+"/upload", url)
			assert.Equal(t, "POST", config.Method)
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":          StatusSuccess,
				"uploadURL":       uploadURL,
				"requiredHeaders": map[string]string{"x-amz-acl": "public-read"},
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	info, err := uploader.getUploadInfo(context.Background(), 1024, 30)
	require.NoError(t, err)
	assert.Equal(t, uploadURL, info.UploadURL)
	assert.Equal(t, StatusSuccess, info.Status)
	assert.Equal(t, "public-read", info.RequiredHeaders["x-amz-acl"])
}

// ---- FindFile ---------------------------------------------------------------

func TestFindFileNonOKStatus(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusAccepted, "")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "findFile request failed: HTTP 202")
}

func TestFindFileInvalidJSON(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusOK, "{invalid}")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode findFile response")
}

func TestFindFileErrorStatus(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, _ *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":      StatusError,
				"code":        "FILE_NOT_FOUND",
				"description": "file does not exist",
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FILE_NOT_FOUND")
}

func TestFindFileSuccess(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			assert.Contains(t, url, testStorageURL+"/find")
			assert.Contains(t, url, "uhrpUrl=")
			assert.Equal(t, "GET", config.Method)
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status": StatusSuccess,
				"data": map[string]any{
					"name":       "test.txt",
					"size":       "100 bytes",
					"mimeType":   testMimeTypeTextPlain,
					"expiryTime": 9999999999,
				},
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	data, err := uploader.FindFile(context.Background(), testUHRPURL)
	require.NoError(t, err)
	assert.Equal(t, "test.txt", data.Name)
	assert.Equal(t, testMimeTypeTextPlain, data.MimeType)
}

// ---- ListUploads ------------------------------------------------------------

func TestListUploadsNonOKStatus(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusAccepted, "")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listUploads request failed: HTTP 202")
}

func TestListUploadsInvalidJSON(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusOK, "bad json")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode listUploads response")
}

func TestListUploadsErrorStatus(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, _ *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":      StatusError,
				"code":        "ACCESS_DENIED",
				"description": "not authorized",
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCESS_DENIED")
}

func TestListUploadsSuccess(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			assert.Equal(t, testStorageURL+"/list", url)
			assert.Equal(t, "GET", config.Method)
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":  StatusSuccess,
				"uploads": []any{"file1", "file2"},
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	result, err := uploader.ListUploads(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ---- RenewFile --------------------------------------------------------------

func TestRenewFileNonOKStatus(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusAccepted, "")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.RenewFile(context.Background(), testUHRPURL, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "renewFile request failed: HTTP 202")
}

func TestRenewFileInvalidJSON(t *testing.T) {
	t.Parallel()
	af := stringFetcher(http.StatusOK, "{not json}")
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.RenewFile(context.Background(), testUHRPURL, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode renewFile response")
}

func TestRenewFileErrorStatus(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, _ *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":      StatusError,
				"code":        "UHRP_NOT_FOUND",
				"description": "UHRP URL not found",
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	_, err := uploader.RenewFile(context.Background(), testUHRPURL, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UHRP_NOT_FOUND")
}

func TestRenewFileSuccess(t *testing.T) {
	t.Parallel()
	prevExpiry := int64(1000000)
	newExpiry := int64(2000000)
	amount := int64(500)

	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			assert.Equal(t, testStorageURL+"/renew", url)
			assert.Equal(t, "POST", config.Method)
			var body map[string]any
			require.NoError(t, json.Unmarshal(config.Body, &body))
			assert.Equal(t, "uhrp://myfile", body["uhrpUrl"])
			assert.InDelta(t, float64(120), body["additionalMinutes"], 0.0001)
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":         StatusSuccess,
				"prevExpiryTime": prevExpiry,
				"newExpiryTime":  newExpiry,
				"amount":         amount,
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	result, err := uploader.RenewFile(context.Background(), "uhrp://myfile", 120)
	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)
	assert.Equal(t, prevExpiry, result.PrevExpiryTime)
	assert.Equal(t, newExpiry, result.NewExpiryTime)
	assert.Equal(t, amount, result.Amount)
}

func TestRenewFileSuccessNilOptionals(t *testing.T) {
	t.Parallel()
	// When PrevExpiryTime, NewExpiryTime, Amount are omitted, they default to 0.
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, _ *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status": StatusSuccess,
			}), nil
		},
	}
	uploader := newMockUploader(t, WithAuthFetcher(af))

	result, err := uploader.RenewFile(context.Background(), testUHRPURL, 30)
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.PrevExpiryTime)
	assert.Equal(t, int64(0), result.NewExpiryTime)
	assert.Equal(t, int64(0), result.Amount)
}

// ---- uploadFile – client.Do error path --------------------------------------

// TestUploadFileConnectionRefused exercises the client.Do error branch by
// injecting a client whose transport always fails.
func TestUploadFileConnectionRefused(t *testing.T) {
	t.Parallel()
	mc := &tu.MockHTTPClient{DoFunc: func(*http.Request) (*http.Response, error) {
		return nil, assert.AnError
	}}
	uploader := newMockUploader(t, WithUploaderClient(mc))

	_, err := uploader.uploadFile(context.Background(), testStorageURL+"/upload", UploadableFile{
		Data: []byte("test data"),
		Type: testMimeTypeTextPlain,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file upload failed")
}

// ---- PublishFile – full success path ----------------------------------------

// TestPublishFileFullSuccess tests the complete PublishFile flow
// (getUploadInfo via AuthFetcher → uploadFile via injected client).
func TestPublishFileFullSuccess(t *testing.T) {
	t.Parallel()
	fileData := []byte("test file for publish")
	putURL := "https://s3.example.com/put-target"

	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, url string, config *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			assert.Equal(t, testStorageURL+"/upload", url)
			assert.Equal(t, "POST", config.Method)
			return tu.JSONResponse(t, http.StatusOK, map[string]any{
				"status":          StatusSuccess,
				"uploadURL":       putURL,
				"requiredHeaders": map[string]string{"x-amz-acl": "public-read"},
			}), nil
		},
	}
	mc := &tu.MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPut, req.Method)
		assert.Equal(t, putURL, req.URL.String())
		assert.Equal(t, testMimeTypeTextPlain, req.Header.Get("Content-Type"))
		assert.Equal(t, "public-read", req.Header.Get("x-amz-acl"))
		return tu.StringResponse(http.StatusOK, ""), nil
	}}

	uploader := newMockUploader(t, WithAuthFetcher(af), WithUploaderClient(mc))
	result, err := uploader.PublishFile(context.Background(), UploadableFile{
		Data: fileData,
		Type: testMimeTypeTextPlain,
	}, 60)
	require.NoError(t, err)
	assert.True(t, result.Published)
	assert.NotEmpty(t, result.UhrpURL)
}

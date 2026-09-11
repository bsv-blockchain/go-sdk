package storage

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

const testMimeTypeTextPlain = "text/plain"

// TestCheckAPIError tests the checkAPIError helper function.
func TestCheckAPIError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      string
		code        string
		description string
		operation   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "success status returns no error",
			status:    StatusSuccess,
			operation: "findFile",
			wantErr:   false,
		},
		{
			name:        "error status with code and description",
			status:      StatusError,
			code:        "NOT_FOUND",
			description: "file not found",
			operation:   "findFile",
			wantErr:     true,
			errContains: "NOT_FOUND",
		},
		{
			name:        "error status with empty code uses unknown-code",
			status:      StatusError,
			code:        "",
			description: "some error",
			operation:   "listUploads",
			wantErr:     true,
			errContains: "unknown-code",
		},
		{
			name:        "error status with empty description uses no-description",
			status:      StatusError,
			code:        "ERR",
			description: "",
			operation:   "renewFile",
			wantErr:     true,
			errContains: "no-description",
		},
		{
			name:        "error status includes operation name",
			status:      StatusError,
			code:        "ERR",
			description: "desc",
			operation:   "myOperation",
			wantErr:     true,
			errContains: "myOperation",
		},
		{
			name:      "non-error non-success status returns no error",
			status:    "pending",
			operation: "upload",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkAPIError(tt.status, tt.code, tt.description, tt.operation)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestUploadFileSuccess tests that uploadFile correctly calls the PUT endpoint.
func TestUploadFileSuccess(t *testing.T) {
	t.Parallel()
	fileData := []byte("hello test content for upload")
	putURL := testStorageURL + "/put-target"

	mc := &tu.MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPut, req.Method)
		assert.Equal(t, putURL, req.URL.String())
		assert.Equal(t, testMimeTypeTextPlain, req.Header.Get("Content-Type"))
		assert.Equal(t, "val1", req.Header.Get("X-Custom"))
		return tu.StringResponse(http.StatusOK, ""), nil
	}}

	uploader := newMockUploader(t, WithUploaderClient(mc))
	result, err := uploader.uploadFile(context.Background(), putURL, UploadableFile{
		Data: fileData,
		Type: testMimeTypeTextPlain,
	}, map[string]string{"X-Custom": "val1"})

	require.NoError(t, err)
	assert.True(t, result.Published)
	assert.NotEmpty(t, result.UhrpURL)
}

// TestUploadFileHTTPError tests that uploadFile returns error on HTTP error response.
func TestUploadFileHTTPError(t *testing.T) {
	t.Parallel()
	mc := &tu.MockHTTPClient{DoFunc: func(*http.Request) (*http.Response, error) {
		return tu.StringResponse(http.StatusForbidden, "forbidden"), nil
	}}

	uploader := newMockUploader(t, WithUploaderClient(mc))
	_, err := uploader.uploadFile(context.Background(), testStorageURL+"/put-target", UploadableFile{
		Data: []byte("data"),
		Type: testMimeTypeTextPlain,
	}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// TestUploadFileInvalidURL tests that uploadFile fails with an invalid URL
// (request creation fails before the client is ever called).
func TestUploadFileInvalidURL(t *testing.T) {
	t.Parallel()
	mc := &tu.MockHTTPClient{}
	uploader := newMockUploader(t, WithUploaderClient(mc))

	_, err := uploader.uploadFile(context.Background(), "://bad-url", UploadableFile{
		Data: []byte("data"),
		Type: testMimeTypeTextPlain,
	}, nil)

	require.Error(t, err)
	assert.Empty(t, mc.Requests) // never reached the client
}

// TestGetUploadInfoErrorResponse tests that PublishFile propagates the
// error-status upload-info response (getUploadInfo -> "upload route returned an error").
func TestGetUploadInfoErrorResponse(t *testing.T) {
	t.Parallel()
	af := &mockAuthFetcher{
		fetchFunc: func(_ context.Context, _ string, _ *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, map[string]string{"status": StatusError}), nil
		},
	}
	mc := &tu.MockHTTPClient{}
	uploader := newMockUploader(t, WithAuthFetcher(af), WithUploaderClient(mc))

	_, err := uploader.PublishFile(context.Background(), UploadableFile{
		Data: []byte("data"),
		Type: testMimeTypeTextPlain,
	}, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload route returned an error")
	assert.Empty(t, mc.Requests) // PUT never attempted because getUploadInfo failed
}

// TestStorageConstants verifies status constants are correct.
func TestStorageConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "success", StatusSuccess)
	assert.Equal(t, "error", StatusError)
}

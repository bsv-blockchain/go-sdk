// Package storage_test runs the ts-stack storage conformance vectors
// (storage/uhrp-http.json, storage/chirp-v1.json) against the Go SDK.
//
// uhrp-http.json describes the generic UHRP HTTP API contract implemented by
// uhrp-services/NanoStore (reference_impl: "uhrp-services"). The TS
// conformance dispatcher (conformance/runner/ts/dispatchers/storage.ts) never
// drives the real @bsv/sdk StorageUploader client against these vectors
// either — it validates method/path/status/body-shape directly against each
// fixture, because the raw HTTP contract documented here does not always
// match what StorageUploader.ts itself sends/expects (for example, the
// vectors' /find response shape {URLs, MIMEType, expiryTime} differs from
// StorageUploader's own {name, size, mimeType, expiryTime} nested under
// {status, data}, and /renew's example body field is "additionalPeriod"
// while the real client sends "additionalMinutes"). This file mirrors that
// same structural strategy so it asserts exactly what the TS runner asserts,
// without inventing a stricter contract than either reference implements.
//
// Where the vector and the real Go client provably agree (POST /upload's
// {fileSize, retentionPeriod} body, confirmed against
// packages/sdk/src/storage/StorageUploader.ts), this file also drives the
// real storage.Uploader end-to-end via an injected AuthFetcher, for genuine
// wire-shape coverage beyond a schema check.
package storage_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/storage"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type uhrpInput struct {
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Headers      map[string]string `json:"headers"`
	Body         map[string]any    `json:"body"`
	QueryParams  map[string]any    `json:"queryParams"`
	SchemaCheck  bool              `json:"_schema_check"`
	LimitDefault *float64          `json:"limit_default"`
	LimitMax     *float64          `json:"limit_max"`
	OffsetMin    *float64          `json:"offset_min"`
	Examples     []string          `json:"examples"`
}

type uhrpExpected struct {
	Status      *int           `json:"status"`
	ContentType string         `json:"content_type"`
	BodyShape   map[string]any `json:"body_shape"`
	Valid       *bool          `json:"valid"`
	Encoding    string         `json:"encoding"`
	HashAlgo    string         `json:"hash_algorithm"`
	PrefixBytes string         `json:"prefix_bytes"`
}

func headerValue(headers map[string]string, key string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func hasAuthHeader(in uhrpInput) bool {
	_, ok := headerValue(in.Headers, "authorization")
	return ok
}

// assertBodyShape mirrors the TS dispatcher's use of expected.body_shape:
// each declared field name must be a non-empty type-name string
// ("string"/"array"/"number"...). The vector never asserts real values for
// these (no server exists to produce them), only that the declared contract
// is well-formed.
func assertBodyShape(t *testing.T, shape map[string]any) {
	t.Helper()
	for field, kind := range shape {
		s, ok := kind.(string)
		if !ok || s == "" {
			t.Errorf("body_shape[%q] = %#v, want a non-empty type name", field, kind)
		}
	}
}

func TestStorageUHRPHTTP(t *testing.T) {
	f := conformance.Load(t, "storage/uhrp-http.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		var in uhrpInput
		v.DecodeInput(t, &in)
		var exp uhrpExpected
		v.DecodeExpected(t, &exp)

		switch {
		case in.LimitDefault != nil || in.LimitMax != nil:
			dispatchListPaginationSchema(t, in, exp)
		case in.SchemaCheck && len(in.Examples) > 0:
			dispatchUhrpURLFormat(t, in, exp)
		case in.SchemaCheck && in.Method == http.MethodPut:
			dispatchUploadPutSchema(t, in, exp)
		case in.Path == "/upload" && in.Method == http.MethodPost:
			dispatchUploadPath(t, in, exp)
		case in.Path == "/find" && in.Method == http.MethodGet:
			dispatchFindPath(t, in, exp)
		case in.Path == "/list" && in.Method == http.MethodGet:
			dispatchListPath(t, in, exp)
		case in.Path == "/renew" && in.Method == http.MethodPost:
			dispatchRenewPath(t, in, exp)
		default:
			t.Fatalf("unrecognized uhrp-http vector shape: %+v", in)
		}
	})
}

func requireStatus(t *testing.T, exp uhrpExpected, want int) {
	t.Helper()
	if exp.Status == nil || *exp.Status != want {
		t.Fatalf("expected.status = %v, want %d", exp.Status, want)
	}
}

func dispatchUploadPath(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if !hasAuthHeader(in) {
		requireStatus(t, exp, http.StatusUnauthorized)
		return
	}
	if _, ok := in.Body["fileSize"]; !ok {
		requireStatus(t, exp, http.StatusBadRequest)
		return
	}

	requireStatusOneOf(t, exp, []int{200, 400, 401, 500})
	if exp.Status != nil && *exp.Status == http.StatusOK {
		assertBodyShape(t, exp.BodyShape)
		if _, ok := exp.BodyShape["uploadURL"]; !ok {
			t.Errorf("200 upload response body_shape missing uploadURL")
		}
		if _, ok := exp.BodyShape["uhrpUrl"]; !ok {
			t.Errorf("200 upload response body_shape missing uhrpUrl")
		}
		exerciseRealUpload(t, in)
	}
}

// exerciseRealUpload drives the real storage.Uploader.PublishFile against a
// fake AuthFetcher + HTTP client, confirming the Go client's actual /upload
// request body is {fileSize, retentionPeriod} -- the shape
// StorageUploader.ts's own #getUploadURL sends -- and that a well-formed
// 200 response is consumed without error.
func exerciseRealUpload(t *testing.T, in uhrpInput) {
	t.Helper()

	var capturedURL string
	var capturedBody map[string]any
	af := fakeAuthFetcherFunc(func(_ context.Context, url string, opts *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
		capturedURL = url
		_ = json.Unmarshal(opts.Body, &capturedBody)
		respBody, err := json.Marshal(map[string]string{
			"status":    "success",
			"uploadURL": "https://presigned.example.com/put/abc",
		})
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(respBody))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	putClient := fakeHTTPClientFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{},
		}, nil
	})

	uploader, err := storage.NewUploader(storage.UploaderConfig{
		StorageURL: "https://storage.example.com",
		Wallet:     wallet.NewTestWalletForRandomKey(t),
	}, storage.WithAuthFetcher(af), storage.WithUploaderClient(putClient))
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}

	fileSize, _ := in.Body["fileSize"].(float64)
	data := make([]byte, int(fileSize))
	result, err := uploader.PublishFile(t.Context(), storage.UploadableFile{Data: data, Type: "image/png"}, 2592000)
	if err != nil {
		t.Fatalf("PublishFile returned an error for a well-formed 200 response: %v", err)
	}
	if !result.Published {
		t.Errorf("PublishFile result.Published = false, want true")
	}
	if result.UhrpURL == "" {
		t.Errorf("PublishFile result.UhrpURL is empty")
	}
	if !strings.HasSuffix(capturedURL, "/upload") {
		t.Errorf("client requested %q, want a path ending in /upload", capturedURL)
	}
	if _, ok := capturedBody["fileSize"]; !ok {
		t.Errorf("client's /upload request body missing fileSize: %v", capturedBody)
	}
	if _, ok := capturedBody["retentionPeriod"]; !ok {
		t.Errorf("client's /upload request body missing retentionPeriod: %v", capturedBody)
	}
}

func dispatchFindPath(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if _, ok := in.QueryParams["uhrpUrl"]; !ok {
		requireStatus(t, exp, http.StatusBadRequest)
		return
	}
	if exp.Status != nil && *exp.Status == http.StatusNotFound {
		return
	}
	requireStatusOneOf(t, exp, []int{200, 400, 404, 500})
	if exp.Status != nil && *exp.Status == http.StatusOK && len(exp.BodyShape) > 0 {
		assertBodyShape(t, exp.BodyShape)
	}
}

func dispatchListPath(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if !hasAuthHeader(in) {
		requireStatus(t, exp, http.StatusUnauthorized)
		return
	}
	requireStatusOneOf(t, exp, []int{200, 401, 500})
	if exp.Status != nil && *exp.Status == http.StatusOK {
		assertBodyShape(t, exp.BodyShape)
	}
}

func dispatchRenewPath(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if !hasAuthHeader(in) {
		requireStatus(t, exp, http.StatusUnauthorized)
		return
	}
	if exp.Status != nil && *exp.Status == http.StatusNotFound {
		return
	}
	requireStatusOneOf(t, exp, []int{200, 401, 404, 500})
	if _, ok := in.Body["uhrpUrl"]; !ok {
		t.Errorf("renew request body missing uhrpUrl")
	}
	if exp.Status != nil && *exp.Status == http.StatusOK {
		assertBodyShape(t, exp.BodyShape)
	}
}

func dispatchListPaginationSchema(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if in.LimitDefault == nil || in.LimitMax == nil || in.OffsetMin == nil {
		t.Fatalf("pagination schema vector missing limit_default/limit_max/offset_min")
	}
	if *in.LimitDefault <= 0 {
		t.Errorf("limit_default = %v, want > 0", *in.LimitDefault)
	}
	if *in.LimitMax < *in.LimitDefault {
		t.Errorf("limit_max = %v, want >= limit_default (%v)", *in.LimitMax, *in.LimitDefault)
	}
	if *in.OffsetMin != 0 {
		t.Errorf("offset_min = %v, want 0", *in.OffsetMin)
	}
	if *in.LimitDefault != 100 {
		t.Errorf("limit_default = %v, want 100", *in.LimitDefault)
	}
	if *in.LimitMax != 1000 {
		t.Errorf("limit_max = %v, want 1000", *in.LimitMax)
	}
	if exp.Valid == nil || !*exp.Valid {
		t.Errorf("expected.valid = %v, want true", exp.Valid)
	}
}

// dispatchUhrpURLFormat exercises the real storage package utilities, mirroring
// storage.ts's dispatchUhrpUrlFormat which calls the real StorageUtils.
func dispatchUhrpURLFormat(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if exp.Encoding != "Base58Check" {
		t.Errorf("encoding = %q, want Base58Check", exp.Encoding)
	}
	if exp.HashAlgo != "SHA-256" {
		t.Errorf("hash_algorithm = %q, want SHA-256", exp.HashAlgo)
	}
	if exp.PrefixBytes != "ce00" {
		t.Errorf("prefix_bytes = %q, want ce00", exp.PrefixBytes)
	}

	for _, url := range in.Examples {
		if !storage.IsValidURL(url) {
			t.Errorf("IsValidURL(%q) = false, want true", url)
			continue
		}
		hash, err := storage.GetHashFromURL(url)
		if err != nil {
			t.Errorf("GetHashFromURL(%q): %v", url, err)
			continue
		}
		if len(hash) != 32 {
			t.Errorf("GetHashFromURL(%q) returned %d bytes, want 32", url, len(hash))
		}
		rebuilt, err := storage.GetURLForHash(hash)
		if err != nil {
			t.Errorf("GetURLForHash: %v", err)
			continue
		}
		rebuiltHash, err := storage.GetHashFromURL(rebuilt)
		if err != nil {
			t.Errorf("GetHashFromURL(rebuilt): %v", err)
			continue
		}
		if string(hash) != string(rebuiltHash) {
			t.Errorf("round trip hash mismatch for %q", url)
		}
	}
}

func dispatchUploadPutSchema(t *testing.T, in uhrpInput, exp uhrpExpected) {
	t.Helper()
	if in.Method != http.MethodPut {
		t.Errorf("method = %q, want PUT", in.Method)
	}
	if in.Path == "" {
		t.Errorf("path is empty")
	}
	requireStatus(t, exp, http.StatusOK)
}

func requireStatusOneOf(t *testing.T, exp uhrpExpected, allowed []int) {
	t.Helper()
	if exp.Status == nil {
		t.Fatalf("expected.status missing")
	}
	for _, a := range allowed {
		if *exp.Status == a {
			return
		}
	}
	t.Errorf("expected.status = %d, want one of %v", *exp.Status, allowed)
}

// ── Test doubles ─────────────────────────────────────────────────────────────

type fakeAuthFetcherFunc func(ctx context.Context, url string, opts *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error)

func (f fakeAuthFetcherFunc) Fetch(ctx context.Context, url string, opts *authhttp.SimplifiedFetchRequestOptions) (*http.Response, error) {
	return f(ctx, url, opts)
}

type fakeHTTPClientFunc func(req *http.Request) (*http.Response, error)

func (f fakeHTTPClientFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

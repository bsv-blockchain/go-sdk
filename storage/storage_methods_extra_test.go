package storage

// storage_methods_extra_test.go – socket-free tests for Resolve output-processing
// and the full Download HTTP loop.
//
// Resolve is driven with a mockLookupFacilitator that returns hand-built BEEF
// outputs (too-few pushdrop fields, expired timestamp, empty host URL, valid host
// URL, out-of-range index, non-pushdrop script, mixed batches).
//
// Download is driven by injecting a *tu.MockHTTPClient (via WithDownloaderClient)
// whose DoFunc returns canned responses. The BEEF carries a fake host URL; no
// local test server or real socket is involved. For the hash-match tests the
// uhrpURL is derived from the exact bytes the mock returns, so
// crypto.Sha256(body) == hash.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

const (
	errUnableToDownload = "unable to download content"
	// fakeHost is a syntactically valid host URL that is never dialed – the
	// injected mock client answers every request without any real network I/O.
	fakeHost = "https://host.test/file"
)

// ---- helpers ----------------------------------------------------------------

// errReadCloser is a response body that always fails on Read, exercising the
// io.ReadAll error branch in Download.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("simulated read error") }
func (errReadCloser) Close() error             { return nil }

// buildMinimalBeef creates a parent→child BEEF with the given locking script.
func buildMinimalBeef(t *testing.T, lockingScript *script.Script) []byte {
	t.Helper()
	parentTx := transaction.NewTransaction()
	parentTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	parentTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      2000,
		LockingScript: &script.Script{},
	})

	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       parentTx.TxID(),
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockingScript,
	})
	tx.Inputs[0].SourceTransaction = parentTx

	beef, err := tx.AtomicBEEF(true)
	require.NoError(t, err)
	return beef
}

// buildUhrpPushDropScript creates a pushdrop script matching the UHRP format
// (fields: hash, uhrpURL, hostURL, expiryVarInt).
// The expiry is encoded using the BSV VarInt format as expected by util.Reader.ReadVarInt.
func buildUhrpPushDropScript(t *testing.T, hash []byte, uhrpURL, hostURL string, expiryUnix int64) *script.Script {
	t.Helper()
	// Encode expiry as a BSV VarInt (used by util.Reader.ReadVarInt)
	expiryBytes := util.VarInt(uint64(expiryUnix)).Bytes() //nolint:gosec // G115 -- test-only expiry timestamps are always non-negative

	s := &script.Script{}
	require.NoError(t, s.AppendPushData(testPushDropPubKeyBytes))
	require.NoError(t, s.AppendOpcodes(script.OpCHECKSIG))
	// Field 0: hash
	require.NoError(t, s.AppendPushData(hash))
	// Field 1: uhrpURL
	require.NoError(t, s.AppendPushData([]byte(uhrpURL)))
	// Field 2: hostURL
	require.NoError(t, s.AppendPushData([]byte(hostURL)))
	// Field 3: expiryTime as VarInt bytes
	require.NoError(t, s.AppendPushData(expiryBytes))
	// Two 2DROPs for 4 fields
	require.NoError(t, s.AppendOpcodes(script.Op2DROP))
	require.NoError(t, s.AppendOpcodes(script.Op2DROP))
	return s
}

// newDownloaderWithFacilitator creates a StorageDownloader from a raw facilitator.
// An optional HTTP client can be supplied for the Download path; when omitted a
// default socket-free mock client is used (sufficient for Resolve-only tests).
func newDownloaderWithFacilitator(facilitator lookup.Facilitator, client ...util.HTTPClient) *StorageDownloader {
	var c util.HTTPClient = &tu.MockHTTPClient{}
	if len(client) > 0 {
		c = client[0]
	}
	resolver := &lookup.LookupResolver{
		Facilitator: facilitator,
		HostOverrides: map[string][]string{
			"ls_uhrp": {"http://mock-host"},
		},
		AdditionalHosts: map[string][]string{},
	}
	return NewStorageDownloader(DownloaderConfig{},
		WithLookupResolver(resolver),
		WithDownloaderClient(c),
	)
}

// multiHostFacilitator builds a mockLookupFacilitator advertising the given hosts
// (each in its own non-expired BEEF output) for a single uhrpURL/hash.
func multiHostFacilitator(t *testing.T, hash []byte, uhrpURL string, hosts ...string) *mockLookupFacilitator {
	t.Helper()
	futureExpiry := time.Now().Add(24 * time.Hour).Unix()
	outputs := make([]*lookup.OutputListItem, 0, len(hosts))
	for _, h := range hosts {
		s := buildUhrpPushDropScript(t, hash, uhrpURL, h, futureExpiry)
		outputs = append(outputs, &lookup.OutputListItem{Beef: buildMinimalBeef(t, s), OutputIndex: 0})
	}
	return &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: outputs,
		},
	}
}

// testPushDropPubKeyBytes is the compressed public key used in pushdrop scripts for tests.
var testPushDropPubKeyBytes = []byte{
	0x02,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
}

// ---- Resolve – output processing paths -------------------------------------

// TestResolveTooFewPushDropFields tests that outputs with < 4 pushdrop fields
// are silently skipped.
func TestResolveTooFewPushDropFields(t *testing.T) {
	t.Parallel()
	// Build a pushdrop script with only 2 data fields (fewer than required 4).
	s := &script.Script{}
	require.NoError(t, s.AppendPushData(testPushDropPubKeyBytes))
	require.NoError(t, s.AppendOpcodes(script.OpCHECKSIG))
	require.NoError(t, s.AppendPushData([]byte("field1")))
	require.NoError(t, s.AppendPushData([]byte("field2")))
	require.NoError(t, s.AppendOpcodes(script.Op2DROP))

	beef := buildMinimalBeef(t, s)
	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), "uhrp://test")
	require.NoError(t, err)
	assert.Empty(t, hosts) // skipped due to too few fields
}

// TestResolveExpiredOutput tests that an output with an expired timestamp is skipped.
func TestResolveExpiredOutput(t *testing.T) {
	t.Parallel()
	content := []byte("test content for expired output")
	hash := crypto.Sha256(content)
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	// Set expiry in the past
	pastExpiry := time.Now().Add(-24 * time.Hour).Unix()
	s := buildUhrpPushDropScript(t, hash, uhrpURL, "http://expired-host.example.com", pastExpiry)
	beef := buildMinimalBeef(t, s)

	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), uhrpURL)
	require.NoError(t, err)
	assert.Empty(t, hosts) // expired, skipped
}

// TestResolveValidHostURL tests that a valid, non-expired output adds a host URL.
func TestResolveValidHostURL(t *testing.T) {
	t.Parallel()
	content := []byte("test content for valid host url")
	hash := crypto.Sha256(content)
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	hostURL := "https://valid-host.example.com/file"
	facilitator := multiHostFacilitator(t, hash, uhrpURL, hostURL)
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), uhrpURL)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, hostURL, hosts[0])
}

// TestResolveEmptyHostURL tests that a valid output with an empty host URL is skipped.
func TestResolveEmptyHostURL(t *testing.T) {
	t.Parallel()
	content := []byte("test content for empty host url")
	hash := crypto.Sha256(content)
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	futureExpiry := time.Now().Add(24 * time.Hour).Unix()
	s := buildUhrpPushDropScript(t, hash, uhrpURL, "", futureExpiry) // empty host
	beef := buildMinimalBeef(t, s)

	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), uhrpURL)
	require.NoError(t, err)
	assert.Empty(t, hosts) // empty host URL skipped
}

// TestResolveOutputIndexOutOfRange tests that an output with an out-of-bounds
// index is silently skipped.
func TestResolveOutputIndexOutOfRange(t *testing.T) {
	t.Parallel()
	futureExpiry := time.Now().Add(24 * time.Hour).Unix()
	s := buildUhrpPushDropScript(t, make([]byte, 32), "url", "http://host", futureExpiry)
	beef := buildMinimalBeef(t, s)

	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 99}}, // out of range
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), "uhrp://any")
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

// TestResolveMultipleOutputsMixed tests that valid and invalid outputs in the
// same answer are handled correctly (valid added, expired skipped).
func TestResolveMultipleOutputsMixed(t *testing.T) {
	t.Parallel()
	content1 := []byte("content for host 1")
	hash1 := crypto.Sha256(content1)
	uhrpURL1, err := GetURLForFile(content1)
	require.NoError(t, err)

	content2 := []byte("content for host 2")
	hash2 := crypto.Sha256(content2)
	uhrpURL2, err := GetURLForFile(content2)
	require.NoError(t, err)

	futureExpiry := time.Now().Add(24 * time.Hour).Unix()
	pastExpiry := time.Now().Add(-1 * time.Hour).Unix()

	validScript := buildUhrpPushDropScript(t, hash1, uhrpURL1, "https://host1.example.com", futureExpiry)
	expiredScript := buildUhrpPushDropScript(t, hash2, uhrpURL2, "https://host2.example.com", pastExpiry)

	validBeef := buildMinimalBeef(t, validScript)
	expiredBeef := buildMinimalBeef(t, expiredScript)

	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type: lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{
				{Beef: validBeef, OutputIndex: 0},
				{Beef: expiredBeef, OutputIndex: 0},
				{Beef: []byte("invalid"), OutputIndex: 0},
			},
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), uhrpURL1)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, "https://host1.example.com", hosts[0])
}

// ---- Download – full HTTP path tests ----------------------------------------

// TestDownloadSuccessfulHashMatch tests the happy path where download succeeds
// with a matching content hash and the MimeType comes from the Content-Type header.
func TestDownloadSuccessfulHashMatch(t *testing.T) {
	t.Parallel()
	content := []byte("exact content to download and verify")
	contentHash := crypto.Sha256(content)
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	mc := &tu.MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, fakeHost, req.URL.String())
		resp := tu.StringResponse(http.StatusOK, string(content))
		resp.Header.Set("Content-Type", "application/octet-stream")
		return resp, nil
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, fakeHost)
	d := newDownloaderWithFacilitator(facilitator, mc)
	result, err := d.Download(context.Background(), uhrpURL)
	require.NoError(t, err)
	assert.Equal(t, content, result.Data)
	assert.Equal(t, "application/octet-stream", result.MimeType)
}

// TestDownloadHTTPErrorStatus tests that a >= 400 HTTP status causes the host
// to be skipped and ultimately returns an error.
func TestDownloadHTTPErrorStatus(t *testing.T) {
	t.Parallel()
	content := []byte("content for 404 test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	mc := &tu.MockHTTPClient{DoFunc: func(*http.Request) (*http.Response, error) {
		return tu.StringResponse(http.StatusNotFound, "not found"), nil
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, fakeHost)
	d := newDownloaderWithFacilitator(facilitator, mc)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnableToDownload)
}

// TestDownloadHashMismatch tests that content with mismatched hash is rejected.
func TestDownloadHashMismatch(t *testing.T) {
	t.Parallel()
	content := []byte("content for hash mismatch test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	mc := &tu.MockHTTPClient{DoFunc: func(*http.Request) (*http.Response, error) {
		// Return different content so the hash will not match.
		return tu.StringResponse(http.StatusOK, "this is different content that won't match the hash"), nil
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, fakeHost)
	d := newDownloaderWithFacilitator(facilitator, mc)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnableToDownload)
}

// TestDownloadAllHostsFailWithLastErr tests the path where all hosts fail and
// lastErr is set (exercises the "unable to download content: %w" branch).
func TestDownloadAllHostsFailWithLastErr(t *testing.T) {
	t.Parallel()
	content := []byte("content for all-hosts-fail test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	const host1 = "https://host1.test/file"
	const host2 = "https://host2.test/file"

	mc := &tu.MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		// Branch on the outgoing host: both fail, exercising the loop over hosts.
		if req.URL.String() == host1 {
			return tu.StringResponse(http.StatusInternalServerError, "server error"), nil
		}
		return tu.StringResponse(http.StatusServiceUnavailable, "also broken"), nil
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, host1, host2)
	d := newDownloaderWithFacilitator(facilitator, mc)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnableToDownload)
	assert.Len(t, mc.Requests, 2) // both hosts were tried
}

// TestDownloadContextCancelled tests that cancelling the context during download
// triggers the request-error path.
func TestDownloadContextCancelled(t *testing.T) {
	t.Parallel()
	content := []byte("content for context cancel test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mc := &tu.MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		// Cancel once the download request is in flight, then report the
		// context error just like a real transport would.
		cancel()
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, fakeHost)
	d := newDownloaderWithFacilitator(facilitator, mc)

	_, err = d.Download(ctx, uhrpURL)
	require.Error(t, err)
}

// TestDownloadBadRequestURL tests a host URL that Resolve rejects, leaving no
// usable hosts (an early return before the client is ever exercised).
func TestDownloadBadRequestURL(t *testing.T) {
	t.Parallel()
	content := []byte("content for bad url test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	futureExpiry := time.Now().Add(24 * time.Hour).Unix()
	// A URL that fails url.Parse, so Resolve discards it and no hosts remain.
	s := buildUhrpPushDropScript(t, contentHash, uhrpURL, "://bad-url-scheme", futureExpiry)
	beef := buildMinimalBeef(t, s)

	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
}

// TestDownloadResolveError tests that a Resolve error propagates.
func TestDownloadResolveError(t *testing.T) {
	t.Parallel()
	content := []byte("content for resolve error test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	facilitator := &mockLookupFacilitator{err: errors.New("network failure")}
	d := newDownloaderWithFacilitator(facilitator)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve UHRP URL")
}

// TestDownloadTruncatedBodyError tests that a short/truncated body fails the hash
// check and is rejected.
func TestDownloadTruncatedBodyError(t *testing.T) {
	t.Parallel()
	content := []byte("content for truncated body test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	mc := &tu.MockHTTPClient{DoFunc: func(*http.Request) (*http.Response, error) {
		// Return fewer bytes than the advertised content, so the hash mismatches.
		return tu.StringResponse(http.StatusOK, "short"), nil
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, fakeHost)
	d := newDownloaderWithFacilitator(facilitator, mc)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), errUnableToDownload)
}

// TestDownloadReadBodyError exercises the body-read error path by returning a
// response whose Body always fails on Read.
func TestDownloadReadBodyError(t *testing.T) {
	t.Parallel()
	content := []byte("content for read body error test")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)
	contentHash := crypto.Sha256(content)

	mc := &tu.MockHTTPClient{DoFunc: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Body:       errReadCloser{},
			Header:     make(http.Header),
		}, nil
	}}

	facilitator := multiHostFacilitator(t, contentHash, uhrpURL, fakeHost)
	d := newDownloaderWithFacilitator(facilitator, mc)
	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error reading response body")
}

// ---- NoPushdropDecoded – nil pushdrop (not a pushdrop script at all) --------

// TestResolveNilPushDrop tests that an output with a non-pushdrop script
// (pd == nil) is skipped. The OP_RETURN script is not a valid pushdrop.
func TestResolveNilPushDrop(t *testing.T) {
	t.Parallel()
	// Build an OP_RETURN script that is not a pushdrop
	s := &script.Script{}
	require.NoError(t, s.AppendOpcodes(script.OpFALSE))
	require.NoError(t, s.AppendOpcodes(script.OpRETURN))
	require.NoError(t, s.AppendPushData([]byte("not pushdrop data")))

	beef := buildMinimalBeef(t, s)

	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		},
	}
	d := newDownloaderWithFacilitator(facilitator)
	hosts, err := d.Resolve(context.Background(), "uhrp://test")
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

// ---- checkAPIError – additional branch (status == "error", empty code/desc) -

func TestCheckAPIErrorErrorStatusEmptyBoth(t *testing.T) {
	t.Parallel()
	err := checkAPIError(StatusError, "", "", "myOp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown-code")
	assert.Contains(t, err.Error(), "no-description")
	assert.Contains(t, err.Error(), "myOp")
}

// TestGetUploadInfoAuthBarrier verifies getUploadInfo surfaces a fetch failure
// from the auth client (socket-free via an injected erroring AuthFetcher).
func TestGetUploadInfoAuthBarrier(t *testing.T) {
	t.Parallel()
	uploader := newMockUploader(t, WithAuthFetcher(erroringFetcher(errors.New("network disabled"))))

	_, err := uploader.getUploadInfo(context.Background(), 100, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get upload info")
}

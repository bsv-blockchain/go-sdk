package storage

import (
	"context"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHostURL = "http://host"
	testUHRPURL = "uhrp://test"
)

// mockLookupFacilitator implements lookup.Facilitator for testing.
type mockLookupFacilitator struct {
	answer *lookup.LookupAnswer
	err    error
}

func (m *mockLookupFacilitator) Lookup(ctx context.Context, url string, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return m.answer, m.err
}

// newDownloaderWithMockFacilitator creates a StorageDownloader with a mock lookup facilitator.
func newDownloaderWithMockFacilitator(facilitator lookup.Facilitator, serviceHostOverride string, hosts []string) *StorageDownloader {
	resolver := &lookup.LookupResolver{
		Facilitator: facilitator,
		HostOverrides: map[string][]string{
			serviceHostOverride: hosts,
		},
		AdditionalHosts: map[string][]string{},
	}
	return &StorageDownloader{resolver: resolver}
}

// TestResolveLookupError tests Resolve when the lookup service returns an error.
func TestResolveLookupError(t *testing.T) {
	facilitator := &mockLookupFacilitator{err: assert.AnError}
	d := newDownloaderWithMockFacilitator(facilitator, "ls_uhrp", []string{testHostURL})

	_, err := d.Resolve(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve UHRP URL")
}

// TestResolveWrongAnswerType tests Resolve when the lookup answer is not output-list.
func TestResolveWrongAnswerType(t *testing.T) {
	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:   lookup.AnswerTypeFreeform,
			Result: "some data",
		},
	}
	d := newDownloaderWithMockFacilitator(facilitator, "ls_uhrp", []string{testHostURL})

	_, err := d.Resolve(context.Background(), testUHRPURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lookup answer must be an output list")
}

// TestResolveEmptyOutputList tests Resolve when lookup returns no outputs.
func TestResolveEmptyOutputList(t *testing.T) {
	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		},
	}
	d := newDownloaderWithMockFacilitator(facilitator, "ls_uhrp", []string{testHostURL})

	hosts, err := d.Resolve(context.Background(), testUHRPURL)
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

// TestResolveInvalidBEEF tests Resolve when lookup output has invalid BEEF.
func TestResolveInvalidBEEF(t *testing.T) {
	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type: lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{
				{Beef: []byte("invalid"), OutputIndex: 0},
			},
		},
	}
	d := newDownloaderWithMockFacilitator(facilitator, "ls_uhrp", []string{testHostURL})

	// Invalid BEEF is silently skipped
	hosts, err := d.Resolve(context.Background(), testUHRPURL)
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

// TestDownloadNoHosts tests Download when Resolve returns no hosts.
func TestDownloadNoHosts(t *testing.T) {
	facilitator := &mockLookupFacilitator{
		answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		},
	}
	d := newDownloaderWithMockFacilitator(facilitator, "ls_uhrp", []string{testHostURL})

	// Generate a valid UHRP URL
	content := []byte("test content for download no hosts")
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	_, err = d.Download(context.Background(), uhrpURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no one currently hosts this file")
}

// TestDownloadInvalidURLRejection tests that Download rejects non-UHRP URLs.
func TestDownloadInvalidURLRejection(t *testing.T) {
	d := NewStorageDownloader(DownloaderConfig{Network: overlay.NetworkMainnet})
	_, err := d.Download(context.Background(), "invalid-url")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid parameter UHRP url")

	_, err = d.Download(context.Background(), "http://example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid parameter UHRP url")
}

// TestDownloadHashVerification verifies that UHRP URL hash extraction works correctly.
func TestDownloadHashVerification(t *testing.T) {
	content := []byte("test content for hash verification")
	contentHash := crypto.Sha256(content)

	// GetURLForFile and hash round-trip
	uhrpURL, err := GetURLForFile(content)
	require.NoError(t, err)

	// Verify that the URL is valid and hash can be extracted
	hash, err := GetHashFromURL(uhrpURL)
	require.NoError(t, err)
	assert.Equal(t, contentHash, hash)
}

// TestNewStorageDownloader tests that NewStorageDownloader initializes correctly.
func TestNewStorageDownloaderTestnet(t *testing.T) {
	d := NewStorageDownloader(DownloaderConfig{Network: overlay.NetworkTestnet})
	assert.NotNil(t, d)
	assert.NotNil(t, d.resolver)
}

// TestResolveContextTimeout tests that Resolve respects context timeout.
func TestResolveContextTimeout(t *testing.T) {
	// Create a facilitator that hangs
	facilitator := &slowDownloadFacilitator{}
	d := newDownloaderWithMockFacilitator(facilitator, "ls_uhrp", []string{testHostURL})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Should fail quickly due to context timeout
	_, err := d.Resolve(ctx, testUHRPURL)
	// Either context timeout or no successful responses error
	require.Error(t, err)
}

// slowDownloadFacilitator simulates a slow lookup.
type slowDownloadFacilitator struct{}

func (s *slowDownloadFacilitator) Lookup(ctx context.Context, url string, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, nil
	}
}

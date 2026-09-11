package storage

// storage_coverage_extra_test.go – covers remaining reachable error branches:
//   - GetHashFromURL: prefix-mismatch path (utils.go)
//   - FindFile: url.Parse failure on a malformed base URL (uploader.go)

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// encodeUHRPPayload builds a Base58Check-style UHRP payload with the supplied
// 2-byte prefix, a fixed 32-byte hash and a 4-byte checksum, then Base58 encodes
// it. The checksum is intentionally arbitrary; callers testing the prefix branch
// never reach checksum validation.
func encodeUHRPPayload(prefix [2]byte) string {
	payload := make([]byte, 0, prefixLength+minHashLength+4)
	payload = append(payload, prefix[0], prefix[1])
	for i := 0; i < minHashLength; i++ {
		payload = append(payload, 0x11)
	}
	payload = append(payload, 0xaa, 0xbb, 0xcc, 0xdd)
	return base58.Encode(payload)
}

func TestGetHashFromURLPrefixMismatch(t *testing.T) {
	t.Parallel()

	// Correct decoded length (38 bytes) but a prefix other than [0xce, 0x00]
	// exercises the ErrInvalidURLPrefix branch before checksum validation.
	url := encodeUHRPPayload([2]byte{0xce, 0x01})

	_, err := GetHashFromURL(url)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidURLPrefix)
}

func TestFindFileInvalidBaseURL(t *testing.T) {
	t.Parallel()

	// A base URL containing a control character is accepted by NewUploader
	// (which only checks for emptiness) but fails url.Parse inside FindFile.
	w := wallet.NewTestWalletForRandomKey(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "http://foo\x7fbar",
		Wallet:     w,
	})
	require.NoError(t, err)

	_, err = uploader.FindFile(context.Background(), "uhrp://example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse find URL")
}

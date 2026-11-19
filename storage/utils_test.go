package storage

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
)

// Test vectors from the TypeScript SDK's StorageUtils.test.ts to test compatibility
const (
	tsTestHashHex = "1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca"
	tsTestURL     = "XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq"
	tsTestFileHex = "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already normalized",
			input:    "abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "uhrp protocol prefix",
			input:    "uhrp://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "uhrp uppercase protocol prefix",
			input:    "UHRP://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "web+uhrp protocol prefix",
			input:    "web+uhrp://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "web+uhrp uppercase protocol prefix",
			input:    "WEB+UHRP://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "new base58check format unchanged",
			input:    tsTestURL,
			expected: tsTestURL,
		},
		{
			name:     "uhrp scheme without slashes",
			input:    "uhrp:abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "uhrp mixed-case scheme without slashes",
			input:    "UhRp:abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "web+uhrp scheme without slashes",
			input:    "web+uhrp:abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "web+uhrp uppercase scheme without slashes",
			input:    "WEB+UHRP:abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "leading slashes without scheme",
			input:    "//abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "only one pair of slashes removed",
			input:    "uhrp:////abcdef12345",
			expected: "//abcdef12345",
		},
		{
			name:     "only one scheme removed",
			input:    "uhrp:uhrp:abcdef12345",
			expected: "uhrp:abcdef12345",
		},
		{
			name:     "scheme only",
			input:    "uhrp:",
			expected: "",
		},
		{
			name:     "other scheme unchanged",
			input:    "https://abcdef12345",
			expected: "https://abcdef12345",
		},
		{
			name:     "scheme not at start unchanged",
			input:    "xuhrp:abcdef12345",
			expected: "xuhrp:abcdef12345",
		},
		{
			name:     "uhrp without colon unchanged",
			input:    "uhrp//abcdef12345",
			expected: "uhrp//abcdef12345",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetURLForHash_MatchesTypeScriptSDK(t *testing.T) {
	// This is the primary cross-SDK compatibility test.
	// The expected URL must match the TypeScript SDK's output exactly.
	testHash, err := hex.DecodeString(tsTestHashHex)
	require.NoError(t, err)

	url, err := GetURLForHash(testHash)
	require.NoError(t, err)
	assert.Equal(t, tsTestURL, url, "GetURLForHash output must match TypeScript SDK test vector")
}

func TestGetURLForHashAndGetHashFromURL(t *testing.T) {
	testHash, err := hex.DecodeString(tsTestHashHex)
	require.NoError(t, err)

	// Generate URL from hash
	url, err := GetURLForHash(testHash)
	require.NoError(t, err)

	// Make sure URL is not empty and matches expected format
	assert.NotEmpty(t, url)
	assert.Equal(t, tsTestURL, url)
	assert.True(t, IsValidURL(url))

	// Extract hash back from URL — round-trip test
	extractedHash, err := GetHashFromURL(url)
	require.NoError(t, err)
	assert.Equal(t, testHash, extractedHash)
}

func TestGetURLForFile(t *testing.T) {
	fileBytes, err := hex.DecodeString(tsTestFileHex)
	require.NoError(t, err)

	// The TS test asserts that getURLForFile(exampleFile) == exampleURL
	url, err := GetURLForFile(fileBytes)
	require.NoError(t, err)
	assert.Equal(t, tsTestURL, url, "GetURLForFile must match TypeScript SDK test vector")
	assert.True(t, IsValidURL(url))
}

func TestGetHashFromURL_WithProtocolPrefix(t *testing.T) {
	testHash, err := hex.DecodeString(tsTestHashHex)
	require.NoError(t, err)

	// Every form the TypeScript SDK's normalizeURL accepts, plus the web+uhrp
	// scheme, must decode to the same hash as the bare Base58Check string.
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "bare", prefix: ""},
		{name: "uhrp with slashes", prefix: "uhrp://"},
		{name: "uppercase uhrp with slashes", prefix: "UHRP://"},
		{name: "uhrp without slashes", prefix: "uhrp:"},
		{name: "uppercase uhrp without slashes", prefix: "UHRP:"},
		{name: "slashes without scheme", prefix: "//"},
		{name: "web+uhrp with slashes", prefix: "web+uhrp://"},
		{name: "uppercase web+uhrp with slashes", prefix: "WEB+UHRP://"},
		{name: "web+uhrp without slashes", prefix: "web+uhrp:"},
		{name: "mixed-case web+uhrp without slashes", prefix: "Web+Uhrp:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractedHash, err := GetHashFromURL(tt.prefix + tsTestURL)
			require.NoError(t, err)
			assert.Equal(t, testHash, extractedHash)
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid URL - new format",
			input:    tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with uhrp:// prefix",
			input:    "uhrp://" + tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with web+uhrp:// prefix",
			input:    "web+uhrp://" + tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with uhrp: prefix",
			input:    "uhrp:" + tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with web+uhrp: prefix",
			input:    "web+uhrp:" + tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with // prefix",
			input:    "//" + tsTestURL,
			expected: true,
		},
		{
			name:     "invalid URL - two pairs of slashes",
			input:    "uhrp:////" + tsTestURL,
			expected: false,
		},
		{
			name:     "invalid URL - repeated scheme",
			input:    "uhrp:uhrp:" + tsTestURL,
			expected: false,
		},
		{
			name:     "invalid URL - other scheme",
			input:    "https://" + tsTestURL,
			expected: false,
		},
		{
			name:     "invalid URL - empty",
			input:    "",
			expected: false,
		},
		{
			name:     "invalid URL - wrong characters",
			input:    "not-a-valid-url",
			expected: false,
		},
		{
			name:     "invalid URL - modified valid URL (bad checksum)",
			input:    tsTestURL[:len(tsTestURL)-1] + "X",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetURLForHash_InvalidInputs(t *testing.T) {
	// Test with invalid hash length
	_, err := GetURLForHash([]byte{1, 2, 3}) // Too short
	require.Error(t, err)
}

func TestGetHashFromURL_InvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "not base58",
			input:   "not-base58",
			wantErr: ErrInvalidBase58,
		},
		{
			name:    "base58 excluded characters",
			input:   "0OIl",
			wantErr: ErrInvalidBase58,
		},
		{
			name:    "two pairs of slashes after scheme",
			input:   "uhrp:////" + tsTestURL,
			wantErr: ErrInvalidBase58,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: ErrInvalidURLLength,
		},
		{
			name:    "scheme only",
			input:   "uhrp:",
			wantErr: ErrInvalidURLLength,
		},
		{
			name:    "payload too short",
			input:   base58.Encode([]byte{0xce, 0x00, 1, 2, 3}),
			wantErr: ErrInvalidURLLength,
		},
		{
			name:    "payload one byte short",
			input:   base58.Encode(append([]byte{0xce, 0x00}, make([]byte, minHashLength+checksumLength-1)...)),
			wantErr: ErrInvalidURLLength,
		},
		{
			name:    "payload one byte long",
			input:   base58.Encode(append([]byte{0xce, 0x00}, make([]byte, minHashLength+checksumLength+1)...)),
			wantErr: ErrInvalidURLLength,
		},
		{
			name:    "bad prefix",
			input:   encodeUHRPPayload([2]byte{0xce, 0x01}),
			wantErr: ErrInvalidURLPrefix,
		},
		{
			name:    "modified valid URL",
			input:   tsTestURL[:len(tsTestURL)-1] + "X",
			wantErr: ErrInvalidChecksum,
		},
		{
			// TS SDK test: known bad checksum URL
			name:    "TS SDK bad checksum vector",
			input:   "XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq",
			wantErr: ErrInvalidChecksum,
		},
	}

	sentinels := []error{ErrInvalidBase58, ErrInvalidURLLength, ErrInvalidURLPrefix, ErrInvalidChecksum}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := GetHashFromURL(tt.input)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, hash)
			assert.False(t, IsValidURL(tt.input))

			// Each failure matches exactly one sentinel, so callers can tell them apart.
			for _, other := range sentinels {
				if !errors.Is(other, tt.wantErr) {
					assert.NotErrorIs(t, err, other)
				}
			}
		})
	}
}

func TestGetHashFromURL_InvalidLengthReportsSize(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		wantMsg string
	}{
		{
			name:    "too short",
			payload: []byte{0xce, 0x00, 1, 2, 3},
			wantMsg: "invalid length: decoded 5 bytes, want 38",
		},
		{
			name:    "too long",
			payload: append([]byte{0xce, 0x00}, make([]byte, 37)...),
			wantMsg: "invalid length: decoded 39 bytes, want 38",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetHashFromURL(base58.Encode(tt.payload))
			require.ErrorIs(t, err, ErrInvalidURLLength)
			require.EqualError(t, err, tt.wantMsg)
		})
	}
}

func TestGetHashFromURL_InvalidBase58WrapsDecodeError(t *testing.T) {
	const input = "0OIl"

	_, decodeErr := base58.Decode(input)
	require.Error(t, decodeErr)

	_, err := GetHashFromURL(input)
	require.ErrorIs(t, err, ErrInvalidBase58)
	require.EqualError(t, err, ErrInvalidBase58.Error()+": "+decodeErr.Error())

	// The decoder's error is wrapped with %w, not only formatted into the message.
	var wrapped interface{ Unwrap() []error }
	require.ErrorAs(t, err, &wrapped, "error should wrap both the sentinel and the decode error")
	require.Len(t, wrapped.Unwrap(), 2)
	require.EqualError(t, wrapped.Unwrap()[1], decodeErr.Error())
}

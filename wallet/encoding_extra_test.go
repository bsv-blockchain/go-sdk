package wallet_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestBytesListUnmarshalJSONError(t *testing.T) {
	t.Parallel()
	var bl wallet.BytesList
	// A JSON string is not a valid []uint8 array.
	err := json.Unmarshal([]byte(`"not-an-array"`), &bl)
	assert.Error(t, err)
}

func TestBytesHexUnmarshalNotAString(t *testing.T) {
	t.Parallel()
	var bh wallet.BytesHex
	err := json.Unmarshal([]byte(`123`), &bh)
	assert.Error(t, err)
}

func TestBytes32Base64UnmarshalErrors(t *testing.T) {
	t.Parallel()

	t.Run("not a string", func(t *testing.T) {
		t.Parallel()
		var b wallet.Bytes32Base64
		err := json.Unmarshal([]byte(`42`), &b)
		assert.Error(t, err)
	})

	t.Run("invalid base64", func(t *testing.T) {
		t.Parallel()
		var b wallet.Bytes32Base64
		err := json.Unmarshal([]byte(`"!!!!"`), &b)
		assert.Error(t, err)
	})
}

func TestBytes33HexUnmarshalErrors(t *testing.T) {
	t.Parallel()

	t.Run("not a string", func(t *testing.T) {
		t.Parallel()
		var b wallet.Bytes33Hex
		err := json.Unmarshal([]byte(`42`), &b)
		assert.Error(t, err)
	})

	t.Run("invalid hex", func(t *testing.T) {
		t.Parallel()
		var b wallet.Bytes33Hex
		err := json.Unmarshal([]byte(`"zz"`), &b)
		assert.Error(t, err)
	})
}

func TestStringBase64ToArrayTooLong(t *testing.T) {
	t.Parallel()
	long := base64.StdEncoding.EncodeToString(make([]byte, 40))
	_, err := wallet.StringBase64(long).ToArray()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "string too long")
}

func TestSignatureUnmarshalJSONErrors(t *testing.T) {
	t.Parallel()

	t.Run("not a byte array", func(t *testing.T) {
		t.Parallel()
		var s wallet.Signature
		err := json.Unmarshal([]byte(`"not-an-array"`), &s)
		assert.Error(t, err)
	})

	t.Run("invalid signature bytes", func(t *testing.T) {
		t.Parallel()
		var s wallet.Signature
		// Valid []uint8 JSON array but not a parseable DER signature.
		err := json.Unmarshal([]byte(`[1,2,3]`), &s)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse signature")
	})
}

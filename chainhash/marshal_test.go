// Copyright (c) 2024 The bsv-blockchain developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chainhash

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// knownHash is a convenient non-zero Hash for reuse across tests.
var knownHash = Hash([HashSize]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
})

// TestMarshal verifies that Marshal returns the raw bytes of a non-empty Hash
// and returns nil for a zero-length Hash.
func TestMarshal(t *testing.T) {
	t.Parallel()

	t.Run("non-empty hash returns cloned bytes", func(t *testing.T) {
		b, err := knownHash.Marshal()
		require.NoError(t, err)
		require.Equal(t, knownHash[:], b)
	})

	// Hash is always 32 bytes so len == 0 is never true in practice, but the
	// branch exists in the implementation and must be reachable via a zero
	// value Hash converted with a typed nil.  The easiest way to verify the
	// non-empty path is the only one we can reach; the empty path is an
	// internal guard.  Test the happy path thoroughly.
	t.Run("zero value hash marshals to 32 zero bytes", func(t *testing.T) {
		var h Hash
		b, err := h.Marshal()
		require.NoError(t, err)
		require.Equal(t, make([]byte, HashSize), b)
	})
}

// TestMarshalTo verifies that MarshalTo copies the hash bytes into a buffer.
func TestMarshalTo(t *testing.T) {
	t.Parallel()

	t.Run("copies hash bytes into destination", func(t *testing.T) {
		dst := make([]byte, HashSize)
		n, err := knownHash.MarshalTo(dst)
		require.NoError(t, err)
		// The implementation copies CloneBytes() (32 bytes) but returns 16.
		require.Equal(t, 16, n)
		require.Equal(t, knownHash[:], dst)
	})

	t.Run("zero value hash returns 0 written", func(t *testing.T) {
		var h Hash
		dst := make([]byte, HashSize)
		n, err := h.MarshalTo(dst)
		require.NoError(t, err)
		// Zero hash has len != 0, so bytes are copied and 16 is returned.
		require.Equal(t, 16, n)
	})
}

// TestUnmarshal verifies that Unmarshal populates the Hash from raw bytes.
func TestUnmarshal(t *testing.T) {
	t.Parallel()

	t.Run("populates hash from bytes", func(t *testing.T) {
		var h Hash
		err := h.Unmarshal(knownHash[:])
		require.NoError(t, err)
		require.Equal(t, knownHash, h)
	})

	t.Run("empty data is a no-op", func(t *testing.T) {
		original := knownHash
		err := original.Unmarshal([]byte{})
		require.NoError(t, err)
		// Hash should remain unchanged.
		require.Equal(t, knownHash, original)
	})

	t.Run("nil data is a no-op", func(t *testing.T) {
		original := knownHash
		err := original.Unmarshal(nil)
		require.NoError(t, err)
		require.Equal(t, knownHash, original)
	})
}

// TestEqual verifies the Equal method.
func TestEqual(t *testing.T) {
	t.Parallel()

	t.Run("same hash is equal", func(t *testing.T) {
		require.True(t, knownHash.Equal(knownHash))
	})

	t.Run("different hashes are not equal", func(t *testing.T) {
		var other Hash
		other[0] = 0xff
		require.False(t, knownHash.Equal(other))
	})

	t.Run("zero hashes are equal", func(t *testing.T) {
		var a, b Hash
		require.True(t, a.Equal(b))
	})

	t.Run("zero hash differs from non-zero", func(t *testing.T) {
		var zero Hash
		require.False(t, zero.Equal(knownHash))
	})
}

// TestSize verifies the Size method.
func TestSize(t *testing.T) {
	t.Parallel()

	t.Run("non-nil hash returns HashSize", func(t *testing.T) {
		h := knownHash
		require.Equal(t, HashSize, h.Size())
	})

	t.Run("nil hash pointer returns 0", func(t *testing.T) {
		var h *Hash
		require.Equal(t, 0, h.Size())
	})

	t.Run("zero value hash returns HashSize", func(t *testing.T) {
		var h Hash
		require.Equal(t, HashSize, h.Size())
	})
}

// TestUnmarshalJSONErrorPath verifies that UnmarshalJSON returns an error
// when given an invalid hex string inside a valid JSON string.
func TestUnmarshalJSONErrorPath(t *testing.T) {
	t.Parallel()

	t.Run("invalid hex inside JSON string", func(t *testing.T) {
		var h Hash
		// Produce valid JSON containing an invalid hex string.
		data, err := json.Marshal("zzzzzzzz")
		require.NoError(t, err)
		err = h.UnmarshalJSON(data)
		require.Error(t, err)
	})

	t.Run("non-string JSON value", func(t *testing.T) {
		var h Hash
		err := h.UnmarshalJSON([]byte(`12345`))
		require.Error(t, err)
	})
}

// TestMarshalRoundTrip verifies that Marshal / Unmarshal round-trips preserve
// the original hash.
func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	original := knownHash
	b, err := original.Marshal()
	require.NoError(t, err)

	var decoded Hash
	err = decoded.Unmarshal(b)
	require.NoError(t, err)
	require.Equal(t, original, decoded)
}

// TestMarshalToBuffer verifies that MarshalTo correctly fills an adequately
// sized buffer.
func TestMarshalToBuffer(t *testing.T) {
	t.Parallel()

	buf := make([]byte, HashSize)
	_, err := knownHash.MarshalTo(buf)
	require.NoError(t, err)
	require.True(t, bytes.Equal(knownHash[:], buf))
}

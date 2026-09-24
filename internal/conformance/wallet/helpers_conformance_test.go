// Package wallet_test runs the pinned ts-stack wallet.brc100 / wallet.brc29 /
// wallet.storage conformance vectors against go-sdk's wallet package.
package wallet_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// defaultRootKeyHex is the root key most vectors use; a handful override it
// via input.root_key.
const defaultRootKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

// vectorInput is the common shape of a wallet.brc100/wallet.brc29 vector's
// "input" object: a root private key, the wire-format method args, and an
// optional originator domain.
type vectorInput struct {
	RootKey    string          `json:"root_key"`
	Args       json.RawMessage `json:"args"`
	Originator string          `json:"originator"`
}

// decodeVectorInput decodes v.Input, filling in the corpus-wide default root
// key when a vector doesn't override it.
func decodeVectorInput(t *testing.T, v conformance.Vector) vectorInput {
	t.Helper()
	var in vectorInput
	v.DecodeInput(t, &in)
	if in.RootKey == "" {
		in.RootKey = defaultRootKeyHex
	}
	if in.Args == nil {
		in.Args = json.RawMessage(`{}`)
	}
	return in
}

func newProtoWallet(t *testing.T, rootKeyHex string) *wallet.ProtoWallet {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(rootKeyHex)
	require.NoError(t, err)
	pw, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
		Type:       wallet.ProtoWalletArgsTypePrivateKey,
		PrivateKey: priv,
	})
	require.NoError(t, err)
	return pw
}

func newCompletedWallet(t *testing.T, rootKeyHex string) *wallet.CompletedProtoWallet {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(rootKeyHex)
	require.NoError(t, err)
	cw, err := wallet.NewCompletedProtoWallet(priv)
	require.NoError(t, err)
	return cw
}

// expectedError is the common shape of a vector's "expected" object when it
// documents a failure. Like the ts-stack reference runner (which only asserts
// `.rejects.toThrow()` for these), we check that the call errors and don't
// match the human-readable "message"/"code" fields, which go-sdk doesn't
// reproduce verbatim.
type expectedError struct {
	Error bool `json:"error"`
}

func vectorExpectsError(t *testing.T, v conformance.Vector) bool {
	t.Helper()
	var e expectedError
	v.DecodeExpected(t, &e)
	return e.Error
}

// normalizeDataField rewrites the named top-level fields of a vector's raw
// args object from a plain UTF-8 string into a byte-value array when needed.
// Several vectors author fields such as "data" as a human-readable string for
// convenience, mirroring the ts-stack reference runner's own `toDataArray`
// helper (conformance/runner/ts/dispatchers/wallet.ts); the actual BRC-100
// wire format for these fields is always a byte array, which is what
// wallet.BytesList decodes. Fields that are already an array, or that are
// absent, are left untouched.
func normalizeDataField(t *testing.T, args json.RawMessage, fields ...string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return args
	}
	changed := false
	for _, field := range fields {
		raw, ok := m[field]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue // not a plain JSON string (already a byte array)
		}
		b := []byte(s)
		nums := make([]int, len(b))
		for i, c := range b {
			nums[i] = int(c)
		}
		encoded, err := json.Marshal(nums)
		require.NoError(t, err)
		m[field] = encoded
		changed = true
	}
	if !changed {
		return args
	}
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

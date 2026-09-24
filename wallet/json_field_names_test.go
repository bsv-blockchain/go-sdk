package wallet_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestWalletJSONFieldNameCasing guards against the same bug class that caused
// a production outage in auth/utils.RequestedCertificateSet (Go emitting
// PascalCase keys like "Certifiers"/"CertificateTypes" instead of the
// BRC-100/BRC-103 wire's lowercase-first camelCase, which a strict TS client
// rejects).
//
// CreateActionOptions, CreateActionResult, SendWithResult, SignableTransaction,
// SignActionOptions and SignActionResult previously had no `json:` struct
// tags at all, so encoding/json fell back to their exported Go field names
// (e.g. "SignAndProcess", "NoSendChange", "SendWithResults") instead of the
// camelCase names ts-stack's Wallet.interfaces.ts documents (e.g.
// "signAndProcess", "noSendChange", "sendWithResults"). These types are on a
// real JSON wire path: wallet/substrates.HTTPWalletJSON round-trips
// CreateActionArgs/Result and SignActionArgs/Result through encoding/json
// directly (see wallet/substrates/http_wallet_json.go), so a PascalCase leak
// here would silently break interop with any TS-side wallet-toolbox HTTP JSON
// client, exactly like the BRC-103 outage this whole conformance effort
// exists to prevent.
//
// This test asserts the exact top-level key set produced by json.Marshal for
// each affected type, so a future regression back to untagged/PascalCase
// fields fails loudly here rather than only tripping the musttag linter (which
// only requires *a* tag, not the *correct* camelCase name).
func TestWalletJSONFieldNameCasing(t *testing.T) {
	trueVal, falseVal := true, false
	hash := chainhash.Hash{0x01}
	outpoint := transaction.Outpoint{Index: 1}

	tests := []struct {
		name     string
		value    any
		wantKeys []string
	}{
		{
			name: "CreateActionOptions",
			value: wallet.CreateActionOptions{
				SignAndProcess:         &trueVal,
				AcceptDelayedBroadcast: &trueVal,
				TrustSelf:              wallet.TrustSelfKnown,
				KnownTxids:             []chainhash.Hash{hash},
				ReturnTXIDOnly:         &falseVal,
				NoSend:                 &falseVal,
				NoSendChange:           []transaction.Outpoint{outpoint},
				SendWith:               []chainhash.Hash{hash},
				RandomizeOutputs:       &trueVal,
			},
			wantKeys: []string{
				"signAndProcess", "acceptDelayedBroadcast", "trustSelf", "knownTxids",
				"returnTXIDOnly", "noSend", "noSendChange", "sendWith", "randomizeOutputs",
			},
		},
		{
			name: "CreateActionResult",
			value: wallet.CreateActionResult{
				Txid:                hash,
				Tx:                  []byte{0x01},
				NoSendChange:        []transaction.Outpoint{outpoint},
				SendWithResults:     []wallet.SendWithResult{{Txid: hash, Status: wallet.ActionResultStatusUnproven}},
				SignableTransaction: &wallet.SignableTransaction{Tx: []byte{0x01}, Reference: []byte{0x02}},
			},
			wantKeys: []string{"txid", "tx", "noSendChange", "sendWithResults", "signableTransaction"},
		},
		{
			name:     "SendWithResult",
			value:    wallet.SendWithResult{Txid: hash, Status: wallet.ActionResultStatusSending},
			wantKeys: []string{"txid", "status"},
		},
		{
			name:     "SignableTransaction",
			value:    wallet.SignableTransaction{Tx: []byte{0x01}, Reference: []byte{0x02}},
			wantKeys: []string{"tx", "reference"},
		},
		{
			name: "SignActionOptions",
			value: wallet.SignActionOptions{
				AcceptDelayedBroadcast: &trueVal,
				ReturnTXIDOnly:         &falseVal,
				NoSend:                 &falseVal,
				SendWith:               []chainhash.Hash{hash},
			},
			wantKeys: []string{"acceptDelayedBroadcast", "returnTXIDOnly", "noSend", "sendWith"},
		},
		{
			name: "SignActionResult",
			value: wallet.SignActionResult{
				Txid:            hash,
				Tx:              []byte{0x01},
				SendWithResults: []wallet.SendWithResult{{Txid: hash, Status: wallet.ActionResultStatusFailed}},
			},
			wantKeys: []string{"txid", "tx", "sendWithResults"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.value)
			require.NoError(t, err)

			var obj map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &obj))

			gotKeys := make([]string, 0, len(obj))
			for k := range obj {
				gotKeys = append(gotKeys, k)
			}
			require.ElementsMatch(t, tc.wantKeys, gotKeys, "json: %s", string(data))
		})
	}
}

// TestWalletJSONLegacyDecodeCompat checks that the six types above still
// decode data written in their old, untagged (PascalCase Go field name)
// shape, so a value stored or sent by a pre-fix go-sdk isn't silently lost by
// the newly-added camelCase tags (see interfaces_legacy_json.go).
func TestWalletJSONLegacyDecodeCompat(t *testing.T) {
	txidHex := "0100000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name       string
		decodeInto func() (any, error)
		check      func(t *testing.T, v any)
	}{
		{
			name: "CreateActionOptions",
			decodeInto: func() (any, error) {
				var v wallet.CreateActionOptions
				err := json.Unmarshal([]byte(`{"SignAndProcess":true,"NoSend":true,"TrustSelf":"known"}`), &v)
				return v, err
			},
			check: func(t *testing.T, v any) {
				o := v.(wallet.CreateActionOptions)
				require.NotNil(t, o.SignAndProcess)
				require.True(t, *o.SignAndProcess)
				require.NotNil(t, o.NoSend)
				require.True(t, *o.NoSend)
				require.Equal(t, wallet.TrustSelfKnown, o.TrustSelf)
			},
		},
		{
			name: "CreateActionResult",
			decodeInto: func() (any, error) {
				var v wallet.CreateActionResult
				err := json.Unmarshal([]byte(`{"Txid":"`+txidHex+`","Tx":[1,2,3]}`), &v)
				return v, err
			},
			check: func(t *testing.T, v any) {
				r := v.(wallet.CreateActionResult)
				require.Equal(t, txidHex, r.Txid.String())
				require.Equal(t, []byte{1, 2, 3}, r.Tx)
			},
		},
		{
			name: "SendWithResult",
			decodeInto: func() (any, error) {
				var v wallet.SendWithResult
				err := json.Unmarshal([]byte(`{"Txid":"`+txidHex+`","Status":"sending"}`), &v)
				return v, err
			},
			check: func(t *testing.T, v any) {
				r := v.(wallet.SendWithResult)
				require.Equal(t, txidHex, r.Txid.String())
				require.Equal(t, wallet.ActionResultStatusSending, r.Status)
			},
		},
		{
			name: "SignableTransaction",
			decodeInto: func() (any, error) {
				var v wallet.SignableTransaction
				err := json.Unmarshal([]byte(`{"Tx":[1,2],"Reference":[3,4]}`), &v)
				return v, err
			},
			check: func(t *testing.T, v any) {
				s := v.(wallet.SignableTransaction)
				require.Equal(t, []byte{1, 2}, s.Tx)
				require.Equal(t, []byte{3, 4}, s.Reference)
			},
		},
		{
			name: "SignActionOptions",
			decodeInto: func() (any, error) {
				var v wallet.SignActionOptions
				err := json.Unmarshal([]byte(`{"NoSend":true,"ReturnTXIDOnly":false}`), &v)
				return v, err
			},
			check: func(t *testing.T, v any) {
				o := v.(wallet.SignActionOptions)
				require.NotNil(t, o.NoSend)
				require.True(t, *o.NoSend)
				require.NotNil(t, o.ReturnTXIDOnly)
				require.False(t, *o.ReturnTXIDOnly)
			},
		},
		{
			name: "SignActionResult",
			decodeInto: func() (any, error) {
				var v wallet.SignActionResult
				err := json.Unmarshal([]byte(`{"Txid":"`+txidHex+`","Tx":[9]}`), &v)
				return v, err
			},
			check: func(t *testing.T, v any) {
				r := v.(wallet.SignActionResult)
				require.Equal(t, txidHex, r.Txid.String())
				require.Equal(t, []byte{9}, r.Tx)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.decodeInto()
			require.NoError(t, err)
			tc.check(t, got)
		})
	}
}

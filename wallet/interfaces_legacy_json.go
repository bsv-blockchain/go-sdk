package wallet

import (
	"encoding/json"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// This file adds backward-compatible JSON decoding for the six
// CreateAction/SignAction-related types below. Before this fix they carried
// no `json:` struct tags at all, so encoding/json fell back to their exported
// Go field names (PascalCase, e.g. "SignAndProcess", "NoSendChange",
// "SendWithResults") wherever they were marshaled — notably by
// wallet/substrates.HTTPWalletJSON, which round-trips them directly through
// json.Marshal/json.Unmarshal on the wire. That is the same bug class as the
// production outage fixed in auth/utils.RequestedCertificateSet: a strict,
// correctly-cased TS peer (ts-stack's Wallet.interfaces.ts) never recognizes
// PascalCase keys.
//
// The struct tags added alongside this file fix the *encoding* side (Go now
// emits the correct camelCase keys). The UnmarshalJSON methods below fix the
// *decoding* side without narrowing it: each still decodes the correct
// camelCase shape first, then also recognizes the old, accidental PascalCase
// shape for any field the modern decode left unset, so data written by an
// older go-sdk version (or a caller that mirrored its old field names) still
// round-trips. A value present under the modern key always wins.

// UnmarshalJSON implements backward-compatible decoding for CreateActionOptions.
func (o *CreateActionOptions) UnmarshalJSON(data []byte) error {
	type alias CreateActionOptions
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*o = CreateActionOptions(a)

	var legacy struct {
		SignAndProcess         *bool                  `json:"SignAndProcess"`
		AcceptDelayedBroadcast *bool                  `json:"AcceptDelayedBroadcast"`
		TrustSelf              TrustSelf              `json:"TrustSelf"`
		KnownTxids             []chainhash.Hash       `json:"KnownTxids"`
		ReturnTXIDOnly         *bool                  `json:"ReturnTXIDOnly"`
		NoSend                 *bool                  `json:"NoSend"`
		NoSendChange           []transaction.Outpoint `json:"NoSendChange"`
		SendWith               []chainhash.Hash       `json:"SendWith"`
		RandomizeOutputs       *bool                  `json:"RandomizeOutputs"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil //nolint:nilerr // best-effort legacy fallback; the modern shape already decoded above
	}
	if o.SignAndProcess == nil {
		o.SignAndProcess = legacy.SignAndProcess
	}
	if o.AcceptDelayedBroadcast == nil {
		o.AcceptDelayedBroadcast = legacy.AcceptDelayedBroadcast
	}
	if o.TrustSelf == "" {
		o.TrustSelf = legacy.TrustSelf
	}
	if len(o.KnownTxids) == 0 {
		o.KnownTxids = legacy.KnownTxids
	}
	if o.ReturnTXIDOnly == nil {
		o.ReturnTXIDOnly = legacy.ReturnTXIDOnly
	}
	if o.NoSend == nil {
		o.NoSend = legacy.NoSend
	}
	if len(o.NoSendChange) == 0 {
		o.NoSendChange = legacy.NoSendChange
	}
	if len(o.SendWith) == 0 {
		o.SendWith = legacy.SendWith
	}
	if o.RandomizeOutputs == nil {
		o.RandomizeOutputs = legacy.RandomizeOutputs
	}
	return nil
}

// UnmarshalJSON implements backward-compatible decoding for CreateActionResult.
func (r *CreateActionResult) UnmarshalJSON(data []byte) error {
	type alias CreateActionResult
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = CreateActionResult(a)

	var legacy struct {
		Txid                chainhash.Hash         `json:"Txid"`
		Tx                  []byte                 `json:"Tx"`
		NoSendChange        []transaction.Outpoint `json:"NoSendChange"`
		SendWithResults     []SendWithResult       `json:"SendWithResults"`
		SignableTransaction *SignableTransaction   `json:"SignableTransaction"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil //nolint:nilerr // best-effort legacy fallback; the modern shape already decoded above
	}
	if r.Txid == (chainhash.Hash{}) {
		r.Txid = legacy.Txid
	}
	if len(r.Tx) == 0 {
		r.Tx = legacy.Tx
	}
	if len(r.NoSendChange) == 0 {
		r.NoSendChange = legacy.NoSendChange
	}
	if len(r.SendWithResults) == 0 {
		r.SendWithResults = legacy.SendWithResults
	}
	if r.SignableTransaction == nil {
		r.SignableTransaction = legacy.SignableTransaction
	}
	return nil
}

// UnmarshalJSON implements backward-compatible decoding for SendWithResult.
func (r *SendWithResult) UnmarshalJSON(data []byte) error {
	type alias SendWithResult
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = SendWithResult(a)

	var legacy struct {
		Txid   chainhash.Hash     `json:"Txid"`
		Status ActionResultStatus `json:"Status"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil //nolint:nilerr // best-effort legacy fallback; the modern shape already decoded above
	}
	if r.Txid == (chainhash.Hash{}) {
		r.Txid = legacy.Txid
	}
	if r.Status == "" {
		r.Status = legacy.Status
	}
	return nil
}

// UnmarshalJSON implements backward-compatible decoding for SignableTransaction.
func (s *SignableTransaction) UnmarshalJSON(data []byte) error {
	type alias SignableTransaction
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*s = SignableTransaction(a)

	var legacy struct {
		Tx        []byte `json:"Tx"`
		Reference []byte `json:"Reference"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil //nolint:nilerr // best-effort legacy fallback; the modern shape already decoded above
	}
	if len(s.Tx) == 0 {
		s.Tx = legacy.Tx
	}
	if len(s.Reference) == 0 {
		s.Reference = legacy.Reference
	}
	return nil
}

// UnmarshalJSON implements backward-compatible decoding for SignActionOptions.
func (o *SignActionOptions) UnmarshalJSON(data []byte) error {
	type alias SignActionOptions
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*o = SignActionOptions(a)

	var legacy struct {
		AcceptDelayedBroadcast *bool            `json:"AcceptDelayedBroadcast"`
		ReturnTXIDOnly         *bool            `json:"ReturnTXIDOnly"`
		NoSend                 *bool            `json:"NoSend"`
		SendWith               []chainhash.Hash `json:"SendWith"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil //nolint:nilerr // best-effort legacy fallback; the modern shape already decoded above
	}
	if o.AcceptDelayedBroadcast == nil {
		o.AcceptDelayedBroadcast = legacy.AcceptDelayedBroadcast
	}
	if o.ReturnTXIDOnly == nil {
		o.ReturnTXIDOnly = legacy.ReturnTXIDOnly
	}
	if o.NoSend == nil {
		o.NoSend = legacy.NoSend
	}
	if len(o.SendWith) == 0 {
		o.SendWith = legacy.SendWith
	}
	return nil
}

// UnmarshalJSON implements backward-compatible decoding for SignActionResult.
func (r *SignActionResult) UnmarshalJSON(data []byte) error {
	type alias SignActionResult
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = SignActionResult(a)

	var legacy struct {
		Txid            chainhash.Hash   `json:"Txid"`
		Tx              []byte           `json:"Tx"`
		SendWithResults []SendWithResult `json:"SendWithResults"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil //nolint:nilerr // best-effort legacy fallback; the modern shape already decoded above
	}
	if r.Txid == (chainhash.Hash{}) {
		r.Txid = legacy.Txid
	}
	if len(r.Tx) == 0 {
		r.Tx = legacy.Tx
	}
	if len(r.SendWithResults) == 0 {
		r.SendWithResults = legacy.SendWithResults
	}
	return nil
}

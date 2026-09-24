package transaction

import (
	"context"
	"encoding/json"
)

type BroadcastSuccess struct {
	Txid    string `json:"txid"`
	Message string `json:"message"`
}

//nolint:errname // BroadcastFailure is established public API used across the SDK; renaming to BroadcastError would be a breaking change
type BroadcastFailure struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	// CompetingTxs lists the competing transaction ids ARC reports alongside
	// a DOUBLE_SPEND_ATTEMPTED txStatus. On the wire it is nested under
	// "more.competingTxs" (see broadcastFailureWire below) to mirror ts-sdk's
	// BroadcastFailure.more.competingTxs shape; this field stays top-level in
	// the Go struct for ergonomic access. It is empty for every other failure.
	CompetingTxs []string `json:"-"`
}

func (e *BroadcastFailure) Error() string {
	return e.Description
}

// broadcastFailureMore mirrors ts-sdk's BroadcastFailure.more object, which
// today carries only competingTxs.
type broadcastFailureMore struct {
	CompetingTxs []string `json:"competingTxs,omitempty"`
}

// broadcastFailureWire is the JSON shape ts-sdk actually emits for a
// BroadcastFailure: competingTxs nested under "more", not top-level. Kept
// separate from BroadcastFailure so the Go API can keep CompetingTxs as a
// plain, top-level field.
type broadcastFailureWire struct {
	Code        string                `json:"code"`
	Description string                `json:"description"`
	More        *broadcastFailureMore `json:"more,omitempty"`
}

// MarshalJSON emits the ts-sdk wire shape: competingTxs nested under "more".
func (e *BroadcastFailure) MarshalJSON() ([]byte, error) {
	wire := broadcastFailureWire{Code: e.Code, Description: e.Description}
	if len(e.CompetingTxs) > 0 {
		wire.More = &broadcastFailureMore{CompetingTxs: e.CompetingTxs}
	}
	return json.Marshal(wire)
}

// UnmarshalJSON reads the ts-sdk wire shape, populating CompetingTxs from
// "more.competingTxs".
func (e *BroadcastFailure) UnmarshalJSON(data []byte) error {
	var wire broadcastFailureWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Code = wire.Code
	e.Description = wire.Description
	e.CompetingTxs = nil
	if wire.More != nil {
		e.CompetingTxs = wire.More.CompetingTxs
	}
	return nil
}

type Broadcaster interface {
	Broadcast(tx *Transaction) (*BroadcastSuccess, *BroadcastFailure)
	BroadcastCtx(ctx context.Context, tx *Transaction) (*BroadcastSuccess, *BroadcastFailure)
}

func (t *Transaction) Broadcast(b Broadcaster) (*BroadcastSuccess, *BroadcastFailure) {
	return b.Broadcast(t)
}

func (t *Transaction) BroadcastCtx(ctx context.Context, b Broadcaster) (*BroadcastSuccess, *BroadcastFailure) {
	return b.BroadcastCtx(ctx, t)
}

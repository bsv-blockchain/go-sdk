package transaction

import "context"

type BroadcastSuccess struct {
	Txid    string `json:"txid"`
	Message string `json:"message"`
}

//nolint:errname // BroadcastFailure is established public API used across the SDK; renaming to BroadcastError would be a breaking change
type BroadcastFailure struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

func (e *BroadcastFailure) Error() string {
	return e.Description
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

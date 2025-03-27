package lookup

import (
	"context"
	"time"
)

type Facilitator interface {
	Lookup(ctx context.Context, url string, question LookupQuestion, timeout time.Duration) (LookupAnswer, error)
}

package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/util"
)

// Facilitator defines the interface for overlay lookup facilitators that can execute lookup queries
type Facilitator interface {
	Lookup(ctx context.Context, url string, question *LookupQuestion) (*LookupAnswer, error)
}

// HTTPSOverlayLookupFacilitator implements the Facilitator interface using HTTPS requests
type HTTPSOverlayLookupFacilitator struct {
	Client util.HTTPClient
}

// Lookup executes a lookup question against the specified URL and returns the answer
func (f *HTTPSOverlayLookupFacilitator) Lookup(ctx context.Context, url string, question *LookupQuestion) (*LookupAnswer, error) {
	if q, err := json.Marshal(question); err != nil {
		return nil, err
	} else {
		req, err := http.NewRequestWithContext(ctx, "POST", url+"/lookup", bytes.NewBuffer(q))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.Client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, &util.HTTPError{
				StatusCode: resp.StatusCode,
				Err:        errors.New("lookup failed"),
			}
		}
		answer := &LookupAnswer{}
		if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
			return nil, err
		}
		return answer, nil

	}
}

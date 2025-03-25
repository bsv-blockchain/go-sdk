package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bsv-blockchain/go-sdk/util"
)

type Facilitator interface {
	Lookup(url string, question *LookupQuestion, timeout time.Duration) (*LookupAnswer, error)
}

type HTTPSOverlayLookupFacilitator struct {
	Client util.HTTPClient
}

func (f *HTTPSOverlayLookupFacilitator) Lookup(url string, question *LookupQuestion, timeout time.Duration) (*LookupAnswer, error) {
	timeoutContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if q, err := json.Marshal(question); err != nil {
		return nil, err
	} else {
		req, err := http.NewRequestWithContext(timeoutContext, "POST", url+"/lookup", bytes.NewBuffer(q))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.Client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
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

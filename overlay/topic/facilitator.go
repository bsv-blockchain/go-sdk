package topic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/util"
)

const MAX_SHIP_QUERY_TIMEOUT = time.Second

type Facilitator interface {
	Send(url string, taggedBEEF *overlay.TaggedBEEF) (*overlay.Steak, error)
}

type HTTPSOverlayBroadcastFacilitator struct {
	Client util.HTTPClient
}

func (f *HTTPSOverlayBroadcastFacilitator) Send(url string, taggedBEEF *overlay.TaggedBEEF) (*overlay.Steak, error) {
	timeoutContext, cancel := context.WithTimeout(context.Background(), MAX_SHIP_QUERY_TIMEOUT)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutContext, "POST", url+"/submit", bytes.NewBuffer(taggedBEEF.Beef))
	if err != nil {
		return nil, err
	}
	if topics, err := json.Marshal(taggedBEEF.Topics); err != nil {
		return nil, err
	} else {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Topics", string(topics))
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
		steak := &overlay.Steak{}
		if err := json.NewDecoder(resp.Body).Decode(&steak); err != nil {
			return nil, err
		}
		return steak, nil
	}
}

package util

import (
	"fmt"
	"net/http"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type HTTPError struct {
	StatusCode int
	Err        error
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d-%s", e.StatusCode, e.Err.Error())
}

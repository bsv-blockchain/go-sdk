package payload

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-sdk/util"
)

var methodsThatTypicallyHaveBody = []string{"POST", "PUT", "PATCH", "DELETE"}

// FromHTTPRequest serializes data from an HTTP request into an AuthMessage payload.
func FromHTTPRequest(requestID []byte, req *http.Request) ([]byte, error) {
	writer := util.NewWriter()
	if len(requestID) != 32 {
		return nil, errors.New("request ID must be 32 bytes long")
	}

	writer.WriteBytes(requestID)
	writer.WriteString(req.Method)
	writer.WriteOptionalString(req.URL.Path)

	searchParams := req.URL.RawQuery
	if searchParams != "" {
		// auth client is using a query string with leading "?", so the middleware needs to include that character also.
		searchParams = "?" + searchParams
	}
	writer.WriteOptionalString(searchParams)

	includedHeaders, err := extractIncludedHeaders(req)
	if err != nil {
		return nil, err
	}

	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i].Name < includedHeaders[j].Name
	})

	writer.WriteVarInt(uint64(len(includedHeaders)))

	for _, header := range includedHeaders {
		writer.WriteString(header.Name)
		writer.WriteString(header.Value)
	}

	body, err := extractBody(req)
	if err != nil {
		return nil, err
	}
	// Write body
	writer.WriteIntBytesOptional(body)

	return writer.Buf, nil
}

type DeserializationOptions struct {
	BaseURL string
}

// WithBaseURL sets given base URL for deserialization options.
func WithBaseURL(baseURL string) func(*DeserializationOptions) {
	return func(options *DeserializationOptions) {
		options.BaseURL = baseURL
	}
}

// ToHTTPRequest parsing a serialized auth.AuthMessage payload into an HTTP request, returning the request ID, the HTTP request.
// You can use WithBaseURL to ensure that the created http.Request URL will start with provided base URL
func ToHTTPRequest(payload []byte, opts ...func(*DeserializationOptions)) (requestID []byte, req *http.Request, err error) {
	options := &DeserializationOptions{}
	for _, opt := range opts {
		opt(options)
	}

	req = &http.Request{
		Header: make(http.Header),
	}
	reader := util.NewReader(payload)

	requestID, err = reader.ReadBytes(32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request ID from payload: %w", err)
	}

	req.Method, err = reader.ReadString()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read method from payload: %w", err)
	}

	reqPath, err := reader.ReadOptionalString()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read path from payload: %w", err)
	}

	searchParams, err := reader.ReadOptionalString()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read search params from payload: %w", err)
	}

	req.URL, err = url.Parse(options.BaseURL + reqPath + searchParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create url from payload: %w", err)
	}

	numHeaders, err := reader.ReadVarInt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read number of headers from payload: %w", err)
	}

	for i := 0; i < int(numHeaders); i++ {
		headerName, err := reader.ReadString()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read header[%d] name from payload: %w", i, err)
		}

		headerValue, err := reader.ReadString()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read header[%d] %s value from payload: %w", i, headerName, err)
		}

		req.Header.Set(headerName, headerValue)
	}

	body, err := reader.ReadOptionalBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read body from payload: %w", err)
	}

	if len(body) != 0 && string(body) != "{}" {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	return requestID, req, nil
}

func extractIncludedHeaders(req *http.Request) ([]includedHeader, error) {
	includedHeaders := make([]includedHeader, 0)
	for name, values := range req.Header {
		headerKey := strings.ToLower(name)
		if strings.HasPrefix(headerKey, "x-bsv-") || headerKey == "authorization" {
			if strings.HasPrefix(headerKey, "x-bsv-auth") {
				return nil, errors.New("request with x-bsv-auth cannot be serialized to payload")
			}
			if len(values) > 1 {
				return nil, fmt.Errorf("multiple values for header %s is not allowed", headerKey)
			}
			includedHeaders = append(includedHeaders,
				includedHeader{
					Name:  headerKey,
					Value: values[0],
				},
			)
		} else if headerKey == "content-type" {
			if len(values) > 1 {
				return nil, fmt.Errorf("multiple values for header %s is not allowed", headerKey)
			}
			contentType := strings.SplitN(values[0], ";", 2)[0]
			includedHeaders = append(includedHeaders, includedHeader{
				Name:  headerKey,
				Value: contentType,
			})
		} else {
			return nil, fmt.Errorf("header %s is not supported by authrite", headerKey)
		}
	}

	return includedHeaders, nil
}

func extractBody(req *http.Request) ([]byte, error) {
	var body []byte

	// Handle nil body case
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// If method typically carries a body and body is empty, default it
	if len(body) == 0 && slices.Contains(methodsThatTypicallyHaveBody, strings.ToUpper(req.Method)) {
		// Check if content-type is application/json
		contentType := req.Header.Get("content-type")
		if strings.Contains(contentType, "application/json") {
			body = []byte("{}")
		} else {
			// If empty and not JSON, use empty string
			body = []byte("")
		}
	}

	return body, nil
}

type includedHeader struct {
	Name  string
	Value string
}

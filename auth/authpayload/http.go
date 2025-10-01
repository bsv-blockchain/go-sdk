package authpayload

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
)

const (
	contentTypeHeader = "content-type"
	contentTypeJSON   = "application/json"
)

var (
	emptyJSONObject              = []byte("{}")
	methodsThatTypicallyHaveBody = []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
)

// FromHTTPRequest serializes data from an HTTP request into an AuthMessage payload.
func FromHTTPRequest(requestID []byte, req *http.Request) ([]byte, error) {
	if len(requestID) != brc104.RequestIDLength {
		return nil, errors.New("request ID must be 32 bytes long")
	}

	writer := util.NewWriter()

	writer.WriteBytes(requestID)

	writer.WriteString(req.Method)

	path := req.URL.Path
	if path == "" {
		// NOTICE: this fallback to "/" for an empty path is needed because server in Go will pass URL to handler with "/" instead of empty string,
		// 	therefore, middleware will verify signature based on wrong assumption about the path, and signature will be considered invalid.
		//  What's more, in JS (both node and browser) new URL(...) will also return "/" for an empty path, so it's aligned with that behavior.
		path = "/"
	}
	writer.WriteString(path)

	searchParams := req.URL.RawQuery
	if searchParams != "" {
		// NOTICE: JS version of auth client is using a query string from new URL(...) which contains leading "?",
		//  but in go URL RawQuery is not prefixed with "?",
		//  therefore, we need to add it here to be aligned with the JS behavior.
		searchParams = "?" + searchParams
	}
	writer.WriteOptionalString(searchParams)

	includedHeaders, err := extractHeadersToInclude(req.Header, IsHeaderToIncludeInRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to build payload from request headers: %w", err)
	}

	writer.WriteVarInt(uint64(len(includedHeaders)))

	for _, header := range includedHeaders {
		writer.WriteString(header.Name)
		writer.WriteString(header.Value)
	}

	body, err := readRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body to prepare payload: %w", err)
	}

	// Write body
	writer.WriteIntBytesOptional(body)

	return writer.Buf, nil
}

// HttpRequestDeserializationOptions contains options for deserializing auth message payload into HTTP request.
type HttpRequestDeserializationOptions struct {
	BaseURL string
}

// WithBaseURL sets given base URL for deserialization options.
func WithBaseURL(baseURL string) func(*HttpRequestDeserializationOptions) {
	return func(options *HttpRequestDeserializationOptions) {
		options.BaseURL = baseURL
	}
}

// ToHTTPRequest parsing a serialized auth.AuthMessage payload into an HTTP request, returning the request ID, the HTTP request.
// You can use WithBaseURL to ensure that the created http.Request URL will start with provided base URL
func ToHTTPRequest(payload []byte, opts ...func(*HttpRequestDeserializationOptions)) (requestID []byte, req *http.Request, err error) {
	options := &HttpRequestDeserializationOptions{}
	for _, opt := range opts {
		opt(options)
	}

	req = &http.Request{
		Header: make(http.Header),
	}
	reader := util.NewReader(payload)

	requestID, err = reader.ReadBytes(brc104.RequestIDLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request ID from payload to create http request: %w", err)
	}

	req.Method, err = reader.ReadString()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read method from payload to create http request: %w", err)
	}

	reqPath, err := reader.ReadOptionalString()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read path from payload to create http request: %w", err)
	}

	searchParams, err := reader.ReadOptionalString()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read search params from payload to create http request: %w", err)
	}

	req.URL, err = url.Parse(options.BaseURL + reqPath + searchParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create url from payload to create http request: %w", err)
	}

	numHeaders, err := reader.ReadVarInt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read number of headers from payload to create http request: %w", err)
	}

	for i := range numHeaders {
		headerName, err := reader.ReadString()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read header[%d] name from payload to create http request: %w", i, err)
		}

		headerValue, err := reader.ReadString()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read header[%d] %s value from payload to create http request: %w", i, headerName, err)
		}

		req.Header.Set(headerName, headerValue)
	}

	body, err := reader.ReadOptionalBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read body from payload to create http request: %w", err)
	}

	if len(body) != 0 && !bytes.Equal(body, emptyJSONObject) {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	return requestID, req, nil
}

// FromHTTPResponse serializes data from an HTTP response into an AuthMessage payload.
func FromHTTPResponse(requestID []byte, res *http.Response) ([]byte, error) {
	body, err := readResponseBody(res)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body to prepare payload: %w", err)
	}

	return FromResponse(requestID, SimplifiedHttpResponse{
		StatusCode: res.StatusCode,
		Header:     res.Header,
		Body:       body,
	})
}

// HttpResponseDeserializationOptions contains options for deserializing auth message payload into HTTP response.
type HttpResponseDeserializationOptions struct {
	senderPublicKey *ec.PublicKey
}

// WithSenderPublicKey sets the given sender public key in header of deserialized response.
func WithSenderPublicKey(senderPublicKey *ec.PublicKey) func(*HttpResponseDeserializationOptions) {
	return func(options *HttpResponseDeserializationOptions) {
		options.senderPublicKey = senderPublicKey
	}
}

// ToHTTPResponse converts a serialized payload into an http.Response, applying optional deserialization options.
// You can use WithSenderPublicKey to ensure that the created http.Response will have the given sender public key in header.
func ToHTTPResponse(payload []byte, opts ...func(*HttpResponseDeserializationOptions)) (requestID []byte, res *http.Response, err error) {
	requestID, simpleRes, err := ToSimplifiedHttpResponse(payload, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve http.Response from payload: %w", err)
	}

	var body io.ReadCloser
	if len(simpleRes.Body) > 0 {
		body = io.NopCloser(bytes.NewReader(simpleRes.Body))
	} else {
		body = http.NoBody
	}

	res = &http.Response{
		StatusCode: simpleRes.StatusCode,
		Status:     http.StatusText(simpleRes.StatusCode),
		Header:     simpleRes.Header,
		Body:       body,
	}
	if res.Status == "" {
		res.Status = strconv.Itoa(res.StatusCode)
	}
	return requestID, res, nil
}

// SimplifiedHttpResponse represents a minimal HTTP response containing status code, headers, and body data.
type SimplifiedHttpResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// FromResponse serializes data from a SimplifiedHttpResponse into an AuthMessage payload.
func FromResponse(requestID []byte, res SimplifiedHttpResponse) ([]byte, error) {
	if len(requestID) != brc104.RequestIDLength {
		return nil, fmt.Errorf("invalid request ID for response payload, must be %d bytes long, got %d", brc104.RequestIDLength, len(requestID))
	}

	writer := util.NewWriter()
	writer.WriteBytes(requestID)
	writer.WriteVarInt(uint64(res.StatusCode))

	includedHeaders, err := extractHeadersToInclude(res.Header, IsHeaderToIncludeInResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to build payload from response headers: %w", err)
	}

	writer.WriteVarInt(uint64(len(includedHeaders)))

	for _, header := range includedHeaders {
		writer.WriteString(header.Name)
		writer.WriteString(header.Value)
	}

	writer.WriteIntBytesOptional(res.Body)

	return writer.Buf, nil
}

// ToSimplifiedHttpResponse converts a serialized payload into a SimplifiedHttpResponse, applying optional deserialization options.
// You can use WithSenderPublicKey to ensure that the created http.Response will have the given sender public key in header.
func ToSimplifiedHttpResponse(payload []byte, opts ...func(*HttpResponseDeserializationOptions)) (requestID []byte, res SimplifiedHttpResponse, err error) {
	options := &HttpResponseDeserializationOptions{}
	for _, opt := range opts {
		opt(options)
	}

	responseReader := util.NewReader(payload)

	requestID, err = responseReader.ReadBytes(32)
	if err != nil {
		return nil, res, fmt.Errorf("failed to read response to create http response: %w", err)
	}

	statusCode, err := responseReader.ReadVarInt32()
	if err != nil {
		return nil, res, fmt.Errorf("failed to read status code to create http response: %w", err)
	}

	nHeaders, err := responseReader.ReadVarInt32()
	if err != nil {
		return nil, res, fmt.Errorf("failed to read header count to create http response: %w", err)
	}
	responseHeaders := make(http.Header, nHeaders)
	for i := range nHeaders {
		headerKey, err := responseReader.ReadString()
		if err != nil {
			return nil, res, fmt.Errorf("failed to read header[%d] key to create http response: %w", i, err)
		}

		headerValue, err := responseReader.ReadString()
		if err != nil {
			return nil, res, fmt.Errorf("failed to read header[%d] value to create http response: %w", i, err)
		}

		responseHeaders.Add(headerKey, headerValue)
	}

	if options.senderPublicKey != nil {
		responseHeaders.Set(brc104.HeaderIdentityKey, options.senderPublicKey.ToDERHex())
	}

	responseBody, err := responseReader.ReadOptionalBytes()
	if err != nil {
		return nil, res, fmt.Errorf("failed to read body: %w", err)
	}

	res.StatusCode = int(statusCode)
	res.Header = responseHeaders
	res.Body = responseBody

	return requestID, res, nil
}

// IsHeaderToIncludeInRequest returns true if the header of given name should be included in the request.
func IsHeaderToIncludeInRequest(headerName string) bool {
	headerName = strings.ToLower(headerName)
	return isBSVHeaderToInclude(headerName) || slices.Contains(brc104.NonXBSVIncludedRequestHeaders, headerName)
}

// IsHeaderToIncludeInResponse returns true if the header of given name should be included in the response.
func IsHeaderToIncludeInResponse(headerName string) bool {
	headerName = strings.ToLower(headerName)
	return isBSVHeaderToInclude(headerName) || slices.Contains(brc104.NonXBSVIncludedResponseHeaders, headerName)
}

func isBSVHeaderToInclude(headerName string) bool {
	return !strings.HasPrefix(headerName, brc104.AuthHeaderPrefix) && strings.HasPrefix(headerName, brc104.XBSVHeaderPrefix)
}

func extractHeadersToInclude(headers http.Header, headersFilter func(headerName string) bool) ([]includedHeader, error) {
	var includedHeaders []includedHeader
	for name, values := range headers {
		headerKey := strings.ToLower(name)
		if !headersFilter(headerKey) {
			continue
		}

		if len(values) > 1 {
			return nil, fmt.Errorf("multiple values for header %s is not supported yet", headerKey)
		}

		value := values[0]
		if headerKey == contentTypeHeader {
			value = strings.SplitN(value, ";", 2)[0]
		}

		includedHeaders = append(includedHeaders,
			includedHeader{
				Name:  headerKey,
				Value: value,
			},
		)
	}

	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i].Name < includedHeaders[j].Name
	})

	return includedHeaders, nil
}

func readRequestBody(req *http.Request) ([]byte, error) {
	var body []byte

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
		contentType := req.Header.Get(contentTypeHeader)
		if strings.Contains(contentType, contentTypeJSON) {
			body = emptyJSONObject[:]
		}
	}

	return body, nil
}

func readResponseBody(res *http.Response) ([]byte, error) {
	var body []byte

	if res.Body != nil {
		var err error
		body, err = io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		res.Body = io.NopCloser(bytes.NewReader(body))
	}

	return body, nil
}

type includedHeader struct {
	Name  string
	Value string
}

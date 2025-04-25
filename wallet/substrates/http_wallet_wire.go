package substrates

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
)

// HTTPWalletWire implements WalletWire interface for HTTP transport
type HTTPWalletWire struct {
	baseURL    string
	httpClient *http.Client
	originator string
}

// NewHTTPWalletWire creates a new HTTPWalletWire instance
func NewHTTPWalletWire(originator string, baseURL string, httpClient *http.Client) *HTTPWalletWire {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "http://localhost:3301" // Default port matches TS version
	}
	return &HTTPWalletWire{
		baseURL:    baseURL,
		httpClient: httpClient,
		originator: originator,
	}
}

// TransmitToWallet sends a binary message to the wallet and returns the response
func (h *HTTPWalletWire) TransmitToWallet(message []byte) ([]byte, error) {
	// Create reader for the message
	reader := bytes.NewReader(message)

	// Read call code (1 byte)
	var callCode uint8
	if err := binary.Read(reader, binary.BigEndian, &callCode); err != nil {
		return nil, fmt.Errorf("failed to read call code: %w", err)
	}

	// Map call code to endpoint name
	callName, ok := callCodeToName[Call(callCode)]
	if !ok {
		return nil, fmt.Errorf("invalid call code")
	}

	// Read originator length (1 byte)
	var originatorLen uint8
	if err := binary.Read(reader, binary.BigEndian, &originatorLen); err != nil {
		return nil, fmt.Errorf("failed to read originator length: %w", err)
	}

	// Read originator if present
	var originator string
	if originatorLen > 0 {
		originatorBytes := make([]byte, originatorLen)
		if n, err := reader.Read(originatorBytes); err != nil {
			return nil, fmt.Errorf("failed to read originator: %w", err)
		} else if n != int(originatorLen) {
			return nil, fmt.Errorf("invalid originator length, expected %d, got %d", originatorLen, n)
		}
		originator = string(originatorBytes)
	}

	// Remaining bytes are the payload
	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", h.baseURL+"/"+callName, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if originator != "" {
		req.Header.Set("Origin", originator)
	}

	// Send request
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %s", resp.Status)
	}

	// Read and return response
	return io.ReadAll(resp.Body)
}

// callCodeToName maps Call codes to endpoint names
var callCodeToName = map[Call]string{
	CallCreateAction:                 "createAction",
	CallSignAction:                   "signAction",
	CallAbortAction:                  "abortAction",
	CallListActions:                  "listActions",
	CallInternalizeAction:            "internalizeAction",
	CallListOutputs:                  "listOutputs",
	CallRelinquishOutput:             "relinquishOutput",
	CallGetPublicKey:                 "getPublicKey",
	CallRevealCounterpartyKeyLinkage: "revealCounterpartyKeyLinkage",
	CallRevealSpecificKeyLinkage:     "revealSpecificKeyLinkage",
	CallEncrypt:                      "encrypt",
	CallDecrypt:                      "decrypt",
	CallCreateHmac:                   "createHmac",
	CallVerifyHmac:                   "verifyHmac",
	CallCreateSignature:              "createSignature",
	CallVerifySignature:              "verifySignature",
	CallAcquireCertificate:           "acquireCertificate",
	CallListCertificates:             "listCertificates",
	CallProveCertificate:             "proveCertificate",
	CallRelinquishCertificate:        "relinquishCertificate",
	CallDiscoverByIdentityKey:        "discoverByIdentityKey",
	CallDiscoverByAttributes:         "discoverByAttributes",
	CallIsAuthenticated:              "isAuthenticated",
	CallWaitForAuthentication:        "waitForAuthentication",
	CallGetHeight:                    "getHeight",
	CallGetHeaderForHeight:           "getHeaderForHeight",
	CallGetNetwork:                   "getNetwork",
	CallGetVersion:                   "getVersion",
}

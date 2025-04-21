package substrates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// HTTPWalletJSON implements wallet.Interface for HTTP transport using JSON
type HTTPWalletJSON struct {
	baseURL    string
	httpClient *http.Client
	originator string
}

// NewHTTPWalletJSON creates a new HTTPWalletJSON instance
func NewHTTPWalletJSON(originator string, baseURL string, httpClient *http.Client) *HTTPWalletJSON {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "http://localhost:3321" // Default port matches TS version
	}
	return &HTTPWalletJSON{
		baseURL:    baseURL,
		httpClient: httpClient,
		originator: originator,
	}
}

// api makes an HTTP POST request to the wallet API
func (h *HTTPWalletJSON) api(call string, args interface{}) ([]byte, error) {
	// Marshal request body
	reqBody, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", h.baseURL+"/"+call, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if h.originator != "" {
		req.Header.Set("Originator", h.originator)
	}

	// Send request
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read and return response
	return io.ReadAll(resp.Body)
}

// CreateAction creates a new transaction
func (h *HTTPWalletJSON) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	data, err := h.api("createAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.CreateActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// SignAction signs a previously created transaction
func (h *HTTPWalletJSON) SignAction(args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	data, err := h.api("signAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.SignActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// AbortAction aborts a transaction in progress
func (h *HTTPWalletJSON) AbortAction(args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	data, err := h.api("abortAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.AbortActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ListActions lists wallet transactions matching filters
func (h *HTTPWalletJSON) ListActions(args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	data, err := h.api("listActions", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ListActionsResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// InternalizeAction imports an external transaction into the wallet
func (h *HTTPWalletJSON) InternalizeAction(args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	data, err := h.api("internalizeAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.InternalizeActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ListOutputs lists wallet outputs matching filters
func (h *HTTPWalletJSON) ListOutputs(args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	data, err := h.api("listOutputs", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ListOutputsResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RelinquishOutput removes an output from basket tracking
func (h *HTTPWalletJSON) RelinquishOutput(args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	data, err := h.api("relinquishOutput", args)
	if err != nil {
		return nil, err
	}
	var result wallet.RelinquishOutputResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetPublicKey retrieves a derived or identity public key
func (h *HTTPWalletJSON) GetPublicKey(args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	data, err := h.api("getPublicKey", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetPublicKeyResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RevealCounterpartyKeyLinkage reveals key linkage between counterparties
func (h *HTTPWalletJSON) RevealCounterpartyKeyLinkage(args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	data, err := h.api("revealCounterpartyKeyLinkage", args)
	if err != nil {
		return nil, err
	}
	var result wallet.RevealCounterpartyKeyLinkageResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RevealSpecificKeyLinkage reveals key linkage for a specific interaction
func (h *HTTPWalletJSON) RevealSpecificKeyLinkage(args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	data, err := h.api("revealSpecificKeyLinkage", args)
	if err != nil {
		return nil, err
	}
	var result wallet.RevealSpecificKeyLinkageResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// Encrypt encrypts data using derived keys
func (h *HTTPWalletJSON) Encrypt(args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error) {
	data, err := h.api("encrypt", args)
	if err != nil {
		return nil, err
	}
	var result wallet.EncryptResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// Decrypt decrypts data using derived keys
func (h *HTTPWalletJSON) Decrypt(args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error) {
	data, err := h.api("decrypt", args)
	if err != nil {
		return nil, err
	}
	var result wallet.DecryptResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// CreateHmac creates an HMAC for data
func (h *HTTPWalletJSON) CreateHmac(args wallet.CreateHmacArgs, originator string) (*wallet.CreateHmacResult, error) {
	data, err := h.api("createHmac", args)
	if err != nil {
		return nil, err
	}
	var result wallet.CreateHmacResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// VerifyHmac verifies an HMAC for data
func (h *HTTPWalletJSON) VerifyHmac(args wallet.VerifyHmacArgs, originator string) (*wallet.VerifyHmacResult, error) {
	data, err := h.api("verifyHmac", args)
	if err != nil {
		return nil, err
	}
	var result wallet.VerifyHmacResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// CreateSignature creates a digital signature
func (h *HTTPWalletJSON) CreateSignature(args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	data, err := h.api("createSignature", args)
	if err != nil {
		return nil, err
	}
	var result wallet.CreateSignatureResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// VerifySignature verifies a digital signature
func (h *HTTPWalletJSON) VerifySignature(args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
	data, err := h.api("verifySignature", args)
	if err != nil {
		return nil, err
	}
	var result wallet.VerifySignatureResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// AcquireCertificate acquires an identity certificate
func (h *HTTPWalletJSON) AcquireCertificate(args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	data, err := h.api("acquireCertificate", args)
	if err != nil {
		return nil, err
	}
	var result wallet.Certificate
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ListCertificates lists identity certificates
func (h *HTTPWalletJSON) ListCertificates(args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	data, err := h.api("listCertificates", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ListCertificatesResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ProveCertificate proves select fields of a certificate
func (h *HTTPWalletJSON) ProveCertificate(args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	data, err := h.api("proveCertificate", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ProveCertificateResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RelinquishCertificate removes an identity certificate
func (h *HTTPWalletJSON) RelinquishCertificate(args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	data, err := h.api("relinquishCertificate", args)
	if err != nil {
		return nil, err
	}
	var result wallet.RelinquishCertificateResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// DiscoverByIdentityKey discovers certificates by identity key
func (h *HTTPWalletJSON) DiscoverByIdentityKey(args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	data, err := h.api("discoverByIdentityKey", args)
	if err != nil {
		return nil, err
	}
	var result wallet.DiscoverCertificatesResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// DiscoverByAttributes discovers certificates by attributes
func (h *HTTPWalletJSON) DiscoverByAttributes(args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	data, err := h.api("discoverByAttributes", args)
	if err != nil {
		return nil, err
	}
	var result wallet.DiscoverCertificatesResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// IsAuthenticated checks authentication status
func (h *HTTPWalletJSON) IsAuthenticated(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	data, err := h.api("isAuthenticated", args)
	if err != nil {
		return nil, err
	}
	var result wallet.AuthenticatedResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// WaitForAuthentication waits until user is authenticated
func (h *HTTPWalletJSON) WaitForAuthentication(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	data, err := h.api("waitForAuthentication", args)
	if err != nil {
		return nil, err
	}
	var result wallet.AuthenticatedResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetHeight gets current blockchain height
func (h *HTTPWalletJSON) GetHeight(args interface{}, originator string) (*wallet.GetHeightResult, error) {
	data, err := h.api("getHeight", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetHeightResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetHeaderForHeight gets block header at height
func (h *HTTPWalletJSON) GetHeaderForHeight(args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	data, err := h.api("getHeaderForHeight", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetHeaderResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetNetwork gets current network (mainnet/testnet)
func (h *HTTPWalletJSON) GetNetwork(args interface{}, originator string) (*wallet.GetNetworkResult, error) {
	data, err := h.api("getNetwork", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetNetworkResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetVersion gets wallet version
func (h *HTTPWalletJSON) GetVersion(args interface{}, originator string) (*wallet.GetVersionResult, error) {
	data, err := h.api("getVersion", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetVersionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

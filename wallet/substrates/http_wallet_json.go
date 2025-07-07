package substrates

import (
	"bytes"
	"context"
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
func (h *HTTPWalletJSON) api(ctx context.Context, call string, args any) ([]byte, error) {
	// Marshal request body
	reqBody, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", h.baseURL+"/"+call, bytes.NewReader(reqBody))
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
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read and return response
	return io.ReadAll(resp.Body)
}

// CreateAction creates a new transaction
func (h *HTTPWalletJSON) CreateAction(ctx context.Context, args wallet.CreateActionArgs) (*wallet.CreateActionResult, error) {
	data, err := h.api(ctx, "createAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.CreateActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// SignAction signs a previously created transaction
func (h *HTTPWalletJSON) SignAction(ctx context.Context, args *wallet.SignActionArgs) (*wallet.SignActionResult, error) {
	data, err := h.api(ctx, "signAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.SignActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// AbortAction aborts a transaction in progress
func (h *HTTPWalletJSON) AbortAction(ctx context.Context, args wallet.AbortActionArgs) (*wallet.AbortActionResult, error) {
	data, err := h.api(ctx, "abortAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.AbortActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ListActions lists wallet transactions matching filters
func (h *HTTPWalletJSON) ListActions(ctx context.Context, args wallet.ListActionsArgs) (*wallet.ListActionsResult, error) {
	data, err := h.api(ctx, "listActions", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ListActionsResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// InternalizeAction imports an external transaction into the wallet
func (h *HTTPWalletJSON) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs) (*wallet.InternalizeActionResult, error) {
	data, err := h.api(ctx, "internalizeAction", args)
	if err != nil {
		return nil, err
	}
	var result wallet.InternalizeActionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ListOutputs lists wallet outputs matching filters
func (h *HTTPWalletJSON) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs) (*wallet.ListOutputsResult, error) {
	data, err := h.api(ctx, "listOutputs", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ListOutputsResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RelinquishOutput removes an output from basket tracking
func (h *HTTPWalletJSON) RelinquishOutput(ctx context.Context, args *wallet.RelinquishOutputArgs) (*wallet.RelinquishOutputResult, error) {
	data, err := h.api(ctx, "relinquishOutput", args)
	if err != nil {
		return nil, err
	}
	var result wallet.RelinquishOutputResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetPublicKey retrieves a derived or identity public key
func (h *HTTPWalletJSON) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs) (*wallet.GetPublicKeyResult, error) {
	data, err := h.api(ctx, "getPublicKey", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetPublicKeyResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RevealCounterpartyKeyLinkage reveals key linkage between counterparties
func (h *HTTPWalletJSON) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	data, err := h.api(ctx, "revealCounterpartyKeyLinkage", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.RevealCounterpartyKeyLinkageResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RevealSpecificKeyLinkage reveals key linkage for a specific interaction
func (h *HTTPWalletJSON) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs) (*wallet.RevealSpecificKeyLinkageResult, error) {
	data, err := h.api(ctx, "revealSpecificKeyLinkage", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.RevealSpecificKeyLinkageResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// Encrypt encrypts data using derived keys
func (h *HTTPWalletJSON) Encrypt(ctx context.Context, args wallet.EncryptArgs) (*wallet.EncryptResult, error) {
	data, err := h.api(ctx, "encrypt", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.EncryptResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// Decrypt decrypts data using derived keys
func (h *HTTPWalletJSON) Decrypt(ctx context.Context, args wallet.DecryptArgs) (*wallet.DecryptResult, error) {
	data, err := h.api(ctx, "decrypt", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.DecryptResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// CreateHMAC creates an HMAC for data
func (h *HTTPWalletJSON) CreateHMAC(ctx context.Context, args wallet.CreateHMACArgs) (*wallet.CreateHMACResult, error) {
	data, err := h.api(ctx, "createHmac", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.CreateHMACResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// VerifyHMAC verifies an HMAC for data
func (h *HTTPWalletJSON) VerifyHMAC(ctx context.Context, args wallet.VerifyHMACArgs) (*wallet.VerifyHMACResult, error) {
	data, err := h.api(ctx, "verifyHmac", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.VerifyHMACResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// CreateSignature creates a digital signature
func (h *HTTPWalletJSON) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs) (*wallet.CreateSignatureResult, error) {
	data, err := h.api(ctx, "createSignature", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.CreateSignatureResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// VerifySignature verifies a digital signature
func (h *HTTPWalletJSON) VerifySignature(ctx context.Context, args wallet.VerifySignatureArgs) (*wallet.VerifySignatureResult, error) {
	data, err := h.api(ctx, "verifySignature", &args)
	if err != nil {
		return nil, err
	}
	var result wallet.VerifySignatureResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// AcquireCertificate acquires an identity certificate
func (h *HTTPWalletJSON) AcquireCertificate(ctx context.Context, args *wallet.AcquireCertificateArgs) (*wallet.Certificate, error) {
	data, err := h.api(ctx, "acquireCertificate", args)
	if err != nil {
		return nil, err
	}
	var result wallet.Certificate
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ListCertificates lists identity certificates
func (h *HTTPWalletJSON) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs) (*wallet.ListCertificatesResult, error) {
	data, err := h.api(ctx, "listCertificates", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ListCertificatesResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// ProveCertificate proves select fields of a certificate
func (h *HTTPWalletJSON) ProveCertificate(ctx context.Context, args *wallet.ProveCertificateArgs) (*wallet.ProveCertificateResult, error) {
	data, err := h.api(ctx, "proveCertificate", args)
	if err != nil {
		return nil, err
	}
	var result wallet.ProveCertificateResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// RelinquishCertificate removes an identity certificate
func (h *HTTPWalletJSON) RelinquishCertificate(ctx context.Context, args *wallet.RelinquishCertificateArgs) (*wallet.RelinquishCertificateResult, error) {
	data, err := h.api(ctx, "relinquishCertificate", args)
	if err != nil {
		return nil, err
	}
	var result wallet.RelinquishCertificateResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// DiscoverByIdentityKey discovers certificates by identity key
func (h *HTTPWalletJSON) DiscoverByIdentityKey(ctx context.Context, args *wallet.DiscoverByIdentityKeyArgs) (*wallet.DiscoverCertificatesResult, error) {
	data, err := h.api(ctx, "discoverByIdentityKey", args)
	if err != nil {
		return nil, err
	}
	var result wallet.DiscoverCertificatesResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// DiscoverByAttributes discovers certificates by attributes
func (h *HTTPWalletJSON) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs) (*wallet.DiscoverCertificatesResult, error) {
	data, err := h.api(ctx, "discoverByAttributes", args)
	if err != nil {
		return nil, err
	}
	var result wallet.DiscoverCertificatesResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// IsAuthenticated checks authentication status
func (h *HTTPWalletJSON) IsAuthenticated(ctx context.Context, args any) (*wallet.AuthenticatedResult, error) {
	data, err := h.api(ctx, "isAuthenticated", args)
	if err != nil {
		return nil, err
	}
	var result wallet.AuthenticatedResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// WaitForAuthentication waits until user is authenticated
func (h *HTTPWalletJSON) WaitForAuthentication(ctx context.Context, args any) (*wallet.AuthenticatedResult, error) {
	data, err := h.api(ctx, "waitForAuthentication", args)
	if err != nil {
		return nil, err
	}
	var result wallet.AuthenticatedResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetHeight gets current blockchain height
func (h *HTTPWalletJSON) GetHeight(ctx context.Context, args any) (*wallet.GetHeightResult, error) {
	data, err := h.api(ctx, "getHeight", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetHeightResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetHeaderForHeight gets block header at height
func (h *HTTPWalletJSON) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs) (*wallet.GetHeaderResult, error) {
	data, err := h.api(ctx, "getHeaderForHeight", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetHeaderResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetNetwork gets current network (mainnet/testnet)
func (h *HTTPWalletJSON) GetNetwork(ctx context.Context, args any) (*wallet.GetNetworkResult, error) {
	data, err := h.api(ctx, "getNetwork", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetNetworkResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

// GetVersion gets wallet version
func (h *HTTPWalletJSON) GetVersion(ctx context.Context, args any) (*wallet.GetVersionResult, error) {
	data, err := h.api(ctx, "getVersion", args)
	if err != nil {
		return nil, err
	}
	var result wallet.GetVersionResult
	err = json.Unmarshal(data, &result)
	return &result, err
}

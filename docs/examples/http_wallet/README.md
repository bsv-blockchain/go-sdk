# HTTP Wallet Example

This example demonstrates how to use the `substrates.HTTPWalletJSON` to interact with a wallet service over HTTP. It specifically shows how to make a `CreateAction` call to a mock HTTP server that simulates a wallet backend.

## Overview

The `substrates.HTTPWalletJSON` provides a client implementation for wallet operations that are exposed via an HTTP JSON API. This example focuses on the `CreateAction` method, which is typically used to initiate the creation of a transaction.

The example includes:
1.  Setting up a mock HTTP server to handle wallet API requests.
2.  Initializing an `HTTPWalletJSON` client to communicate with the mock server.
3.  Preparing `CreateActionArgs` with transaction details.
4.  Calling the `CreateAction` method on the HTTP wallet client.
5.  Processing the `CreateActionResult` received from the mock server.

## Code Walkthrough

### 1. Mock HTTP Server Setup

To simulate a backend wallet service, a mock HTTP server is created using `net/http/httptest`. This server will respond to the `/createAction` endpoint.

```go
// Mock server setup
mux := http.NewServeMux()

// Mock CreateAction
var mockCreateActionReference = []byte("mock-tx-reference-123")
mockCreateActionTxId, _ := chainhash.NewHashFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
mux.HandleFunc("/createAction", func(w http.ResponseWriter, r *http.Request) {
    var args wallet.CreateActionArgs
    if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
        http.Error(w, "Failed to decode request for createAction", http.StatusBadRequest)
        return
    }
    fmt.Printf("Mock Server: Received CreateAction with Description: %s\n", args.Description)

    // Use an anonymous struct for the JSON response to send Txid as a string
    jsonResponse := struct {
        Txid                string                      `json:"txid"`
        SignableTransaction *wallet.SignableTransaction `json:"signableTransaction,omitempty"`
    }{
        Txid: mockCreateActionTxId.String(), // Marshal as hex string
        SignableTransaction: &wallet.SignableTransaction{
            Reference: mockCreateActionReference,
        },
    }
    writeJSONResponse(w, jsonResponse)
})

server := httptest.NewServer(mux)
defer server.Close()

// Helper to write JSON responses for the mock server
func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
```
The mock server listens for POST requests on `/createAction`. When a request is received, it decodes the `wallet.CreateActionArgs`, prints the description, and sends back a mocked `CreateActionResult` containing a `Txid` and a `SignableTransaction` with a reference.

### 2. Initialize HTTPWalletJSON Client

An `HTTPWalletJSON` client is initialized with the URL of the mock server.

```go
originator := "my-app-example"
// Use the mock server's URL
baseURL := server.URL
httpClient := server.Client()

w := substrates.NewHTTPWalletJSON(originator, baseURL, httpClient)
ctx := context.Background()
```
The `originator` string is an identifier for the application making the request. The `httpClient` from the `httptest.Server` is used to ensure requests go to the mock server.

### 3. Prepare and Call CreateAction

Arguments for `CreateAction` are prepared, including a description, output details (amount and locking script), and labels.

```go
// --- CreateAction ---
fmt.Println("\n--- CreateAction ---")
// Create a P2PKH script for the output
mockToAddress, err := script.NewAddressFromString("mfZQtGMnf2aP17fF3a9TzWMRw2NXp25hN2") // Using a valid testnet address format
if err != nil {
    fmt.Printf("Error creating mock address: %v\n", err)
    return
}
p2pkhScript, _ := p2pkh.Lock(mockToAddress)

createActionArgs := wallet.CreateActionArgs{
    Description: "Test transaction from example",
    Outputs: []wallet.CreateActionOutput{
        {
            Satoshis:      1000, // Amount in satoshis
            LockingScript: p2pkhScript.Bytes(),
        },
    },
    Labels: []string{"test", "example"},
}
createActionResult, err := w.CreateAction(ctx, createActionArgs)
if err != nil {
    fmt.Printf("Error creating action: %v\n", err)
}
var currentActionReference []byte
if createActionResult != nil {
    fmt.Printf("CreateAction Result - TxID: %s\n", createActionResult.Txid.String())
    if createActionResult.SignableTransaction != nil {
        currentActionReference = createActionResult.SignableTransaction.Reference
        fmt.Printf("CreateAction Result - Reference: %s\n", string(currentActionReference))
    } else {
        fmt.Println("CreateAction Result - No SignableTransaction returned by mock.")
    }
} else {
    fmt.Println("CreateAction failed or mock returned nil.")
}
```
A P2PKH (Pay-to-Public-Key-Hash) script is created for the transaction output. The `CreateAction` method is then called on the `HTTPWalletJSON` client. The result, including the transaction ID and any signable transaction reference, is printed.

## Running the Example

To run this example:

```bash
cd go-sdk/docs/examples/http_wallet
go mod tidy
go run http_wallet.go
```

This will start the mock server, send a `CreateAction` request to it, and print the results to the console.

## Key Concepts

-   **`substrates.HTTPWalletJSON`**: A client for interacting with a wallet service that exposes a JSON HTTP API. It implements the `wallet.Wallet` interface.
-   **Mock Server**: The example uses `net/http/httptest` to create a mock HTTP server that simulates the behavior of a real wallet backend for the `/createAction` endpoint. This is useful for testing client integrations without needing a live wallet service.
-   **`wallet.CreateActionArgs`**: This struct encapsulates the parameters needed to create a transaction, such as outputs (amount and script), description, and labels.
-   **`wallet.CreateActionResult`**: This struct represents the response from a `CreateAction` call, typically including the `Txid` of the created transaction and, if applicable, a `SignableTransaction` object which might contain a reference for further signing steps.
-   **Originator**: An identifier for the client application making the wallet requests.

## Additional Resources

-   [go-sdk `wallet/substrates` package documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet/substrates)
-   [go-sdk `wallet` package documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet)

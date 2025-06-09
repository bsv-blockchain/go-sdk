package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
)

// Helper to write JSON responses for the mock server
func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func main() {
	originator := "my-app-example"

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
			// Add other fields from CreateActionResult if the client expects them (e.g., Tx, NoSendChange)
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

	// Use the mock server's URL
	baseURL := server.URL
	httpClient := server.Client()

	w := substrates.NewHTTPWalletJSON(originator, baseURL, httpClient)
	ctx := context.Background()

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

}

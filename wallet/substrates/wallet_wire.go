package substrates

import "context"

// WalletWire is an abstraction over a raw transport medium
// where binary data can be sent to and subsequently received from a wallet.
type WalletWire interface {
	TransmitToWallet(ctx context.Context, message []byte) ([]byte, error)
}

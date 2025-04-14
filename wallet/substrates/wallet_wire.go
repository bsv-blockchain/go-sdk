package substrates

// WalletWire is an abstraction over a raw transport medium
// where binary data can be sent to and subsequently received from a wallet.
type WalletWire interface {
	TransmitToWallet(message []byte) ([]byte, error)
}

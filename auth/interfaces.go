package auth

import "github.com/bsv-blockchain/go-sdk/wallet"

// CertificateQuery defines criteria for retrieving certificates
type CertificateQuery struct {
	// List of certifier identity keys (hex-encoded public keys)
	Certifiers []string

	// List of certificate type IDs
	Types []string

	// Subject identity key (who the certificate is about)
	Subject string
}

// WalletAuthInterface defines the wallet functionality required by the auth package
type WalletAuthInterface interface {
	// CreateSignature creates a signature using the wallet's private key
	CreateSignature(args *wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error)

	// GetPublicKey retrieves a public key from the wallet
	GetPublicKey(args *wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error)

	// VerifySignature verifies a signature using the wallet
	VerifySignature(args *wallet.VerifySignatureArgs) (*wallet.VerifySignatureResult, error)

	// GetCertificates retrieves certificates stored in the wallet
	// This is commented out since we need to implement it in the wallet package first
	// GetCertificates(query CertificateQuery) ([]*certificates.VerifiableCertificate, error)
}

package wallet

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Certificate represents a basic certificate in the wallet
type Certificate struct {
	Type               string            // Base64-encoded certificate type ID
	SerialNumber       string            // Base64-encoded unique serial number
	Subject            *ec.PublicKey     // Public key of the certificate subject
	Certifier          *ec.PublicKey     // Public key of the certificate issuer
	RevocationOutpoint string            // Format: "txid:outputIndex"
	Fields             map[string]string // Field name -> field value (encrypted)
	Signature          string            // Hex-encoded signature
}

// CreateActionInput represents an input to be spent in a transaction
type CreateActionInput struct {
	Outpoint              string // Format: "txid:outputIndex"
	InputDescription      string
	UnlockingScript       string // Hex encoded
	UnlockingScriptLength uint32
	SequenceNumber        uint32
}

// CreateActionOutput represents an output to be created in a transaction
type CreateActionOutput struct {
	LockingScript      string // Hex encoded
	Satoshis           uint64
	OutputDescription  string
	Basket             string
	CustomInstructions string
	Tags               []string
}

// CreateActionOptions contains optional parameters for creating a new transaction
type CreateActionOptions struct {
	SignAndProcess         *bool
	AcceptDelayedBroadcast *bool
	TrustSelf              string // "known" or ""
	KnownTxids             []string
	ReturnTXIDOnly         *bool
	NoSend                 *bool
	NoSendChange           []string
	SendWith               []string
	RandomizeOutputs       *bool
}

// CreateActionArgs contains all data needed to create a new transaction
type CreateActionArgs struct {
	Description string
	InputBEEF   []byte
	Inputs      []CreateActionInput
	Outputs     []CreateActionOutput
	LockTime    uint32
	Version     uint32
	Labels      []string
	Options     *CreateActionOptions
}

// CreateActionResult contains the results of creating a transaction
type CreateActionResult struct {
	Txid                string
	Tx                  []byte
	NoSendChange        []string
	SendWithResults     []SendWithResult
	SignableTransaction *SignableTransaction
}

type SendWithResult struct {
	Txid   string
	Status string // "unproven" | "sending" | "failed"
}

type SignableTransaction struct {
	Tx        []byte
	Reference string
}

// ListCertificatesArgs contains parameters for listing certificates
type ListCertificatesArgs struct {
	// Certifiers to filter by (public keys)
	Certifiers []string

	// Certificate types to filter by
	Types []string
}

// ListCertificatesResult contains the results of listing certificates
type ListCertificatesResult struct {
	// The matching certificates
	Certificates []Certificate
}

// ProveCertificateArgs contains parameters for creating verifiable certificates
type ProveCertificateArgs struct {
	// The certificate to create a verifiable version of
	Certificate Certificate

	// Fields to reveal in the certificate
	FieldsToReveal []string

	// The verifier's identity key
	Verifier string
}

// ProveCertificateResult contains the result of creating a verifiable certificate
type ProveCertificateResult struct {
	// Keyring for revealing specific fields to the verifier
	KeyringForVerifier map[string]string
}

// Note: The following types are defined in wallet.go:
// - CounterpartyType
// - CreateHmacArgs/Result
// - VerifyHmacArgs/Result
// - CreateSignatureArgs/Result
// - VerifySignatureArgs/Result
// - EncryptArgs/Result
// - DecryptArgs/Result
// - GetPublicKeyArgs/Result

// Interface defines the interface for wallet operations
// This should match the TypeScript SDK's WalletInterface
type Interface interface {
	// Transaction creation
	CreateAction(args CreateActionArgs, originator string) (*CreateActionResult, error)

	// Certificate management
	ListCertificates(args ListCertificatesArgs) (*ListCertificatesResult, error)
	ProveCertificate(args ProveCertificateArgs) (*ProveCertificateResult, error)

	// HMAC operations
	CreateHmac(args CreateHmacArgs) (*CreateHmacResult, error)
	VerifyHmac(args VerifyHmacArgs) (*VerifyHmacResult, error)

	// Signature operations
	CreateSignature(args *CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
	VerifySignature(args *VerifySignatureArgs) (*VerifySignatureResult, error)

	// Encryption operations
	Encrypt(args *EncryptArgs) (*EncryptResult, error)
	Decrypt(args *DecryptArgs) (*DecryptResult, error)

	// Key operations
	GetPublicKey(args *GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)

	// Authentication
	IsAuthenticated(args any) (bool, error)
	GetHeight(args any) (uint32, error)
	GetNetwork(args any) (string, error)
	GetVersion(args any) (string, error)
}

type CertificateFieldNameUnder50Bytes string

type Base64String string

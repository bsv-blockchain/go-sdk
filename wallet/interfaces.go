package wallet

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type PublicKeyGetter interface {
	GetPublicKey(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)
}

type CipherOperations interface {
	Encrypt(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error)
	Decrypt(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error)
}

type HMACOperations interface {
	CreateHMAC(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error)
	VerifyHMAC(ctx context.Context, args VerifyHMACArgs, originator string) (*VerifyHMACResult, error)
}

type SignatureOperations interface {
	CreateSignature(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
	VerifySignature(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)
}

// KeyOperations defines the interface for cryptographic operations.
type KeyOperations interface {
	PublicKeyGetter
	CipherOperations
	HMACOperations
	SignatureOperations
}

// Interface defines the core wallet operations for transaction creation, signing and querying.
type Interface interface {
	KeyOperations
	CreateAction(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error)
	SignAction(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error)
	AbortAction(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error)
	ListActions(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error)
	InternalizeAction(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error)
	ListOutputs(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error)
	RelinquishOutput(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error)
	RevealCounterpartyKeyLinkage(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error)
	RevealSpecificKeyLinkage(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error)
	AcquireCertificate(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error)
	ListCertificates(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error)
	ProveCertificate(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error)
	RelinquishCertificate(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error)
	DiscoverByIdentityKey(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error)
	DiscoverByAttributes(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error)
	IsAuthenticated(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)
	WaitForAuthentication(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)
	GetHeight(ctx context.Context, args any, originator string) (*GetHeightResult, error)
	GetHeaderForHeight(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error)
	GetNetwork(ctx context.Context, args any, originator string) (*GetNetworkResult, error)
	GetVersion(ctx context.Context, args any, originator string) (*GetVersionResult, error)
}

type (
	CertificateType [32]byte
	SerialNumber    [32]byte
)

func (c CertificateType) Bytes() []byte {
	return c[:]
}

// Certificate represents a basic certificate in the wallet
type Certificate struct {
	Type               CertificateType       `json:"type"`
	SerialNumber       SerialNumber          `json:"serialNumber"`
	Subject            *ec.PublicKey         `json:"subject"`
	Certifier          *ec.PublicKey         `json:"certifier"`
	RevocationOutpoint *transaction.Outpoint `json:"revocationOutpoint,omitempty"`
	Fields             map[string]string     `json:"fields,omitempty"` // Field name -> field value (encrypted)
	Signature          *ec.Signature         `json:"signature,omitempty"`
}

// CreateActionInput represents an input to be spent in a transaction
type CreateActionInput struct {
	Outpoint              transaction.Outpoint `json:"outpoint"` // Format: "txid:outputIndex"
	InputDescription      string               `json:"inputDescription"`
	UnlockingScript       []byte               `json:"unlockingScript,omitempty"`
	UnlockingScriptLength uint32               `json:"unlockingScriptLength,omitempty"`
	SequenceNumber        *uint32              `json:"sequenceNumber,omitempty"`
}

// CreateActionOutput represents an output to be created in a transaction
type CreateActionOutput struct {
	LockingScript      []byte   `json:"lockingScript,omitempty"`
	Satoshis           uint64   `json:"satoshis,omitempty"`
	OutputDescription  string   `json:"outputDescription,omitempty"`
	Basket             string   `json:"basket,omitempty"`
	CustomInstructions string   `json:"customInstructions,omitempty"`
	Tags               []string `json:"tags,omitempty"`
}

// TrustSelf represents a trust level for self-referential operations.
type TrustSelf string

const (
	// TrustSelfKnown indicates that the wallet should trust itself for known operations.
	TrustSelfKnown TrustSelf = "known"
)

// CreateActionOptions contains optional parameters for creating a new transaction
type CreateActionOptions struct {
	SignAndProcess         *bool
	AcceptDelayedBroadcast *bool
	TrustSelf              TrustSelf // "known" or ""
	KnownTxids             []chainhash.Hash
	ReturnTXIDOnly         *bool
	NoSend                 *bool
	NoSendChange           []transaction.Outpoint
	SendWith               []chainhash.Hash
	RandomizeOutputs       *bool
}

// CreateActionArgs contains all data needed to create a new transaction
type CreateActionArgs struct {
	Description string               `json:"description"`
	InputBEEF   []byte               `json:"inputBEEF,omitempty"`
	Inputs      []CreateActionInput  `json:"inputs,omitempty"`
	Outputs     []CreateActionOutput `json:"outputs,omitempty"`
	LockTime    *uint32              `json:"lockTime,omitempty"`
	Version     *uint32              `json:"version,omitempty"`
	Labels      []string             `json:"labels,omitempty"`
	Options     *CreateActionOptions `json:"options,omitempty"`
}

// CreateActionResult contains the results of creating a transaction
type CreateActionResult struct {
	Txid                chainhash.Hash
	Tx                  []byte
	NoSendChange        []transaction.Outpoint
	SendWithResults     []SendWithResult
	SignableTransaction *SignableTransaction
}

// ActionResultStatus represents the current state of a transaction action.
type ActionResultStatus string

const (
	ActionResultStatusUnproven ActionResultStatus = "unproven"
	ActionResultStatusSending  ActionResultStatus = "sending"
	ActionResultStatusFailed   ActionResultStatus = "failed"
)

// SendWithResult tracks the status of transactions sent as part of a batch.
type SendWithResult struct {
	Txid   chainhash.Hash
	Status ActionResultStatus
}

// SignableTransaction contains data needed to complete signing of a partial transaction.
type SignableTransaction struct {
	Tx        []byte
	Reference []byte
}

// SignActionSpend provides the unlocking script and sequence number for a specific input.
type SignActionSpend struct {
	UnlockingScript []byte  `json:"unlockingScript"`
	SequenceNumber  *uint32 `json:"sequenceNumber,omitempty"`
}

// SignActionOptions controls signing and broadcasting behavior.
type SignActionOptions struct {
	AcceptDelayedBroadcast *bool
	ReturnTXIDOnly         *bool
	NoSend                 *bool
	SendWith               []chainhash.Hash
}

// SignActionArgs contains data needed to sign a previously created transaction.
type SignActionArgs struct {
	Reference []byte                     `json:"reference"`
	Spends    map[uint32]SignActionSpend `json:"spends"` // Key is input index
	Options   *SignActionOptions         `json:"options,omitempty"`
}

// SignActionResult contains the output of a successful signing operation.
type SignActionResult struct {
	Txid            chainhash.Hash
	Tx              []byte
	SendWithResults []SendWithResult
}

// ActionInput describes a transaction input with full details.
type ActionInput struct {
	SourceOutpoint      transaction.Outpoint `json:"sourceOutpoint"`
	SourceSatoshis      uint64               `json:"sourceSatoshis"`
	SourceLockingScript []byte               `json:"sourceLockingScript,omitempty"`
	UnlockingScript     []byte               `json:"unlockingScript,omitempty"`
	InputDescription    string               `json:"inputDescription"`
	SequenceNumber      uint32               `json:"sequenceNumber"`
}

// ActionOutput describes a transaction output with full details.
type ActionOutput struct {
	Satoshis           uint64   `json:"satoshis"`
	LockingScript      []byte   `json:"lockingScript,omitempty"`
	Spendable          bool     `json:"spendable"`
	CustomInstructions string   `json:"customInstructions,omitempty"`
	Tags               []string `json:"tags"`
	OutputIndex        uint32   `json:"outputIndex"`
	OutputDescription  string   `json:"outputDescription"`
	Basket             string   `json:"basket"`
}

// ActionStatus represents the current state of a transaction.
type ActionStatus string

const (
	ActionStatusCompleted   ActionStatus = "completed"
	ActionStatusUnprocessed ActionStatus = "unprocessed"
	ActionStatusSending     ActionStatus = "sending"
	ActionStatusUnproven    ActionStatus = "unproven"
	ActionStatusUnsigned    ActionStatus = "unsigned"
	ActionStatusNoSend      ActionStatus = "nosend"
	ActionStatusNonFinal    ActionStatus = "nonfinal"
)

// Action contains full details about a wallet transaction including inputs, outputs and metadata.
type Action struct {
	Txid        chainhash.Hash `json:"txid"`
	Satoshis    int64          `json:"satoshis"`
	Status      ActionStatus   `json:"status"`
	IsOutgoing  bool           `json:"isOutgoing"`
	Description string         `json:"description"`
	Labels      []string       `json:"labels,omitempty"`
	Version     uint32         `json:"version"`
	LockTime    uint32         `json:"lockTime"`
	Inputs      []ActionInput  `json:"inputs,omitempty"`
	Outputs     []ActionOutput `json:"outputs,omitempty"`
}

// QueryMode specifies how multiple criteria should be combined in queries.
type QueryMode string

const (
	QueryModeAny QueryMode = "any"
	QueryModeAll QueryMode = "all"
)

// QueryModeFromString converts a string to a QueryMode with validation.
// Valid values are "any" and "all".
func QueryModeFromString(s string) (QueryMode, error) {
	qms := QueryMode(s)
	switch qms {
	case "", QueryModeAny, QueryModeAll:
		return qms, nil
	}
	return "", fmt.Errorf("invalid query mode: %s", s)
}

const MaxActionsLimit = 10000

// ListActionsArgs defines filtering and pagination options for listing wallet transactions.
type ListActionsArgs struct {
	Labels                           []string  `json:"labels"`
	LabelQueryMode                   QueryMode `json:"labelQueryMode,omitempty"` // "any" | "all"
	IncludeLabels                    *bool     `json:"includeLabels,omitempty"`
	IncludeInputs                    *bool     `json:"includeInputs,omitempty"`
	IncludeInputSourceLockingScripts *bool     `json:"includeInputSourceLockingScripts,omitempty"`
	IncludeInputUnlockingScripts     *bool     `json:"includeInputUnlockingScripts,omitempty"`
	IncludeOutputs                   *bool     `json:"includeOutputs,omitempty"`
	IncludeOutputLockingScripts      *bool     `json:"includeOutputLockingScripts,omitempty"`
	Limit                            *uint32   `json:"limit,omitempty"` // Default 10, max 10000
	Offset                           *uint32   `json:"offset,omitempty"`
	SeekPermission                   *bool     `json:"seekPermission,omitempty"` // Default true
}

// ListActionsResult contains a paginated list of wallet transactions matching the query.
type ListActionsResult struct {
	TotalActions uint32   `json:"totalActions"`
	Actions      []Action `json:"actions"`
}

// OutputInclude specifies what additional data to include with output listings.
type OutputInclude string

const (
	OutputIncludeLockingScripts     OutputInclude = "locking scripts"
	OutputIncludeEntireTransactions OutputInclude = "entire transactions"
)

// OutputIncludeFromString converts a string to an OutputInclude with validation.
// Valid values are "locking scripts" and "entire transactions".
func OutputIncludeFromString(s string) (OutputInclude, error) {
	oi := OutputInclude(s)
	switch oi {
	case "", OutputIncludeLockingScripts, OutputIncludeEntireTransactions:
		return oi, nil
	}
	return "", fmt.Errorf("invalid output include option: %s", s)
}

// ListOutputsArgs defines filtering and options for listing wallet outputs.
type ListOutputsArgs struct {
	Basket                    string        `json:"basket"`
	Tags                      []string      `json:"tags"`
	TagQueryMode              QueryMode     `json:"tagQueryMode"` // "any" | "all"
	Include                   OutputInclude `json:"include"`      // "locking scripts" | "entire transactions"
	IncludeCustomInstructions *bool         `json:"includeCustomInstructions,omitempty"`
	IncludeTags               *bool         `json:"includeTags,omitempty"`
	IncludeLabels             *bool         `json:"includeLabels,omitempty"`
	Limit                     *uint32       `json:"limit,omitempty"` // Default 10, max 10000
	Offset                    *uint32       `json:"offset,omitempty"`
	SeekPermission            *bool         `json:"seekPermission,omitempty"` // Default true
}

// Output represents a wallet UTXO with its metadata
type Output struct {
	Satoshis           uint64               `json:"satoshis"`
	LockingScript      []byte               `json:"lockingScript,omitempty"` // Hex encoded
	Spendable          bool                 `json:"spendable"`
	CustomInstructions string               `json:"customInstructions,omitempty"`
	Tags               []string             `json:"tags,omitempty"`
	Outpoint           transaction.Outpoint `json:"outpoint"` // Format: "txid.index"
	Labels             []string             `json:"labels,omitempty"`
}

// ListOutputsResult contains a paginated list of wallet outputs matching the query.
type ListOutputsResult struct {
	TotalOutputs uint32   `json:"totalOutputs"`
	BEEF         []byte   `json:"BEEF,omitempty"`
	Outputs      []Output `json:"outputs"`
}

// AbortActionArgs identifies a transaction to abort using its reference string.
type AbortActionArgs struct {
	Reference []byte `json:"reference"`
}

// AbortActionResult confirms whether a transaction was successfully aborted.
type AbortActionResult struct {
	Aborted bool `json:"aborted"`
}

// Payment contains derivation and identity data for wallet payment outputs.
type Payment struct {
	DerivationPrefix  []byte        `json:"derivationPrefix"`
	DerivationSuffix  []byte        `json:"derivationSuffix"`
	SenderIdentityKey *ec.PublicKey `json:"senderIdentityKey"`
}

// BasketInsertion contains metadata for outputs being inserted into baskets.
type BasketInsertion struct {
	Basket             string   `json:"basket"`
	CustomInstructions string   `json:"customInstructions"`
	Tags               []string `json:"tags"`
}

// InternalizeProtocol specifies the protocol used for internalizing transaction outputs.
type InternalizeProtocol string

const (
	InternalizeProtocolWalletPayment   InternalizeProtocol = "wallet payment"
	InternalizeProtocolBasketInsertion InternalizeProtocol = "basket insertion"
)

// InternalizeProtocolFromString converts a string to an InternalizeProtocol with validation.
// Valid values are "wallet payment" and "basket insertion".
func InternalizeProtocolFromString(s string) (InternalizeProtocol, error) {
	op := InternalizeProtocol(s)
	switch op {
	case "", InternalizeProtocolWalletPayment, InternalizeProtocolBasketInsertion:
		return op, nil
	}
	return "", fmt.Errorf("invalid internalize protocol: %s", s)
}

// InternalizeOutput defines how to process a transaction output - as payment or basket insertion.
type InternalizeOutput struct {
	OutputIndex         uint32              `json:"outputIndex"`
	Protocol            InternalizeProtocol `json:"protocol"` // "wallet payment" | "basket insertion"
	PaymentRemittance   *Payment            `json:"paymentRemittance,omitempty"`
	InsertionRemittance *BasketInsertion    `json:"insertionRemittance,omitempty"`
}

// InternalizeActionArgs contains data needed to import an external transaction into the wallet.
type InternalizeActionArgs struct {
	Tx             []byte              `json:"tx"` // BEEF encoded transaction
	Description    string              `json:"description"`
	Labels         []string            `json:"labels"`
	SeekPermission *bool               `json:"seekPermission,omitempty"`
	Outputs        []InternalizeOutput `json:"outputs"`
}

// InternalizeActionResult confirms whether a transaction was successfully internalized.
type InternalizeActionResult struct {
	Accepted bool `json:"accepted"`
}

// RevealCounterpartyKeyLinkageArgs contains parameters for revealing key linkage between counterparties.
// This operation exposes the cryptographic relationship between the wallet and a specific counterparty.
type RevealCounterpartyKeyLinkageArgs struct {
	Counterparty     *ec.PublicKey `json:"counterparty"`
	Verifier         *ec.PublicKey `json:"verifier"`
	Privileged       *bool         `json:"privileged,omitempty"`
	PrivilegedReason string        `json:"privilegedReason,omitempty"`
}

// RevealCounterpartyKeyLinkageResult contains the encrypted linkage data and proof
// that demonstrates the relationship between the prover and counterparty.
type RevealCounterpartyKeyLinkageResult struct {
	Prover                *ec.PublicKey `json:"prover"`
	Counterparty          *ec.PublicKey `json:"counterparty"`
	Verifier              *ec.PublicKey `json:"verifier"`
	RevelationTime        string        `json:"revelationTime"`
	EncryptedLinkage      []byte        `json:"encryptedLinkage"`
	EncryptedLinkageProof []byte        `json:"encryptedLinkageProof"`
}

// RevealSpecificKeyLinkageArgs contains parameters for revealing specific key linkage information.
// This operation exposes the relationship for a specific protocol and key combination.
type RevealSpecificKeyLinkageArgs struct {
	Counterparty     Counterparty  `json:"counterparty"`
	Verifier         *ec.PublicKey `json:"verifier"`
	ProtocolID       Protocol      `json:"protocolID"`
	KeyID            string        `json:"keyID"`
	Privileged       *bool         `json:"privileged,omitempty"`
	PrivilegedReason string        `json:"privilegedReason,omitempty"`
}

// RevealSpecificKeyLinkageResult contains the specific encrypted linkage data and proof
// for a particular protocol and key combination.
type RevealSpecificKeyLinkageResult struct {
	EncryptedLinkage      []byte        `json:"encryptedLinkage"`
	EncryptedLinkageProof []byte        `json:"encryptedLinkageProof"`
	Prover                *ec.PublicKey `json:"prover"`
	Verifier              *ec.PublicKey `json:"verifier"`
	Counterparty          *ec.PublicKey `json:"counterparty"`
	ProtocolID            Protocol      `json:"protocolID"`
	KeyID                 string        `json:"keyID"`
	ProofType             byte          `json:"proofType"`
}

// IdentityCertifier represents information about an entity that issues identity certificates.
// It contains metadata about the certifier including trust level and display information.
type IdentityCertifier struct {
	Name        string `json:"name"`
	IconUrl     string `json:"iconUrl"`
	Description string `json:"description"`
	Trust       uint8  `json:"trust"`
}

type IdentityCertificate struct {
	Certificate                               // Embedded
	CertifierInfo           IdentityCertifier `json:"certifierInfo"`
	PubliclyRevealedKeyring map[string]string `json:"publiclyRevealedKeyring"`
	DecryptedFields         map[string]string `json:"decryptedFields"`
}

// AcquisitionProtocol specifies the method used to acquire a certificate.
type AcquisitionProtocol string

const (
	AcquisitionProtocolDirect   AcquisitionProtocol = "direct"
	AcquisitionProtocolIssuance AcquisitionProtocol = "issuance"
)

// AcquisitionProtocolFromString converts a string to an AcquisitionProtocol with validation.
// Valid values are "direct" and "issuance".
func AcquisitionProtocolFromString(s string) (AcquisitionProtocol, error) {
	ap := AcquisitionProtocol(s)
	switch ap {
	case "", AcquisitionProtocolDirect, AcquisitionProtocolIssuance:
		return ap, nil
	}
	return "", fmt.Errorf("invalid acquisition protocol: %s", s)
}

const KeyringRevealerCertifier = "certifier"

// KeyringRevealer is a special JSON type used for identifying the revealer of a keyring.
// It can either point to the certifier or be a public key.
type KeyringRevealer struct {
	Certifier bool
	PubKey    *ec.PublicKey
}

// AcquireCertificateArgs contains parameters for acquiring a new certificate.
// This includes the certificate type, certifier information, and acquisition method.
type AcquireCertificateArgs struct {
	Type                CertificateType       `json:"type"`
	Certifier           *ec.PublicKey         `json:"certifier"`
	AcquisitionProtocol AcquisitionProtocol   `json:"acquisitionProtocol"` // "direct" | "issuance"
	Fields              map[string]string     `json:"fields,omitempty"`
	SerialNumber        *SerialNumber         `json:"serialNumber,omitempty"`
	RevocationOutpoint  *transaction.Outpoint `json:"revocationOutpoint,omitempty"`
	Signature           *ec.Signature         `json:"signature,omitempty"`
	CertifierUrl        string                `json:"certifierUrl,omitempty"`
	KeyringRevealer     *KeyringRevealer      `json:"keyringRevealer,omitempty"` // "certifier" | PubKeyHex
	KeyringForSubject   map[string]string     `json:"keyringForSubject,omitempty"`
	Privileged          *bool                 `json:"privileged,omitempty"`
	PrivilegedReason    string                `json:"privilegedReason,omitempty"`
}

// ListCertificatesArgs contains parameters for listing certificates with filtering and pagination.
type ListCertificatesArgs struct {
	Certifiers       []*ec.PublicKey   `json:"certifiers"`
	Types            []CertificateType `json:"types"`
	Limit            *uint32           `json:"limit,omitempty"`
	Offset           *uint32           `json:"offset,omitempty"`
	Privileged       *bool             `json:"privileged,omitempty"`
	PrivilegedReason string            `json:"privilegedReason,omitempty"`
}

// CertificateResult represents a certificate with its associated keyring and verifier information.
type CertificateResult struct {
	Certificate                   // Embed certificate fields directly. They already have tags.
	Keyring     map[string]string `json:"keyring"`
	Verifier    []byte            `json:"verifier"`
}

// ListCertificatesResult contains a paginated list of certificates matching the query criteria.
type ListCertificatesResult struct {
	TotalCertificates uint32              `json:"totalCertificates"`
	Certificates      []CertificateResult `json:"certificates"`
}

// RelinquishCertificateArgs contains parameters for relinquishing ownership of a certificate.
type RelinquishCertificateArgs struct {
	Type         CertificateType `json:"type"`
	SerialNumber SerialNumber    `json:"serialNumber"`
	Certifier    *ec.PublicKey   `json:"certifier"`
}

// RelinquishOutputArgs contains parameters for relinquishing ownership of an output.
type RelinquishOutputArgs struct {
	Basket string               `json:"basket"`
	Output transaction.Outpoint `json:"output"`
}

// RelinquishOutputResult indicates whether an output was successfully relinquished.
type RelinquishOutputResult struct {
	Relinquished bool `json:"relinquished"`
}

// RelinquishCertificateResult indicates whether a certificate was successfully relinquished.
type RelinquishCertificateResult struct {
	Relinquished bool `json:"relinquished"`
}

// DiscoverByIdentityKeyArgs contains parameters for discovering certificates by identity key.
// This allows finding certificates associated with a specific public key identity.
type DiscoverByIdentityKeyArgs struct {
	IdentityKey    *ec.PublicKey `json:"identityKey"`
	Limit          *uint32       `json:"limit"`
	Offset         *uint32       `json:"offset"`
	SeekPermission *bool         `json:"seekPermission,omitempty"`
}

// DiscoverByAttributesArgs contains parameters for discovering certificates by their attributes.
// This allows finding certificates that contain specific field values.
type DiscoverByAttributesArgs struct {
	Attributes     map[string]string `json:"attributes"`
	Limit          *uint32           `json:"limit"`
	Offset         *uint32           `json:"offset"`
	SeekPermission *bool             `json:"seekPermission,omitempty"`
}

// DiscoverCertificatesResult contains a paginated list of identity certificates found during discovery.
type DiscoverCertificatesResult struct {
	TotalCertificates uint32                `json:"totalCertificates"`
	Certificates      []IdentityCertificate `json:"certificates"`
}

// AuthenticatedResult indicates whether the current session is authenticated.
type AuthenticatedResult struct {
	Authenticated bool `json:"authenticated"`
}

// GetHeightResult contains the current blockchain height information.
type GetHeightResult struct {
	Height uint32 `json:"height"`
}

// GetHeaderArgs contains parameters for retrieving a blockchain header at a specific height.
type GetHeaderArgs struct {
	Height uint32 `json:"height"`
}

// GetHeaderResult contains the blockchain header data for the requested height.
type GetHeaderResult struct {
	Header []byte `json:"header"`
}

// Network represents the blockchain network type.
type Network string

const (
	NetworkMainnet Network = "mainnet"
	NetworkTestnet Network = "testnet"
)

// NetworkFromString converts a string to a Network with validation.
// Valid values are "mainnet" and "testnet".
func NetworkFromString(s string) (Network, error) {
	n := Network(s)
	switch n {
	case "", NetworkMainnet, NetworkTestnet:
		return n, nil
	}
	return "", fmt.Errorf("invalid network: %s", s)
}

// GetNetworkResult contains information about the current blockchain network.
type GetNetworkResult struct {
	Network Network `json:"network"` // "mainnet" | "testnet"
}

// GetVersionResult contains version information about the wallet implementation.
type GetVersionResult struct {
	Version string `json:"version"`
}

// ProveCertificateArgs contains parameters for creating verifiable certificates
type ProveCertificateArgs struct {
	// The certificate to create a verifiable version of
	Certificate Certificate `json:"certificate"`

	// Fields to reveal in the certificate
	FieldsToReveal []string `json:"fieldsToReveal"`

	// The verifier's identity key
	Verifier         *ec.PublicKey `json:"verifier"`
	Privileged       *bool         `json:"privileged,omitempty"`
	PrivilegedReason string        `json:"privilegedReason,omitempty"`
}

// ProveCertificateResult contains the result of creating a verifiable certificate
type ProveCertificateResult struct {
	// Keyring for revealing specific fields to the verifier
	KeyringForVerifier map[string]string `json:"keyringForVerifier"`
}

// CertificateFieldNameUnder50Bytes represents a certificate field name with length restrictions.
// Field names must be under 50 bytes to ensure efficient storage and processing.
type CertificateFieldNameUnder50Bytes string

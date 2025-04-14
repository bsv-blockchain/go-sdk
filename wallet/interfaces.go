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

// type Certificate struct {
// 	Type               string
// 	Subject            string
// 	SerialNumber       string
// 	Certifier          string
// 	RevocationOutpoint string
// 	Signature          string
// 	Fields             map[string]string
// }

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

// SendWithResult tracks the status of transactions sent as part of a batch.
type SendWithResult struct {
	Txid   string
	Status string // "unproven" | "sending" | "failed"
}

// SignableTransaction contains data needed to complete signing of a partial transaction.
type SignableTransaction struct {
	Tx        []byte
	Reference string
}

// SignActionSpend provides the unlocking script and sequence number for a specific input.
type SignActionSpend struct {
	UnlockingScript string // Hex encoded
	SequenceNumber  uint32
}

// SignActionOptions controls signing and broadcasting behavior.
type SignActionOptions struct {
	AcceptDelayedBroadcast *bool
	ReturnTXIDOnly         *bool
	NoSend                 *bool
	SendWith               []string
}

// SignActionArgs contains data needed to sign a previously created transaction.
type SignActionArgs struct {
	Spends    map[uint32]SignActionSpend // Key is input index
	Reference string                     // Base64 encoded
	Options   *SignActionOptions
}

// SignActionResult contains the output of a successful signing operation.
type SignActionResult struct {
	Txid            string
	Tx              []byte
	SendWithResults []SendWithResult
}

// ActionInput describes a transaction input with full details.
type ActionInput struct {
	SourceOutpoint      string
	SourceSatoshis      uint64
	SourceLockingScript string // Hex encoded
	UnlockingScript     string // Hex encoded
	InputDescription    string
	SequenceNumber      uint32
}

// ActionOutput describes a transaction output with full details.
type ActionOutput struct {
	Satoshis           uint64
	LockingScript      string // Hex encoded
	Spendable          bool
	CustomInstructions string
	Tags               []string
	OutputIndex        uint32
	OutputDescription  string
	Basket             string
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

// ActionStatusCode is the numeric representation of ActionStatus.
type ActionStatusCode uint8

const (
	ActionStatusCodeCompleted   ActionStatusCode = 1
	ActionStatusCodeUnprocessed ActionStatusCode = 2
	ActionStatusCodeSending     ActionStatusCode = 3
	ActionStatusCodeUnproven    ActionStatusCode = 4
	ActionStatusCodeUnsigned    ActionStatusCode = 5
	ActionStatusCodeNoSend      ActionStatusCode = 6
	ActionStatusCodeNonFinal    ActionStatusCode = 7
)

// Action contains full details about a wallet transaction including inputs, outputs and metadata.
type Action struct {
	Txid        string
	Satoshis    uint64
	Status      ActionStatus
	IsOutgoing  bool
	Description string
	Labels      []string
	Version     uint32
	LockTime    uint32
	Inputs      []ActionInput
	Outputs     []ActionOutput
}

// ListActionsArgs defines filtering and pagination options for listing wallet transactions.
type ListActionsArgs struct {
	Labels                           []string
	LabelQueryMode                   string // "any" | "all"
	IncludeLabels                    *bool
	IncludeInputs                    *bool
	IncludeInputSourceLockingScripts *bool
	IncludeInputUnlockingScripts     *bool
	IncludeOutputs                   *bool
	IncludeOutputLockingScripts      *bool
	Limit                            uint32 // Default 10, max 10000
	Offset                           uint32
	SeekPermission                   *bool // Default true
}

// ListActionsResult contains a paginated list of wallet transactions matching the query.
type ListActionsResult struct {
	TotalActions uint32
	Actions      []Action
}

// ListOutputsArgs defines filtering and options for listing wallet outputs.
type ListOutputsArgs struct {
	Basket                    string
	Tags                      []string
	TagQueryMode              string // "any" | "all"
	Include                   string // "locking scripts" | "entire transactions"
	IncludeCustomInstructions *bool
	IncludeTags               *bool
	IncludeLabels             *bool
	Limit                     uint32 // Default 10, max 10000
	Offset                    uint32
	SeekPermission            *bool // Default true
}

// Output represents a wallet UTXO with its metadata
type Output struct {
	Satoshis           uint64
	LockingScript      string // Hex encoded
	Spendable          bool
	CustomInstructions string
	Tags               []string
	Outpoint           string // Format: "txid.index"
	Labels             []string
}

// ListOutputsResult contains a paginated list of wallet outputs matching the query.
type ListOutputsResult struct {
	TotalOutputs uint32
	BEEF         []byte
	Outputs      []Output
}

// Interface defines the core wallet operations for transaction creation, signing and querying.
type Interface interface {
	CreateAction(args CreateActionArgs, originator string) (*CreateActionResult, error)
	SignAction(args SignActionArgs, originator string) (*SignActionResult, error)
	AbortAction(args AbortActionArgs, originator string) (*AbortActionResult, error)
	ListActions(args ListActionsArgs, originator string) (*ListActionsResult, error)
	InternalizeAction(args InternalizeActionArgs, originator string) (*InternalizeActionResult, error)
	ListOutputs(args ListOutputsArgs, originator string) (*ListOutputsResult, error)
	RelinquishOutput(args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error)
	GetPublicKey(args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)
	RevealCounterpartyKeyLinkage(args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error)
	RevealSpecificKeyLinkage(args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error)
	Encrypt(args EncryptArgs, originator string) (*EncryptResult, error)
	Decrypt(args DecryptArgs, originator string) (*DecryptResult, error)
	CreateHmac(args CreateHmacArgs, originator string) (*CreateHmacResult, error)
	VerifyHmac(args VerifyHmacArgs, originator string) (*VerifyHmacResult, error)
	CreateSignature(args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
	VerifySignature(args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)
	AcquireCertificate(args AcquireCertificateArgs, originator string) (*Certificate, error)
	ListCertificates(args ListCertificatesArgs, originator string) (*ListCertificatesResult, error)
	ProveCertificate(args ProveCertificateArgs, originator string) (*ProveCertificateResult, error)
	RelinquishCertificate(args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error)
	DiscoverByIdentityKey(args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error)
	DiscoverByAttributes(args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error)
	IsAuthenticated(args interface{}, originator string) (*AuthenticatedResult, error)
	WaitForAuthentication(args interface{}, originator string) (*AuthenticatedResult, error)
	GetHeight(args interface{}, originator string) (*GetHeightResult, error)
	GetHeaderForHeight(args GetHeaderArgs, originator string) (*GetHeaderResult, error)
	GetNetwork(args interface{}, originator string) (*GetNetworkResult, error)
	GetVersion(args interface{}, originator string) (*GetVersionResult, error)
}

// AbortActionArgs identifies a transaction to abort using its reference string.
type AbortActionArgs struct {
	Reference string // Base64 encoded reference
}

// AbortActionResult confirms whether a transaction was successfully aborted.
type AbortActionResult struct {
	Aborted bool
}

// Payment contains derivation and identity data for wallet payment outputs.
type Payment struct {
	DerivationPrefix  string
	DerivationSuffix  string
	SenderIdentityKey string
}

// BasketInsertion contains metadata for outputs being inserted into baskets.
type BasketInsertion struct {
	Basket             string
	CustomInstructions string
	Tags               []string
}

// InternalizeOutput defines how to process a transaction output - as payment or basket insertion.
type InternalizeOutput struct {
	OutputIndex         uint32
	Protocol            string // "wallet payment" | "basket insertion"
	PaymentRemittance   *Payment
	InsertionRemittance *BasketInsertion
}

// InternalizeActionArgs contains data needed to import an external transaction into the wallet.
type InternalizeActionArgs struct {
	Tx             []byte
	Outputs        []InternalizeOutput
	Description    string
	Labels         []string
	SeekPermission *bool
}

// InternalizeActionResult confirms whether a transaction was successfully internalized.
type InternalizeActionResult struct {
	Accepted bool
}

type RevealCounterpartyKeyLinkageArgs struct {
	Counterparty     string
	Verifier         string
	Privileged       *bool
	PrivilegedReason string
}

type RevealCounterpartyKeyLinkageResult struct {
	EncryptedLinkage      []byte
	EncryptedLinkageProof []byte
	Prover                string
	Verifier              string
	Counterparty          string
	RevelationTime        string
}

type RevealSpecificKeyLinkageArgs struct {
	Counterparty     Counterparty
	Verifier         string
	ProtocolID       Protocol
	KeyID            string
	Privileged       *bool
	PrivilegedReason string
}

type RevealSpecificKeyLinkageResult struct {
	EncryptedLinkage      []byte
	EncryptedLinkageProof []byte
	Prover                []byte
	Verifier              []byte
	Counterparty          Counterparty
	ProtocolID            Protocol
	KeyID                 string
	ProofType             byte
}

type IdentityCertifier struct {
	Name        string
	IconUrl     string
	Description string
	Trust       uint8
}

type IdentityCertificate struct {
	Certificate
	CertifierInfo           IdentityCertifier
	PubliclyRevealedKeyring map[string]string
	DecryptedFields         map[string]string
}

type AcquireCertificateArgs struct {
	Type                string
	Certifier           string
	AcquisitionProtocol string
	Fields              map[string]string
	SerialNumber        string
	RevocationOutpoint  string
	Signature           string
	CertifierUrl        string
	KeyringRevealer     string
	KeyringForSubject   map[string]string
	Privileged          *bool
	PrivilegedReason    string
}

type ListCertificatesArgs struct {
	Certifiers       []string
	Types            []string
	Limit            uint32
	Offset           uint32
	Privileged       *bool
	PrivilegedReason string
}

type CertificateResult struct {
	Certificate
	Keyring  map[string]string
	Verifier string
}

type ListCertificatesResult struct {
	TotalCertificates uint32
	Certificates      []CertificateResult
}

// type ProveCertificateResult struct {
// 	KeyringForVerifier map[string]string
// 	Certificate        *Certificate
// 	Verifier           string
// }

type RelinquishCertificateArgs struct {
	Type         string
	SerialNumber string
	Certifier    string
}

type RelinquishOutputArgs struct {
	Basket string
	Output string
}

type RelinquishOutputResult struct {
	Relinquished bool
}

type RelinquishCertificateResult struct {
	Relinquished bool
}

type DiscoverByIdentityKeyArgs struct {
	IdentityKey    string
	Limit          uint32
	Offset         uint32
	SeekPermission *bool
}

type DiscoverByAttributesArgs struct {
	Attributes     map[string]string
	Limit          uint32
	Offset         uint32
	SeekPermission *bool
}

type DiscoverCertificatesResult struct {
	TotalCertificates uint32
	Certificates      []IdentityCertificate
}

type AuthenticatedResult struct {
	Authenticated bool
}

type GetHeightResult struct {
	Height uint32
}

type GetHeaderArgs struct {
	Height uint32
}

type GetHeaderResult struct {
	Header string
}

type GetNetworkResult struct {
	Network string // "mainnet" | "testnet"
}

type GetVersionResult struct {
	Version string
}

// ListCertificatesResult contains the results of listing certificates
// type ListCertificatesResult struct {
// 	// The matching certificates
// 	Certificates []Certificate
// }

// ProveCertificateArgs contains parameters for creating verifiable certificates
type ProveCertificateArgs struct {
	// The certificate to create a verifiable version of
	Certificate Certificate

	// Fields to reveal in the certificate
	FieldsToReveal []string

	// The verifier's identity key
	Verifier         string
	Privileged       *bool
	PrivilegedReason string
}

// ProveCertificateResult contains the result of creating a verifiable certificate
type ProveCertificateResult struct {
	// Keyring for revealing specific fields to the verifier
	KeyringForVerifier map[string]string
}

type CertificateFieldNameUnder50Bytes string

type Base64String string

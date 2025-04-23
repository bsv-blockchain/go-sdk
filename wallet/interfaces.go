package wallet

import (
	"context"
	"encoding/json"

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
	LockingScript      string   `json:"lockingScript,omitempty"` // Hex encoded
	Satoshis           uint64   `json:"satoshis,omitempty"`
	OutputDescription  string   `json:"outputDescription,omitempty"`
	Basket             string   `json:"basket,omitempty"`
	CustomInstructions string   `json:"customInstructions,omitempty"`
	Tags               []string `json:"tags,omitempty"`
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
	Description string               `json:"description"`
	InputBEEF   []byte               `json:"inputBEEF,omitempty"`
	Inputs      []CreateActionInput  `json:"inputs,omitempty"`
	Outputs     []CreateActionOutput `json:"outputs,omitempty"`
	LockTime    uint32               `json:"lockTime,omitempty"`
	Version     uint32               `json:"version,omitempty"`
	Labels      []string             `json:"labels,omitempty"`
	Options     *CreateActionOptions `json:"options,omitempty"`
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
	UnlockingScript string `json:"unlockingScript"` // Hex encoded
	SequenceNumber  uint32 `json:"sequenceNumber,omitempty"`
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
	Reference string                     `json:"reference"` // Base64 encoded
	Spends    map[uint32]SignActionSpend `json:"spends"`    // Key is input index
	Options   *SignActionOptions         `json:"options,omitempty"`
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
	Basket                    string   `json:"basket"`
	Tags                      []string `json:"tags"`
	TagQueryMode              string   `json:"tagQueryMode"` // "any" | "all"
	Include                   string   `json:"include"`      // "locking scripts" | "entire transactions"
	IncludeCustomInstructions *bool    `json:"includeCustomInstructions,omitempty"`
	IncludeTags               *bool    `json:"includeTags,omitempty"`
	IncludeLabels             *bool    `json:"includeLabels,omitempty"`
	Limit                     uint32   `json:"limit"` // Default 10, max 10000
	Offset                    uint32   `json:"offset,omitempty"`
	SeekPermission            *bool    `json:"seekPermission,omitempty"` // Default true
}

// Output represents a wallet UTXO with its metadata
type Output struct {
	Satoshis           uint64   `json:"satoshis"`
	LockingScript      string   `json:"lockingScript,omitempty"` // Hex encoded
	Spendable          bool     `json:"spendable"`
	CustomInstructions string   `json:"customInstructions,omitempty"`
	Tags               []string `json:"tags,omitempty"`
	Outpoint           string   `json:"outpoint"` // Format: "txid.index"
	Labels             []string `json:"labels,omitempty"`
}

// ListOutputsResult contains a paginated list of wallet outputs matching the query.
type ListOutputsResult struct {
	TotalOutputs uint32 `json:"totalOutputs"`
	BEEF         JsonByteNoBase64
	Outputs      []Output `json:"outputs"`
}

// KeyOperations defines the interface for cryptographic operations.
type KeyOperations interface {
	GetPublicKey(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)
	Encrypt(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error)
	Decrypt(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error)
	CreateHmac(ctx context.Context, args CreateHmacArgs, originator string) (*CreateHmacResult, error)
	VerifyHmac(ctx context.Context, args VerifyHmacArgs, originator string) (*VerifyHmacResult, error)
	CreateSignature(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
	VerifySignature(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)
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
	IsAuthenticated(ctx context.Context, args interface{}, originator string) (*AuthenticatedResult, error)
	WaitForAuthentication(ctx context.Context, args interface{}, originator string) (*AuthenticatedResult, error)
	GetHeight(ctx context.Context, args interface{}, originator string) (*GetHeightResult, error)
	GetHeaderForHeight(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error)
	GetNetwork(ctx context.Context, args interface{}, originator string) (*GetNetworkResult, error)
	GetVersion(ctx context.Context, args interface{}, originator string) (*GetVersionResult, error)
}

// AbortActionArgs identifies a transaction to abort using its reference string.
type AbortActionArgs struct {
	// TODO: Use []byte instead of Base64 encoded string, will automatically Marshall/Unmarshall to/from Base64
	Reference []byte `json:"reference"` // Base64 encoded reference
}

// AbortActionResult confirms whether a transaction was successfully aborted.
type AbortActionResult struct {
	Aborted bool `json:"aborted"`
}

// Payment contains derivation and identity data for wallet payment outputs.
type Payment struct {
	DerivationPrefix  string `json:"derivationPrefix"`
	DerivationSuffix  string `json:"derivationSuffix"`
	SenderIdentityKey string `json:"senderIdentityKey"`
}

// BasketInsertion contains metadata for outputs being inserted into baskets.
type BasketInsertion struct {
	Basket             string   `json:"basket"`
	CustomInstructions string   `json:"customInstructions"`
	Tags               []string `json:"tags"`
}

// InternalizeOutput defines how to process a transaction output - as payment or basket insertion.
type InternalizeOutput struct {
	OutputIndex         uint32           `json:"outputIndex"`
	Protocol            string           `json:"protocol"` // "wallet payment" | "basket insertion"
	PaymentRemittance   *Payment         `json:"paymentRemittance,omitempty"`
	InsertionRemittance *BasketInsertion `json:"insertionRemittance,omitempty"`
}

// JsonByteNoBase64 is a custom type for JSON serialization of byte arrays that don't use base64 encoding.
type JsonByteNoBase64 []byte

func (s *JsonByteNoBase64) MarshalJSON() ([]byte, error) {
	// Marshal as a plain number array, not base64
	arr := make([]int, len(*s))
	for i, b := range *s {
		arr[i] = int(b)
	}
	return json.Marshal(arr)
}

func (s *JsonByteNoBase64) UnmarshalJSON(data []byte) error {
	var temp []uint8
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	*s = temp
	return nil
}

// InternalizeActionArgs contains data needed to import an external transaction into the wallet.
type InternalizeActionArgs struct {
	Tx             JsonByteNoBase64    `json:"tx"` // BEEF encoded transaction, uint8 makes json.Marshall use numbers
	Description    string              `json:"description"`
	Labels         []string            `json:"labels"`
	SeekPermission *bool               `json:"seekPermission,omitempty"`
	Outputs        []InternalizeOutput `json:"outputs"`
}

// InternalizeActionResult confirms whether a transaction was successfully internalized.
type InternalizeActionResult struct {
	Accepted bool `json:"accepted"`
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

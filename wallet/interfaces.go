package wallet

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

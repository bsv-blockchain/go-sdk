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

type SendWithResult struct {
	Txid   string
	Status string // "unproven" | "sending" | "failed"
}

type SignableTransaction struct {
	Tx        []byte
	Reference string
}

type SignActionSpend struct {
	UnlockingScript string // Hex encoded
	SequenceNumber  uint32
}

type SignActionOptions struct {
	AcceptDelayedBroadcast *bool
	ReturnTXIDOnly         *bool
	NoSend                 *bool
	SendWith               []string
}

type SignActionArgs struct {
	Spends    map[uint32]SignActionSpend // Key is input index
	Reference string                     // Base64 encoded
	Options   *SignActionOptions
}

type SignActionResult struct {
	Txid            string
	Tx              []byte
	SendWithResults []SendWithResult
}

type ActionInput struct {
	SourceOutpoint      string
	SourceSatoshis      uint64
	SourceLockingScript string // Hex encoded
	UnlockingScript     string // Hex encoded
	InputDescription    string
	SequenceNumber      uint32
}

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

type ListActionsResult struct {
	TotalActions uint32
	Actions      []Action
}

type Interface interface {
	CreateAction(args CreateActionArgs, originator string) (*CreateActionResult, error)
	SignAction(args SignActionArgs, originator string) (*SignActionResult, error)
	AbortAction(args AbortActionArgs, originator string) (*AbortActionResult, error)
	ListActions(args ListActionsArgs, originator string) (*ListActionsResult, error)
}

type AbortActionArgs struct {
	Reference string // Base64 encoded reference
}

type AbortActionResult struct {
	Aborted bool
}

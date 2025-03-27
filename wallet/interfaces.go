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

type Interface interface {
	CreateAction(args CreateActionArgs) (*CreateActionResult, error)
}

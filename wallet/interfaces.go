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

// CreateActionArgs contains all data needed to create a new transaction
type CreateActionArgs struct {
	Description            string
	Inputs                 []CreateActionInput
	Outputs                []CreateActionOutput
	LockTime               uint32
	Version                uint32
	Labels                 []string
	SignAndProcess         bool
	AcceptDelayedBroadcast bool
	ReturnTXIDOnly         bool
	NoSend                 bool
	RandomizeOutputs       bool
}

// CreateActionResult contains the results of creating a transaction
type CreateActionResult struct {
	Txid            string
	Tx              []byte // Serialized transaction
	Status          string // "completed", "unprocessed", etc.
	NoSendChange    []string
	SendWithResults []struct {
		Txid   string
		Status string
	}
	SignableTransaction *struct {
		Tx        []byte
		Reference string
	}
}

type Interface interface {
	CreateAction(args CreateActionArgs) (*CreateActionResult, error)
}

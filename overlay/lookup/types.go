package lookup

import (
	"encoding/json"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// AnswerType represents the type of answer returned by a lookup service
type AnswerType string

var (
	AnswerTypeOutputList AnswerType = "output-list"
	AnswerTypeFreeform   AnswerType = "freeform"
	AnswerTypeFormula    AnswerType = "formula"
)

// OutputListItem represents a transaction output with its BEEF and output index
type OutputListItem struct {
	Beef        []byte `json:"beef"`
	OutputIndex uint32 `json:"outputIndex"`
}

// LookupQuestion represents a question asked to an overlay lookup service
type LookupQuestion struct {
	Service string          `json:"service"`
	Query   json.RawMessage `json:"query"`
}

// LookupFormula represents a formula for computing lookup results
type LookupFormula struct {
	Outpoint *transaction.Outpoint
	History  func(beef []byte, outputIndex uint32, currentDepth uint32) bool
	// HistoryDepth uint32
}

// LookupAnswer represents the response from an overlay lookup service
type LookupAnswer struct {
	Type     AnswerType        `json:"type"`
	Outputs  []*OutputListItem `json:"outputs,omitempty"`
	Formulas []LookupFormula   `json:"-"`
	Result   any               `json:"result,omitempty"`
}

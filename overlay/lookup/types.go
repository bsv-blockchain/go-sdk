package lookup

import (
	"encoding/json"

	"github.com/bsv-blockchain/go-sdk/overlay"
)

type AnswerType string

var (
	AnswerTypeOutputList AnswerType = "output-list"
	AnswerTypeFreeform   AnswerType = "freeform"
	AnswerTypeFormula    AnswerType = "formula"
)

type OutputListItem struct {
	Beef        []byte `json:"beef"`
	OutputIndex uint32 `json:"outputIndex"`
}

type LookupQuestion struct {
	Service string          `json:"service"`
	Query   json.RawMessage `json:"query"`
}

type LookupFormula struct {
	Outpoint *overlay.Outpoint
	Histoy   func(beef []byte, outputIndex uint32, currentDepth uint32) bool
	// HistoryDepth uint32
}

type LookupAnswer struct {
	Type     AnswerType        `json:"type"`
	Outputs  []*OutputListItem `json:"outputs,omitempty"`
	Formulas []LookupFormula   `json:"-"`
	Result   any               `json:"result,omitempty"`
}

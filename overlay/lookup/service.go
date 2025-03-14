package lookup

import (
	"github.com/bsv-blockchain/go-sdk/overlay"
)

type AnswerType string

var (
	AnswerTypeOutputList AnswerType = "output-list"
	AnswerTypeFreeform   AnswerType = "freeform"
	AnswerTypeFormula    AnswerType = "formula"
)

type OutputListItem struct {
	Beef        []byte
	OutputIndex uint32
}

type LookupQuestion struct {
	Service string
	Query   any
}

type LookupFormula interface{}

type LookupAnswer struct {
	Type    AnswerType
	Outputs []*OutputListItem
	Result  any
}

type LookupService interface {
	OutputAdded(ctx overlay.SubmitContext, outputIndex uint32, topic string) error
	OutputSpent(ctx overlay.SubmitContext, inputIndex uint32, topic string) error
	OutputDeleted(outpoint *overlay.Outpoint, topic string) error
	Lookup(question LookupQuestion) (LookupAnswer, error)
	GetDocumentation() string
	GetMetaData() overlay.MetaData
}

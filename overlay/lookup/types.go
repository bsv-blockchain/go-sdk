package lookup

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

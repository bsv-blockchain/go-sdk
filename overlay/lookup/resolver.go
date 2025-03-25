package lookup

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const MAX_TRACKER_WAIT_TIME = time.Second

type LookupResolver struct {
	Facilitator     Facilitator
	SLAPTrackers    []string
	HostOverrides   map[string][]string
	AdditionalHosts map[string][]string
	NetworkPreset   overlay.Network
}

func (l *LookupResolver) Query(question *LookupQuestion, timeout time.Duration) (*LookupAnswer, error) {
	var competentHosts []string
	if l.NetworkPreset == overlay.NetworkLocal {
		competentHosts = []string{"http://localhost:8080"}
	} else if question.Service == "ls_slap" {
		competentHosts = l.SLAPTrackers
	} else if hosts, ok := l.HostOverrides[question.Service]; ok {
		competentHosts = hosts
	} else {
		var err error
		if competentHosts, err = l.FindCompetentHosts(question.Service); err != nil {
			return nil, err
		}
	}
	if hosts, ok := l.AdditionalHosts[question.Service]; ok {
		competentHosts = append(competentHosts, hosts...)
	}
	if len(competentHosts) < 1 {
		return nil, errors.New("no-competent-hosts")
	}

	responses := make(chan *LookupAnswer, len(competentHosts))
	var wg sync.WaitGroup
	for _, host := range competentHosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if answer, err := l.Facilitator.Lookup(host, question, timeout); err != nil {
				log.Println("Error querying host", host, err)
			} else {
				responses <- answer
			}
		}(host)
	}
	wg.Wait()

	var successfulResponses []*LookupAnswer
	for result := range responses {
		if result != nil {
			successfulResponses = append(successfulResponses, result)
		}
	}

	if len(successfulResponses) == 0 {
		return nil, errors.New("no-successful-responses")
	}

	if successfulResponses[0].Type == AnswerTypeFreeform {
		return successfulResponses[0], nil
	}

	outputsMap := make(map[string]*OutputListItem)
	for _, response := range successfulResponses {
		if response.Type != AnswerTypeOutputList {
			continue
		}
		for _, output := range response.Outputs {
			if tx, err := transaction.NewTransactionFromBEEF(output.Beef); err != nil {
				log.Println("Error parsing transaction ID:", err)
			} else {
				outputsMap[fmt.Sprintf("%s.%d", tx.TxID().String(), output.OutputIndex)] = output
			}
		}
	}
	answer := &LookupAnswer{
		Type:    AnswerTypeOutputList,
		Outputs: make([]*OutputListItem, 0, len(outputsMap)),
	}
	for _, output := range outputsMap {
		answer.Outputs = append(answer.Outputs, output)
	}
	return answer, nil
}

func (l *LookupResolver) FindCompetentHosts(service string) ([]string, error) {
	query := &LookupQuestion{
		Service: "ls_slap",
		Query:   map[string]string{"service": service},
	}

	responses := make(chan *LookupAnswer, len(l.SLAPTrackers))
	var wg sync.WaitGroup
	for _, url := range l.SLAPTrackers {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if answer, err := l.Facilitator.Lookup(url, query, MAX_TRACKER_WAIT_TIME); err != nil {
				log.Println("Error querying tracker", url, err)
			} else {
				responses <- answer
			}
		}(url)
	}
	wg.Wait()

	hosts := make(map[string]struct{})
	for result := range responses {
		if result.Type != AnswerTypeOutputList {
			continue
		}
		for _, output := range result.Outputs {
			if tx, err := transaction.NewTransactionFromBEEF(output.Beef); err != nil {
				log.Println("Error parsing transaction ID:", err)
			} else {
				script := tx.Outputs[output.OutputIndex].LockingScript
				if parsed, err := admintoken.Decode(script); err != nil {
					log.Println("Error parsing overlay admin token template:", err)
				} else if parsed.TopicOrService != service || parsed.Protocol != "SLAP" {
					continue
				} else {
					hosts[parsed.Domain] = struct{}{}
				}
			}
		}
	}

	return nil, nil
}

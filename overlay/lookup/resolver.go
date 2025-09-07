package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const MAX_TRACKER_WAIT_TIME = time.Second

var DEFAULT_SLAP_TRACKERS = []string{"https://users.bapp.dev"}
var DEFAULT_TESTNET_SLAP_TRACKERS = []string{"https://testnet-users.bapp.dev"}

// LookupResolver resolves overlay service hosts and executes lookup queries with resiliency across multiple services
type LookupResolver struct {
	Facilitator     Facilitator
	SLAPTrackers    []string
	HostOverrides   map[string][]string
	AdditionalHosts map[string][]string
	NetworkPreset   overlay.Network
}

// NewLookupResolver creates a new LookupResolver with the provided configuration
func NewLookupResolver(cfg *LookupResolver) *LookupResolver {
	resolver := &LookupResolver{
		Facilitator:     cfg.Facilitator,
		SLAPTrackers:    cfg.SLAPTrackers,
		HostOverrides:   cfg.HostOverrides,
		AdditionalHosts: cfg.AdditionalHosts,
		NetworkPreset:   cfg.NetworkPreset,
	}
	if resolver.Facilitator == nil {
		resolver.Facilitator = &HTTPSOverlayLookupFacilitator{
			Client: http.DefaultClient,
		}
	}
	if resolver.SLAPTrackers == nil {
		if resolver.NetworkPreset == overlay.NetworkMainnet {
			resolver.SLAPTrackers = DEFAULT_SLAP_TRACKERS
		} else {
			resolver.SLAPTrackers = DEFAULT_TESTNET_SLAP_TRACKERS
		}
	}
	if resolver.HostOverrides == nil {
		resolver.HostOverrides = make(map[string][]string)
	}
	if resolver.AdditionalHosts == nil {
		resolver.AdditionalHosts = make(map[string][]string)
	}
	return resolver
}

// Query executes a lookup question and aggregates responses from multiple overlay service hosts
func (l *LookupResolver) Query(ctx context.Context, question *LookupQuestion) (*LookupAnswer, error) {
	var competentHosts []string
	if l.NetworkPreset == overlay.NetworkLocal {
		competentHosts = []string{"http://localhost:8080"}
	} else if question.Service == "ls_slap" {
		competentHosts = l.SLAPTrackers
	} else if hosts, ok := l.HostOverrides[question.Service]; ok {
		competentHosts = hosts
	} else {
		var err error
		if competentHosts, err = l.FindCompetentHosts(ctx, question.Service); err != nil {
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
			if answer, err := l.Facilitator.Lookup(ctx, host, question); err != nil {
				slog.Error("Error querying host", "host", host, "error", err)
			} else {
				responses <- answer
			}
		}(host)
	}
	wg.Wait()
	close(responses)

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
			if beef, err := transaction.NewBeefFromBytes(output.Beef); err != nil {
				slog.Error(fmt.Sprintf("Error parsing BEEF: %v", err))
			} else if tx := findTransactionForOutput(beef, output.OutputIndex); tx == nil {
				slog.Error(fmt.Sprintf("Error finding transaction for output index: %v", output.OutputIndex))
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

// FindCompetentHosts discovers overlay service hosts that can handle the specified service using SLAP trackers
func (l *LookupResolver) FindCompetentHosts(ctx context.Context, service string) (competentHosts []string, err error) {
	query := &LookupQuestion{
		Service: "ls_slap",
	}
	if query.Query, err = json.Marshal(map[string]any{"service": service}); err != nil {
		return nil, fmt.Errorf("error marshalling query: %w", err)
	}

	responses := make(chan *LookupAnswer, len(l.SLAPTrackers))
	var wg sync.WaitGroup
	for _, url := range l.SLAPTrackers {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			ctxWithTimeout, cancel := context.WithTimeout(ctx, MAX_TRACKER_WAIT_TIME)
			defer cancel()

			if answer, err := l.Facilitator.Lookup(ctxWithTimeout, url, query); err != nil {
				slog.Error(fmt.Sprintf("Error querying tracker: %s %v", url, err))
			} else {
				responses <- answer
			}
		}(url)
	}
	wg.Wait()
	close(responses)

	hosts := make(map[string]struct{})
	for result := range responses {
		if result.Type != AnswerTypeOutputList {
			continue
		}
		for _, output := range result.Outputs {
			if beef, err := transaction.NewBeefFromBytes(output.Beef); err != nil {
				slog.Error("Error parsing BEEF:", err)
			} else if tx := findTransactionForOutput(beef, output.OutputIndex); tx == nil {
				slog.Error("Error finding transaction for output index:", output.OutputIndex)
			} else {
				script := tx.Outputs[output.OutputIndex].LockingScript
				if parsed := admintoken.Decode(script); parsed == nil || parsed.TopicOrService != service || parsed.Protocol != "SLAP" {
					continue
				} else if _, ok := hosts[parsed.Domain]; !ok {
					competentHosts = append(competentHosts, parsed.Domain)
					hosts[parsed.Domain] = struct{}{}
				}
			}
		}
	}

	return
}

// findTransactionForOutput finds the transaction in a BEEF that contains the specified output index
func findTransactionForOutput(beef *transaction.Beef, outputIndex uint32) *transaction.Transaction {
	// Try to find a transaction that has enough outputs to contain the requested index
	for _, beefTx := range beef.Transactions {
		if beefTx.Transaction != nil && len(beefTx.Transaction.Outputs) > int(outputIndex) {
			return beefTx.Transaction
		}
	}
	// If no transaction found with enough outputs, return any available transaction
	// This maintains compatibility with the original behavior
	for _, beefTx := range beef.Transactions {
		if beefTx.Transaction != nil {
			return beefTx.Transaction
		}
	}
	return nil
}

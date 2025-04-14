package topic

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type RequireAck int

const (
	RequireAckNone RequireAck = 0
	RequireAckAny  RequireAck = 1
	RequireAckSome RequireAck = 2
	RequireAckAll  RequireAck = 3
)

type AckFrom struct {
	RequireAck RequireAck
	Topics     []string
}

type Response struct {
	Host    string
	Success bool
	Steak   *overlay.Steak
	Error   error
}

type BroadcasterConfig struct {
	NetworkPreset overlay.Network
	Facilitator   Facilitator
	Resolver      *lookup.LookupResolver
	AckFromAll    *AckFrom
	AckFromAny    *AckFrom
	AckFromHost   map[string]AckFrom
}
type Broadcaster struct {
	Topics        []string
	Facilitator   Facilitator
	Resolver      lookup.LookupResolver
	AckFromAll    AckFrom
	AckFromAny    AckFrom
	AckFromHost   map[string]AckFrom
	NetworkPreset overlay.Network
}

func NewBroadcaster(topics []string, cfg *BroadcasterConfig) (*Broadcaster, error) {
	if topics == nil {
		return nil, fmt.Errorf("at least 1 topic required")
	}
	for _, topic := range topics {
		if !strings.HasPrefix(topic, "tm_") {
			return nil, fmt.Errorf("topic %s must start with 'tm_'", topic)
		}
	}
	broadcaster := &Broadcaster{
		Topics:      topics,
		Facilitator: cfg.Facilitator,
	}
	if cfg.Facilitator == nil {
		broadcaster.Facilitator = &HTTPSOverlayBroadcastFacilitator{
			Client: http.DefaultClient,
		}
	}
	if cfg.Resolver != nil {
		broadcaster.Resolver = *cfg.Resolver
	} else {
		broadcaster.Resolver = *lookup.NewLookupResolver(&lookup.LookupResolver{})
	}
	if cfg.AckFromAll != nil {
		broadcaster.AckFromAll = *cfg.AckFromAll
	} else {
		broadcaster.AckFromAll = AckFrom{RequireAck: RequireAckNone}
	}
	if cfg.AckFromAny != nil {
		broadcaster.AckFromAny = *cfg.AckFromAny
	} else {
		broadcaster.AckFromAny = AckFrom{RequireAck: RequireAckAll}
	}
	if cfg.AckFromHost != nil {
		broadcaster.AckFromHost = cfg.AckFromHost
	} else {
		broadcaster.AckFromHost = make(map[string]AckFrom)
	}

	return broadcaster, nil
}

func (b *Broadcaster) Broadcast(tx *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return b.BroadcastCtx(context.Background(), tx)
}

func (b *Broadcaster) BroadcastCtx(ctx context.Context, tx *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	taggedBeef := &overlay.TaggedBEEF{
		Topics: b.Topics,
	}
	var err error
	var interestedHosts []string
	if taggedBeef.Beef, err = tx.AtomicBEEF(false); err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "400",
			Description: err.Error(),
		}
	} else if b.NetworkPreset == overlay.NetworkLocal {
		interestedHosts = append(interestedHosts, "http://localhost:8080")
	} else if interestedHosts, err = b.FindInterestedHosts(ctx); err != nil {
		return nil, &transaction.BroadcastFailure{
			Code:        "500",
			Description: err.Error(),
		}
	}

	if len(interestedHosts) == 0 {
		return nil, &transaction.BroadcastFailure{
			Code:        "ERR_NO_HOSTS_INTERESTED",
			Description: fmt.Sprintf("No %s hosts are interested in receiving this transaction.", overlay.NetworkNames[b.NetworkPreset]),
		}
	}
	var wg sync.WaitGroup
	results := make(chan *Response, len(interestedHosts))
	for _, host := range interestedHosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if steak, err := b.Facilitator.Send(host, taggedBeef); err != nil {
				results <- &Response{
					Host:  host,
					Error: err,
				}
			} else {
				results <- &Response{
					Host:    host,
					Success: true,
					Steak:   steak,
				}
			}
		}(host)
	}
	wg.Wait()

	successfulHosts := make([]*Response, 0, len(interestedHosts))
	for result := range results {
		if result != nil {
			successfulHosts = append(successfulHosts, result)
		}
	}
	if len(successfulHosts) == 0 {
		return nil, &transaction.BroadcastFailure{
			Code:        "ERR_ALL_HOSTS_REJECTED",
			Description: fmt.Sprintf("`All %s topical hosts have rejected the transaction.", overlay.NetworkNames[b.NetworkPreset]),
		}
	}
	hostAcks := make(map[string]map[string]struct{})
	for _, result := range successfulHosts {
		ackTopics := make(map[string]struct{})
		for topic, admittance := range *result.Steak {
			if len(admittance.OutputsToAdmit) > 0 || len(admittance.CoinsToRetain) > 0 || len(admittance.CoinsRemoved) > 0 {
				ackTopics[topic] = struct{}{}
			}
		}
		hostAcks[result.Host] = ackTopics
	}

	var requireTopics []string
	var requireHosts RequireAck
	switch b.AckFromAll.RequireAck {
	case RequireAckAny:
		requireTopics = b.Topics
		requireHosts = RequireAckAny
	case RequireAckSome:
		requireTopics = b.AckFromAll.Topics
		requireHosts = RequireAckAll
	default:
		requireTopics = b.Topics
		requireHosts = RequireAckAll
	}
	if len(requireTopics) > 0 {
		if !b.checkAcknowledgmentFromAllHosts(hostAcks, requireTopics, requireHosts) {
			return nil, &transaction.BroadcastFailure{
				Code:        "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED",
				Description: "Not all hosts acknowledged the required topics.",
			}
		}
	}

	switch b.AckFromAny.RequireAck {
	case RequireAckAny:
		requireTopics = b.Topics
		requireHosts = RequireAckAny
	case RequireAckSome:
		requireTopics = b.AckFromAny.Topics
		requireHosts = RequireAckAll
	default:
		requireTopics = b.Topics
		requireHosts = RequireAckAll
	}
	if len(requireTopics) > 0 {
		if !b.checkAcknowledgmentFromAnyHost(hostAcks, requireTopics, requireHosts) {
			return nil, &transaction.BroadcastFailure{
				Code:        "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED",
				Description: "No host acknowledged the required topics.",
			}
		}
	}

	if len(b.AckFromHost) > 0 {
		if !b.checkAcknowledgmentFromSpecificHosts(hostAcks, b.AckFromHost) {
			return nil, &transaction.BroadcastFailure{
				Code:        "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED",
				Description: "Specific hosts did not acknowledge the required topics.",
			}
		}
	}

	return &transaction.BroadcastSuccess{
		Txid:    tx.TxID().String(),
		Message: fmt.Sprintf("Sent to %d Overlay Service host(s)", len(successfulHosts)),
	}, nil
}

func (b *Broadcaster) FindInterestedHosts(ctx context.Context) ([]string, error) {
	results := make(map[string]map[string]struct{})
	query, err := json.Marshal(map[string][]string{
		"topics": b.Topics,
	})
	if err != nil {
		return nil, err
	}
	answer, err := b.Resolver.Query(
		ctx,
		&lookup.LookupQuestion{
			Service: "ls_ship",
			Query:   query,
		},
		MAX_SHIP_QUERY_TIMEOUT,
	)
	if err != nil {
		return nil, err
	}
	if answer.Type != lookup.AnswerTypeOutputList {
		return nil, fmt.Errorf("SHIP answer is not an output list")
	}
	for _, output := range answer.Outputs {
		tx, err := transaction.NewTransactionFromBEEF(output.Beef)
		if err != nil {
			continue
		}
		script := tx.Outputs[output.OutputIndex].LockingScript
		parsed, err := admintoken.Decode(script)
		if err != nil {
			log.Println(err)
			continue
		} else if !slices.Contains(b.Topics, parsed.TopicOrService) || parsed.Protocol != "SHIP" {
			continue
		} else if _, ok := results[parsed.Domain]; !ok {
			results[parsed.Domain] = make(map[string]struct{})
		}
		results[parsed.Domain][parsed.TopicOrService] = struct{}{}
	}
	interestedHosts := make([]string, 0, len(results))
	for host := range results {
		interestedHosts = append(interestedHosts, host)
	}
	return interestedHosts, nil
}

func (t *Broadcaster) checkAcknowledgmentFromAllHosts(hostAcks map[string]map[string]struct{}, topics []string, requireHost RequireAck) bool {
	for _, acknowledgedTopics := range hostAcks {
		if requireHost == RequireAckAll {
			for _, topic := range topics {
				if _, ok := acknowledgedTopics[topic]; !ok {
					return false
				}
			}
		} else if requireHost == RequireAckAny {
			anyAcknowledged := false
			for _, topic := range topics {
				if _, ok := acknowledgedTopics[topic]; ok {
					anyAcknowledged = true
					break
				}
			}
			if !anyAcknowledged {
				return false
			}
		}
	}
	return true
}

func (t *Broadcaster) checkAcknowledgmentFromAnyHost(hostAcks map[string]map[string]struct{}, topics []string, requireHost RequireAck) bool {
	for _, acknowledgedTopics := range hostAcks {
		if requireHost == RequireAckAll {
			for _, topic := range topics {
				if _, ok := acknowledgedTopics[topic]; !ok {
					return false
				}
			}
			return true
		} else {
			for _, topic := range topics {
				if _, ok := acknowledgedTopics[topic]; ok {
					return true
				}
			}
		}
	}
	return false
}

func (t *Broadcaster) checkAcknowledgmentFromSpecificHosts(hostAcks map[string]map[string]struct{}, requirements map[string]AckFrom) bool {
	for host, requiredHost := range requirements {
		acknowledgedTopics, ok := hostAcks[host]
		if !ok {
			return false
		}
		var requiredTopics []string
		var require RequireAck
		if requiredHost.RequireAck == RequireAckAll || requiredHost.RequireAck == RequireAckAny {
			require = requiredHost.RequireAck
			requiredTopics = t.Topics
		} else if requiredHost.RequireAck == RequireAckSome {
			require = RequireAckAll
			requiredTopics = requiredHost.Topics
		} else {
			continue
		}
		if require == RequireAckAll {
			for _, topic := range requiredTopics {
				if _, ok := acknowledgedTopics[topic]; !ok {
					return false
				}
			}
		} else if require == RequireAckAny {
			anyAcknowledged := false
			for _, topic := range requiredTopics {
				if _, ok := acknowledgedTopics[topic]; ok {
					anyAcknowledged = true
					break
				}
			}
			if !anyAcknowledged {
				return false
			}
		}
	}
	return true
}

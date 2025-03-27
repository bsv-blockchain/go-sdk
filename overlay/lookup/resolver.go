package lookup

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/bitcoin-sv/go-sdk/overlay"
)

const MAX_TRACKER_WAIT_TIME = time.Second

type LookupResolver struct {
	Facilitator     Facilitator
	SLAPTrackers    []string
	HostOverrides   map[string][]string
	AdditionalHosts map[string][]string
	NetworkPreset   overlay.Network
}

func (l *LookupResolver) Query(ctx context.Context, question LookupQuestion, timeout time.Duration) (LookupAnswer, error) {
	// // var competentHosts []string
	// if question.Service == "ls_slap" {
	// 	if l.NetworkPreset == types.NetworkLocal {
	// 		competentHosts = []string{"http://localhost:8080"}
	// 	} else {
	// 		competentHosts = l.SLAPTrackers
	// 	}
	// } else if overrides, ok := l.HostOverrides[question.Service]; ok {
	// 	competentHosts = overrides
	// } else if l.NetworkPreset == types.NetworkLocal {
	// 	competentHosts = []string{"http://localhost:8080"}
	// } else {
	// 	// competentHosts, err =
	// }
	return l.Facilitator.Lookup(ctx, l.SLAPTrackers[0], question, timeout)
}

func (l *LookupResolver) FindCompetentHosts(ctx context.Context, service string) ([]string, error) {
	query := LookupQuestion{
		Service: "ls_slap",
		Query:   map[string]string{"service": service},
	}

	responses := make(chan LookupAnswer, len(l.SLAPTrackers))
	var wg sync.WaitGroup
	for _, url := range l.SLAPTrackers {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if answer, err := l.Facilitator.Lookup(ctx, url, query, MAX_TRACKER_WAIT_TIME); err != nil {
				log.Println("Error querying tracker", url, err)
			} else {
				responses <- answer
			}
		}(url)
	}
	wg.Wait()

	// for result := range responses {
	// 	// if result.
	// }
	return nil, nil
}

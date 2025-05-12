# Overlay Tools

Overlay Tools is a collection of components to interact with the Overlay Services network, providing mechanisms for broadcasting transactions to service hosts and retrieving information via lookups.

## Core Concepts

### SHIP (Service Host Interconnect Protocol)
SHIP enables broadcasting transactions to Overlay Service hosts, which can then process these transactions according to their topic managers' rules. Clients can tag BEEF (Binary Encoded Envelope Format) with topics and submit them to hosts.

### SLAP (Service Lookup Availability Protocol)
SLAP allows discovering which hosts provide specific lookup services. SLAP servers maintain a registry of service advertisements, and clients can query these servers to find hosts that offer a particular service.

### Admittance Instructions
When a transaction is submitted through SHIP, the service host responds with Admittance Instructions for each topic, indicating which outputs should be admitted, which coins should be retained, and which are considered spent.

## Key Components

### TaggedBEEF
A transaction (in BEEF format) tagged with one or more topics for submission to Overlay hosts.

```go
type TaggedBEEF struct {
    Beef   []byte
    Topics []string
}
```

### Steak (Submitted Transaction Execution AcKnowledgment)
The response returned from a SHIP host after processing a submitted transaction.

```go
type Steak map[string]*AdmittanceInstructions

type AdmittanceInstructions struct {
    OutputsToAdmit []uint32
    CoinsToRetain  []uint32
    CoinsRemoved   []uint32
    AncillaryTxids []*chainhash.Hash
}
```

### LookupQuestion and LookupAnswer
The query sent to and response received from Overlay lookup services.

```go
type LookupQuestion struct {
    Service string          `json:"service"`
    Query   json.RawMessage `json:"query"`
}

type LookupAnswer struct {
    Type     AnswerType        `json:"type"`
    Outputs  []*OutputListItem `json:"outputs,omitempty"`
    Formulas []LookupFormula   `json:"-"`
    Result   any               `json:"result,omitempty"`
}
```

### BroadcastSuccess and BroadcastFailure
The response types returned when broadcasting a transaction.

```go
type BroadcastSuccess struct {
    Txid    string `json:"txid"`
    Message string `json:"message"`
}

type BroadcastFailure struct {
    Code        string `json:"code"`
    Description string `json:"description"`
}
```

## Broadcaster Interface

All broadcasters in the SDK implement the `Broadcaster` interface:

```go
type Broadcaster interface {
    Broadcast(tx *Transaction) (*BroadcastSuccess, *BroadcastFailure)
    BroadcastCtx(ctx context.Context, tx *Transaction) (*BroadcastSuccess, *BroadcastFailure)
}
```

The transaction type also provides convenience methods:

```go
func (t *Transaction) Broadcast(b Broadcaster) (*BroadcastSuccess, *BroadcastFailure)
func (t *Transaction) BroadcastCtx(ctx context.Context, b Broadcaster) (*BroadcastSuccess, *BroadcastFailure)
```

## TopicBroadcaster

The `TopicBroadcaster` implements the `Broadcaster` interface and submits transactions to Overlay Services hosts that are interested in specific topics.

```go
// Create a new broadcaster
broadcaster, err := topic.NewBroadcaster(
    []string{"tm_example"},
    &topic.BroadcasterConfig{
        NetworkPreset: overlay.NetworkMainnet,
    },
)

// Broadcast a transaction using default context
success, failure := broadcaster.Broadcast(transaction)

// Broadcast with a custom context
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
success, failure := broadcaster.BroadcastCtx(ctx, transaction)

// Or use the transaction's convenience methods
success, failure = transaction.Broadcast(broadcaster)
success, failure = transaction.BroadcastCtx(ctx, broadcaster)
```

The broadcaster handles finding interested hosts via SLAP, sending the transaction to these hosts, and verifying the acknowledgments from hosts meet the configured requirements.

## Lookup Resolver

The `LookupResolver` facilitates lookups to Overlay Services hosts, with support for aggregating responses across multiple hosts.

```go
// Create a resolver
resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
    NetworkPreset: overlay.NetworkMainnet,
})

// Perform a lookup
ctx := context.Background()
question := &lookup.LookupQuestion{
    Service: "ls_example",
    Query:   json.RawMessage(`{"key": "value"}`),
}
answer, err := resolver.Query(ctx, question, 5*time.Second)
```

## Admin Token

The `OverlayAdminTokenTemplate` enables the creation and unlocking of SHIP and SLAP advertisement tokens, allowing hosts to advertise their services.

```go
template := &admintoken.OverlayAdminTokenTemplate{
    PushDrop: myPushDropTemplate,
}

// Create a SHIP advertisement
ctx := context.Background()
lockingScript, err := template.Lock(
    ctx,
    overlay.ProtocolSHIP,
    "https://example.com",
    "tm_example",
)

// Unlock a SHIP advertisement
unlocker := template.Unlock(
    ctx,
    overlay.ProtocolSHIP,
)
```

## Network Presets

The SDK supports several network presets for easy configuration:

```go
var (
    NetworkMainnet Network = 0
    NetworkTestnet Network = 1
    NetworkLocal   Network = 2
)
```

- `NetworkMainnet`: Uses mainnet SLAP trackers and HTTPS facilitator
- `NetworkTestnet`: Uses testnet SLAP trackers and HTTPS facilitator
- `NetworkLocal`: Directly queries localhost:8080 with a facilitator that permits HTTP

## Default SLAP Trackers

The SDK provides default SLAP trackers for both mainnet and testnet networks:

```go
var DEFAULT_SLAP_TRACKERS = []string{"https://users.bapp.dev"}
var DEFAULT_TESTNET_SLAP_TRACKERS = []string{"https://testnet-users.bapp.dev"}
```

## Facilitators

Facilitators handle the actual HTTP communication with Overlay Services hosts:

### HTTPSOverlayLookupFacilitator

Handles lookup requests to hosts:

```go
facilitator := &lookup.HTTPSOverlayLookupFacilitator{
    Client: http.DefaultClient,
}
ctx := context.Background()
answer, err := facilitator.Lookup(ctx, "https://example.com", question, timeout)
```

### HTTPSOverlayBroadcastFacilitator

Handles sending BEEF to hosts:

```go
facilitator := &topic.HTTPSOverlayBroadcastFacilitator{
    Client: http.DefaultClient,
}
steak, err := facilitator.Send("https://example.com", taggedBeef)
```

## Configuration Examples

### Full TopicBroadcaster Configuration

```go
broadcaster, err := topic.NewBroadcaster(
    []string{"tm_example"},
    &topic.BroadcasterConfig{
        NetworkPreset: overlay.NetworkMainnet,
        Facilitator:   customFacilitator,
        Resolver:      customResolver,
        AckFromAll:    &topic.AckFrom{RequireAck: topic.RequireAckAll, Topics: []string{"tm_important"}},
        AckFromAny:    &topic.AckFrom{RequireAck: topic.RequireAckAny, Topics: []string{"tm_optional"}},
    },
)
```

### Full LookupResolver Configuration

```go
resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
    NetworkPreset:   overlay.NetworkMainnet,
    Facilitator:     customFacilitator,
    SLAPTrackers:    []string{"https://custom-tracker.example.com"},
    HostOverrides:   map[string][]string{"ls_example": {"https://fixed-host.example.com"}},
    AdditionalHosts: map[string][]string{"ls_example": {"https://extra-host.example.com"}},
})
```

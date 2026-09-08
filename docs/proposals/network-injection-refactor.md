# Proposal: Injectable HTTP Clients for All Network Paths

**Status:** Proposal — *not implemented*. Filed for team review.

**Author:** @mrz1836

**Related work:** `feature/test-coverage-benchmarks-fuzz` (test-hermeticity, benchmarks, fuzzing).
That branch made the unit tests network-free **without touching production code**. This document
captures the *production* changes that were deliberately deferred, because they alter public-facing
behavior across every SDK consumer and therefore need a coordinated review + release.

<br>

## Motivation

The SDK already defines a clean seam for HTTP injection:

```go
// util/http-client.go
type HTTPClient interface {
    Do(req *http.Request) (*http.Response, error)
}
```

Several production types accept a `util.HTTPClient` (e.g. `broadcaster.WhatsOnChain`,
`broadcaster.Arc`, `broadcaster.TAALBroadcast`, `overlay/lookup.HTTPSOverlayLookupFacilitator`),
which makes them trivially mockable. But a handful of network paths **bypass that seam**:

- they call `http.DefaultClient.Do` directly, or
- they construct an inline `&http.Client{}` per call, or
- they hold an `HTTPClient` field but never use it.

For those paths a test can only be made hermetic by swapping the process-global
`http.DefaultTransport` (see `transaction/broadcaster/stub_transport_test.go`) — a real but blunt
technique: it mutates global state, forbids `t.Parallel()`, and cannot assert on the request the way
an injected mock can. Routing every path through `util.HTTPClient` would remove the need for the
global swap and let every consumer inject timeouts, tracing, retries, and test doubles uniformly.

The changes below are ordered from lowest to highest blast radius.

<br>

---

## 1. `transaction/broadcaster/taal.go` — nil `Client` panics

**Current** (`taal.go:53`): `BroadcastCtx` dereferences `b.Client` with no nil guard.

```go
type TAALBroadcast struct {
    ApiKey string
    Client util.HTTPClient
}

func (b *TAALBroadcast) BroadcastCtx(ctx context.Context, t *transaction.Transaction) (...) {
    // ...
    if resp, err := b.Client.Do(req); err != nil { // panics if b.Client == nil
```

This is inconsistent with `WhatsOnChain` (`woc.go:46`) and `Arc` (`arc.go:136`, `arc.go:205`), which
both default a nil `Client` to `http.DefaultClient`.

**Proposed:** default it, matching the sibling broadcasters.

```go
if b.Client == nil {
    b.Client = http.DefaultClient
}
if resp, err := b.Client.Do(req); err != nil {
```

**Backward-compat / risk:** **Very low.** Turns a guaranteed nil-pointer panic into a working default.
No existing caller that sets `Client` is affected. The only behavior change is for callers that today
crash; they would instead perform a real broadcast — acceptable, and consistent with the other
broadcasters.

**Testability win:** the `Client == nil` branch becomes assertable with an injected mock instead of
requiring the global-transport swap.

<br>

---

## 2. `transaction/chaintracker/headers_client/headers_client.go` — inline clients bypass `getHTTPClient()`

**Current:** the type already has an injection helper (`headers_client.go:43`):

```go
func (c *Client) getHTTPClient() *http.Client {
    if c.httpClient != nil {
        return c.httpClient
    }
    return &http.Client{}
}
```

`GetMerkleRoots`, `RegisterWebhook`, `UnregisterWebhook`, and `GetWebhook` correctly route through it.
But four methods build a fresh inline `&http.Client{}` and ignore the helper entirely:

- `IsValidRootForHeight` (`headers_client.go:70`)
- `BlockByHeight` (`headers_client.go:96`)
- `GetBlockState` (`headers_client.go:130`)
- `GetChaintip` (`headers_client.go:149`)

```go
client := &http.Client{}          // ignores c.httpClient
resp, err := client.Do(req)
```

**Proposed:** replace each inline `&http.Client{}` with `c.getHTTPClient()`.

```go
resp, err := c.getHTTPClient().Do(req)
```

Optionally add an exported setter/option so callers can supply `httpClient` (today the field is
unexported and can only be set within the package).

**Backward-compat / risk:** **Low.** `getHTTPClient()` already returns `&http.Client{}` when
`httpClient` is nil, so the default behavior is byte-for-byte identical. The only change is that a
`httpClient` set on the struct is finally honored by all four methods — which is the documented intent
of the field.

**Testability win:** all four methods become injectable; today they can only be exercised against a
`httptest` server (the current tests already do this, so no test regression) but never with a mock
that asserts on the request or simulates transport errors without a live listener.

<br>

---

## 3. `transaction/chaintracker/whatsonchain.go` — unused `client` field + direct `http.DefaultClient`

**Current:** the struct holds a `client` field that is set in the constructor but **never read**
(`whatsonchain.go:34`, `:46`), and both methods call `http.DefaultClient.Do` directly
(`whatsonchain.go:60`, `:99`):

```go
type WhatsOnChain struct {
    Network Network
    ApiKey  string
    baseURL string
    client  *http.Client // set in NewWhatsOnChain, never used
}

func NewWhatsOnChain(network Network, apiKey string) *WhatsOnChain {
    return &WhatsOnChain{
        // ...
        client: http.DefaultClient,
    }
}

func (w *WhatsOnChain) GetBlockHeader(ctx context.Context, height uint32) (...) {
    // ...
    resp, err := http.DefaultClient.Do(req) // ignores w.client
}
```

**Proposed:**

1. Change the field type from `*http.Client` to `util.HTTPClient` and actually use it:

   ```go
   type WhatsOnChain struct {
       Network Network
       ApiKey  string
       baseURL string
       client  util.HTTPClient
   }

   func (w *WhatsOnChain) GetBlockHeader(ctx context.Context, height uint32) (...) {
       // ...
       resp, err := w.client.Do(req)
   }
   ```

2. Add an option/setter (e.g. `WithHTTPClient(util.HTTPClient)` or a functional-options variant of
   `NewWhatsOnChain`) so callers can inject a client. Keep the `http.DefaultClient` default in the
   constructor.

**Backward-compat / risk:** **Medium (source-compatible, behavior change).** The field is unexported,
so no consumer references it — the struct-shape change is source-compatible. The behavioral change is
that `w.client` is now honored instead of always using `http.DefaultClient`; for existing callers
(who never had a way to set it) the effective default is unchanged. The one subtlety: constructing
the struct as a bare literal `&WhatsOnChain{...}` (bypassing `NewWhatsOnChain`) would leave `client`
nil and then panic; a nil-guard defaulting to `http.DefaultClient` inside the methods removes that
foot-gun.

**Testability win:** removes the dead field, and lets tests inject a mock instead of pointing
`baseURL` at a `httptest` server (the current tests point `baseURL` at `httptest`, which stays valid).

<br>

---

## 4. `storage/downloader.go` — per-call inline `&http.Client{Timeout: 30s}`

**Current** (`downloader.go:126`): `Download` builds a fresh client with a hard-coded 30s timeout that
cannot be overridden or mocked:

```go
func (d *StorageDownloader) Download(ctx context.Context, uhrpURL string) (DownloadResult, error) {
    // ...
    client := &http.Client{
        Timeout: time.Second * 30,
    }
    // ...
    resp, err := client.Do(req)
}
```

The host-download loop is the one part of `StorageDownloader` that a test cannot currently reach
without a live `httptest` server (the existing tests do exactly that).

**Proposed:** add an injectable `util.HTTPClient` to `DownloaderConfig` and `StorageDownloader`,
defaulting to `&http.Client{Timeout: 30 * time.Second}` when unset:

```go
type DownloaderConfig struct {
    Network overlay.Network
    Client  util.HTTPClient // optional; defaults to a 30s-timeout http.Client
}

type StorageDownloader struct {
    resolver *lookup.LookupResolver
    client   util.HTTPClient
}

func NewStorageDownloader(cfg DownloaderConfig) *StorageDownloader {
    client := cfg.Client
    if client == nil {
        client = &http.Client{Timeout: 30 * time.Second}
    }
    // ...
    return &StorageDownloader{resolver: resolver, client: client}
}
```

**Backward-compat / risk:** **Low–Medium.** Adding a field to `DownloaderConfig` is source-compatible
(struct literals with field names keep compiling; positional literals — unlikely for a config — would
break). Default behavior (30s timeout) is preserved. Consumers gain the ability to set timeouts,
transports, and test doubles.

**Testability win:** the download loop (status ≥ 400, hash mismatch, body-read error, all-hosts-fail)
becomes assertable with a mock, without spinning up `httptest` servers.

<br>

---

## Summary

| # | Location | Change | Risk | Consumer-visible? |
|---|----------|--------|------|-------------------|
| 1 | `broadcaster/taal.go:53` | default nil `Client` to `http.DefaultClient` | Very low | Panic → works |
| 2 | `chaintracker/headers_client` (4 methods) | use existing `getHTTPClient()` | Low | No (default identical) |
| 3 | `chaintracker/whatsonchain.go` | use the `client` field (typed `util.HTTPClient`) + setter | Medium | Source-compatible |
| 4 | `storage/downloader.go:126` | injectable `util.HTTPClient` on config | Low–Medium | New optional field |

**Common theme:** every one of these already *could* funnel through `util.HTTPClient`; the seam
exists. Adopting it uniformly would (a) let every network path be mocked at the interface, (b) remove
the need for the process-global `http.DefaultTransport` swap used by the current hermetic tests, and
(c) give consumers a single, consistent place to configure timeouts, retries, and tracing.

**Recommended sequencing:** land #1 and #2 first (near-zero risk, no public API change), then #3 and
#4 together in a minor release with release notes calling out the new options.

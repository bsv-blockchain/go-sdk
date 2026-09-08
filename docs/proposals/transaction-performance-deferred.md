# Proposal: Deferred Transaction Performance Candidates

**Status:** Proposal — *not implemented*. Filed for team review.

**Author:** go-sdk maintainers

**Related work:** `feature/transaction-performance` landed the non-breaking,
benchstat-proven wins (arithmetic `Size()`, direct-append serialization, the
additive `SigHashCache` for O(N) signing, and `OutputsHash` pre-sizing) under
the gate in `go-bt-porting-procedure.md`. This document captures the candidates
that were **deliberately deferred** because they add public API, change
observable behavior, touch consensus-critical/rarely-exercised code, or deliver
a win within the measurement noise. Each needs its own review before landing.

<br>

## 1. Guarded pre-sizing of `Transaction.ReadFrom` slices

**Current** (`transaction.go` `ReadFrom`): `tx.Inputs`/`tx.Outputs` are grown
with `append` in the parse loops, with no pre-allocation. The loop is already
DoS-safe because it reads one element at a time and stops when the reader is
exhausted.

**Proposed:** call `guardParseCount(r, count, minBytesPerElem, ...)` (min 41 for
an input, 9 for an output) and then `make([]*T, 0, count)` before each loop,
mirroring `merklepath.go`/`beef.go`.

**Why deferred:** the only saving is the handful of slice-regrowth reallocations
(~1–2% of parse allocations at 64 inputs; per-element allocations dominate), which
is within the run-to-run noise band, so it fails acceptance-gate #4. Pre-sizing an
attacker-controlled count is only safe *after* the guard, so it adds guard
plumbing and `//nolint:gosec` conversions to fuzzed, consensus-critical code for
a sub-noise gain. Revisit if parse throughput becomes a measured bottleneck.

**Risk:** Low, but non-zero (parser). Guarded by the parser fuzz targets.

<br>

## 2. Legacy (pre-fork) sighash preimage optimization

**Current** (`signaturehash.go` `CalcInputPreimageLegacy`): `ShallowClone`s the
whole transaction per call, then serializes into an un-presized `make([]byte, 0)`
with a `make([]byte, 4/8)` scratch slice and a `VarInt.Bytes()` allocation per
input and per output (inputs=64: ~333 allocations for a single preimage).

**Proposed:** pre-size the buffer via arithmetic and append with the shared
zero-alloc writers (as done for the BIP143 path), and evaluate eliminating the
per-call `ShallowClone` by serializing the modified view directly.

**Why deferred:** the legacy (non-`FORKID`) algorithm is effectively unused on
BSV, and — unlike the BIP143 path — its exact bytes are **not** pinned by a
golden test (`TestGoldenSigHashDigests` covers only `FORKID` flags). Landing it
safely requires first adding a legacy golden characterization test, then a
careful byte-for-byte refactor of consensus-critical code, for a rarely-hit path.

**Prerequisite:** add golden digests for the legacy flags (`All`, `None`,
`Single`, each with/without `AnyOneCanPay`) before touching the code.

**Risk:** Medium (consensus-critical, currently under-pinned).

<br>

## 3. Opt-in cached txid (`SetTxHash`) — go-bt pattern

**Current** (`transaction.go` `TxID`): re-serializes and double-hashes on every
call; there is no cache (the struct's fields are all exported and mutable, so a
read-populated cache could silently go stale).

**Proposed:** add an unexported `atomic.Pointer[chainhash.Hash]` populated
**only** by an explicit `SetTxHash(*chainhash.Hash)` and read by `TxID` — never
auto-populated (go-bt's `tx.go` approach). Callers that know a transaction is
immutable opt in; the getter never writes the cache, so it cannot go stale on
its own.

**Why deferred:** additive but semantics-sensitive — it places an
immutability contract on the caller. Needs a documented policy and review.
(Within a single operation, redundant `TxID()` calls should first be hoisted to
a local — a pure, non-caching win worth doing independently; see item 8.)

**Risk:** Medium (staleness foot-gun if misused).

<br>

## 4. Zero-alloc streaming serialization API (`AppendBytes` / `WriteTo`)

*Implemented on this branch.* `AppendBytes(dst []byte) []byte` appends the raw
serialization into a caller-provided buffer (0 B / 0 allocs when the buffer is
reused), and `WriteTo(io.Writer) (int64, error)` streams it field-by-field via a
stack buffer (a constant ~16 B/op regardless of transaction size), implementing
io.WriterTo. `toBytesHelper` delegates to a shared `appendBytesHelper`, so
`Bytes()`/`EF()` are unchanged and byte-identical. Both are backward-compatible
additive methods (semver-minor).

**Risk:** Low (purely additive) — landed.

<br>

## 5. Arena allocator for batch deserialization (`ReadFromWithArena`)

**Proposed:** port go-bt's bump-allocator (`arena.go` + `ReadFromWithArena`
variants) to amortize per-script `[]byte` allocations when decoding many
transactions. The base `ReadFrom` stays unchanged (passes a nil arena).

**Why deferred:** new public API with a lifetime contract (slices are invalid
after `Reset`) and a single-goroutine ownership constraint. Only worthwhile for
bulk-decode workloads and needs careful API + safety review.

**Risk:** Medium (lifetime/aliasing contract).

<br>

## 6. `Clone()` field-copy rewrite (+ remove `log.Fatal`)

**Current** (`transaction.go` `Clone`): clones via `NewTransactionFromBytes(tx.Bytes())`
— a full serialize + full re-parse — and calls `log.Fatal` on error (which would
`os.Exit` a consuming process).

**Proposed:** build the clone by deep-copying fields (as `ShallowClone` does, but
recursing into source transactions) and return an error instead of `log.Fatal`.

**Why deferred:** removing `log.Fatal` changes error behavior on malformed input
(a behavior change, even though a validly-constructed tx never hits it), and
changing the signature to return an error would break callers. Needs a decision
on the error contract.

**Risk:** Medium (behavior/signature change).

<br>

## 7. Merkle / BEEF deep optimization

**Current:** `merklepath.go` `ComputeRoot` allocates a map per tree level and a
`PathElement` per interior node; `MerkleTreeParent` allocates a 64-byte concat
per call; `MerklePath.Bytes` is un-presized and `CloneBytes()`es each leaf;
`Beef.Bytes`/`AtomicBytes` copy each transaction two–three times.

**Proposed:** reuse a single 64-byte scratch in `MerkleTreeParent`, pre-size
`MerklePath.Bytes`, slice leaf hashes with `[:]`, and remove the redundant BEEF
buffer copies.

**Why deferred:** medium risk on merkle-root byte-identity; a larger surface than
the core tx paths. Should be its own reviewed change with `ComputeRoot`/BEEF
benchmarks and the BEEF golden round-trips as guards.

**Risk:** Medium (merkle-root correctness).

<br>

## 8. Smaller, independent follow-ups

- **Hoist redundant `TxID()` within a single operation** — *implemented on this
  branch* for `AddMerkleProof`, the `NewBeefFromBytes` V1 nested BUMP×leaf loop,
  `AtomicBEEF`, and `collectAncestors`. A residual opportunity remains in
  `ValidateTransactions`, where a validated txid is recomputed across the
  separate result-collection loops; hoisting it would need a per-tx map and is
  lower value.
- **PushDrop cache adoption.** `pushdrop.Unlocker.Sign(tx, inputIndex int)` does
  not implement `UnlockingScriptTemplate` (it takes `int`, and `EstimateLength`
  takes no args), so it is driven manually rather than by `tx.Sign()` and does
  not benefit from the `SigHashCache` dispatch. If it is migrated to the standard
  template interface, also add `SignWithCache` so multi-input PushDrop signing is
  O(N).
- **Normalize `script/interpreter/opcodeparser_bench_test.go`** to `b.Loop()` +
  `b.ReportAllocs()` so its results are comparable to the rest of the suite.

<br>

## Summary

| # | Candidate | Kind | Risk |
|---|-----------|------|------|
| 1 | Guarded `ReadFrom` pre-size | pure internal | Low (sub-noise win) |
| 2 | Legacy sighash preimage | pure internal | Medium (under-pinned) |
| 3 | `SetTxHash` opt-in txid cache | additive | Medium (staleness) |
| 4 | `AppendBytes`/`WriteTo` — *implemented* | additive | Low |
| 5 | Arena allocator | additive | Medium (lifetime) |
| 6 | `Clone()` rewrite | behavior/signature | Medium |
| 7 | Merkle/BEEF deep opt | pure internal | Medium (correctness) |
| 8 | PushDrop cache, bench normalize (+ residual `ValidateTransactions` txid) | mixed | Low |

**Recommended sequencing:** the additive `SetTxHash` cache (3) behind a reviewed
minor release, then the higher-risk internal refactors (2, 7) each with a
characterization test added first, and finally 5 and 6 as separate reviewed
changes.

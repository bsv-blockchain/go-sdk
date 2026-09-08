# Procedure: Porting Performance Improvements Safely (incl. from go-bt)

**Status:** Adopted procedure — used by the `feature/transaction-performance` work.

**Author:** go-sdk maintainers

**Related work:** the transaction hot-path optimizations on
`feature/transaction-performance` (arithmetic `Size()`, direct-append
serialization, `SigHashCache`, `OutputsHash` pre-sizing). Each landed as a
small, benchstat-proven, behavior-preserving commit using the gate below.

<br>

## Purpose

`github.com/bsv-blockchain/go-sdk` is widely consumed, so performance work must
not change observable behavior or break the public API. The sibling repository
`github.com/bsv-blockchain/go-bt` (v2) — which already depends on go-sdk and
shares its `primitives/hash` — has independently optimized the same transaction
hot paths. Both are first-party BSV Association code, so proven go-bt techniques
can be **re-implemented as first-party go-sdk code** (no third-party attribution
or license notice required). This document is the repeatable recipe for pulling
such improvements in safely.

Techniques are re-implemented against go-sdk's own types and idioms — never
copied verbatim — so go-sdk keeps its API, its struct layout, and its license
header.

<br>

## The acceptance gate (apply to every commit)

Each optimization is a **small, individually reviewable commit** that must pass
all five gates. Nothing is cached on exported, mutable structs; prefer pure
computation, buffer pre-sizing, and reuse.

1. **Baseline captured.** Record a benchstat baseline of the affected
   benchmarks *before* the change (`-count>=6`).
2. **No behavior change.** Existing exported signatures are unchanged and output
   is **byte-identical**. New exported symbols are allowed only when
   backward-compatible (a semver *minor*, never a major bump) and are reviewed
   for API surface — see the deferred-candidates proposal for anything that
   would change an existing signature or observable behavior.
3. **Green.** The golden txid/hex/sighash characterization tests, the full suite
   (`magex test`), and the parser fuzz targets all pass with no crashers.
4. **Proven faster.** benchstat before/after shows a *real* improvement (clearly
   outside the run-to-run noise band) and no regression elsewhere. A change that
   cannot beat noise is deferred, not committed.
5. **Clean.** `magex lint` is clean and `gitleaks` finds nothing before pushing.

The repo's `go-pre-commit` hook already runs whitespace, `mod-tidy`, `gitleaks`,
`lint`, `eof`, and `fumpt` on every commit, so gates 3 (lint) and 5 are enforced
automatically; the benchmark and full-suite gates are run manually.

<br>

## Running the gate

```sh
# 1. Baseline (before the change), on the affected package:
go test -run '^$' -bench . -benchmem -count=10 ./transaction/ > /tmp/base.txt

# ...make the change...

# 4. After, then compare:
go test -run '^$' -bench . -benchmem -count=10 ./transaction/ > /tmp/new.txt
benchstat /tmp/base.txt /tmp/new.txt          # or: magex bench time=1s count=10

# 3. Behavior + full suite:
magex test                                     # golden hex/txid/sighash + everything
go test -run x -fuzz=FuzzNewTransactionFromBytes -fuzztime=10s ./transaction/
go test -run x -fuzz=FuzzNewTransactionFromBEEF -fuzztime=10s ./transaction/

# 5. Lint + secrets:
magex lint
gitleaks git --log-opts="master..HEAD"
```

Golden characterization guards live in `transaction/signing_scenarios_test.go`
(`TestGoldenP2PKHSignedTransaction` pins txid + raw hex;
`TestGoldenSigHashDigests` pins per-flag sighash digests). Byte-level
regressions in serialization or signing therefore fail loudly and
deterministically (signing is RFC 6979).

<br>

## What ports cleanly (pattern catalog)

These transformations preserve bytes and the public API, so they pass the gate
as pure internal changes:

- **Arithmetic sizing.** Compute a serialized length by summing field widths and
  `util.VarInt(...).Length()` instead of serializing and taking `len()`. Add
  unexported per-element `size()` helpers and lock the result with a
  `Size() == len(Bytes())` property test.
- **Pre-sized, direct-append serialization.** Size the output buffer once, then
  append each field with zero-alloc primitives (`VarInt.PutBytes` via a small
  `appendVarInt` helper, `binary.LittleEndian.AppendUint*`). Have the public
  `Bytes()` delegate to unexported `appendTo(buf)` writers so a per-element
  throwaway `[]byte` is never allocated. Slice with `hash[:]` rather than
  `CloneBytes()` when the bytes are immediately copied.
- **Transient, caller-owned caches** for values that are identical across a
  batch (e.g. BIP143 midstates across a transaction's inputs). The cache is a
  new value type built by a constructor and passed in per call — **never a field
  on an exported mutable struct**, so it can never go stale. Expose the fast
  path additively and let existing entry points opt in via an *optional
  interface* (type assertion), so external implementations keep working
  unchanged.

Changes that would alter an existing signature or observable behavior, or that
rely on caching on an exported mutable struct, do **not** go through this gate —
they are captured in `transaction-performance-deferred.md` for a separate,
coordinated review.

<br>

## Worked examples (`feature/transaction-performance`)

| Change | Kind | Result (benchstat) |
|---|---|---|
| Arithmetic `Size()` | pure internal | `Size` −97%…−99%, 68→**0 allocs** |
| Direct-append serialization | pure internal | SerializeRaw/EF −37%…−59%, TxID −21%…−30%; package **geomean −31%** |
| `SigHashCache` (O(N) signing) | additive (minor) | preimage over all inputs: **26× / −87% allocs** at 64 inputs |
| `OutputsHash` pre-sizing | pure internal | uncached preimage **−27% allocs** at 64 inputs |

Each was committed separately with its benchstat numbers in the commit body.

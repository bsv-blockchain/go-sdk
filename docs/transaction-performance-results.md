# Transaction Performance — Results

**Status:** Results summary for the `feature/transaction-performance` branch. For
review. The **Cumulative benchstat** and tables below cover the initial phase;
the **Continuation** section adds the later deserialization, BEEF and
legacy-sighash commits.

**Scope:** non-breaking performance work on the `transaction` package, plus a few
additive (semver-minor) opt-in APIs. Every change is byte-identical on existing
behavior and went through the acceptance gate in
[`proposals/go-bt-porting-procedure.md`](proposals/go-bt-porting-procedure.md).
Remaining non-breaking follow-ups are listed in the **Still deferred** section at
the end of this document.

<br>

## Validation (whole branch)

| Check | Result |
|---|---|
| `magex test` | ✅ all unit tests pass |
| `magex lint` | ✅ 0 issues (golangci-lint, 53 linters) + `go vet` |
| `go-pre-commit run --all-files` | ✅ 6/6 checks on 694 files |
| `gitleaks git --log-opts="master..HEAD"` | ✅ no leaks (24 commits) |
| Parser fuzzers (`FuzzNewTransactionFromBytes`, `…FromBEEF`, `FuzzMerklePathFromBinary`) | ✅ no crashers |

<br>

## Cumulative benchstat (initial phase)

`go test -bench . -benchmem -benchtime=100ms -count=10 ./transaction/`, Apple M4.
Measured on the pre-existing benchmarks, i.e. the improvement to code that
already existed. **Package geomean: −31.5% sec/op.** (The Continuation section
below reports the later parse/BEEF/legacy-sighash work separately.)

| Benchmark (inputs/leaves) | sec/op | allocs/op |
|---|---|---|
| `Size/1` | 95.9n → 2.9n (**−97%**) | 4 → **0** |
| `Size/64` | 2790n → 53n (**−98%**) | 68 → **0** |
| `SerializeRaw/64` | 2776n → 1097n (**−60%**) | 68 → **1** |
| `SerializeExtended/64` | 3244n → 1513n (−53%) | 68 → **1** |
| `TxID/64` | 5634n → 3951n (−30%) | 70 → **3** |
| `TxRoundTrip/64` | 8946n → 6972n (−22%) | — |
| `CalcInputPreimage/64` | 1434n → 1391n (−3%) | 11 → 8 |
| `EFRoundTrip` | 357n → 325n (−9%) | — |
| `BEEFRoundTrip/issue96` | 17.59µ → 15.76µ (−10%) | — |
| `ComputeRoot/1024` | 65.3µ → 64.3µ (−1.4%) | 121 → 111 |

`SignP2PKH` (single input) is unchanged, as expected — a single signature is
ECDSA-bound and the sighash cache only helps multi-input signing.

<br>

## New / opt-in APIs (additive, semver-minor)

New capabilities; numbers compare the new path with the existing one.

| Capability | Benchmark | Result |
|---|---|---|
| **O(N) multi-input signing** — `SigHashCache`, `CalcInputPreimageWithCache`, `CalcInputSignatureHashWithCache`, `UnlockingScriptTemplateWithCache`; wired into `tx.Sign()` | preimage over all 64 inputs | O(N²)→O(N): **~26× faster, allocs 704 → 76** |
| **Zero-alloc serialization into a reused buffer** — `AppendBytes(dst)` | 64 inputs | `tx.Bytes()` 9728 B / 1 alloc → **0 B / 0 allocs** |
| **Streaming serialization** — `WriteTo(io.Writer)` (implements `io.WriterTo`) | 64 inputs | constant **16 B/op** regardless of tx size (vs 9728 B) |
| **Opt-in cached txid** — `SetTxHash(*chainhash.Hash)` | `TxID`, 64 inputs | 3888 ns / 9792 B / 3 allocs → **1.6 ns / 0 B / 0 allocs** |

<br>

## Internal optimizations (byte-identical, no API change)

| Area | Result |
|---|---|
| Arithmetic `Size()` | serializes nothing; 68 → **0 allocs** |
| Direct-append serialization (`toBytesHelper`) | per-element throwaway slices removed; Serialize/TxID/EF/BEEF all faster |
| `OutputsHash` / `BytesForSigHash` pre-sizing | uncached preimage, 64 inputs: **704 → 512 allocs** |
| TxID hoisting (`AddMerkleProof`, BEEF V1 parse, `AtomicBEEF`) | `AddMerkleProof`/1024 leaves: 115.4µs / 3072 allocs → **2.03µs / 3 allocs** (O(N)→O(1)) |
| `MerkleTreeParent` stack buffer + `sha256.Sum256` | 2 → **1 alloc**, −11% |
| `MerklePath.Bytes` pre-size + `Hash[:]` | 256 leaves: 17 → **1 alloc**, −62% |

<br>

## Commits (oldest → newest)

```
2031d12 perf(transaction): compute Size() arithmetically (zero-alloc)
e53b767 perf(transaction): serialize by direct-append into a pre-sized buffer
6ccdc86 feat(transaction): O(N) multi-input signing via optional SigHashCache
f43b793 perf(transaction): pre-size OutputsHash and share appendTo for output sighash
a418168 docs(proposals): add go-bt porting procedure and deferred perf candidates
3b47449 perf(transaction): hoist repeated TxID() out of loops and predicates
f7cccea test(transaction): lock BytesForSigHash==Bytes and serializedSize across modes
dc76f0c test(transaction): cover cache fallback paths; drop dead sighash branch
209bb79 feat(transaction): add zero-alloc AppendBytes and streaming WriteTo
5e71141 docs(proposals): mark AppendBytes/WriteTo implemented
b5de902 feat(transaction): opt-in cached TxID via SetTxHash
d372686 perf(transaction): buffer reuse in MerkleTreeParent and MerklePath.Bytes
2b59152 docs(proposals): mark SetTxHash and merkle buffer reuse implemented
```

<br>

## Continuation (this PR, after the summary above)

Baseline = branch tip before these commits; `-benchtime=100ms -count=10`, Apple M4.
Byte-identical; guarded by the parser fuzzers, golden txid/hex tests, and new
parse round-trip / `readVarInt`-equivalence tests.

### Deserialization scratch reuse + guarded slice pre-size

`Transaction.ReadFrom` threads one 32-byte scratch through input/output parsing
(fixed-size fields read into it and parsed in place) and reads length prefixes
via an allocation-free `readVarInt`, then pre-sizes the input/output slices for
in-memory readers behind `guardParseCount`.

| Benchmark | sec/op | B/op | allocs/op |
|---|---|---|---|
| `NewTransactionFromBytes/64` | 5513n → 4011n (**−27%**) | 18.6Ki → 15.3Ki (−18%) | 537 → **267** (−50%) |
| `ReadFrom/64` | 5475n → 3986n (**−27%**) | 18.5Ki → 15.2Ki (−18%) | 535 → **265** (−50%) |
| `NewTransactionFromBytesEF/64` | 8136n → 6188n (−24%) | 24.3Ki → 20.3Ki (−16%) | 859 → **459** (−47%) |

Parse geomean: scratch reuse −45% allocs / −24% sec/op; the pre-size adds a
further −6% allocs / −4% sec/op (measurably above noise, `p ≤ 0.001`).

### BEEF serialization copy elimination

`Beef.Bytes()` now appends each transaction once, straight into the pre-sized
output buffer via `Transaction.AppendBytes`, instead of a throwaway `tx.Bytes()`
+ a per-transaction temporary + a final copy; `AtomicBytes()` appends the body
into its atomic-prefixed buffer instead of re-copying the whole BEEF.

| Benchmark (BEEFSet) | sec/op | B/op | allocs/op |
|---|---|---|---|
| `BeefBytes` | 2520n → 2200n (−13%) | 9.1Ki → 7.0Ki (−23%) | 26 → **18** |
| `BeefAtomicBytes` | 2830n → 2249n (−21%) | 12.5Ki → 7.3Ki (**−42%**) | 27 → **19** |

### Legacy (non-FORKID) sighash preimage

`CalcInputPreimageLegacy` now pre-sizes the preimage buffer arithmetically and
appends with the shared zero-alloc writers instead of an un-presized buffer with
per-input/output `make`/`VarInt.Bytes()`/`CloneBytes()` scratch. The per-call
`ShallowClone` is kept (it still dominates the remaining alloc count), so the
sec/op and B/op wins outrun the alloc-count reduction. Byte-identical: the legacy
`None`/`Single`/`AnyOneCanPay` flags are newly golden-pinned and were
cross-checked byte-for-byte against go-bt before the refactor.

| Benchmark | sec/op | B/op | allocs/op |
|---|---|---|---|
| `CalcInputPreimageLegacy/64/All` | 3772n → 2919n (−23%) | 21.5Ki → 13.6Ki (**−37%**) | 333 → 324 |
| geomean (flags × inputs) | **−18.6%** | **−26.2%** | −10.9% |

### Whole-session cross-check (no regressions)

A full `-count=10` run of the pre-existing `transaction` benchmarks before the
continuation (`b240ab7`) vs. after confirms no regression on paths this work did
not touch — `TxID`, `SerializeRaw`/`Extended`, `Size`, the FORKID
`CalcInputPreimage`, `SignP2PKH` and cached `TxID` are all flat (identical B/op
and allocs). `BEEFRoundTrip/issue96` improved as a side effect of the faster
parse it round-trips through: 933 → **656 allocs (−30%)**, −8.8% sec/op.

<br>

## Continuation 2 — core primitives + `ComputeRoot` maps

Baseline = branch tip before these commits; `-benchtime=100ms -count=10`, Apple
M4. Same acceptance gate: byte-identical, benchstat-proven, full suite + fuzzers
green, lint clean. This pass targeted the shared primitives that sit *under*
every package and the last non-breaking merkle candidate. Two changes proved
out; two more were measured and found **already optimal** and are recorded here
so they are not re-investigated.

### Zero-alloc varint reads (`util.Reader.ReadVarInt`)

`Reader.ReadVarInt` routed through `VarInt.ReadFrom`, which passes scratch
buffers to `io.ReadFull`; crossing the `io.Reader` interface boundary forces
them to the heap, so every length prefix / count read cost 1–2 allocations.
It now decodes straight from the reader's backing slice via the existing
zero-alloc `NewVarIntFromBytes` (bounds-checked by on-wire width).
`VarInt.ReadFrom` is unchanged for external streaming callers. Backs every
count/length in `wallet/`, `auth/`, `overlay/`, `message/`, `compat/`.

| Benchmark | sec/op | allocs/op |
|---|---|---|
| `ReadVarInt/1byte` | 9.00n → **1.74n** (−81%) | 1 → **0** |
| `ReadVarInt/3byte` | 17.14n → **1.70n** (−90%) | 2 → **0** |
| `ReadVarInt/5byte` | 16.94n → **1.71n** (−90%) | 2 → **0** |
| `ReadVarInt/9byte` | 16.66n → **1.88n** (−89%) | 2 → **0** |

Byte-identical: pinned by a differential test against `ReadFrom` (value,
bytes-consumed, error parity), boundary/truncation tests, and the existing
`FuzzReadVarInt`/`FuzzReader` targets.

### Merkle root without per-level index maps (`ComputeRoot`)

`MerklePath.ComputeRoot` built one `map[uint64]*PathElement` per tree level
(inserting every node) before climbing. It now looks each node up directly in
the already-populated `Path` via the existing `FindLeafByOffset` (order-
independent, so no sort assumption). The exported `IndexedPath`/`GetOffsetLeaf`
are retained unchanged for API compatibility, just no longer used internally.

| Benchmark | sec/op | B/op | allocs/op |
|---|---|---|---|
| `ComputeRoot_LargePath/leaves=256` | 16.50µs → **0.96µs** (−94%) | 37.6Ki → **256** | 70 → **8** |
| `ComputeRoot_LargePath/leaves=1024` | 65.20µs → **1.53µs** (−98%) | 149.6Ki → **320** | 111 → **10** |

Byte-identical root (same `MerkleTreeParent` inputs in the same order): pinned by
the `BRC74Root` golden tests, `TestMerklePathSingleLevelCompound`,
`FuzzMerklePathFromBinary`, and a new `TestComputeRootCharacterization` that
cross-checks every leaf of fully-populated and sparse BUMPs (sizes 2…1024)
against an independent bottom-up reference root.

### Investigated, already optimal — no change (benchmarks added to lock it in)

- **`primitives/hash.Sha256d` / `Hash160`** read statically as if they allocate a
  throwaway intermediate, but benchstat shows **1 alloc** (the returned hash)
  and identical timing either way: the compiler already inlines and
  stack-allocates the intermediate `[32]byte`. An explicit `sha256.Sum256`
  stack rewrite did not beat noise, so it was **not committed**
  (`BenchmarkSha256d`/`BenchmarkHash160`).
- **`util.Writer.WriteVarInt` / `WriteString` / `WriteBytesReverse`** are already
  **0 alloc / 0 B**: escape analysis stack-allocates the encode scratch because
  it only flows into `append`. New `BenchmarkWriteVarInt`/`WriteString`/
  `WriteBytesReverse` document this and guard against regression.

<br>

## Still deferred

Non-breaking, byte-identical follow-ups discovered during the broad sweep but
left for a separate reviewed pass:

- **Script interpreter (medium value):** `MakeScriptNumber` little-endian decode
  → int64 accumulator (`script/interpreter/number.go`); `ScriptNumber.Bytes()`
  redundant `Val.Bytes()`/`big.Int` copy; hoist the loop-invariant `Unparse(scr)`
  out of `opcodeCheckMultiSig` (`operations.go`); pre-size `DecodeScript`/
  `ParseOps` (`script_chunk.go`). Normalize `opcodeparser_bench_test.go` to
  `b.Loop()`+`b.ReportAllocs()` first so these are measurable.
- **Long tail:** `chainhash.MarshalTo` throwaway `CloneBytes` and `String()`
  stack buffer; `base58.Encode` hoist `new(big.Int)` out of the loop;
  `block/header.go` pre-sized `Bytes`/`Read`; `compat/ecies`,
  `message/encrypted|signed`, `compat/bsm` append pre-sizing; `primitives/ec`
  `decompressPoint` `PutBytes`.
- **`transaction` (needs a benchmark first):** `ValidateTransactions` recomputes
  a validated txid across its result-collection loops; `AtomicBEEF` computes
  `TxID()` twice.
- **Correctness (non-perf, flag separately):** `chainhash.Hash.MarshalTo` returns
  `16` for a 32-byte hash — looks like a latent bug, unrelated to this work.
- **Breaking (separate decision, out of scope here):** the arena allocator for
  batch deserialization; the `Clone()` field-copy rewrite (drops `log.Fatal`);
  migrating PushDrop `Unlocker` to the standard `UnlockingScriptTemplate` +
  `SignWithCache` (changes exported `Sign`/`EstimateLength` signatures).

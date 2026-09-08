# Transaction Performance — Results

**Status:** Results summary for the `feature/transaction-performance` branch (13
commits off `master`). For review.

**Scope:** non-breaking performance work on the `transaction` package, plus a few
additive (semver-minor) opt-in APIs. Every change is byte-identical on existing
behavior and went through the acceptance gate in
[`proposals/go-bt-porting-procedure.md`](proposals/go-bt-porting-procedure.md).
Deferred follow-ups are tracked in
[`proposals/transaction-performance-deferred.md`](proposals/transaction-performance-deferred.md).

<br>

## Validation (whole branch)

| Check | Result |
|---|---|
| `magex test` | ✅ all unit tests pass |
| `magex lint` | ✅ 0 issues (golangci-lint, 53 linters) + `go vet` |
| `go-pre-commit run --all-files` | ✅ 6/6 checks on 692 files |
| `gitleaks git --log-opts="master..HEAD"` | ✅ no leaks (13 commits) |
| Parser fuzzers (`FuzzNewTransactionFromBytes`, `…FromBEEF`, `FuzzMerklePathFromBinary`) | ✅ no crashers |

<br>

## Cumulative benchstat (master → HEAD)

`go test -bench . -benchmem -benchtime=100ms -count=10 ./transaction/`, Apple M4.
Measured on the pre-existing benchmarks, i.e. the improvement to code that
already existed. **Package geomean: −31.5% sec/op.**

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

## Still deferred

See [`proposals/transaction-performance-deferred.md`](proposals/transaction-performance-deferred.md):

- Guarded `ReadFrom` slice pre-size (sub-noise win)
- Legacy (non-FORKID) sighash preimage (needs a legacy golden characterization test first)
- `ComputeRoot` per-level index maps + redundant `Beef.Bytes`/`AtomicBytes` copies (algorithmic; medium byte-identity risk)
- Arena allocator for batch deserialization; `Clone()` field-copy rewrite; opcodeparser bench normalization; PushDrop cache adoption

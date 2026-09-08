# BEEF wire compatibility fixtures

`ts-interop-fixtures.json` contains bytes emitted by actual `@bsv/sdk` 2.5.0
primitives from frozen ts-stack source `2bc799a8d8e535242e6de2d305f426ce3975ea7b`.
`source-provenance.json` records source/emitted-JS hashes, build runtime and
pinned BRC revisions. The 17 fixtures cover V1/V2, Atomic V1/V2, a shared
ancestor and join, multiple roots, two alternate proofs for the same txid,
and V2 txid-only ancestors and subjects. Expected metadata is generated from
those SDK bytes. `check-fixtures.py` independently checks double-SHA256 txids
and the corpus's four distinct two-leaf proof roots with Python hashlib.

`identity.json` preserves the exact `c01-confirmed-signed-spend` fixture
provided by the Go identity topic task, derived from accepted TS C01 commit
`c58f81787e7c2a985a167c15db9fd9ca5fed6c35`:

- Original V1 BEEF SHA-256: `65906444e47ea496b889c772002f7914cb0ab43fdf49c7d63867f23a0ccdc5c4`.
- Original AtomicBEEF SHA-256: `4b42892ae32793bc2d2543748cdce64c526e9ba063e088c829e41d599e06b6a4`.
- Subject: `2b566060722bee71793c9c1f3cf4e78fdad5760566b09b1ad759707362a014db`.

This fixture reproduces the published Go SDK v1.4.1 (`e60a054`) panic at V1
BUMP index 72. Maintained Go baseline `50502c8` already guards that V1 index,
but still writes the malformed V1-header/V2-body combination and returns an
error. The corrected serializer retains V1 and reproduces the exact original
identity BEEF and AtomicBEEF bytes.

Certificate/admission metadata in the identity fixture is provenance context.
These tests establish wire structure, raw identities, proof references and
computed roots. They do not establish certificate validity, script/SPV
verification against canonical headers, or unspentness. Synthetic OP_TRUE
transactions use disposable invented proof anchors and are never broadcast.

## Contract decisions

[BRC-62](https://bsv.brc.dev/transactions/0062) V1 writes raw transaction,
then has-BUMP flag and optional index. [BRC-96](https://bsv.brc.dev/transactions/0096)
V2 writes data format, optional index, then raw transaction (or 32-byte txid).
The serializer preserves the requested version and explicitly rejects V1
with txid-only entries. No implicit version conversion mutates the caller.

[BRC-95](https://bsv.brc.dev/transactions/0095) Atomic serialization selects
the subject and available dependencies, stopping at matching proof entries
or txid-only entries. Proof selection copies entry indices; it does not alter
the caller's maps, version, subject, proof leaves or transaction graph. Atomic
parsing checks that the declared subject exists; transaction-returning Atomic
APIs also require its raw transaction. Those checks do not validate an entire
Atomic dependency graph, reject every unrelated entry, or prove SPV validity.
Incomplete ancestry remains representable for later verification.

Existing prefix parsing and permissive overlong VarInt decoding are retained;
serialization uses minimal VarInts. Strict framing belongs to the caller.
Malformed counts, truncated txids, invalid formats/indexes and zero-depth
BUMPs now return errors at the affected BEEF parsing boundary.

## Reproduction

Run Go tests from the Go SDK root. No TypeScript dependency is needed for the
committed Go tests or Python checker:

```sh
GOTOOLCHAIN=go1.26.8 go test ./transaction -count=1
python3 transaction/testdata/beef-compatibility/check-fixtures.py
```

To regenerate or cross-check, build the exact pinned TS SDK in a separate
checkout, set `TS_STACK_ROOT` to that root, and run the following from the Go
SDK root. Output paths below are disposable; no absolute replace paths or
fake module versions are committed.

```sh
export TS_STACK_ROOT=/path/to/pinned-ts-stack
export TS_INTEROP_FIXTURES=transaction/testdata/beef-compatibility/ts-interop-fixtures.json
export IDENTITY_ORIGINAL_JSON=transaction/testdata/beef-compatibility/identity.json
node transaction/testdata/beef-compatibility/generate-ts-interop-fixtures.mjs > /tmp/regenerated-beef.json
cmp "$TS_INTEROP_FIXTURES" /tmp/regenerated-beef.json
export GO_BEEF_PROBE_OUTPUT=/tmp/go-beef-forward.json
export GO_REVERSE_OUTPUT=/tmp/go-beef-reverse.json
GOTOOLCHAIN=go1.26.8 go run ./transaction/testdata/beef-compatibility/forward "$TS_INTEROP_FIXTURES" > "$GO_BEEF_PROBE_OUTPUT"
GOTOOLCHAIN=go1.26.8 go run ./transaction/testdata/beef-compatibility/reverse "$TS_INTEROP_FIXTURES" > "$GO_REVERSE_OUTPUT"
node transaction/testdata/beef-compatibility/check-go-output-with-ts.mjs
node transaction/testdata/beef-compatibility/check-go-reverse-with-ts.mjs
```

The forward probe invokes `Beef.Bytes` and `Beef.AtomicBytes` on parsed TS BEEF.
The reverse probe builds BEEF from raw-transaction/BUMP SDK primitives in both
versions; it asserts V1 rejection for unrepresentable txid-only cases. The TS
checkers compare raw bytes, independently recomputed txids, selected proof
bytes/roots, parent ordering and subject closure. They allow valid differences
in sibling ordering and proof-index renumbering. Exact identity bytes are
compared without that allowance. No hosted CI, publication or runtime engine
integration is implied by these checks.

# GoBDK integration

The `transaction/bdk` package is an opt-in adapter between go-sdk and GoBDK's
native transaction-validation and secp256k1 implementations.

```bash
go run ./docs/examples/bdk
```

The adapter is available with CGO on Linux and macOS for amd64 and arm64. It
uses the native libraries distributed in
`github.com/bitcoin-sv/bdk/module/gobdk`.

## Transaction validation

`NewValidator` supplies SDK-aware methods for full transaction validation,
script validation, custom script flags, signature-operation counting, and
batch validation. Transactions are converted to extended format, so every
input must include its source output's locking script and satoshis. Validation
also requires one UTXO height per input.

Use `validator.Native()` to configure GoBDK policy settings that the adapter
does not duplicate. Passing `consensus=false` to a validation method performs
policy and consensus checks. Passing `consensus=true` performs consensus checks
only.

The SDK batch wrapper retains GoBDK's input buffers until `Clear` is called.
Build and validate a batch on one goroutine, or provide external
synchronization.

## Signature backend

`InstallSignatureBackend` selects GoBDK for the SDK's regular secp256k1 ECDSA
signature creation and verification. It integrates at `PrivateKey.Sign` and
`Signature.Verify`, so their callers—including wallet and message operations,
transaction templates, `OP_CHECKSIG`, and `OP_CHECKMULTISIG`—use GoBDK as well.
Compact signatures retain their SDK serialization and recovery logic while the
underlying ECDSA signature is created by GoBDK.

The signature backend accepts 32-byte message digests. Installation is explicit
and process-wide, so configure it during application startup. Call
`ResetSignatureBackend` to restore the pure-Go defaults. The separate generic
P-256 package under `primitives/ecdsa` is unaffected.

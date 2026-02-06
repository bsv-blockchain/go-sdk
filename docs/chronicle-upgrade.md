# Chronicle Upgrade Support

The Chronicle release (BSV Node v1.2.0) activates on MainNet April 7, 2026 at block 943,816. This document describes the go-sdk support for Chronicle features.

## Features

### OTDA (Original Transaction Digest Algorithm)

Chronicle introduces a new sighash flag `0x20` that enables the Original Transaction Digest Algorithm. When set, signatures use the legacy (pre-UAHF) digest format.

```go
import "github.com/bsv-blockchain/go-sdk/transaction/sighash"

// Use Chronicle sighash flags for signing
sigHashFlag := sighash.AllChronicle  // 0x21
// Other options: sighash.NoneChronicle, sighash.SingleChronicle
// Can combine with AnyOneCanPay: sighash.AllChronicle | sighash.AnyOneCanPay
```

### Restored Opcodes

Chronicle restores several opcodes that were previously disabled:

| Opcode | Hex | Description |
|--------|-----|-------------|
| OP_VER | 0x62 | Push transaction version to stack |
| OP_VERIF | 0x65 | Version-based conditional (if tx.Version >= threshold) |
| OP_VERNOTIF | 0x66 | Version-based conditional (if tx.Version < threshold) |
| OP_2MUL | 0x8d | Multiply top stack item by 2 |
| OP_2DIV | 0x8e | Divide top stack item by 2 |
| OP_SUBSTR | 0xb3 | Extract substring from string |
| OP_LEFT | 0xb4 | Get left N bytes of string |
| OP_RIGHT | 0xb5 | Get right N bytes of string |
| OP_LSHIFTNUM | 0xb6 | Numerical left shift (preserves sign) |
| OP_RSHIFTNUM | 0xb7 | Numerical right shift (preserves sign) |

### Malleability Opt-Out

Transactions with `Version > 0x01000000` (16,777,216) opt out of:
- Clean Stack Rule
- Low S Requirement
- NULLFAIL
- MINIMALIF
- Minimal Encoding
- PUSHDATAONLY for unlocking scripts

### Increased Script Number Length

The maximum script number length increases from 750KB to 32MB for post-genesis UTXOs.

## Usage

### Script Execution

Use `WithAfterChronicle()` to enable Chronicle features in the interpreter:

```go
import (
    "github.com/bsv-blockchain/go-sdk/script/interpreter"
)

err := interpreter.NewEngine().Execute(
    interpreter.WithTx(tx, inputIdx, prevOutput),
    interpreter.WithAfterChronicle(),  // Enables Chronicle opcodes
    interpreter.WithForkID(),
)
```

Note: `WithAfterChronicle()` automatically includes `WithAfterGenesis()` since Chronicle activates after Genesis.

### Transaction Signing with OTDA

```go
import (
    "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// Calculate signature hash using OTDA
hash, err := tx.CalcInputSignatureHash(inputIdx, sighash.AllChronicle)
```

### Using Restored Opcodes in Scripts

```go
import "github.com/bsv-blockchain/go-sdk/script"

// Build a script using Chronicle opcodes
s := &script.Script{}
s.AppendOpcodes(script.OpDUP)
s.AppendOpcodes(script.Op2MUL)  // Multiply by 2
s.AppendOpcodes(script.OpEQUAL)
```

## Backward Compatibility

- Existing code using `WithAfterGenesis()` continues to work unchanged
- Chronicle opcodes only activate when `WithAfterChronicle()` is used
- Without Chronicle flag, NOP4-NOP8 remain as NOPs
- OTDA signing requires explicit use of `sighash.Chronicle` flag

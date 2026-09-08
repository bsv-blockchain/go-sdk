package interpreter

import (
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// Benchmarks for the script engine hot paths: executing a standard P2PKH spend
// end to end, and the big.Int-backed script number arithmetic that opcodes lean
// on. Setup is done outside the timer.

// BenchmarkEngineExecuteP2PKH measures verifying a signed P2PKH input through
// the full engine (unlocking script pushes sig+pubkey, locking script runs
// OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG).
func BenchmarkEngineExecuteP2PKH(b *testing.B) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	if err != nil {
		b.Fatal(err)
	}
	lock, err := p2pkh.Lock(addr)
	if err != nil {
		b.Fatal(err)
	}
	unlock, err := p2pkh.Unlock(priv, nil)
	if err != nil {
		b.Fatal(err)
	}

	prevTx := transaction.NewTransaction()
	prevTx.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})

	tx := transaction.NewTransaction()
	tx.AddInputFromTx(prevTx, 0, unlock)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
	if err = tx.Sign(); err != nil {
		b.Fatal(err)
	}

	prevOutput := prevTx.Outputs[0]

	b.ReportAllocs()
	for b.Loop() {
		if err := NewEngine().Execute(
			WithTx(tx, 0, prevOutput),
			WithForkID(),
			WithAfterGenesis(),
		); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScriptNumberArithmetic measures each big.Int-backed script number
// operation. The receiver is reset to a fixed value each iteration so results
// stay bounded and comparable (the ops mutate the receiver in place).
func BenchmarkScriptNumberArithmetic(b *testing.B) {
	const seed = int64(1234567890123)
	operand := &ScriptNumber{Val: big.NewInt(98765)}

	ops := []struct {
		name string
		fn   func(a *ScriptNumber)
	}{
		{"add", func(a *ScriptNumber) { a.Add(operand) }},
		{"sub", func(a *ScriptNumber) { a.Sub(operand) }},
		{"mul", func(a *ScriptNumber) { a.Mul(operand) }},
		{"div", func(a *ScriptNumber) { a.Div(operand) }},
		{"mod", func(a *ScriptNumber) { a.Mod(operand) }},
	}

	for _, op := range ops {
		b.Run(op.name, func(b *testing.B) {
			a := &ScriptNumber{Val: new(big.Int)}

			b.ReportAllocs()
			for b.Loop() {
				a.Val.SetInt64(seed)
				op.fn(a)
			}
		})
	}
}

// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package interpreter

// Engine is the virtual machine that executes scripts.
type Engine interface {
	Execute(opts ...ExecutionOptionFunc) error
}

type engine struct{}

// NewEngine returns a new script engine for the provided locking script
// (of a previous transaction out), transaction, and input index.  The
// flags modify the behavior of the script engine according to the
// description provided by each flag.
func NewEngine() Engine {
	return &engine{}
}

// Execute will execute all scripts in the script engine and return either nil
// for successful validation or an error if one occurred.
//
// By default scripts are executed under after-Chronicle rules, the rules in
// force on BSV mainnet since the Chronicle upgrade (SV Node v1.2.0, April 2026).
// To verify the spend of an older UTXO, name its epoch explicitly:
//
//	options                                 epoch
//	(none)                                  after-Chronicle
//	WithAfterChronicle()                    after-Chronicle
//	WithAfterGenesis()                      after-Genesis, pre-Chronicle
//	WithBeforeGenesis()                     pre-Genesis
//	WithFlags(f)                            taken from f: UTXOAfterChronicle,
//	                                        UTXOAfterGenesis, or pre-Genesis if
//	                                        f names neither (SV node semantics)
//
// When several epochs are named, the most recent one wins. WithForkID and
// WithP2SH do not affect the epoch.
//
// Execute with tx example:
//
//	if err := engine.Execute(
//	    interpreter.WithTx(tx, inputIdx, previousOutput),
//	    interpreter.WithForkID(),
//	); err != nil {
//	    // handle err
//	}
//
// Execute with scripts example, for a UTXO created before Chronicle:
//
//	if err := engine.Execute(
//	    interpreter.WithScripts(lockingScript, unlockingScript),
//	    interpreter.WithAfterGenesis(),
//	    interpreter.WithForkID(),
//	); err != nil {
//	    // handle err
//	}
func (e *engine) Execute(oo ...ExecutionOptionFunc) error {
	opts := &execOpts{}
	for _, o := range oo {
		o(opts)
	}

	t, err := createThread(opts)
	if err != nil {
		return err
	}

	if err := t.execute(); err != nil {
		t.afterError(err)
		return err
	}

	return nil
}

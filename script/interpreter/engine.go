// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package interpreter

import "github.com/bsv-blockchain/go-sdk/script/interpreter/errs"

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
//	WithGenesis() / WithChronicle()         pre-Genesis, unless an epoch above
//	                                        is also named
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
//
// Without any flag option (WithFlags, WithForkID, WithP2SH or an era option),
// Execute enables SIGHASH_FORKID, as every block since the UAHF does, so that
// current signatures verify. Flags given with WithFlags are used exactly as
// given, as bitcoin-sv uses its flag word.
//
// Breaking change from v1.6.0: SIGHASH_FORKID implies VerifyStrictEncoding
// (interpreter.cpp:2315-2319), so with no flag option a signature without
// SIGHASH_FORKID now fails with errs.ErrMustUseForkID, where v1.6.0 verified
// it against the legacy digest. To verify a spend from before the UAHF, pass
// flags without EnableSighashForkID, such as those
// scriptflag.ActivationHeights.BlockValidationFlags gives for its height.
//
// Execution has no time limit unless WithContext gives it one.
//
// Scripts are often supplied by untrusted parties, so a panic while executing
// them is reported as an ErrInternal error, which fails validation, rather
// than crashing the caller.
func (e *engine) Execute(oo ...ExecutionOptionFunc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.NewError(errs.ErrInternal, "script execution panicked: %v", r)
		}
	}()

	opts := &execOpts{}
	for _, o := range oo {
		o(opts)
	}

	t, err := createThread(opts)
	if err != nil {
		return err
	}

	if err = t.execute(); err != nil {
		t.afterError(err)
		return err
	}

	return nil
}

package p2pkh

import (
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

var (
	ErrBadPublicKeyHash = errors.New("invalid public key hash")
	ErrNoPrivateKey     = errors.New("private key not supplied")
)

func Decode(s *script.Script, mainnet bool) *script.Address {
	if len(*s) != 25 {
		return nil
	}
	if chunks, err := s.Chunks(); err != nil {
		return nil
	} else if chunks[0].Op != script.OpDUP || chunks[1].Op != script.OpHASH160 || len(chunks[2].Data) != 20 || chunks[3].Op != script.OpEQUALVERIFY || chunks[4].Op != script.OpCHECKSIG {
		return nil
	} else {
		address, _ := script.NewAddressFromPublicKeyHash(chunks[2].Data, mainnet)
		return address
	}
}

func Lock(a *script.Address) (*script.Script, error) {
	if len(a.PublicKeyHash) != 20 {
		return nil, ErrBadPublicKeyHash
	}
	b := make([]byte, 0, 25)
	b = append(b, script.OpDUP, script.OpHASH160, script.OpDATA20)
	b = append(b, a.PublicKeyHash...)
	b = append(b, script.OpEQUALVERIFY, script.OpCHECKSIG)
	s := script.Script(b)
	return &s, nil
}

// UnlockOption is a functional option for configuring P2PKH unlock parameters
type UnlockOption func(*P2PKH)

// WithSourceSatoshis sets the source satoshis for the P2PKH unlock
func WithSourceSatoshis(satoshis uint64) UnlockOption {
	return func(p *P2PKH) {
		p.SourceSatoshis = &satoshis
	}
}

// WithLockingScript sets the locking script for the P2PKH unlock
func WithLockingScript(script *script.Script) UnlockOption {
	return func(p *P2PKH) {
		p.LockingScript = script
	}
}

func Unlock(key *ec.PrivateKey, sigHashFlag *sighash.Flag, opts ...UnlockOption) (*P2PKH, error) {
	if key == nil {
		return nil, ErrNoPrivateKey
	}
	if sigHashFlag == nil {
		shf := sighash.AllForkID
		sigHashFlag = &shf
	}
	p := &P2PKH{
		PrivateKey:  key,
		SigHashFlag: sigHashFlag,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

type P2PKH struct {
	PrivateKey     *ec.PrivateKey
	SigHashFlag    *sighash.Flag
	SourceSatoshis *uint64
	LockingScript  *script.Script
	// optionally could support a code separator index
}

func (p *P2PKH) Sign(tx *transaction.Transaction, inputIndex uint32) (*script.Script, error) {
	input := tx.Inputs[inputIndex]
	
	// If optional parameters are provided, temporarily set them
	var originalOutput *transaction.TransactionOutput
	if p.SourceSatoshis != nil || p.LockingScript != nil {
		originalOutput = input.SourceTxOutput()
		
		// Create a temporary output with the provided values
		tempOutput := &transaction.TransactionOutput{}
		
		// Use provided satoshis or fall back to original
		if p.SourceSatoshis != nil {
			tempOutput.Satoshis = *p.SourceSatoshis
		} else if originalOutput != nil {
			tempOutput.Satoshis = originalOutput.Satoshis
		}
		
		// Use provided locking script or fall back to original
		if p.LockingScript != nil {
			tempOutput.LockingScript = p.LockingScript
		} else if originalOutput != nil {
			tempOutput.LockingScript = originalOutput.LockingScript
		}
		
		input.SetSourceTxOutput(tempOutput)
		defer func() {
			// Restore original output
			input.SetSourceTxOutput(originalOutput)
		}()
	}
	
	if input.SourceTxOutput() == nil {
		return nil, transaction.ErrEmptyPreviousTx
	}

	sh, err := tx.CalcInputSignatureHash(inputIndex, *p.SigHashFlag)
	if err != nil {
		return nil, err
	}

	sig, err := p.PrivateKey.Sign(sh)
	if err != nil {
		return nil, err
	}

	pubKey := p.PrivateKey.PubKey().Compressed()
	signature := sig.Serialize()

	sigBuf := make([]byte, 0)
	sigBuf = append(sigBuf, signature...)
	sigBuf = append(sigBuf, uint8(*p.SigHashFlag))

	s := &script.Script{}
	if err = s.AppendPushData(sigBuf); err != nil {
		return nil, err
	} else if err = s.AppendPushData(pubKey); err != nil {
		return nil, err
	}

	return s, nil
}

func (p *P2PKH) EstimateLength(_ *transaction.Transaction, inputIndex uint32) uint32 {
	return 106
}

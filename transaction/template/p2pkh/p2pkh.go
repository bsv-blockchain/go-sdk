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

func Unlock(key *ec.PrivateKey, sigHashFlag *sighash.Flag) (*P2PKH, error) {
	if key == nil {
		return nil, ErrNoPrivateKey
	}
	if sigHashFlag == nil {
		shf := sighash.AllForkID
		sigHashFlag = &shf
	}
	return &P2PKH{
		PrivateKey:  key,
		SigHashFlag: sigHashFlag,
	}, nil
}

type P2PKH struct {
	PrivateKey  *ec.PrivateKey
	SigHashFlag *sighash.Flag
	// optionally could support a code separator index
}

func (p *P2PKH) Sign(tx *transaction.Transaction, inputIndex uint32) (*script.Script, error) {
	if tx.Inputs[inputIndex].SourceTxOutput() == nil {
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

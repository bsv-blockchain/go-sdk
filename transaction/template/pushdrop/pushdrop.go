package pushdrop

import (
	"context"
	"crypto/sha256"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type PushDropData struct {
	LockingPublicKey *ec.PublicKey
	Fields           [][]byte
}

func Decode(s *script.Script) *PushDropData {
	pushDrop := &PushDropData{}
	if chunks, err := s.Chunks(); err != nil {
		return nil
	} else if pushDrop.LockingPublicKey, err = ec.PublicKeyFromBytes(chunks[0].Data); err != nil {
		return nil
	} else {
		for i := 2; i < len(chunks); i++ {
			nextOpcode := chunks[i+1].Op
			chunk := chunks[i].Data
			if len(chunk) == 0 {
				if chunks[i].Op >= 80 && chunks[i].Op <= 95 {
					chunk = []byte{byte(chunks[i].Op - 80)}
				} else if chunks[i].Op == 0 {
					chunk = []byte{0}
				} else if chunks[i].Op == 0x4f {
					chunk = []byte{0x81}
				}
			}
			pushDrop.Fields = append(pushDrop.Fields, chunk)
			if nextOpcode == script.OpDROP || nextOpcode == script.Op2DROP {
				break
			}
		}
		return pushDrop
	}
}

type PushDropTemplate struct {
	Wallet     wallet.Interface
	Originator string
}

func (p *PushDropTemplate) Lock(
	ctx context.Context,
	fields [][]byte,
	protocolID wallet.Protocol,
	keyID string,
	counterparty wallet.Counterparty,
	forSelf bool,
	includeSignatures bool,
	lockPosBefore bool,
) (*script.Script, error) {
	pub, err := p.Wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        keyID,
			Counterparty: counterparty,
		},
		ForSelf: forSelf,
	}, p.Originator)
	if err != nil {
		return nil, err
	}
	lockChunks := make([]*script.ScriptChunk, 0)
	pubKeyBytes := pub.PublicKey.Compressed()
	lockChunks = append(lockChunks, &script.ScriptChunk{
		Op:   byte(len(pubKeyBytes)),
		Data: pubKeyBytes,
	})
	lockChunks = append(lockChunks, &script.ScriptChunk{
		Op: script.OpCHECKSIG,
	})
	if includeSignatures {
		dataToSign := make([]byte, 0)
		for _, e := range fields {
			dataToSign = append(dataToSign, e...)
		}
		sig, err := p.Wallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   protocolID,
				KeyID:        keyID,
				Counterparty: counterparty,
			},
			Data: dataToSign,
		}, p.Originator)
		if err != nil {
			return nil, fmt.Errorf("error creating wallet signature for lock: %w", err)
		}
		fields = append(fields, sig.Signature)
	}
	pushDropChunks := make([]*script.ScriptChunk, 0)
	for _, field := range fields {
		pushDropChunks = append(pushDropChunks, CreateMinimallyEncodedScriptChunk(field))
	}
	notYetDropped := len(fields)
	for notYetDropped > 1 {
		pushDropChunks = append(pushDropChunks, &script.ScriptChunk{
			Op: script.Op2DROP,
		})
		notYetDropped -= 2
	}
	if notYetDropped != 0 {
		pushDropChunks = append(pushDropChunks, &script.ScriptChunk{
			Op: script.OpDROP,
		})
	}
	if lockPosBefore {
		return script.NewScriptFromScriptOps(append(lockChunks, pushDropChunks...))
	} else {
		return script.NewScriptFromScriptOps(append(pushDropChunks, lockChunks...))
	}
}

func (p *PushDropTemplate) Unlock(
	ctx context.Context,
	protocolID wallet.Protocol,
	keyID string,
	counterparty wallet.Counterparty,
	signOutputs wallet.SignOutputs,
	anyoneCanPay bool,
) *PushDropUnlocker {
	return &PushDropUnlocker{
		ctx:          ctx,
		protocolID:   protocolID,
		keyID:        keyID,
		counterparty: counterparty,
		signOutputs:  signOutputs,
		anyoneCanPay: anyoneCanPay,
		pushDrop:     p,
	}
}

type PushDropUnlocker struct {
	ctx          context.Context
	protocolID   wallet.Protocol
	keyID        string
	counterparty wallet.Counterparty
	signOutputs  wallet.SignOutputs
	anyoneCanPay bool
	pushDrop     *PushDropTemplate
}

func (p *PushDropUnlocker) Sign(
	tx *transaction.Transaction,
	inputIndex uint32,
) (*script.Script, error) {
	signatureScope := sighash.ForkID
	switch p.signOutputs {
	case wallet.SignOutputsAll:
		signatureScope |= sighash.All
	case wallet.SignOutputsNone:
		signatureScope |= sighash.None
	case wallet.SignOutputsSingle:
		signatureScope |= sighash.Single
	}
	if p.anyoneCanPay {
		signatureScope |= sighash.AnyOneCanPay
	}

	if sh, err := tx.CalcInputSignatureHash(inputIndex, signatureScope); err != nil {
		return nil, err
	} else {
		preimageHash := sha256.Sum256(sh)
		sig, err := p.pushDrop.Wallet.CreateSignature(p.ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   p.protocolID,
				KeyID:        p.keyID,
				Counterparty: p.counterparty,
			},
			Data: preimageHash[:],
		}, p.pushDrop.Originator)
		if err != nil {
			return nil, fmt.Errorf("unable to create wallet signature for sign: %w", err)
		}
		s := (&script.Script{})
		// Error throws if data is too big which wont happen here
		_ = s.AppendPushData(sig.Signature)
		return s, nil
	}

}

func (p *PushDropUnlocker) EstimateLength() uint32 {
	return 73
}

func CreateMinimallyEncodedScriptChunk(data []byte) *script.ScriptChunk {
	if len(data) == 0 {
		return &script.ScriptChunk{
			Op: 0,
		}
	}
	if len(data) == 1 && data[0] == 0 {
		return &script.ScriptChunk{
			Op: 0,
		}
	}
	if len(data) == 1 && data[0] > 0 && data[0] <= 16 {
		return &script.ScriptChunk{
			Op: 0x50 + data[0],
		}
	}
	if len(data) == 1 && data[0] == 0x81 {
		return &script.ScriptChunk{
			Op: 0x4f,
		}
	}
	if len(data) <= 75 {
		return &script.ScriptChunk{
			Op:   byte(len(data)),
			Data: data,
		}
	}
	if len(data) <= 255 {
		return &script.ScriptChunk{
			Op:   0x4c,
			Data: data,
		}
	}
	if len(data) <= 65535 {
		return &script.ScriptChunk{
			Op:   0x4d,
			Data: data,
		}
	}
	return &script.ScriptChunk{
		Op:   0x4e,
		Data: data,
	}
}

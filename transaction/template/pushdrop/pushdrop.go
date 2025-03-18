package pushdrop

import (
	"crypto/sha256"

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

func Decode(s *script.Script) (*PushDropData, error) {
	pushDrop := &PushDropData{}
	if chunks, err := s.Chunks(); err != nil {
		return nil, err
	} else if pushDrop.LockingPublicKey, err = ec.PublicKeyFromBytes(chunks[0].Data); err != nil {
		return nil, err
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
		return pushDrop, nil
	}
}

type PushDropTemplate struct {
	Wallet     wallet.Wallet
	Originator string
}

func (p *PushDropTemplate) Lock(
	fields [][]byte,
	protocolID wallet.WalletProtocol,
	keyID string,
	counterparty wallet.WalletCounterparty,
	forSelf bool,
	includeSignatures bool,
	lockPosBefore bool,
) (*script.Script, error) {
	pub := p.Wallet.GetPublicKey(&wallet.GetPublicKeyArgs{
		WalletEncryptionArgs: wallet.WalletEncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        keyID,
			Counterparty: counterparty,
		},
		ForSelf: forSelf,
	}, p.Originator)
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
		sig := p.Wallet.CreateSignature(&wallet.CreateSignatureArgs{
			WalletEncryptionArgs: wallet.WalletEncryptionArgs{
				ProtocolID:   protocolID,
				KeyID:        keyID,
				Counterparty: counterparty,
			},
			Data: dataToSign,
		}, p.Originator)
		fields = append(fields, sig.Signature.Serialize())
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
	protocolID wallet.WalletProtocol,
	keyID string,
	counterparty wallet.WalletCounterparty,
	signOutputs wallet.SignOutputs,
	anyoneCanPay bool,
) *PushDropUnlocker {
	return &PushDropUnlocker{
		protocolID:   protocolID,
		keyID:        keyID,
		counterparty: counterparty,
		signOutputs:  signOutputs,
		anyoneCanPay: anyoneCanPay,
		pushDrop:     p,
	}
}

type PushDropUnlocker struct {
	protocolID   wallet.WalletProtocol
	keyID        string
	counterparty wallet.WalletCounterparty
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
		sig := p.pushDrop.Wallet.CreateSignature(&wallet.CreateSignatureArgs{
			WalletEncryptionArgs: wallet.WalletEncryptionArgs{
				ProtocolID:   p.protocolID,
				KeyID:        p.keyID,
				Counterparty: p.counterparty,
			},
			Data: preimageHash[:],
		}, p.pushDrop.Originator)
		s := (&script.Script{})
		s.AppendPushData(sig.Signature.Serialize())
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

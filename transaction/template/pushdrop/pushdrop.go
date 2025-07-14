package pushdrop

import (
	"context"
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
	chunks, err := s.Chunks()
	if err != nil || len(chunks) < 2 {
		return nil
	}

	pushDrop := &PushDropData{}

	// Check if this is a lock-before pattern (pubkey at start)
	if pubKey, err := ec.PublicKeyFromBytes(chunks[0].Data); err == nil && chunks[1].Op == script.OpCHECKSIG {
		// Lock-before pattern: [pubkey, CHECKSIG, data..., DROP/2DROP...]
		pushDrop.LockingPublicKey = pubKey
		for i := 2; i < len(chunks); i++ {
			chunk := chunks[i].Data
			if len(chunk) == 0 {
				if chunks[i].Op >= script.Op1-1 && chunks[i].Op <= script.Op16 {
					chunk = []byte{chunks[i].Op - 80}
				} else if chunks[i].Op == script.Op0 {
					chunk = []byte{0}
				} else if chunks[i].Op == script.Op1NEGATE {
					chunk = []byte{0x81} // -1 in Bitcoin script number encoding
				}
			}
			pushDrop.Fields = append(pushDrop.Fields, chunk)
			// Check if the next chunk exists and is DROP or 2DROP
			if i+1 < len(chunks) {
				nextOpcode := chunks[i+1].Op
				if nextOpcode == script.OpDROP || nextOpcode == script.Op2DROP {
					break
				}
			}
		}
		return pushDrop
	}

	// NOTE: The following code is commented out as this pattern handling is not present in the TypeScript
	// implementation and the exact logic for this use case is not defined.
	/*
		// Check if this is a lock-after pattern (pubkey at end)
		// Find the last occurrence of CHECKSIG
		checksigIndex := -1
		for i := len(chunks) - 1; i >= 1; i-- {
			if chunks[i].Op == script.OpCHECKSIG {
				checksigIndex = i
				break
			}
		}

		if checksigIndex > 0 {
			// Try to parse the public key before CHECKSIG
			if pubKey, err := ec.PublicKeyFromBytes(chunks[checksigIndex-1].Data); err == nil {
				// Lock-after pattern: [data..., DROP/2DROP..., pubkey, CHECKSIG]
				pushDrop.LockingPublicKey = pubKey
				for i := range checksigIndex {
					chunk := chunks[i].Data
					if len(chunk) == 0 {
						if chunks[i].Op >= script.Op1 && chunks[i].Op <= script.Op16 {
							chunk = []byte{chunks[i].Op - 80}
						} else if chunks[i].Op == script.Op0 {
							chunk = []byte{0}
						} else if chunks[i].Op == script.Op1NEGATE {
							chunk = []byte{script.Op1}
						}
					}
					// Only add if it's not a DROP operation
					if chunks[i].Op != script.OpDROP && chunks[i].Op != script.Op2DROP {
						pushDrop.Fields = append(pushDrop.Fields, chunk)
					}
				}
				return pushDrop
			}
		}
	*/

	return nil
}

// LockPosition type for lock position parameter
type LockPosition string

const (
	LockBefore LockPosition = "before"
	LockAfter  LockPosition = "after"
)

// PushDrop provides a simpler API matching TypeScript patterns
type PushDrop struct {
	Wallet     wallet.Interface
	Originator string
}

// Lock creates a PushDrop locking script matching TypeScript's API
func (p *PushDrop) Lock(
	ctx context.Context,
	fields [][]byte,
	protocolID wallet.Protocol,
	keyID string,
	counterparty wallet.Counterparty,
	forSelf bool,
	includeSignature bool,
	lockPosition LockPosition,
) (*script.Script, error) {
	lockBefore := (lockPosition == LockBefore || lockPosition == "")

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
	if includeSignature {
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
	if lockBefore {
		return script.NewScriptFromScriptOps(append(lockChunks, pushDropChunks...))
	} else {
		return script.NewScriptFromScriptOps(append(pushDropChunks, lockChunks...))
	}
}

// Unlocker provides the unlock interface matching TypeScript
type Unlocker struct {
	pushDrop       *PushDrop
	ctx            context.Context
	protocol       wallet.Protocol
	keyID          string
	counterparty   wallet.Counterparty
	signOutputs    wallet.SignOutputs
	anyoneCanPay   bool
	sourceSatoshis *uint64
	lockingScript  *script.Script
}

// Sign implements the TypeScript sign method
func (u *Unlocker) Sign(tx *transaction.Transaction, inputIndex int) (*script.Script, error) {
	signatureScope := sighash.ForkID
	switch u.signOutputs {
	case wallet.SignOutputsAll:
		signatureScope |= sighash.All
	case wallet.SignOutputsNone:
		signatureScope |= sighash.None
	case wallet.SignOutputsSingle:
		signatureScope |= sighash.Single
	}
	if u.anyoneCanPay {
		signatureScope |= sighash.AnyOneCanPay
	}

	if sigHash, err := tx.CalcInputSignatureHash(uint32(inputIndex), signatureScope); err != nil {
		return nil, err
	} else {
		sig, err := u.pushDrop.Wallet.CreateSignature(u.ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   u.protocol,
				KeyID:        u.keyID,
				Counterparty: u.counterparty,
			},
			HashToDirectlySign: sigHash,
		}, u.pushDrop.Originator)
		if err != nil {
			return nil, fmt.Errorf("unable to create wallet signature for sign: %w", err)
		}
		// Append signature with sighash type
		sigBytes := sig.Signature.Serialize()
		sigWithHashType := append(sigBytes, byte(signatureScope))

		s := (&script.Script{})
		// Error throws if data is too big which wont happen here
		_ = s.AppendPushData(sigWithHashType)
		return s, nil
	}
}

// EstimateLength returns the estimated script length
func (u *Unlocker) EstimateLength() uint32 {
	return 73
}

// UnlockOptions contains optional parameters for Unlock method
type UnlockOptions struct {
	SourceSatoshis *uint64
	LockingScript  *script.Script
}

// Unlock creates an unlocker for spending a PushDrop token output
// This matches TypeScript's unlock method that returns an object with sign() and estimateLength()
func (p *PushDrop) Unlock(
	ctx context.Context,
	protocolID wallet.Protocol,
	keyID string,
	counterparty wallet.Counterparty,
	signOutputs wallet.SignOutputs,
	anyoneCanPay bool,
	opts ...UnlockOptions,
) *Unlocker {
	unlocker := &Unlocker{
		pushDrop:     p,
		ctx:          ctx,
		protocol:     protocolID,
		keyID:        keyID,
		counterparty: counterparty,
		signOutputs:  signOutputs,
		anyoneCanPay: anyoneCanPay,
	}

	// Apply optional parameters if provided
	if len(opts) > 0 {
		unlocker.sourceSatoshis = opts[0].SourceSatoshis
		unlocker.lockingScript = opts[0].LockingScript
	}

	return unlocker
}

func CreateMinimallyEncodedScriptChunk(data []byte) *script.ScriptChunk {
	if len(data) == 0 {
		return &script.ScriptChunk{
			Op: script.Op0,
		}
	}
	if len(data) == 1 && data[0] == 0 {
		return &script.ScriptChunk{
			Op: script.Op0,
		}
	}
	if len(data) == 1 && data[0] > 0 && data[0] <= 16 {
		return &script.ScriptChunk{
			Op: 80 + data[0], // OP_1 through OP_16
		}
	}
	if len(data) == 1 && data[0] == 0x81 { // -1 in Bitcoin script number encoding
		return &script.ScriptChunk{
			Op: script.Op1NEGATE,
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
			Op:   script.OpPUSHDATA1,
			Data: data,
		}
	}
	if len(data) <= 65535 {
		return &script.ScriptChunk{
			Op:   script.OpPUSHDATA2,
			Data: data,
		}
	}
	return &script.ScriptChunk{
		Op:   script.OpPUSHDATA4,
		Data: data,
	}
}

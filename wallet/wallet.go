package wallet

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	transaction "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

type SecurityLevel int

var (
	SecurityLevelSilent                  SecurityLevel = 0
	SecurityLevelEveryApp                SecurityLevel = 1
	SecurityLevelEveryAppAndCounterparty SecurityLevel = 2
)

type WalletProtocol struct {
	SecurityLevel SecurityLevel
	Protocol      string
}

type CounterpartyType int

const (
	CounterpartyTypeAnyone CounterpartyType = 0
	CounterpartyTypeSelf   CounterpartyType = 1
	CounterpartyTypeOther  CounterpartyType = 2
)

type WalletCounterparty struct {
	Type         CounterpartyType
	Counterparty *ec.PublicKey
}

// TODO: Build out wallet
type Wallet struct{}

type WalletEncryptionArgs struct {
	ProtocolID       WalletProtocol
	KeyID            string
	Counterparty     WalletCounterparty
	Privileged       bool
	PrivilegedReason string
	SeekPermission   bool
}

type GetPublicKeyArgs struct {
	WalletEncryptionArgs
	IdentityKey bool
	ForSelf     bool
}

type GetPublicKeyResult struct {
	PublicKey *ec.PublicKey `json:"publicKey"`
}

func (w *Wallet) GetPublicKey(args *GetPublicKeyArgs, originator string) GetPublicKeyResult {
	return GetPublicKeyResult{
		PublicKey: &ec.PublicKey{},
	}
}

type CreateSignatureArgs struct {
	WalletEncryptionArgs
	Data               []byte
	DashToDirectlySign []byte
}

type CreateSignatureResult struct {
	Signature ec.Signature
}

type SignOutputs transaction.Flag

var (
	SignOutputsAll    SignOutputs = SignOutputs(sighash.All)
	SignOutputsNone   SignOutputs = SignOutputs(sighash.None)
	SignOutputsSingle SignOutputs = SignOutputs(sighash.Single)
)

func (w *Wallet) CreateSignature(args *CreateSignatureArgs, originator string) CreateSignatureResult {
	// a := sighash.All
	return CreateSignatureResult{
		Signature: ec.Signature{},
	}
}

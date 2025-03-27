package certificates

import (
	"errors"

	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var ErrNoKeyRing = errors.New("no-key-ring")

type VerifiableCertificate struct {
	Type               []byte            `json:"type"`
	SerialNumber       []byte            `json:"serialNumber"`
	Subject            ec.PublicKey      `json:"subject"`
	Certifier          ec.PublicKey      `json:"certifier"`
	RevocationOutpoint *overlay.Outpoint `json:"revocationOutpoint"`
	Fields             map[string]string `json:"fields"`
	Signature          ec.Signature      `json:"signature,omitempty"`
	KeyRing            map[string]string
	DecryptedFields    map[string]string `json:"decryptedFields,omitempty"`
}

func (c *VerifiableCertificate) DecryptFields(
	verifierWallet wallet.Wallet,
	Privileged bool,
	PrivilegedReason string,
) (decrypted map[string]string, err error) {
	// if c.KeyRing == nil || len(c.KeyRing) == 0 {
	// 	return nil, ErrNoKeyRing
	// }
	// decrypted = make(map[string]string, len(c.Fields))
	// for v, k := range c.Fields {
	// verifierWallet.Decr
	// }

	return nil, nil
}

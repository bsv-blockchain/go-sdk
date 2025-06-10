package primitives

import (
	e "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Sign generates an ECDSA signature for a given hashed message using the provided private key.
// If forceLowS is true, the function ensures that the 'S' value is in the lower half of the curve order.
func Sign(msg []byte, privateKey *e.PrivateKey, forceLowS bool, customK *big.Int) (*ec.Signature, error) {
	curve := elliptic.P256() // or another curve as needed

	// Generate the signature
	if customK != nil {
		return SignWithCustomK(msg, privateKey, forceLowS, customK)
	}
	r, s, err := e.Sign(rand.Reader, privateKey, msg)
	if err != nil {
		return nil, err
	}

	// Enforce low S values if required
	if forceLowS {
		halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
		if s.Cmp(halfOrder) > 0 {
			s.Sub(curve.Params().N, s)
		}
	}

	return &ec.Signature{R: r, S: s}, nil
}

// SignWithCustomK generates an ECDSA signature for a given hashed
// message using the provided private key and custom K value.
func SignWithCustomK(msg []byte, privateKey *e.PrivateKey, forceLowS bool, customK *big.Int) (*ec.Signature, error) {
	curve := privateKey.Curve
	N := curve.Params().N

	if customK.Cmp(big.NewInt(1)) < 0 || customK.Cmp(new(big.Int).Sub(N, big.NewInt(1))) > 0 {
		return nil, errors.New("customK is out of valid range")
	}

	// Calculate r = (kG).X mod N
	kGx, _ := curve.ScalarBaseMult(customK.Bytes())
	r := new(big.Int).Mod(kGx, N)
	if r.Sign() == 0 {
		return nil, errors.New("r is zero")
	}

	// Calculate s = k^(-1) * (hash + priv.D * r) mod N
	e := new(big.Int).SetBytes(msg)
	s := new(big.Int).Mul(privateKey.D, r)
	s.Add(s, e)
	s.Mul(s, new(big.Int).ModInverse(customK, N))
	s.Mod(s, N)
	if s.Sign() == 0 {
		return nil, errors.New("s is zero")
	}

	// Enforce low S values if required
	if forceLowS {
		halfOrder := new(big.Int).Rsh(N, 1)
		if s.Cmp(halfOrder) > 0 {
			s.Sub(N, s)
		}
	}

	return &ec.Signature{R: r, S: s}, nil
}

// Verify verifies an ECDSA signature for a given hashed message using the provided public key.
func Verify(msg []byte, signature *ec.Signature, publicKey *e.PublicKey) bool {
	return e.Verify(publicKey, msg, signature.R, signature.S)
}

package primitives

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	keyshares "github.com/bsv-blockchain/go-sdk/primitives/keyshares"
	"github.com/bsv-blockchain/go-sdk/util"
)

// ToPolynomial creates a polynomial of the given threshold using the private key
// as the constant term (point at x=0).
func (p *PrivateKey) ToPolynomial(threshold int) (*keyshares.Polynomial, error) {
	// Check for invalid threshold
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}

	curve := keyshares.NewCurve()
	points := make([]*keyshares.PointInFiniteField, 0)

	// Set the first point to (0, key)
	points = append(points, keyshares.NewPointInFiniteField(big.NewInt(0), p.D))

	// Generate random points for the rest of the polynomial
	for i := 1; i < threshold; i++ {
		x := util.Umod(util.NewRandomBigInt(32), curve.P)
		y := util.Umod(util.NewRandomBigInt(32), curve.P)

		points = append(points, keyshares.NewPointInFiniteField(x, y))
	}
	return keyshares.NewPolynomial(points, threshold), nil
}

// ToKeyShares splits the private key into shares using Shamir's Secret Sharing Scheme.
func (p *PrivateKey) ToKeyShares(threshold int, totalShares int) (keyShares *keyshares.KeyShares, error error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if totalShares < 2 {
		return nil, errors.New("totalShares must be at least 2")
	}
	if threshold > totalShares {
		return nil, errors.New("threshold should be less than or equal to totalShares")
	}

	poly, err := p.ToPolynomial(threshold)
	if err != nil {
		return nil, err
	}

	points := make([]*keyshares.PointInFiniteField, 0, totalShares)
	curve := keyshares.NewCurve()
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	usedX := make(map[string]struct{})

	for i := range totalShares {
		const maxAttempts = 5
		attempts := 0
		var x *big.Int
		for {
			// counter: i (4 bytes) | attempt (4 bytes) | 32 bytes randomness
			counter := make([]byte, 0, 40)
			var ib [4]byte
			var ab [4]byte
			binary.BigEndian.PutUint32(ib[:], uint32(i))
			binary.BigEndian.PutUint32(ab[:], uint32(attempts))
			counter = append(counter, ib[:]...)
			counter = append(counter, ab[:]...)
			rnd := make([]byte, 32)
			if _, err := rand.Read(rnd); err != nil {
				return nil, fmt.Errorf("failed to read randomness: %w", err)
			}
			counter = append(counter, rnd...)

			h := crypto.Sha512HMAC(counter, seed)
			x = new(big.Int).SetBytes(h)
			x.Mod(x, curve.P)

			attempts++
			if attempts > maxAttempts {
				return nil, fmt.Errorf("failed to generate unique x coordinate after %d attempts", maxAttempts)
			}
			if x.Sign() == 0 {
				continue
			}
			key := x.String()
			if _, exists := usedX[key]; exists {
				continue
			}
			usedX[key] = struct{}{}
			break
		}

		y := new(big.Int).Set(poly.ValueAt(x))
		points = append(points, keyshares.NewPointInFiniteField(x, y))
	}

	integrity := hex.EncodeToString(p.PubKey().Hash())[:8]
	return keyshares.NewKeyShares(points, threshold, integrity), nil
}

// PrivateKeyFromKeyShares combines shares to reconstruct the private key.
func PrivateKeyFromKeyShares(keyShares *keyshares.KeyShares) (*PrivateKey, error) {
	if keyShares.Threshold < 2 {
		return nil, errors.New("threshold should be at least 2")
	}

	if len(keyShares.Points) < keyShares.Threshold {
		return nil, fmt.Errorf("at least %d shares are required to reconstruct the private key", keyShares.Threshold)
	}

	// check to see if two points have the same x value
	for i := 0; i < keyShares.Threshold; i++ {
		for j := i + 1; j < keyShares.Threshold; j++ {
			if keyShares.Points[i].X.Cmp(keyShares.Points[j].X) == 0 {
				return nil, fmt.Errorf("duplicate share detected, each must be unique")
			}
		}
	}

	poly := keyshares.NewPolynomial(keyShares.Points, keyShares.Threshold)
	polyBytes := poly.ValueAt(big.NewInt(0)).Bytes()
	privateKey, publicKey := PrivateKeyFromBytes(polyBytes)
	integrityHash := hex.EncodeToString(publicKey.Hash())[:8]
	if keyShares.Integrity != integrityHash {
		return nil, fmt.Errorf("integrity hash mismatch %s != %s", keyShares.Integrity, integrityHash)
	}
	return privateKey, nil
}

// ToBackupShares creates a backup of the private key by splitting it into shares.
func (p *PrivateKey) ToBackupShares(threshold int, shares int) ([]string, error) {
	keyShares, err := p.ToKeyShares(threshold, shares)
	if err != nil {
		return nil, err
	}
	return keyShares.ToBackupFormat()
}

// PrivateKeyFromBackupShares creates a private key from backup shares.
func PrivateKeyFromBackupShares(shares []string) (*PrivateKey, error) {
	keyShares, err := keyshares.NewKeySharesFromBackupFormat(shares)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromKeyShares(keyShares)
}

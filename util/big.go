package util

import (
	"crypto/rand"
	"math/big"
)

// Umod returns the unsigned modulus of x and y.
// It ensures the result is always non-negative.
func Umod(x, y *big.Int) *big.Int {
	// Ensure divisor y is not zero
	if y.Sign() == 0 {
		panic("division by zero")
	}

	// If the dividend x is zero, the modulus is zero
	if x.Sign() == 0 {
		return big.NewInt(0)
	}

	mod := new(big.Int)

	// Handle cases where x is negative and y is positive
	if x.Sign() < 0 && y.Sign() > 0 {
		mod.Neg(x)
		mod.Mod(mod, y)
		mod.Neg(mod)
		if mod.Sign() < 0 {
			mod.Add(mod, y)
		}
	} else if x.Sign() > 0 && y.Sign() < 0 {
		// Handle cases where x is positive and y is negative
		mod.Mod(x, new(big.Int).Neg(y))
	} else if x.Sign() < 0 && y.Sign() < 0 {
		// Handle cases where both x and y are negative
		mod.Neg(x)
		mod.Mod(mod, new(big.Int).Neg(y))
		mod.Neg(mod)
		if mod.Sign() < 0 {
			mod.Sub(mod, y)
		}
	} else {
		// Both numbers are positive
		mod.Mod(x, y)
	}

	// Ensure the result is non-negative
	if mod.Sign() < 0 {
		mod.Add(mod, new(big.Int).Abs(y))
	}

	return mod
}

func NewRandomBigInt(byteLen int) *big.Int {
	b := make([]byte, byteLen)
	maxRetries := 10
	// gracefully handle errors in low entropy environments
	// or extreme resource constraints, embedded systems
	for retries := 0; retries < maxRetries; retries++ {
		_, err := rand.Read(b)
		if err == nil {
			return new(big.Int).SetBytes(b)
		}
	}
	// Failure here indicates a critical error
	panic("failed to generate random big.Int")
}

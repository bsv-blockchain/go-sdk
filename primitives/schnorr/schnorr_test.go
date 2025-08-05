package schnorr

import (
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchnorr_GenerateAndVerifyProof(t *testing.T) {
	s := New()

	// Generate private keys
	a, err := ec.NewPrivateKey()
	require.NoError(t, err)
	b, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// Get public keys
	A := a.PubKey()
	B := b.PubKey()

	// Calculate shared secret S = B * a = A * b
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.NotNil(t, proof.R)
	require.NotNil(t, proof.SPrime)
	require.NotNil(t, proof.Z)

	// Verify proof
	result := s.VerifyProof(A, B, S, proof)
	assert.True(t, result, "Valid proof should verify successfully")
}

func TestSchnorr_FailVerificationWithTamperedR(t *testing.T) {
	s := New()

	// Generate keys and shared secret
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	A := a.PubKey()
	B := b.PubKey()
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Tamper with R by adding the generator point
	curve := A.Curve
	tamperedR := new(ec.PublicKey)
	tamperedR.Curve = curve
	tamperedR.X, tamperedR.Y = curve.Add(proof.R.X, proof.R.Y, curve.Params().Gx, curve.Params().Gy)
	tamperedProof := &Proof{
		R:      tamperedR,
		SPrime: proof.SPrime,
		Z:      proof.Z,
	}

	// Verify should fail
	result := s.VerifyProof(A, B, S, tamperedProof)
	assert.False(t, result, "Tampered proof should fail verification")
}

func TestSchnorr_FailVerificationWithTamperedZ(t *testing.T) {
	s := New()

	// Generate keys and shared secret
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	A := a.PubKey()
	B := b.PubKey()
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Tamper with z
	tamperedZ := new(big.Int).Add(proof.Z, big.NewInt(1))
	tamperedZ.Mod(tamperedZ, A.Curve.Params().N)
	tamperedProof := &Proof{
		R:      proof.R,
		SPrime: proof.SPrime,
		Z:      tamperedZ,
	}

	// Verify should fail
	result := s.VerifyProof(A, B, S, tamperedProof)
	assert.False(t, result, "Tampered proof should fail verification")
}

func TestSchnorr_FailVerificationWithTamperedSPrime(t *testing.T) {
	s := New()

	// Generate keys and shared secret
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	A := a.PubKey()
	B := b.PubKey()
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Tamper with S'
	curve := A.Curve
	tamperedSPrime := new(ec.PublicKey)
	tamperedSPrime.Curve = curve
	tamperedSPrime.X, tamperedSPrime.Y = curve.Add(proof.SPrime.X, proof.SPrime.Y, curve.Params().Gx, curve.Params().Gy)
	tamperedProof := &Proof{
		R:      proof.R,
		SPrime: tamperedSPrime,
		Z:      proof.Z,
	}

	// Verify should fail
	result := s.VerifyProof(A, B, S, tamperedProof)
	assert.False(t, result, "Tampered proof should fail verification")
}

func TestSchnorr_FailVerificationWithWrongPublicKey(t *testing.T) {
	s := New()

	// Generate keys and shared secret
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	A := a.PubKey()
	B := b.PubKey()
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Use wrong public key for verification
	wrongA, _ := ec.NewPrivateKey()
	wrongAPublic := wrongA.PubKey()

	// Verify should fail
	result := s.VerifyProof(wrongAPublic, B, S, proof)
	assert.False(t, result, "Wrong public key should fail verification")
}

func TestSchnorr_FailVerificationWithWrongSharedSecret(t *testing.T) {
	s := New()

	// Generate keys and shared secret
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	A := a.PubKey()
	B := b.PubKey()
	S := B.Mul(a.D)

	// Generate proof with correct S
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Create wrong shared secret
	c, _ := ec.NewPrivateKey()
	wrongS := B.Mul(c.D)

	// Verify should fail
	result := s.VerifyProof(A, B, wrongS, proof)
	assert.False(t, result, "Wrong shared secret should fail verification")
}

func TestSchnorr_VerifyWithFixedKeys(t *testing.T) {
	s := New()

	// Use fixed private keys for determinism (matching TypeScript test)
	a, err := ec.PrivateKeyFromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	require.NoError(t, err)
	
	b, err := ec.PrivateKeyFromHex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
	require.NoError(t, err)

	// Get public keys
	A := a.PubKey()
	B := b.PubKey()

	// Calculate shared secret
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Verify proof
	result := s.VerifyProof(A, B, S, proof)
	assert.True(t, result, "Fixed key proof should verify successfully")
}

func TestSchnorr_ProofComponentsNotNil(t *testing.T) {
	s := New()

	// Generate random keys
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	A := a.PubKey()
	B := b.PubKey()
	S := B.Mul(a.D)

	// Generate proof
	proof, err := s.GenerateProof(a, A, B, S)
	require.NoError(t, err)

	// Check all components are present
	assert.NotNil(t, proof.R)
	assert.NotNil(t, proof.R.X)
	assert.NotNil(t, proof.R.Y)
	assert.NotNil(t, proof.SPrime)
	assert.NotNil(t, proof.SPrime.X)
	assert.NotNil(t, proof.SPrime.Y)
	assert.NotNil(t, proof.Z)
	assert.Greater(t, proof.Z.BitLen(), 0, "Z should not be zero")
}
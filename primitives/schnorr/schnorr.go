package schnorr

import (
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// Proof represents a Schnorr zero-knowledge proof
type Proof struct {
	R      *ec.PublicKey
	SPrime *ec.PublicKey
	Z      *big.Int
}

// Schnorr provides methods to generate and verify proofs that demonstrate knowledge
// of a secret without revealing it. Specifically, it allows one party to prove to
// another that they know the private key corresponding to a public key and have
// correctly computed a shared secret.
type Schnorr struct{}

// New creates a new Schnorr instance
func New() *Schnorr {
	return &Schnorr{}
}

// GenerateProof generates a proof that demonstrates the link between public key A and shared secret S
// Parameters:
//   - a: Private key corresponding to public key A
//   - A: Public key of the prover
//   - B: Other party's public key
//   - S: Shared secret (should be B multiplied by a)
//
// Returns a proof (R, S', z) that can be verified without revealing the private key
func (s *Schnorr) GenerateProof(a *ec.PrivateKey, A *ec.PublicKey, B *ec.PublicKey, S *ec.PublicKey) (*Proof, error) {
	// Generate random value r
	r, err := ec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	// Calculate R = r*G (where G is the generator point)
	R := r.PubKey()

	// Calculate S' = r*B
	SPrime := B.Mul(r.D)

	// Compute challenge e = H(A || B || S || S' || R)
	e := s.computeChallenge(A, B, S, SPrime, R)

	// Calculate z = r + e*a (mod n)
	z := new(big.Int).Set(r.D)
	ea := new(big.Int).Mul(e, a.D)
	z.Add(z, ea)
	z.Mod(z, ec.S256().Params().N)

	return &Proof{
		R:      R,
		SPrime: SPrime,
		Z:      z,
	}, nil
}

// VerifyProof verifies the proof of the link between public key A and shared secret S
// Parameters:
//   - A: Public key of the prover
//   - B: Other party's public key
//   - S: Shared secret
//   - proof: The proof to verify
//
// Returns true if the proof is valid, false otherwise
func (s *Schnorr) VerifyProof(A *ec.PublicKey, B *ec.PublicKey, S *ec.PublicKey, proof *Proof) bool {
	// Compute challenge e = H(A || B || S || S' || R)
	e := s.computeChallenge(A, B, S, proof.SPrime, proof.R)

	// Check z*G = R + e*A
	curve := ec.S256()
	zGx, zGy := curve.ScalarBaseMult(proof.Z.Bytes())
	zG := &ec.PublicKey{Curve: curve, X: zGx, Y: zGy}
	eA := A.Mul(e)
	RpluseA := new(ec.PublicKey)
	RpluseA.Curve = curve
	RpluseA.X, RpluseA.Y = curve.Add(proof.R.X, proof.R.Y, eA.X, eA.Y)

	if zG.X.Cmp(RpluseA.X) != 0 || zG.Y.Cmp(RpluseA.Y) != 0 {
		return false
	}

	// Check z*B = S' + e*S
	zB := B.Mul(proof.Z)
	eS := S.Mul(e)
	SprimepluseS := new(ec.PublicKey)
	SprimepluseS.Curve = curve
	SprimepluseS.X, SprimepluseS.Y = curve.Add(proof.SPrime.X, proof.SPrime.Y, eS.X, eS.Y)

	if zB.X.Cmp(SprimepluseS.X) != 0 || zB.Y.Cmp(SprimepluseS.Y) != 0 {
		return false
	}

	return true
}

// computeChallenge computes the challenge value e = H(A || B || S || S' || R)
func (s *Schnorr) computeChallenge(A, B, S, SPrime, R *ec.PublicKey) *big.Int {
	// Concatenate all points in compressed format
	message := make([]byte, 0, 33*5)
	message = append(message, A.Compressed()...)
	message = append(message, B.Compressed()...)
	message = append(message, S.Compressed()...)
	message = append(message, SPrime.Compressed()...)
	message = append(message, R.Compressed()...)

	// Hash the concatenated points
	h := hash.Sha256(message)

	// Convert hash to big.Int and reduce modulo curve order
	e := new(big.Int).SetBytes(h)
	e.Mod(e, ec.S256().Params().N)

	return e
}

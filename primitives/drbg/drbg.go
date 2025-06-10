package primitives

import (
	"errors"
	"fmt"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// DRBG represents a HMAC-based Deterministic Random Bit Generator
type DRBG struct {
	K             []byte
	V             []byte
	ReseedCounter int
}

// NewDRBG creates a new DRBG instance
func NewDRBG(entropy, nonce []byte) (*DRBG, error) {
	if len(entropy) < 32 {
		return nil, fmt.Errorf("not enough entropy. Minimum is 256 bits")
	}

	seed := append(entropy, nonce...)
	drbg := &DRBG{
		K:             make([]byte, 32), // K is initialized to 32 bytes
		V:             make([]byte, 32), // V is initialized to 32 bytes
		ReseedCounter: 1,
	}

	for i := range drbg.V {
		drbg.V[i] = 0x01
	}

	drbg.update(seed)
	return drbg, nil
}

// hmacSHA256 is a helper function to compute HMAC-SHA256
func (d *DRBG) hmacSHA256(data []byte) []byte {
	return crypto.Sha256HMAC(data, d.K)
}

// update updates the internal state of the DRBG
func (d *DRBG) update(seed []byte) {
	var seedMaterial []byte
	seedMaterial = append(seedMaterial, d.V...)
	seedMaterial = append(seedMaterial, 0x00)
	if seed != nil {
		seedMaterial = append(seedMaterial, seed...)
	}
	d.K = d.hmacSHA256(seedMaterial)

	d.V = d.hmacSHA256(d.V)

	if seed != nil {
		seedMaterial = append(d.V, 0x01)
		seedMaterial = append(seedMaterial, seed...)
		d.K = d.hmacSHA256(seedMaterial)
		d.V = d.hmacSHA256(d.V)
	}
}

// Generate produces random data and updates the internal state
func (d *DRBG) Generate(length int) ([]byte, error) {
	if d.ReseedCounter > 10000 {
		return nil, errors.New("drbg: reseed required")
	}

	if length > 937 { // MaxBytesPerGenerate
		return nil, errors.New("drbg: request too large")
	}

	temp := make([]byte, 0, length)
	for len(temp) < length {
		d.V = d.hmacSHA256(d.V)
		temp = append(temp, d.V...)
	}

	result := temp[:length]
	d.update(nil)
	d.ReseedCounter++
	return result, nil
}

// Reseed allows reseeding the DRBG with new entropy
func (d *DRBG) Reseed(entropy []byte) error {
	if len(entropy) < 32 {
		return fmt.Errorf("drbg: not enough entropy for reseed")
	}

	d.update(entropy)
	d.ReseedCounter = 1
	return nil
}

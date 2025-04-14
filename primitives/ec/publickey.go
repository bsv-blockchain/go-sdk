package primitives

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// These constants define the lengths of serialized public keys.
const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
	PubKeyBytesLenHybrid       = 65
)

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// decompressPoint decompresses a point on the secp256k1 curve given the X point and
// the solution to use.
func decompressPoint(bigX *big.Int, ybit bool) (*big.Int, error) {
	var x fieldVal
	x.SetByteSlice(bigX.Bytes())

	// Compute x^3 + B mod p.
	var x3 fieldVal
	x3.SquareVal(&x).Mul(&x)
	x3.Add(S256().fieldB).Normalise()

	// Now calculate sqrt mod p of x^3 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	var y fieldVal
	y.SqrtVal(&x3).Normalise()
	if ybit != y.IsOdd() {
		y.Negate(1).Normalise()
	}

	// Check that y is a square root of x^3 + B.
	var y2 fieldVal
	y2.SquareVal(&y).Normalise()
	if !y2.Equals(&x3) {
		return nil, fmt.Errorf("invalid square root")
	}

	// Verify that y-coord has expected parity.
	if ybit != y.IsOdd() {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}

	return new(big.Int).SetBytes(y.Bytes()[:]), nil
}

const (
	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
	pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
)

// IsCompressedPubKey returns true the the passed serialized public key has
// been encoded in compressed format, and false otherwise.
func IsCompressedPubKey(pubKey []byte) bool {
	// The public key is only compressed if it is the correct length and
	// the format (first byte) is one of the compressed pubkey values.
	return len(pubKey) == PubKeyBytesLenCompressed &&
		(pubKey[0]&^byte(0x1) == pubkeyCompressed)
}

// ParsePubKey parses a public key for a koblitz curve from a bytestring into a
// ecdsa.Publickey, verifying that it is valid. It supports compressed,
// uncompressed and hybrid signature formats.
func ParsePubKey(pubKeyStr []byte) (key *PublicKey, err error) {
	pubkey := PublicKey{}
	pubkey.Curve = S256()

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed && format != pubkeyHybrid {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+
				"%d", pubKeyStr[0])
		}

		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyStr[33:])
		// hybrid keys have extra information, make use of it.
		if format == pubkeyHybrid && ybit != isOdd(pubkey.Y) {
			return nil, fmt.Errorf("ybit doesn't match oddness")
		}

		if pubkey.X.Cmp(pubkey.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey X parameter is >= to P")
		}
		if pubkey.Y.Cmp(pubkey.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey Y parameter is >= to P")
		}
		if !pubkey.IsOnCurve(pubkey.X, pubkey.Y) {
			return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
		}

	case PubKeyBytesLenCompressed:
		// format is 0x2 | solution, <X coordinate>
		// solution determines which solution of the curve we use.
		/// y^2 = x^3 + Curve.B
		if format != pubkeyCompressed {
			return nil, fmt.Errorf("invalid magic in compressed "+
				"pubkey string: %d", pubKeyStr[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y, err = decompressPoint(pubkey.X, ybit)
		if err != nil {
			return nil, err
		}

	default: // wrong!
		return nil, fmt.Errorf("invalid pub key length %d",
			len(pubKeyStr))
	}

	return &pubkey, nil
}

// PublicKey is an ecdsa.PublicKey with additional functions to
// serialize in uncompressed, compressed, and hybrid formats.
type PublicKey ecdsa.PublicKey

// ToECDSA returns the public key as a *ecdsa.PublicKey.
func (p *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(p)
}

// Uncompressed serializes a public key in a 65-byte uncompressed
// format.
func (p *PublicKey) Uncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// Compressed serializes a public key in a 33-byte compressed format.
func (p *PublicKey) Compressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// Hybrid serializes a public key in a 65-byte hybrid format.
func (p *PublicKey) Hybrid() []byte {
	b := make([]byte, 0, PubKeyBytesLenHybrid)
	format := pubkeyHybrid
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// IsEqual compares this PublicKey instance to the one passed, returning true if
// both PublicKeys are equivalent. A PublicKey is equivalent to another, if they
// both have the same X and Y coordinate.
func (p *PublicKey) IsEqual(otherPubKey *PublicKey) bool {
	return p.X.Cmp(otherPubKey.X) == 0 &&
		p.Y.Cmp(otherPubKey.Y) == 0
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte { //nolint:unparam // reasons
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// PublicKeyFromString returns a PublicKey from a hex string.
func PublicKeyFromString(pubKeyHex string) (*PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	pubKey, err := ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func PublicKeyFromBytes(pubKeyBytes []byte) (*PublicKey, error) {
	pubKey, err := ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// validate key belongs on given curve
func (p *PublicKey) Validate() bool {
	return p.IsOnCurve(p.X, p.Y)
}

// Multiplies this Point by a scalar value
func (p *PublicKey) Mul(k *big.Int) *PublicKey {
	x, y := p.ScalarMult(p.X, p.Y, k.Bytes())
	return &PublicKey{
		Curve: p.Curve,
		X:     x,
		Y:     y,
	}
}

/**
 * Hash sha256 and ripemd160 of the public key.
 *
 * @returns Returns the hash of the public key.
 *
 * @example
 * const publicKeyHash = pubkey.Hash()
 */
func (p *PublicKey) Hash() []byte {
	return crypto.Ripemd160(crypto.Sha256(p.Compressed()))
}

// //nolint:unparam // only compact is used
// func (p *PublicKey) encode(compact bool) []byte {
// 	byteLen := (p.Curve.Params().BitSize + 7) >> 3

// 	xBytes := p.X.Bytes()
// 	yBytes := p.Y.Bytes()

// 	// Prepend zeros if necessary to match byteLen
// 	for len(xBytes) < byteLen {
// 		xBytes = append([]byte{0}, xBytes...)
// 	}
// 	for len(yBytes) < byteLen {
// 		yBytes = append([]byte{0}, yBytes...)
// 	}

// 	if compact {
// 		prefix := byte(0x02)
// 		if new(big.Int).And(p.Y, big.NewInt(1)).Cmp(big.NewInt(0)) != 0 {
// 			prefix = 0x03
// 		}
// 		return append([]byte{prefix}, xBytes...)
// 	}

// 	// Non-compact format
// 	return append(append([]byte{0x04}, xBytes...), yBytes...)
// }

func (p *PublicKey) ToDER() []byte {
	encoded := p.Compressed()
	return encoded
}

func (p *PublicKey) ToDERHex() string {
	return hex.EncodeToString(p.ToDER())
}

func (p *PublicKey) DeriveChild(privateKey *PrivateKey, invoiceNumber string) (*PublicKey, error) {
	invoiceNumberBin := []byte(invoiceNumber)
	sharedSecret, err := p.DeriveSharedSecret(privateKey)
	if err != nil {
		return nil, err
	}
	pubKeyEncoded := sharedSecret.Compressed()
	hmac := crypto.Sha256HMAC(invoiceNumberBin, pubKeyEncoded)

	newPointX, newPointY := S256().ScalarBaseMult(hmac)
	newPubKeyX, newPubKeyY := S256().Add(newPointX, newPointY, p.X, p.Y)
	return &PublicKey{
		Curve: S256(),
		X:     newPubKeyX,
		Y:     newPubKeyY,
	}, nil
}

// TODO: refactor to have 1 function for both private and public key
// call it multiply point with scalar or something and pass in private key
// and public key
func (p *PublicKey) DeriveSharedSecret(priv *PrivateKey) (*PublicKey, error) {
	if !p.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("public key not valid for secret derivation")
	}
	return p.Mul(priv.D), nil
}

// Verify a signature of a message using this public key.
func (p *PublicKey) Verify(msg []byte, sig *Signature) bool {
	msgHash := crypto.Sha256(msg)
	return sig.Verify(msgHash, p)
}

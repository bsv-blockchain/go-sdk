package primitives

import (
	"bytes"
	e "crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

var (
	// ErrChecksumMismatch describes an error where decoding failed due
	// to a bad checksum.
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrMalformedPrivateKey describes an error where a WIF-encoded private
	// key cannot be decoded due to being improperly formatted.  This may occur
	// if the byte length is incorrect or an unexpected magic number was
	// encountered.
	ErrMalformedPrivateKey = errors.New("malformed private key")
)

type Network byte

var (
	MainNet Network = 0x80
	TestNet Network = 0xef
)

// compressMagic is the magic byte used to identify a WIF encoding for
// an address created from a compressed serialized public key.
const compressMagic byte = 0x01

// PrivateKey wraps an ecdsa.PrivateKey as a convenience mainly for signing
// things with the the private key without having to directly import the ecdsa
// package.
type PrivateKey e.PrivateKey

// PrivateKeyFromBytes returns a private and public key based on the
// private key passed as an argument as a byte slice.
func PrivateKeyFromBytes(pk []byte) (*PrivateKey, *PublicKey) {
	x, y := S256().ScalarBaseMult(pk)
	priv := &e.PrivateKey{
		PublicKey: e.PublicKey{
			Curve: S256(),
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}
	return (*PrivateKey)(priv), (*PublicKey)(&priv.PublicKey)
}

// NewPrivateKey is a wrapper for ecdsa.GenerateKey that returns a PrivateKey
func NewPrivateKey() (*PrivateKey, error) {
	key, err := e.GenerateKey(S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(key), nil
}

// PrivateKeyFromHex returns a private key from a hex string.
func PrivateKeyFromHex(privKeyHex string) (*PrivateKey, error) {
	if len(privKeyHex) == 0 {
		return nil, errors.New("private key hex is empty")
	}
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, err
	}
	privKey, _ := PrivateKeyFromBytes(privKeyBytes)
	return privKey, nil
}

// PrivateKeyFromWif returns a private key from a WIF string.
func PrivateKeyFromWif(wif string) (*PrivateKey, error) {
	decoded, err := base58.Decode(wif)
	if err != nil {
		return nil, err
	}
	decodedLen := len(decoded)
	var compress bool

	// Length of base58 decoded WIF must be 32 bytes + an optional 1 byte
	// (0x01) if compressed, plus 1 byte for netID + 4 bytes of checksum.
	switch decodedLen {
	case 1 + PrivateKeyBytesLen + 1 + 4:
		if decoded[33] != compressMagic {
			return nil, ErrMalformedPrivateKey
		}
		compress = true
	case 1 + PrivateKeyBytesLen + 4:
		compress = false
	default:
		return nil, ErrMalformedPrivateKey
	}

	// Checksum is first four bytes of double SHA256 of the identifier byte
	// and privKey.  Verify this matches the final 4 bytes of the decoded
	// private key.
	var tosum []byte
	if compress {
		tosum = decoded[:1+PrivateKeyBytesLen+1]
	} else {
		tosum = decoded[:1+PrivateKeyBytesLen]
	}
	cksum := crypto.Sha256d(tosum)[:4]
	if !bytes.Equal(cksum, decoded[decodedLen-4:]) {
		return nil, ErrChecksumMismatch
	}

	// netID := decoded[0]
	privKeyBytes := decoded[1 : 1+PrivateKeyBytesLen]
	privKey, _ := PrivateKeyFromBytes(privKeyBytes)
	return privKey, nil
}

func (p *PrivateKey) Wif() string {
	return p.WifPrefix(byte(MainNet))
}

func (p *PrivateKey) WifPrefix(prefix byte) string {
	// Precalculate size.  Maximum number of bytes before base58 encoding
	// is one byte for the network, 32 bytes of private key, possibly one
	// extra byte if the pubkey is to be compressed, and finally four
	// bytes of checksum.

	encodeLen := 1 + PrivateKeyBytesLen + 4
	// For now, we assume compressed = true
	// if compress {
	encodeLen++
	// }

	a := make([]byte, 0, encodeLen)
	a = append(a, prefix)
	// Pad and append bytes manually, instead of using Serialize, to
	// avoid another call to make.
	b := p.D.Bytes()
	a = paddedAppend(PrivateKeyBytesLen, a, b)

	// For now, we assume compressed = true
	// if compress {
	a = append(a, compressMagic)
	// }
	cksum := crypto.Sha256d(a)[:4]
	a = append(a, cksum...)
	return base58.Encode(a)
}

// PubKey returns the PublicKey corresponding to this private key.
func (p *PrivateKey) PubKey() *PublicKey {
	return (*PublicKey)(&p.PublicKey)
}

// Sign generates an ECDSA signature for the provided hash (which should be the result
// of hashing a larger message) using the private key. Produced signature
// is deterministic (same message and same key yield the same signature) and canonical
// in accordance with RFC6979 and BIP0062.
func (p *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return signRFC6979(p, hash)
}

// PrivateKeyBytesLen defines the length in bytes of a serialized private key.
const PrivateKeyBytesLen = 32

// Serialize returns the private key number d as a big-endian binary-encoded
// number, padded to a length of 32 bytes.
func (p *PrivateKey) Serialize() []byte {
	b := make([]byte, 0, PrivateKeyBytesLen)
	return paddedAppend(PrivateKeyBytesLen, b, p.D.Bytes())
}

// Hex returns the hexadecimal string representation of the serialized private key.
func (p *PrivateKey) Hex() string {
	return hex.EncodeToString(p.Serialize())
}

func (p *PrivateKey) DeriveSharedSecret(key *PublicKey) (*PublicKey, error) {
	if !key.Validate() {
		return nil, fmt.Errorf("public key is not on the curve")
	}
	return key.Mul(p.D), nil
}

// Derives a child key with BRC-42
//
// See BRC-42 spec here: https://github.com/bitcoin-sv/BRCs/blob/master/key-derivation/0042.md
func (p *PrivateKey) DeriveChild(pub *PublicKey, invoiceNumber string) (*PrivateKey, error) {
	invoiceNumberBin := []byte(invoiceNumber)
	sharedSecret, err := p.DeriveSharedSecret(pub)
	if err != nil {
		return nil, err
	}
	hmac := crypto.Sha256HMAC(invoiceNumberBin, sharedSecret.Compressed())

	newPrivKey := new(big.Int)
	newPrivKey.Add(p.D, new(big.Int).SetBytes(hmac))
	newPrivKey.Mod(newPrivKey, S256().N)
	privKey, _ := PrivateKeyFromBytes(newPrivKey.Bytes())
	return privKey, nil
}

package compat

import (
	"bytes"
	"encoding/base64"
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/util"
)

const hBSV = "Bitcoin Signed Message:\n"

// MagicHash computes the Bitcoin Signed Message digest: SHA-256d of the
// varint-length-prefixed "Bitcoin Signed Message:\n" magic string followed
// by the varint-length-prefixed message. This is the digest that
// SignMessage signs and VerifyMessage checks against; it is exposed
// standalone for callers that need it directly, mirroring the TS
// reference's BSM.magicHash.
func MagicHash(message []byte) []byte {
	b := new(bytes.Buffer)

	varInt := util.VarInt(len(hBSV))
	b.Write(varInt.Bytes())

	// append the hBsv to buff
	b.WriteString(hBSV)

	varInt = util.VarInt(len(message))
	b.Write(varInt.Bytes())

	// append the data to buff
	b.Write(message)

	return crypto.Sha256d(b.Bytes())
}

// SignMessage signs a string with the provided PrivateKey using Bitcoin Signed Message encoding
// sigRefCompressedKey bool determines whether the signature will reference a compressed or uncompresed key
// Spec: https://github.com/bitcoin/bitcoin/pull/524
func SignMessage(privateKey *ec.PrivateKey, message []byte) ([]byte, error) {
	return SignMessageWithCompression(privateKey, message, true)
}

func SignMessageWithCompression(privateKey *ec.PrivateKey, message []byte, sigRefCompressedKey bool) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}

	// Sign
	return ec.SignCompact(ec.S256(), privateKey, MagicHash(message), sigRefCompressedKey)
}

// SignMessageString signs the message and returns the signature as a base64-encoded string
func SignMessageString(privateKey *ec.PrivateKey, message []byte) (string, error) {
	sigBytes, err := SignMessageWithCompression(privateKey, message, true)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

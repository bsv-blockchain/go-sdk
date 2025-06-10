package compat

import (
	"bytes"
	"encoding/base64"
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/v2/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/v2/util"
)

const hBSV = "Bitcoin Signed Message:\n"

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

	b := new(bytes.Buffer)

	varInt := util.VarInt(len(hBSV))
	b.Write(varInt.Bytes())

	// append the hBsv to buff
	b.WriteString(hBSV)

	varInt = util.VarInt(len(message))
	b.Write(varInt.Bytes())

	// append the data to buff
	b.Write(message)

	// Create the hash
	messageHash := crypto.Sha256d(b.Bytes())

	// Sign
	return ec.SignCompact(ec.S256(), privateKey, messageHash, sigRefCompressedKey)
}

// SignMessageString signs the message and returns the signature as a base64-encoded string
func SignMessageString(privateKey *ec.PrivateKey, message []byte) (string, error) {
	sigBytes, err := SignMessageWithCompression(privateKey, message, true)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

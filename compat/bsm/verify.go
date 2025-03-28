package compat

import (
	"bytes"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// PubKeyFromSignature gets a publickey for a signature and tells you whether is was compressed
func PubKeyFromSignature(sig, data []byte) (pubKey *ec.PublicKey, wasCompressed bool, err error) {

	// Validate the signature - this just shows that it was valid at all
	// we will compare it with the key next
	var buf bytes.Buffer

	varInt := transaction.VarInt(len(hBSV))
	buf.Write(varInt.Bytes())
	// append the hBsv to buff
	buf.WriteString(hBSV)

	varInt = transaction.VarInt(len(data))
	buf.Write(varInt.Bytes())
	// append the data to buff
	buf.Write(data)

	// Create the hash
	expectedMessageHash := crypto.Sha256d(buf.Bytes())
	return ec.RecoverCompact(sig, expectedMessageHash)
}

// VerifyMessage verifies a string and address against the provided
// signature and assumes Bitcoin Signed Message encoding.
// The key referenced by the signature must relate to the address provided.
// Do not provide an address from an uncompressed key along with
// a signature from a compressed key
//
// Error will occur if verify fails or verification is not successful (no bool)
// Spec: https://github.com/bitcoin/bitcoin/pull/524
func VerifyMessage(address string, sig, data []byte) error {
	// Reconstruct the pubkey
	publicKey, wasCompressed, err := PubKeyFromSignature(sig, data)
	if err != nil {
		return err
	}

	// Get the address
	var scriptAddress *script.Address
	if scriptAddress, err = script.NewAddressFromPublicKeyWithCompression(publicKey, true, wasCompressed); err != nil {
		return err
	}

	// Return nil if addresses match.
	if scriptAddress.AddressString == address {
		return nil
	}
	return fmt.Errorf(
		"address (%s) not found - compressed: %t\n%s was found instead",
		address,
		wasCompressed,
		scriptAddress.AddressString,
	)
}

// VerifyMessageDER will take a message string, a public key string and a signature string
// (in strict DER format) and verify that the message was signed by the public key.
func VerifyMessageDER(hash [32]byte, pubKey string, signature string) (verified bool, err error) {

	// Decode the signature string
	var sigBytes []byte
	if sigBytes, err = hex.DecodeString(signature); err != nil {
		return
	}

	// Parse the signature
	var sig *ec.Signature
	if sig, err = ec.ParseDERSignature(sigBytes); err != nil {
		return
	}

	// Decode the pubKey
	var pubKeyBytes []byte
	if pubKeyBytes, err = hex.DecodeString(pubKey); err != nil {
		return
	}

	// Parse the pubKey
	var rawPubKey *ec.PublicKey
	if rawPubKey, err = ec.ParsePubKey(pubKeyBytes); err != nil {
		return
	}

	// Verify the signature against the pubKey
	verified = sig.Verify(hash[:], rawPubKey)
	return
}

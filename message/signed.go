package message

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/bitcoin-sv/go-sdk/ec"
)

type SignedMessage struct {
	Version            []byte
	SenderPublicKey    *ec.PublicKey
	RecipientPublicKey *ec.PublicKey
	KeyID              []byte
	Signature          *ec.Signature
}

func Sign(message []byte, signer *ec.PrivateKey, verifier *ec.PublicKey) ([]byte, error) {
	recipientAnyone := verifier == nil
	if recipientAnyone {
		anyone, _ := ec.PrivateKeyFromBytes(ec.S256(), []byte{1})
		anyonePointX, anyonePointY := ec.S256().ScalarMult(anyone.X, anyone.Y, anyone.Serialise())
		verifier = &ec.PublicKey{X: anyonePointX, Y: anyonePointY, Curve: ec.S256()}
	}

	keyID := make([]byte, 32)
	_, err := rand.Read(keyID)
	if err != nil {
		return nil, err
	}
	keyIDBase64 := base64.StdEncoding.EncodeToString(keyID)
	invoiceNumber := "2-message signing-" + keyIDBase64
	signingPriv, err := signer.DeriveChild(verifier, invoiceNumber)
	if err != nil {
		return nil, err
	}
	signature, err := signingPriv.Sign(message)
	if err != nil {
		return nil, err
	}
	senderPublicKey := signer.PubKey()

	sig := append(VERSION_BYTES, senderPublicKey.SerialiseCompressed()...)
	if recipientAnyone {
		sig = append(sig, 0)
	} else {
		sig = append(sig, verifier.SerialiseCompressed()...)
	}
	sig = append(sig, keyID...)
	signatureDER, err := signature.ToDER()
	if err != nil {
		return nil, err
	}
	sig = append(sig, signatureDER...)
	return sig, nil
}

func Verify(message []byte, sig []byte, recipient *ec.PrivateKey) (bool, error) {
	messageVersion := sig[:4]
	if !bytes.Equal(messageVersion, VERSION_BYTES) {
		return false, fmt.Errorf("Message version mismatch: Expected %x, received %x", VERSION_BYTES, messageVersion)
	}
	pubKeyBytes := sig[4:37]
	signer, err := ec.ParsePubKey(pubKeyBytes, ec.S256())
	if err != nil {
		return false, err
	}
	verifierFirst := sig[37]
	if verifierFirst == 0 {
		recipient, _ = ec.PrivateKeyFromBytes(ec.S256(), []byte{1})
	} else {
		verifierRest := sig[38:70]
		verifierDER := append([]byte{verifierFirst}, verifierRest...)
		if recipient == nil {
			return false, nil
		}
		recipientDER := recipient.PubKey().SerialiseCompressed()
		if !bytes.Equal(verifierDER, recipientDER) {
			err = fmt.Errorf("the recipient public key is %x but the signature requres the recipient to have public key %x", recipientDER, verifierDER)
			return false, err
		}
	}
	keyID := sig[70:102]
	signatureDER := sig[102:]
	signature, err := ec.FromDER(signatureDER)
	if err != nil {
		return false, err
	}
	keyIDBase64 := base64.StdEncoding.EncodeToString(keyID)
	invoiceNumber := "2-message signing-" + keyIDBase64
	signingKey, err := signer.DeriveChild(recipient, invoiceNumber)
	if err != nil {
		return false, err
	}
	verified := signature.Verify(message, signingKey)
	return verified, nil

}

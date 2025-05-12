package compat

import (
	"crypto/hmac"
	"encoding/base64"
	"math/big"
	"reflect"

	"errors"

	ecies "github.com/bsv-blockchain/go-sdk/primitives/aescbc"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	c "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// EncryptSingle is a helper that uses Electrum ECIES method to encrypt a message
func EncryptSingle(message string, privateKey *ec.PrivateKey) (string, error) {
	messageBytes := []byte(message)
	if privateKey == nil {
		return "", errors.New("private key is required")
	}
	decryptedBytes, _ := ElectrumEncrypt(messageBytes, privateKey.PubKey(), nil, false)
	return base64.StdEncoding.EncodeToString(decryptedBytes), nil
}

// DecryptSingle is a helper that uses Electrum ECIES method to decrypt a message
func DecryptSingle(encryptedData string, privateKey *ec.PrivateKey) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	plainBytes, err := ElectrumDecrypt(encryptedBytes, privateKey, nil)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

// EncryptShared is a helper that uses Electrum ECIES method to encrypt a message for a target public key
func EncryptShared(message string, toPublicKey *ec.PublicKey, fromPrivateKey *ec.PrivateKey) (string, error) {
	messageBytes := []byte(message)
	decryptedBytes, err := ElectrumEncrypt(messageBytes, toPublicKey, fromPrivateKey, false)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decryptedBytes), nil
}

// DecryptShared is a helper that uses Electrum ECIES method to decrypt a message from a target public key
func DecryptShared(encryptedData string, toPrivateKey *ec.PrivateKey, fromPublicKey *ec.PublicKey) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	plainBytes, err := ElectrumDecrypt(encryptedBytes, toPrivateKey, fromPublicKey)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

// ElectrumEncrypt encrypts a message using ECIES	using Electrum encryption method
func ElectrumEncrypt(message []byte,
	toPublicKey *ec.PublicKey,
	fromPrivateKey *ec.PrivateKey,
	noKey bool,
) ([]byte, error) {
	// Generate an ephemeral EC private key if fromPrivateKey is nil
	var ephemeralPrivateKey *ec.PrivateKey
	if fromPrivateKey == nil {
		ephemeralPrivateKey, _ = ec.NewPrivateKey()
	} else {
		ephemeralPrivateKey = fromPrivateKey
	}

	// Derive ECDH key
	x, y := toPublicKey.ScalarMult(toPublicKey.X, toPublicKey.Y, ephemeralPrivateKey.D.Bytes())
	ecdhKey := (&ec.PublicKey{X: x, Y: y}).Compressed()

	// SHA512(ECDH_KEY)
	key := c.Sha512(ecdhKey)
	iv, keyE, keyM := key[0:16], key[16:32], key[32:]

	// AES encryption
	cipherText, err := ecies.AESCBCEncrypt(message, keyE, iv, false)
	if err != nil {
		return nil, err
	}

	ephemeralPublicKey := ephemeralPrivateKey.PubKey()
	var encrypted []byte
	if noKey {
		// encrypted = magic_bytes(4 bytes) + cipher
		encrypted = append([]byte("BIE1"), cipherText...)
	} else {
		// encrypted = magic_bytes(4 bytes) + ephemeral_public_key(33 bytes) + cipher
		encrypted = append(append([]byte("BIE1"), ephemeralPublicKey.Compressed()...), cipherText...)
	}

	mac := c.Sha256HMAC(encrypted, keyM)

	return append(encrypted, mac...), nil
}

// ElectrumDecrypt decrypts a message using ECIES using Electrum decryption method
func ElectrumDecrypt(encryptedData []byte, toPrivateKey *ec.PrivateKey, fromPublicKey *ec.PublicKey) ([]byte, error) {

	if len(encryptedData) < 52 { // Minimum length: 4 (magic) + 16 (min cipher) + 32 (mac)
		return nil, errors.New("invalid encrypted text: length")
	}
	magic := encryptedData[:4]
	if string(magic) != "BIE1" {
		return nil, errors.New("invalid cipher text: invalid magic bytes")
	}

	var sharedSecret []byte
	var cipherText []byte

	if fromPublicKey != nil {
		// Use counterparty public key to derive shared secret
		x, y := toPrivateKey.ScalarMult(fromPublicKey.X, fromPublicKey.Y, toPrivateKey.D.Bytes())
		sharedSecret = (&ec.PublicKey{X: x, Y: y}).Compressed()
		if len(encryptedData) > 69 { // 4 (magic) + 33 (pubkey) + 32 (mac)
			cipherText = encryptedData[37 : len(encryptedData)-32]
		} else {
			cipherText = encryptedData[4 : len(encryptedData)-32]
		}
	} else {
		// Use ephemeral public key to derive shared secret
		ephemeralPublicKey, err := ec.ParsePubKey(encryptedData[4:37])
		if err != nil {
			return nil, err
		}
		x, y := ephemeralPublicKey.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, toPrivateKey.D.Bytes())
		sharedSecret = (&ec.PublicKey{X: x, Y: y}).Compressed()
		cipherText = encryptedData[37 : len(encryptedData)-32]
	}

	// Derive key_e, iv and key_m
	key := c.Sha512(sharedSecret)
	iv, keyE, keyM := key[0:16], key[16:32], key[32:]

	// Verify mac
	mac := encryptedData[len(encryptedData)-32:]
	macRecalculated := c.Sha256HMAC(encryptedData[:len(encryptedData)-32], keyM)
	if !reflect.DeepEqual(mac, macRecalculated) {
		return nil, errors.New("incorrect password")
	}

	// AES decryption
	plain, err := ecies.AESCBCDecrypt(cipherText, keyE, iv)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// BitcoreEncrypt encrypts a message using ECIES using Bitcore encryption method
func BitcoreEncrypt(message []byte,
	toPublicKey *ec.PublicKey,
	fromPrivateKey *ec.PrivateKey,
	iv []byte,
) ([]byte, error) {

	// If IV is not provided, fill it with zeros
	if iv == nil {
		iv = make([]byte, 16)
	}

	// If fromPrivateKey is not provided, generate a random one
	if fromPrivateKey == nil {
		fromPrivateKey, _ = ec.NewPrivateKey()
	}

	RBuf := fromPrivateKey.PubKey().ToDER()
	P := toPublicKey.Mul(fromPrivateKey.D)

	Sbuf := P.X.Bytes()
	kEkM := c.Sha512(Sbuf)
	kE := kEkM[:32]
	kM := kEkM[32:]
	cc, err := ecies.AESCBCEncrypt(message, kE, iv, true)
	if err != nil {
		return nil, err
	}
	d := c.Sha256HMAC(cc, kM)
	encBuf := append(RBuf, cc...)
	encBuf = append(encBuf, d...)

	return encBuf, nil
}

// BitcoreDecrypt decrypts a message using ECIES using Bitcore decryption method
func BitcoreDecrypt(encryptedMessage []byte, toPrivatKey *ec.PrivateKey) ([]byte, error) {

	fromPublicKey, err := ec.ParsePubKey(encryptedMessage[:33])
	if err != nil {
		return nil, err
	}

	P := fromPublicKey.Mul(toPrivatKey.D)
	if P.X.Cmp(big.NewInt(0)) == 0 && P.Y.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("p equals 0")
	}

	Sbuf := P.X.Bytes()
	kEkM := c.Sha512(Sbuf)
	kE := kEkM[:32]
	kM := kEkM[32:]

	cipherText := encryptedMessage[33 : len(encryptedMessage)-32]
	mac := encryptedMessage[len(encryptedMessage)-32:]
	expectedMAC := c.Sha256HMAC(cipherText, kM)
	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("invalid ciphertext: HMAC mismatch")
	}
	iv := cipherText[:16]
	return ecies.AESCBCDecrypt(cipherText[16:], kE, iv)
}

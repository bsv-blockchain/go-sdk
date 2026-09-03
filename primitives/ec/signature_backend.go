package primitives

import "sync"

type externalSignatureBackend struct {
	sync.RWMutex

	signer   func(message, privateKey []byte) ([]byte, error)
	verifier func(message, signature, publicKey []byte) bool
}

var signatureBackend externalSignatureBackend

// InjectExternalSignerFn installs an external secp256k1 ECDSA signer. The
// signer receives a message digest and a 32-byte private key and must return a
// canonical, low-S, strict DER-encoded signature. Passing nil restores the
// built-in pure-Go signer.
//
// The configured signer is process-wide and safe to call concurrently.
// Applications should normally configure it during startup.
func InjectExternalSignerFn(fn func(message, privateKey []byte) ([]byte, error)) {
	signatureBackend.Lock()
	signatureBackend.signer = fn
	signatureBackend.Unlock()
}

// InjectExternalVerifySignatureFn installs an external secp256k1 ECDSA
// verifier. The verifier receives a message digest, a strict DER-encoded
// signature, and a compressed public key. Passing nil restores the built-in
// pure-Go verifier.
//
// The configured verifier is process-wide and safe to call concurrently.
// Applications should normally configure it during startup.
func InjectExternalVerifySignatureFn(fn func(message, signature, publicKey []byte) bool) {
	signatureBackend.Lock()
	signatureBackend.verifier = fn
	signatureBackend.Unlock()
}

func getExternalSignerFn() func(message, privateKey []byte) ([]byte, error) {
	signatureBackend.RLock()
	fn := signatureBackend.signer
	signatureBackend.RUnlock()
	return fn
}

func getExternalVerifySignatureFn() func(message, signature, publicKey []byte) bool {
	signatureBackend.RLock()
	fn := signatureBackend.verifier
	signatureBackend.RUnlock()
	return fn
}

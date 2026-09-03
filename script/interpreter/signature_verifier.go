package interpreter

import "sync"

var externalSignatureVerifier = struct {
	sync.RWMutex

	fn func(payload, signature, publicKey []byte) bool
}{}

// InjectExternalVerifySignatureFn installs an external signature verifier for
// OP_CHECKSIG and OP_CHECKSIGVERIFY. Passing nil restores the built-in
// verifier.
//
// The configured verifier is process-wide and safe to call concurrently.
// Applications should normally configure it during startup.
func InjectExternalVerifySignatureFn(fn func(payload, signature, publicKey []byte) bool) {
	externalSignatureVerifier.Lock()
	externalSignatureVerifier.fn = fn
	externalSignatureVerifier.Unlock()
}

func getExternalVerifySignatureFn() func(payload, signature, publicKey []byte) bool {
	externalSignatureVerifier.RLock()
	fn := externalSignatureVerifier.fn
	externalSignatureVerifier.RUnlock()
	return fn
}

package primitives

import (
	"testing"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// Benchmarks for the ECDSA hot paths that back transaction signing and
// verification. Key generation and message hashing are done outside the timer;
// only the signing or verifying operation is measured.

// benchSigHash is a fixed 32-byte digest reused across the signing benchmarks so
// each iteration signs the same message.
var benchSigHash = crypto.Sha256([]byte("go-sdk ecdsa benchmark message"))

// BenchmarkECDSASign measures signing a 32-byte digest with a secp256k1 key.
func BenchmarkECDSASign(b *testing.B) {
	priv, err := NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := priv.Sign(benchSigHash); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkECDSAVerify measures verifying a valid signature over a 32-byte
// digest.
func BenchmarkECDSAVerify(b *testing.B) {
	priv, err := NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.PubKey()
	sig, err := priv.Sign(benchSigHash)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if !sig.Verify(benchSigHash, pub) {
			b.Fatal("signature failed to verify")
		}
	}
}

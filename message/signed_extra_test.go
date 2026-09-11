package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestVerifyInvalidSignerPublicKey covers the branch where the embedded signer
// public key bytes do not parse as a valid point.
func TestVerifyInvalidSignerPublicKey(t *testing.T) {
	t.Parallel()
	recipient, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// VERSION_BYTES followed by 33 zero bytes (an invalid compressed key).
	sig := append([]byte{}, VERSION_BYTES...)
	sig = append(sig, make([]byte, 33)...)

	_, err = Verify([]byte("msg"), sig, recipient)
	require.Error(t, err)
}

// TestVerifyInvalidSignatureDER covers the branch where the trailing signature
// bytes are not valid DER.
func TestVerifyInvalidSignatureDER(t *testing.T) {
	t.Parallel()
	signer, err := ec.NewPrivateKey()
	require.NoError(t, err)
	recipient, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// version + valid signer pubkey + verifierFirst==0 (anyone) + keyID + bad DER
	sig := append([]byte{}, VERSION_BYTES...)
	sig = append(sig, signer.PubKey().Compressed()...)
	sig = append(sig, 0x00)                  // verifierFirst == 0 -> "anyone" path
	sig = append(sig, make([]byte, 32)...)   // keyID
	sig = append(sig, []byte{0x00, 0x01}...) // invalid DER signature

	_, err = Verify([]byte("msg"), sig, recipient)
	require.Error(t, err)
}

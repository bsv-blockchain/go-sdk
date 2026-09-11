package primitives

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSignatureDERRoundTrip covers ToDER and FromDER, including the FromDER
// error branch on malformed input.
func TestSignatureDERRoundTrip(t *testing.T) {
	t.Parallel()

	priv, err := NewPrivateKey()
	require.NoError(t, err)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	sig, err := priv.Sign(hash)
	require.NoError(t, err)

	der, err := sig.ToDER()
	require.NoError(t, err)
	require.NotEmpty(t, der)

	got, err := FromDER(der)
	require.NoError(t, err)
	require.Zero(t, got.R.Cmp(sig.R))
	require.Zero(t, got.S.Cmp(sig.S))

	t.Run("malformed DER returns error", func(t *testing.T) {
		t.Parallel()
		_, err := FromDER([]byte{0xff, 0x00, 0x01})
		require.Error(t, err)
	})
}

// TestPublicKeyJSONMarshalling covers MarshalJSON and UnmarshalJSON including
// error branches.
func TestPublicKeyJSONMarshalling(t *testing.T) {
	t.Parallel()

	priv, err := NewPrivateKey()
	require.NoError(t, err)
	pub := priv.PubKey()

	data, err := json.Marshal(pub)
	require.NoError(t, err)

	var decoded PublicKey
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.True(t, pub.IsEqual(&decoded))

	t.Run("nil pubkey marshals to null", func(t *testing.T) {
		t.Parallel()
		var p *PublicKey
		b, err := p.MarshalJSON()
		require.NoError(t, err)
		require.JSONEq(t, "null", string(b))
	})

	t.Run("unmarshal non-string fails", func(t *testing.T) {
		t.Parallel()
		var p PublicKey
		require.Error(t, p.UnmarshalJSON([]byte("123")))
	})

	t.Run("unmarshal invalid hex fails", func(t *testing.T) {
		t.Parallel()
		var p PublicKey
		require.Error(t, p.UnmarshalJSON([]byte(`"zzzz"`)))
	})
}

// TestPublicKeyFromBytesAndString covers PublicKeyFromBytes and the error
// branches of PublicKeyFromString.
func TestPublicKeyFromBytesAndString(t *testing.T) {
	t.Parallel()

	priv, err := NewPrivateKey()
	require.NoError(t, err)
	pub := priv.PubKey()
	compressed := pub.Compressed()

	t.Run("from bytes valid", func(t *testing.T) {
		t.Parallel()
		got, err := PublicKeyFromBytes(compressed)
		require.NoError(t, err)
		require.True(t, pub.IsEqual(got))
	})

	t.Run("from bytes invalid", func(t *testing.T) {
		t.Parallel()
		_, err := PublicKeyFromBytes([]byte{0x02, 0x00})
		require.Error(t, err)
	})

	t.Run("from string bad hex", func(t *testing.T) {
		t.Parallel()
		_, err := PublicKeyFromString("zzz")
		require.Error(t, err)
	})

	t.Run("from string valid hex bad point", func(t *testing.T) {
		t.Parallel()
		_, err := PublicKeyFromString("0200")
		require.Error(t, err)
	})
}

// TestDeriveSharedSecretNotOnCurve covers the error branch of DeriveSharedSecret
// when the public key is not a valid curve point.
func TestDeriveSharedSecretNotOnCurve(t *testing.T) {
	t.Parallel()

	priv, err := NewPrivateKey()
	require.NoError(t, err)

	badPub := &PublicKey{
		Curve: S256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
	}
	_, err = badPub.DeriveSharedSecret(priv)
	require.Error(t, err)
}

// TestSymmetricKeyStringHelpers covers EncryptString, DecryptString and FromBytes.
func TestSymmetricKeyStringHelpers(t *testing.T) {
	t.Parallel()

	key := NewSymmetricKeyFromRandom()

	t.Run("encrypt/decrypt string round trip", func(t *testing.T) {
		t.Parallel()
		const msg = "the quick brown fox"
		ct, err := key.EncryptString(msg)
		require.NoError(t, err)
		require.NotEmpty(t, ct)

		pt, err := key.DecryptString(ct)
		require.NoError(t, err)
		require.Equal(t, msg, pt)
	})

	t.Run("decrypt string too short fails", func(t *testing.T) {
		t.Parallel()
		_, err := key.DecryptString("short")
		require.Error(t, err)
	})

	t.Run("from bytes builds usable key", func(t *testing.T) {
		t.Parallel()
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = byte(i + 1)
		}
		built := (&SymmetricKey{}).FromBytes(raw)
		require.Equal(t, raw, built.ToBytes())

		ct, err := built.Encrypt([]byte("hi"))
		require.NoError(t, err)
		pt, err := built.Decrypt(ct)
		require.NoError(t, err)
		require.Equal(t, []byte("hi"), pt)
	})
}

// TestCurveDouble covers the KoblitzCurve.Double method, both the zero-y
// short-circuit and the general point doubling path.
func TestCurveDouble(t *testing.T) {
	t.Parallel()

	curve := S256()

	t.Run("zero y returns point at infinity", func(t *testing.T) {
		t.Parallel()
		x, y := curve.Double(big.NewInt(5), big.NewInt(0))
		require.Zero(t, x.Sign())
		require.Zero(t, y.Sign())
	})

	t.Run("doubles the generator point", func(t *testing.T) {
		t.Parallel()
		x, y := curve.Double(curve.Gx, curve.Gy)
		require.True(t, curve.IsOnCurve(x, y))
		// Doubling G must match ScalarBaseMult(2).
		ex, ey := curve.ScalarBaseMult([]byte{2})
		require.Zero(t, x.Cmp(ex))
		require.Zero(t, y.Cmp(ey))
	})
}

// TestCurveConstants covers QPlus1Div4 and Q.
func TestCurveConstants(t *testing.T) {
	t.Parallel()

	curve := S256()
	require.NotNil(t, curve.QPlus1Div4())
	require.NotNil(t, curve.Q())
	require.Zero(t, curve.QPlus1Div4().Cmp(curve.Q()))
}

// TestFromHexPanicsOnInvalid covers the panic branch of FromHex.
func TestFromHexPanicsOnInvalid(t *testing.T) {
	t.Parallel()

	require.NotNil(t, FromHex("ff"))
	require.Panics(t, func() {
		_ = FromHex("nothex")
	})
}

// TestModuloReduce covers the long-input reduction branch of moduloReduce.
func TestModuloReduce(t *testing.T) {
	t.Parallel()

	curve := S256()

	// Input longer than the curve byte size triggers the modulo path.
	long, err := hex.DecodeString(
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	)
	require.NoError(t, err)
	reduced := curve.moduloReduce(long)
	require.LessOrEqual(t, len(reduced), curve.byteSize)

	// Short input is returned effectively unchanged (<= byteSize).
	short := curve.moduloReduce([]byte{0x01, 0x02})
	require.LessOrEqual(t, len(short), curve.byteSize)
}

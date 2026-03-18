package wallet_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- BytesList ----

func TestBytesListMarshalJSON(t *testing.T) {
	bl := wallet.BytesList{1, 2, 3, 255}
	data, err := json.Marshal(bl)
	require.NoError(t, err)
	assert.Equal(t, "[1,2,3,255]", string(data))
}

func TestBytesListUnmarshalJSON(t *testing.T) {
	var bl wallet.BytesList
	err := json.Unmarshal([]byte("[10,20,30]"), &bl)
	require.NoError(t, err)
	assert.Equal(t, wallet.BytesList{10, 20, 30}, bl)
}

func TestBytesListRoundTrip(t *testing.T) {
	original := wallet.BytesList{0, 127, 128, 255}
	data, err := json.Marshal(original)
	require.NoError(t, err)

	var result wallet.BytesList
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	assert.Equal(t, original, result)
}

// ---- BytesHex ----

func TestBytesHexMarshalJSON(t *testing.T) {
	bh := wallet.BytesHex{0xde, 0xad, 0xbe, 0xef}
	data, err := json.Marshal(bh)
	require.NoError(t, err)
	assert.Equal(t, `"deadbeef"`, string(data))
}

func TestBytesHexUnmarshalJSON(t *testing.T) {
	var bh wallet.BytesHex
	err := json.Unmarshal([]byte(`"cafebabe"`), &bh)
	require.NoError(t, err)
	assert.Equal(t, wallet.BytesHex{0xca, 0xfe, 0xba, 0xbe}, bh)
}

func TestBytesHexUnmarshalInvalidHex(t *testing.T) {
	var bh wallet.BytesHex
	err := json.Unmarshal([]byte(`"xyz"`), &bh)
	assert.Error(t, err)
}

// ---- Bytes32Base64 ----

func TestBytes32Base64MarshalJSON(t *testing.T) {
	var b wallet.Bytes32Base64
	copy(b[:], []byte("hello world test"))
	data, err := json.Marshal(b)
	require.NoError(t, err)
	// Should be base64 encoded
	var str string
	err = json.Unmarshal(data, &str)
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(str)
	require.NoError(t, err)
	assert.Equal(t, 32, len(decoded))
}

func TestBytes32Base64UnmarshalJSON(t *testing.T) {
	var src wallet.Bytes32Base64
	copy(src[:], []byte("abcdefghijklmnop"))
	data, _ := json.Marshal(src)

	var dst wallet.Bytes32Base64
	err := json.Unmarshal(data, &dst)
	require.NoError(t, err)
	assert.Equal(t, src, dst)
}

func TestBytes32Base64UnmarshalWrongLength(t *testing.T) {
	// 16 bytes encoded - should fail
	b16 := make([]byte, 16)
	encoded := base64.StdEncoding.EncodeToString(b16)
	jsonStr, _ := json.Marshal(encoded)

	var dst wallet.Bytes32Base64
	err := json.Unmarshal(jsonStr, &dst)
	assert.Error(t, err)
}

// ---- Bytes33Hex ----

func TestBytes33HexMarshalJSON(t *testing.T) {
	var b wallet.Bytes33Hex
	for i := range b {
		b[i] = byte(i)
	}
	data, err := json.Marshal(b)
	require.NoError(t, err)
	var str string
	err = json.Unmarshal(data, &str)
	require.NoError(t, err)
	assert.Equal(t, 66, len(str)) // 33 bytes = 66 hex chars
}

func TestBytes33HexUnmarshalJSON(t *testing.T) {
	var src wallet.Bytes33Hex
	for i := range src {
		src[i] = byte(i + 1)
	}
	data, _ := json.Marshal(src)

	var dst wallet.Bytes33Hex
	err := json.Unmarshal(data, &dst)
	require.NoError(t, err)
	assert.Equal(t, src, dst)
}

func TestBytes33HexUnmarshalWrongLength(t *testing.T) {
	// 32 bytes hex = wrong length
	b32 := make([]byte, 32)
	hexStr := make([]byte, 64)
	for i := range b32 {
		hexStr[i*2] = "0123456789abcdef"[b32[i]>>4]
		hexStr[i*2+1] = "0123456789abcdef"[b32[i]&0xf]
	}
	jsonStr, _ := json.Marshal(string(hexStr))

	var dst wallet.Bytes33Hex
	err := json.Unmarshal(jsonStr, &dst)
	assert.Error(t, err)
}

// ---- StringBase64 ----

func TestStringBase64ToArray(t *testing.T) {
	arr := [32]byte{}
	copy(arr[:], []byte("test data here!!"))
	s := wallet.StringBase64FromArray(arr)

	result, err := s.ToArray()
	require.NoError(t, err)
	assert.Equal(t, arr, result)
}

func TestStringBase64ToArrayInvalid(t *testing.T) {
	s := wallet.StringBase64("not-valid-base64!!!")
	_, err := s.ToArray()
	assert.Error(t, err)
}

func TestStringBase64ToArrayEmpty(t *testing.T) {
	empty := [32]byte{}
	s := wallet.StringBase64FromArray(empty)
	result, err := s.ToArray()
	require.NoError(t, err)
	assert.Equal(t, empty, result)
}

// ---- Signature ----

func TestSignatureMarshalUnmarshalJSON(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	sig, err := privKey.Sign(hash)
	require.NoError(t, err)

	walletSig := wallet.Signature(*sig)
	data, err := json.Marshal(walletSig)
	require.NoError(t, err)

	var decoded wallet.Signature
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify the decoded signature works
	decodedECSig := (*ec.Signature)(&decoded)
	assert.True(t, decodedECSig.Verify(hash, privKey.PubKey()))
}

func TestSignatureMarshalNilROrS(t *testing.T) {
	walletSig := wallet.Signature{}
	data, err := json.Marshal(walletSig)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

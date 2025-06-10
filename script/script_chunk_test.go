package script_test

import (
	"encoding/hex"
	"testing"

	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/require"
)

func TestDecodeScript(t *testing.T) {
	t.Parallel()

	t.Run("simple", func(t *testing.T) {
		parts, err := script.DecodeScriptHex("05000102030401FF02ABCD")
		require.NoError(t, err)
		require.Len(t, parts, 3)
	})

	t.Run("simple and encode", func(t *testing.T) {
		parts, err := script.DecodeScriptHex("05000102030401FF02ABCD")
		require.NoError(t, err)
		require.Len(t, parts, 3)

		pushes := make([][]byte, len(parts))
		for i, p := range parts {
			pushes[i] = p.Data
		}

		var p []byte
		p, err = script.EncodePushDatas(pushes)
		require.NoError(t, err)

		require.Equal(t, "05000102030401ff02abcd", hex.EncodeToString(p))
	})

	t.Run("empty parts", func(t *testing.T) {
		parts, err := script.DecodeScriptHex("")
		require.NoError(t, err)
		require.Empty(t, parts)
	})

	t.Run("complex parts", func(t *testing.T) {
		s := "524c53ff0488b21e000000000000000000362f7a9030543db8751401c387d6a71e870f1895b3a62569d455e8ee5f5f5e5f03036624c6df96984db6b4e625b6707c017eb0e0d137cd13a0c989bfa77a4473fd000000004c53ff0488b21e0000000000000000008b20425398995f3c866ea6ce5c1828a516b007379cf97b136bffbdc86f75df14036454bad23b019eae34f10aff8b8d6d8deb18cb31354e5a169ee09d8a4560e8250000000052ae"
		parts, err := script.DecodeScriptHex(s)
		require.NoError(t, err)
		require.Len(t, parts, 5)
	})

	t.Run("bad parts", func(t *testing.T) {
		_, err := script.DecodeScriptHex("05000000")
		require.Error(t, err)
		require.EqualError(t, err, "not enough data")

		_, err = script.DecodeScriptHex("4c05000000")
		require.Error(t, err)
		require.EqualError(t, err, "not enough data")
	})

	t.Run("decode using OP_PUSHDATA1", func(t *testing.T) {

		data := "testing"
		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA1)
		b = append(b, byte(len(data)))
		b = append(b, []byte(data)...)

		decoded, err := script.DecodeScript(b)
		require.NoError(t, err)
		require.NotEmpty(t, decoded)
	})

	t.Run("invalid decode using OP_PUSHDATA1 - missing data payload", func(t *testing.T) {

		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA1)

		decoded, err := script.DecodeScript(b)
		require.Error(t, err)
		require.Empty(t, decoded)
	})

	t.Run("invalid decode using OP_PUSHDATA2 - payload too small", func(t *testing.T) {

		data := "testing the code OP_PUSHDATA2"
		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA2)
		b = append(b, byte(len(data)))
		b = append(b, []byte(data)...)

		decoded, err := script.DecodeScript(b)
		require.Error(t, err)
		require.Empty(t, decoded)
	})

	t.Run("invalid decode using OP_PUSHDATA2 - missing data payload", func(t *testing.T) {

		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA2)

		decoded, err := script.DecodeScript(b)
		require.Error(t, err)
		require.Empty(t, decoded)
	})

	t.Run("invalid decode using OP_PUSHDATA2 - overflow", func(t *testing.T) {

		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA2)
		b = append(b, 0xff)
		b = append(b, 0xff)

		bigScript := make([]byte, 0xffff)

		b = append(b, bigScript...)

		t.Logf("Script len is %d", len(b))

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic detected: %v", r)
			}
		}()

		_, err := script.DecodeScript(b)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("invalid decode using OP_PUSHDATA4 - payload too small", func(t *testing.T) {

		data := "testing the code OP_PUSHDATA4"
		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA4)
		b = append(b, byte(len(data)))
		b = append(b, []byte(data)...)

		decoded, err := script.DecodeScript(b)
		require.Error(t, err)
		require.Empty(t, decoded)
	})

	t.Run("invalid decode using OP_PUSHDATA4 - missing data payload", func(t *testing.T) {

		b := make([]byte, 0)
		b = append(b, script.OpPUSHDATA4)

		decoded, err := script.DecodeScript(b)
		require.Error(t, err)
		require.Empty(t, decoded)
	})
}

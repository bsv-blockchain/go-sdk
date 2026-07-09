package transaction

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

const outputHexStr = "8a08ac4a000000001976a9148bf10d323ac757268eb715e613cb8e8e1d1793aa88ac00000000"

func TestNewOutputFromBytes(t *testing.T) {
	t.Parallel()

	t.Run("invalid output, too short", func(t *testing.T) {
		o, s, err := newOutputFromBytes([]byte(""))
		require.Error(t, err)
		require.Nil(t, o)
		require.Equal(t, 0, s)
	})

	t.Run("invalid output, too short + script", func(t *testing.T) {
		o, s, err := newOutputFromBytes([]byte("0000000000000"))
		require.Error(t, err)
		require.Nil(t, o)
		require.Equal(t, 0, s)
	})

	t.Run("valid output", func(t *testing.T) {
		bytes, err := hex.DecodeString(outputHexStr)
		require.NoError(t, err)

		var o *TransactionOutput
		var s int
		o, s, err = newOutputFromBytes(bytes)
		require.NoError(t, err)
		require.NotNil(t, o)

		require.Equal(t, 34, s)
		require.Equal(t, uint64(1252788362), o.Satoshis)
		require.Len(t, *o.LockingScript, 25)
		require.Equal(t, "76a9148bf10d323ac757268eb715e613cb8e8e1d1793aa88ac", o.LockingScriptHex())
	})
}

func TestOutput_String(t *testing.T) {
	t.Run("compare string output", func(t *testing.T) {
		bytes, err := hex.DecodeString(outputHexStr)
		require.NoError(t, err)

		var o *TransactionOutput
		o, _, err = newOutputFromBytes(bytes)
		require.NoError(t, err)
		require.NotNil(t, o)

		require.Equal(t, "value:     1252788362\nscriptLen: 25\nscript:    76a9148bf10d323ac757268eb715e613cb8e8e1d1793aa88ac\n", o.String())
	})
}

package serializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// xtValidKeyParams returns encoded key-related params for a self counterparty.
func xtValidKeyParams(t *testing.T) []byte {
	t.Helper()
	kp, err := encodeKeyRelatedParams(KeyRelatedParams{
		ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "p"},
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
	})
	require.NoError(t, err)
	return kp
}

func TestDeserializeListActionsArgsInvalidQueryMode(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteStringSlice([]string{}) // labels
	w.WriteByteValue(0x05)         // invalid label query mode byte
	_, err := DeserializeListActionsArgs(w.Buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid label query mode byte")
}

func TestDeserializeListActionsResultInvalidStatus(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteVarInt(1)                      // TotalActions
	w.WriteBytesReverse(make([]byte, 32)) // txid
	w.WriteVarInt(1000)                   // satoshis
	w.WriteByteValue(0x09)                // invalid status byte
	_, err := DeserializeListActionsResult(w.Buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status byte")
}

func TestDeserializeInternalizeActionArgsErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid protocol byte", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(0)       // tx length
		w.WriteVarInt(1)       // output count
		w.WriteVarInt(0)       // output index
		w.WriteByteValue(0x09) // invalid protocol
		_, err := DeserializeInternalizeActionArgs(w.Buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid internalize action protocol")
	})

	t.Run("bad sender identity key", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(0)               // tx length
		w.WriteVarInt(1)               // output count
		w.WriteVarInt(0)               // output index
		w.WriteByteValue(1)            // wallet payment protocol
		w.WriteByteValue(0x01)         // invalid pubkey magic
		w.WriteBytes(make([]byte, 32)) // rest of the (invalid) 33-byte key
		_, err := DeserializeInternalizeActionArgs(w.Buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error parsing sender identity key")
	})
}

func TestDeserializeCreateSignatureArgsInvalidDataFlag(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteBytes(xtValidKeyParams(t))
	w.WriteByteValue(0x09) // invalid data type flag
	_, err := DeserializeCreateSignatureArgs(w.Buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type flag")
}

func TestDeserializeVerifySignatureArgsInvalidDataFlag(t *testing.T) {
	t.Parallel()

	sig := newTestSignature(t)
	w := util.NewWriter()
	w.WriteBytes(xtValidKeyParams(t))
	w.WriteOptionalBool(nil)         // forSelf
	w.WriteIntBytes(sig.Serialize()) // valid signature
	w.WriteByteValue(0x09)           // invalid data type flag
	_, err := DeserializeVerifySignatureArgs(w.Buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type flag")
}

func TestDeserializeAcquireCertificateArgsInvalidProtocolFlag(t *testing.T) {
	t.Parallel()

	pub := xtPub(t)
	w := util.NewWriter()
	w.WriteBytes(make([]byte, 32))                // type
	w.WriteBytes(pub.Compressed())                // valid certifier
	w.WriteVarInt(0)                              // fields length
	w.WriteBytes(encodePrivilegedParams(nil, "")) // privileged params
	w.WriteByteValue(0x09)                        // invalid acquisition protocol flag
	_, err := DeserializeAcquireCertificateArgs(w.Buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid acquisition protocol flag")
}

func TestDeserializeCreateHMACResultTooShort(t *testing.T) {
	t.Parallel()

	_, err := DeserializeCreateHMACResult(make([]byte, 31))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data too short")
}

func TestDeserializeRelinquishOutputResultNonEmpty(t *testing.T) {
	t.Parallel()

	_, err := DeserializeRelinquishOutputResult([]byte{0x01})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid result data length")
}

func TestDeserializeGetPublicKeyResultInvalid(t *testing.T) {
	t.Parallel()

	_, err := DeserializeGetPublicKeyResult([]byte{0x01})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing result public key")
}

func TestDeserializeCreateSignatureResultInvalid(t *testing.T) {
	t.Parallel()

	_, err := DeserializeCreateSignatureResult([]byte{0x01, 0x02})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing signature")
}

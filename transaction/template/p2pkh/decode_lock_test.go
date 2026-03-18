package p2pkh_test

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/stretchr/testify/require"
)

// knownP2PKHHex is a standard P2PKH locking script for a known address.
// Corresponds to address 1EXaDXx3f8H3u4BNPBXSb8roFkgJ7CDVMA (mainnet).
const knownP2PKHHex = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac"

// knownPubKeyHashHex is the 20-byte hash embedded in knownP2PKHHex.
const knownPubKeyHashHex = "c0a3c167a28cabb9fbb495affa0761e6e74ac60d"

// TestDecodeValidP2PKH verifies that a well-formed 25-byte P2PKH script
// is decoded to a non-nil Address.
func TestDecodeValidP2PKH(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromHex(knownP2PKHHex)
	require.NoError(t, err)

	addr := p2pkh.Decode(s, true)
	require.NotNil(t, addr, "should decode valid P2PKH script")
	require.Len(t, addr.PublicKeyHash, 20)
}

// TestDecodeMainnetVsTestnet verifies that the mainnet flag affects the
// resulting address string but not the public-key hash.
func TestDecodeMainnetVsTestnet(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromHex(knownP2PKHHex)
	require.NoError(t, err)

	addrMain := p2pkh.Decode(s, true)
	addrTest := p2pkh.Decode(s, false)

	require.NotNil(t, addrMain)
	require.NotNil(t, addrTest)
	require.Equal(t, addrMain.PublicKeyHash, addrTest.PublicKeyHash,
		"public key hash should be the same for mainnet and testnet")
	require.NotEqual(t, addrMain.AddressString, addrTest.AddressString,
		"address strings should differ between mainnet and testnet")
}

// TestDecodeWrongLength verifies that scripts with length != 25 return nil.
func TestDecodeWrongLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hex  string
	}{
		{"too short", "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d"},
		{"empty", ""},
		{"single byte", "76"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := script.NewFromHex(tt.hex)
			require.NoError(t, err)
			addr := p2pkh.Decode(s, true)
			require.Nil(t, addr, "non-25-byte script should return nil")
		})
	}
}

// TestDecodeWrongOpCodes verifies that a 25-byte script whose opcodes don't
// match P2PKH structure returns nil.
func TestDecodeWrongOpCodes(t *testing.T) {
	t.Parallel()

	// Build a 25-byte script that is NOT P2PKH by flipping the first opcode.
	raw := make([]byte, 25)
	raw[0] = script.OpNOP // should be OpDUP
	raw[1] = script.OpHASH160
	raw[2] = script.OpDATA20
	for i := 3; i < 23; i++ {
		raw[i] = byte(i)
	}
	raw[23] = script.OpEQUALVERIFY
	raw[24] = script.OpCHECKSIG
	s := script.Script(raw)
	addr := p2pkh.Decode(&s, true)
	require.Nil(t, addr, "wrong opcodes should return nil")
}

// TestDecodeChunksError verifies that a malformed 25-byte script (one that
// causes Chunks() to return an error) is treated as non-P2PKH and nil is
// returned.
func TestDecodeChunksError(t *testing.T) {
	t.Parallel()

	// OpPUSHDATA1 (0x4c) at position 0 tells the decoder to read a 1-byte
	// length prefix at position 1 and then that many data bytes.  By setting
	// position 1 to 0xff (255 bytes expected) but providing only 23 more bytes
	// we guarantee ErrDataTooSmall from DecodeScript.
	raw := make([]byte, 25)
	raw[0] = script.OpPUSHDATA1 // 0x4c
	raw[1] = 0xff               // claims 255 bytes of data follow; only 23 remain
	for i := 2; i < 25; i++ {
		raw[i] = byte(i)
	}
	s := script.Script(raw)
	addr := p2pkh.Decode(&s, true)
	require.Nil(t, addr, "malformed script causing Chunks error should return nil")
}

// TestLockValidAddress verifies that Lock produces a 25-byte P2PKH script
// for a valid 20-byte public key hash.
func TestLockValidAddress(t *testing.T) {
	t.Parallel()

	addr, err := script.NewAddressFromString("1EXaDXx3f8H3u4BNPBXSb8roFkgJ7CDVMA")
	require.NoError(t, err)
	require.Len(t, addr.PublicKeyHash, 20)

	s, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Len(t, *s, 25, "P2PKH locking script must be 25 bytes")

	// Confirm round-trip: decoding should restore the original address.
	decoded := p2pkh.Decode(s, true)
	require.NotNil(t, decoded)
	require.Equal(t, addr.PublicKeyHash, decoded.PublicKeyHash)
}

// TestLockBadPublicKeyHash verifies that Lock returns ErrBadPublicKeyHash
// when the address has a hash that is not exactly 20 bytes.
func TestLockBadPublicKeyHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash []byte
	}{
		{"nil hash", nil},
		{"too short (19 bytes)", make([]byte, 19)},
		{"too long (21 bytes)", make([]byte, 21)},
		{"empty hash", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := &script.Address{PublicKeyHash: tt.hash}
			s, err := p2pkh.Lock(addr)
			require.Nil(t, s)
			require.ErrorIs(t, err, p2pkh.ErrBadPublicKeyHash)
		})
	}
}

// TestLockRoundTrip verifies that Lock -> Decode is idempotent.
func TestLockRoundTrip(t *testing.T) {
	t.Parallel()

	// Derive an address from a known private key.
	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), false /* testnet */)
	require.NoError(t, err)

	lockScript, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	require.NotNil(t, lockScript)

	decoded := p2pkh.Decode(lockScript, false)
	require.NotNil(t, decoded)
	require.Equal(t, addr.PublicKeyHash, decoded.PublicKeyHash)
}

// TestUnlockNilKey verifies that Unlock returns ErrNoPrivateKey when the
// supplied key is nil.
func TestUnlockNilKey(t *testing.T) {
	t.Parallel()

	p, err := p2pkh.Unlock(nil, nil)
	require.Nil(t, p)
	require.ErrorIs(t, err, p2pkh.ErrNoPrivateKey)
}

// TestUnlockWithExplicitSigHashFlag verifies that an explicit sighash flag is
// accepted and preserved.
func TestUnlockWithExplicitSigHashFlag(t *testing.T) {
	t.Parallel()

	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	flag := sighash.AllForkID
	unlocker, err := p2pkh.Unlock(priv, &flag)
	require.NoError(t, err)
	require.NotNil(t, unlocker)
}

// TestEstimateLength verifies that EstimateLength always returns 106.
func TestEstimateLength(t *testing.T) {
	t.Parallel()

	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	// EstimateLength should return 106 regardless of transaction and input index.
	require.Equal(t, uint32(106), unlocker.EstimateLength(nil, 0))
	require.Equal(t, uint32(106), unlocker.EstimateLength(nil, 99))

	// Also verify with a real transaction.
	tx := transaction.NewTransaction()
	require.Equal(t, uint32(106), unlocker.EstimateLength(tx, 0))
}

// TestLockOutputScriptStructure validates that the bytes of the produced
// locking script match the expected P2PKH template exactly.
func TestLockOutputScriptStructure(t *testing.T) {
	t.Parallel()

	hash := make([]byte, 20)
	for i := range hash {
		hash[i] = byte(i + 1) // 0x01..0x14
	}
	addr := &script.Address{PublicKeyHash: hash}

	s, err := p2pkh.Lock(addr)
	require.NoError(t, err)

	raw := []byte(*s)
	require.Len(t, raw, 25)
	require.Equal(t, byte(script.OpDUP), raw[0])
	require.Equal(t, byte(script.OpHASH160), raw[1])
	require.Equal(t, byte(script.OpDATA20), raw[2])
	require.Equal(t, hash, raw[3:23])
	require.Equal(t, byte(script.OpEQUALVERIFY), raw[23])
	require.Equal(t, byte(script.OpCHECKSIG), raw[24])
}

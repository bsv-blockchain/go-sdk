package interpreter

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// TestParseSignatureLax walks every branch of ecdsa_signature_parse_der_lax
// (bitcoin-sv pubkey.cpp:32-175).
func TestParseSignatureLax(t *testing.T) {
	t.Parallel()

	nHex := hex.EncodeToString(ec.S256().N.Bytes())
	for _, tc := range []struct {
		name string
		sig  string
		ok   bool
		r, s int64 // expected values when ok (0 also covers the overflow case)
	}{
		{"strict", "3006020101020102", true, 1, 2},
		{"long-form sequence length", "308106020101020102", true, 1, 2},
		{"sequence length 0x80 (no length bytes)", "3080020101020102", true, 1, 2},
		{"sequence length is ignored", "3000020101020102", true, 1, 2},
		{"sequence length bytes past the end", "30ff020101020102", false, 0, 0},
		{"long-form R length", "3008028200010502 0102", true, 5, 2},
		{"R length with 7 leading zero length bytes", "300d0288000000000000000105020102", true, 5, 2},
		{"R length with 8 significant length bytes", "300d0288010000000000000105020102", false, 0, 0},
		{"R length past the end", "3006020201020102", false, 0, 0},
		{"zero-length R", "30050200020102", true, 0, 2},
		{"zero-length S", "30050201010200", true, 1, 0},
		{"leading zeroes in R and S", "300a02030000010203000702", true, 1, 0x0702},
		{"negative R read as unsigned", "3006020181020102", true, 0x81, 2},
		{"trailing garbage after S", "3006020101020102deadbeef", true, 1, 2},
		{"R >= N overflows to zero", "3026022100" + nHex + "020102", true, 0, 0},
		{"S >= N overflows to zero", "3026020101022100" + nHex, true, 0, 0},
		{"33 significant R bytes overflow to zero", "3027022101" + strings.Repeat("00", 32) + "020102", true, 0, 0},
		{"missing S", "3003020101", false, 0, 0},
		{"S tag wrong", "3006020101030102", false, 0, 0},
		{"S truncated", "30060201010202 02", false, 0, 0},
		{"R tag wrong", "3006030101020102", false, 0, 0},
		{"sequence tag wrong", "3106020101020102", false, 0, 0},
		{"sequence tag only", "30", false, 0, 0},
		{"empty", "", false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig, err := hex.DecodeString(strings.ReplaceAll(tc.sig, " ", ""))
			require.NoError(t, err)
			r, s, ok := parseSignatureLax(sig)
			require.Equal(t, tc.ok, ok)
			if ok {
				require.Zero(t, big.NewInt(tc.r).Cmp(r), "r = %v", r)
				require.Zero(t, big.NewInt(tc.s).Cmp(s), "s = %v", s)
			}
		})
	}
}

// TestParseCheckSigSignature checks the lax path only applies without
// DERSIG/LOW_S/STRICTENC, normalises S and never returns a zero R or S.
func TestParseCheckSigSignature(t *testing.T) {
	t.Parallel()

	n := ec.S256().N
	highS := new(big.Int).Sub(n, big.NewInt(2))
	// Long-form sequence length, R = 1, S = N-2 (high).
	laxHighS, err := hex.DecodeString("308102" + "020101" + "022100" + hex.EncodeToString(highS.Bytes()))
	require.NoError(t, err)

	lax := &thread{}
	signature := lax.parseCheckSigSignature(laxHighS)
	require.NotNil(t, signature)
	require.Equal(t, big.NewInt(1), signature.R)
	require.Equal(t, big.NewInt(2), signature.S, "S is normalised to N-S")

	for _, flag := range []scriptflag.Flag{scriptflag.VerifyDERSignatures, scriptflag.VerifyLowS, scriptflag.VerifyStrictEncoding} {
		strict := &thread{flags: flag}
		require.Nil(t, strict.parseCheckSigSignature(laxHighS), "flag %v keeps the strict parser", flag)
	}

	zeroR, err := hex.DecodeString("30050200020102")
	require.NoError(t, err)
	require.Nil(t, lax.parseCheckSigSignature(zeroR))
	overflow, err := hex.DecodeString("3026022100" + hex.EncodeToString(n.Bytes()) + "020102")
	require.NoError(t, err)
	require.Nil(t, lax.parseCheckSigSignature(overflow))
}

// TestIsValidCheckSigPubKey mirrors CPubKey::IsValid's prefix/length table.
func TestIsValidCheckSigPubKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prefix byte
		size   int
		want   bool
	}{
		{0x02, 33, true},
		{0x03, 33, true},
		{0x04, 65, true},
		{0x06, 65, true},
		{0x07, 65, true},
		{0x02, 65, false},
		{0x04, 33, false},
		{0x05, 65, false},
		{0x05, 33, false},
		{0x00, 65, false},
		{0x02, 34, false},
		{0x04, 66, false},
		{0x02, 1, false},
	} {
		key := make([]byte, tc.size)
		key[0] = tc.prefix
		require.Equal(t, tc.want, isValidCheckSigPubKey(key), "prefix %#x size %d", tc.prefix, tc.size)
	}
	require.False(t, isValidCheckSigPubKey(nil))
}

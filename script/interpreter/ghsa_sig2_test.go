package interpreter

// Further regression vectors for GHSA-rh54-8fpg-8wwf's signature-checking
// area: lax DER parsing without DERSIG/LOW_S/STRICTENC, FindAndDelete of the
// canonical push only with OP_CODESEPARATORs kept in the shared scriptCode,
// CHECKMULTISIG encoding-check order, CPubKey::IsValid, CPubKey::CheckLowS
// and CHECKMULTISIG in the unlocking script. Every table vector was judged
// by the real bitcoin-sv node (879fc8b42, via GoBDK) under each flag word it
// lists, and this interpreter must reach the same verdict. Helper names use
// the "sig2" prefix.

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Locking-script fragments shared by several vectors.
const (
	// <pk> OP_CHECKSIG.
	sig2P2PK = "2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac"
	// OP_2 <0x05-prefixed 33-byte key> <pk2> <pk3> <pk4> OP_4
	// OP_CHECKMULTISIG OP_NOT (the 2-of-4 bad-key1 lock).
	sig2Core2of4 = "52210511111111111111111111111111111111111111111111111111111111111111112103e6680756685e5ff22181b617156e1ae53bbe1de77b6d0700b209a3c01704c6dd210331511ecfb35519754c2efdff91dc4ab4fa8c5d45e2230a31bf89fe7ad90416f221020005d9e06336c1fca195ba6abfd07dea262118f5dd638d5fc9a44d61d05da64b54ae91"
	// Same shape with other keys.
	sig2Core2of4Gen = "5221051111111111111111111111111111111111111111111111111111111111111111210245d3b9ce0f54f4d6a17edfe3f9e0993b94d6b299c1a6e5a728ff036ecd9e139f210257a62b05e99914350ce87639a68d0f3dd588e98afaf6c1131235a855d41962f32103d8c8a60a727a72f25e654bf1ed517fa05fb2ffc8e1036d3bf5e46ae819fc955f54ae91"
	// OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG OP_NOT.
	sig2Core2of2 = "52210242914f41e1f6bfefa90ffc972b939b104b5ec4a7d4329fda592e72f7c8c0ccb6210245d3b9ce0f54f4d6a17edfe3f9e0993b94d6b299c1a6e5a728ff036ecd9e139f52ae91"
)

// sig2WordFlags maps a node flag word to scriptflag.Flag bit by bit (node
// bit -> SDK flag).
func sig2WordFlags(word uint32) scriptflag.Flag {
	bits := map[uint32]scriptflag.Flag{
		1 << 0:  scriptflag.Bip16,
		1 << 1:  scriptflag.VerifyStrictEncoding,
		1 << 2:  scriptflag.VerifyDERSignatures,
		1 << 3:  scriptflag.VerifyLowS,
		1 << 4:  scriptflag.StrictMultiSig,
		1 << 5:  scriptflag.VerifySigPushOnly,
		1 << 6:  scriptflag.VerifyMinimalData,
		1 << 7:  scriptflag.DiscourageUpgradableNops,
		1 << 8:  scriptflag.VerifyCleanStack,
		1 << 9:  scriptflag.VerifyCheckLockTimeVerify,
		1 << 10: scriptflag.VerifyCheckSequenceVerify,
		1 << 13: scriptflag.VerifyMinimalIf,
		1 << 14: scriptflag.VerifyNullFail,
		1 << 16: scriptflag.EnableSighashForkID,
		1 << 18: scriptflag.Genesis,
		1 << 19: scriptflag.UTXOAfterGenesis,
		1 << 20: scriptflag.Chronicle,
		1 << 21: scriptflag.UTXOAfterChronicle,
	}
	var f scriptflag.Flag
	for bit, flag := range bits {
		if word&bit != 0 {
			f |= flag
		}
	}
	return f
}

// sig2Case is one spend, judged by bitcoin-sv (GoBDK), of a single
// 1000-satoshi output locked by lock, with the node's verdict (true = valid)
// per flag word.
type sig2Case struct {
	name    string
	tx      string
	lock    string
	perWord map[uint32]bool
}

func (c sig2Case) run(t *testing.T) {
	t.Helper()

	tx, err := transaction.NewTransactionFromHex(c.tx)
	require.NoError(t, err)
	lockBytes, err := hex.DecodeString(c.lock)
	require.NoError(t, err)
	prevs := make([]*transaction.TransactionOutput, len(tx.Inputs))
	for i := range tx.Inputs {
		prevs[i] = &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lockBytes), Satoshis: 1000}
		tx.Inputs[i].SetSourceTxOutput(prevs[i])
	}

	for word, wantValid := range c.perWord {
		var gotErr error
		for i := range tx.Inputs {
			if gotErr = NewEngine().Execute(WithTx(tx, i, prevs[i]), WithFlags(sig2WordFlags(word))); gotErr != nil {
				break
			}
		}
		if wantValid {
			require.NoError(t, gotErr, "%s: node accepts under word 0x%06x", c.name, word)
		} else {
			require.Error(t, gotErr, "%s: node rejects under word 0x%06x", c.name, word)
		}
	}
}

// TestGHSASig2OracleVectors replays the vectors judged by bitcoin-sv (GoBDK):
//
//   - lax DER: a valid signature re-encoded with every ecdsa_signature_parse_der_lax
//     leniency (and every way that parser fails or overflows), accepted or
//     rejected exactly like the node under the pre-BIP66 words 0x0/0x1 and
//     always rejected under DERSIG (0x5, 0x605), STRICTENC (0x2) and LOW_S
//     (0x8, 0xe);
//   - CPubKey::IsValid: a 65-byte key with prefix 0x05 is never used;
//   - CheckLowS: an R or S >= N overflows to a zero signature, which is low-S;
//   - FindAndDelete: an empty signature deletes OP_0 only (not PUSHDATA-encoded
//     empties, OP_1NEGATE, or anything else), including inside a top-level
//     OP_RETURN tail and up to a malformed instruction; OP_CODESEPARATORs stay
//     in the BIP143 scriptCode; a junk signature deletes only its canonical
//     push, and only when it is not a FORKID signature under FORKID;
//   - CHECKMULTISIG executing in a post-Chronicle unlocking script hashes the
//     unlocking-script tail plus the whole locking script;
//   - CHECKMULTISIG with a badly encoded key, empty or R=0 signatures and
//     OP_0/OP_CODESEPARATOR removal from the scriptCode, and lax DER under
//     the P2SH-only word 0x1.
func TestGHSASig2OracleVectors(t *testing.T) {
	t.Parallel()

	cases := []sig2Case{
		// ---- lax DER (pubkey.cpp ecdsa_signature_parse_der_lax) ----
		{
			name:    "lax DER outer-81 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a49308145022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER outer-80 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483080022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER outer-len-00 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483000022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER outer-ff-overrun p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000494830ff022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER outer-84-skip p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004e4c4c308401020304022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-82 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b4a30470282002100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-88-zeros p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000524c50304d0288000000000000002100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-88-nonzero p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000524c50304d0288000000000000012100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-87-huge p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000514c4f304c02870100000000000000ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-81-overrun p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a4930460281ff00ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-80-empty p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000028273024028002204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-len-83-zeros p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004c4b3048022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102830000204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-pad3 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b4a30470223000000ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-neg-nopad p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000484730440220ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-high-strict p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a493046022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d1022100b176d62d733dde915e42e425251345e030bf910afc1b4c1227f1abeef78e453c01feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: true, 0x000605: true, 0x000002: true, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER trailing-garbage p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004e4c4c3045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc05deadbeef01feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-plus-n p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022101ee0fc41d865732d69ac56d225305a96bab632aa0cdf42f37178c348acd85d81202204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-plus-n p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a493046022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d10221014e8929d28cc2216ea1bd1bdadaecba1d449e28c26275f46557b3112aa8de3d4601feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-33-significant p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022101ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-zero-len p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000028273024020002204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-truncated p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000048473045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc01feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-len-overrun p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102214e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER missing-s p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000027263023022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d101feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER header-only p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000003023001feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER everything-lax p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000524c503081000281220000ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d10282002100b176d62d733dde915e42e425251345e030bf910afc1b4c1227f1abeef78e453caabb01feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER outer-81 ms1-not ht=05",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a0048308144022063984cf8d548fde5f05871ef86a1f6ec454391dbef2d76452bd5fa6ae92e0d7302206ba448d9a2ec692805f73afc25978a6153f5bee6af7fcbadf5270725e120527505feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae91",
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-plus-n p2pk-not ht=83",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022101da24febe113040af167acd8e11fe0e795b7b60461c260fedfa302cf8b9324d4302203e2f8685a8878bcb09190e38b7ac4b49e82b96319af715f970c79e230dc1d5e483feffffff010100000000000000015100000000",
			lock:    sig2P2PK + "91",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: true, 0x000605: true, 0x000002: true, 0x000008: true, 0x00000e: true},
		},
		{
			name:    "lax DER r-plus-n ms1-not ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a0048304502210141a448b74c8fd306e2118aea958fa91fde74172551976ac6ffb86f4a2f05293b022018436c40df8e829a497187f9a914099a28902837f0be6415f1f6faadbfd6b09d01feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae91",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: true, 0x000605: true, 0x000002: true, 0x000008: true, 0x00000e: true},
		},
		{
			name:    "lax DER everything-lax ms1-not ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000053004c503081000281220000dd982590ab04e7163e6a74b1eea8bcc88bdbb10a636725dd4cd11878a66339030282002100b4cc65cfca755c705913c4e9fd3fc48fe8ac58bcf991279dc716f23178670e70aabb01feffffff010100000000000000015102000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae91",
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		// More lax encodings: 0x81/0x82 R and S lengths, 0x7f/0x82 outer
		// lengths, padded, negative (33 significant bytes) and zero-length or
		// zero-valued R/S, garbage between S and the hash type, bad tags.
		{
			name:    "lax DER strict p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: true, 0x000605: true, 0x000002: true, 0x000008: true, 0x00000e: true},
		},
		{
			name:    "lax DER outer-82 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b4a30820045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER outer-len-7f p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004948307f022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER seq-len-only p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000403300001feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-81 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a49304602812100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-len-81 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a493046022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d10281204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-len-82 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b4a3047022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d1028200204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-pad3 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004c4b3048022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102230000004e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-pad40 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000714c6f306c024800000000000000000000000000000000000000000000000000000000000000000000000000000000ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-high-nopad p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d10220b176d62d733dde915e42e425251345e030bf910afc1b4c1227f1abeef78e453c01feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER trailing-garbage-outer-covers p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b4a3047022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc05050001feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER trailing-02 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a493045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc050201feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-neg-33 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022180ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-neg-33 p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a493046022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d10221ff4e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-33-zero-pad-negative-next p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: true, 0x000605: true, 0x000002: true, 0x000008: true, 0x00000e: true},
		},
		{
			name:    "lax DER s-zero-len p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000029283025022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d1020001feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-zero-value p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000002928302502010002204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-zero-value p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000002a293026022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102010001feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER bad-seq-tag p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483145022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER bad-r-tag p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045032100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER bad-s-tag p2pk ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d103204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000",
			lock:    sig2P2PK,
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-len-81 ms1 ht=01",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b00493046028121008ab067d1162f2909db2a9c6bd1345295b65be67b1ea459e8e2f7b50dce223a4202201c27a94956bf7ebc8581d562e7cd1bb26a7bfa2781a33342fc1f404913c9d5a301feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-len-82 ms1 ht=83",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0049304602200b003a2ac23476d60d30e01ada736a75b61d59f1b889f213e818b8c75891aba7028200200f2f0e01e22904c4b4964e5ffbce9316be1c660a550efc10569076ad82f0cb8683feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER r-pad40 ms1 ht=41",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000072004c6f306c02480000000000000000000000000000000000000000000000000000000000000000000000000000000034df3ae7b61cda3238a4e451afbac342c636545a8b654c44dbf18620f04570e002202eb69533a5317a5bc26e51c46069b9f5242af31651950cb6aee28f6d8ed77e0941feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER trailing-02 ms1 ht=83",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a0048304402200b003a2ac23476d60d30e01ada736a75b61d59f1b889f213e818b8c75891aba702200f2f0e01e22904c4b4964e5ffbce9316be1c660a550efc10569076ad82f0cb860283feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-neg-33 ms1 ht=83",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a0048304502200b003a2ac23476d60d30e01ada736a75b61d59f1b889f213e818b8c75891aba70221ff0f2f0e01e22904c4b4964e5ffbce9316be1c660a550efc10569076ad82f0cb8683feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae",
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-len-81 ms1-not ht=83",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a004830450220236ad31a9be5cc25a56aaf58d29361f34c69f0ef9299659dc0d233fef7cfbf2a0281203fcb0b426e528f0e3f6af67f1fb03133fcfd37edc0a06a1d0b4714835fdb2e9483feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae91",
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		{
			name:    "lax DER s-zero-len ms1-not ht=41",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000029002730240220235ba83714a9a0fb041acf0c20d9a618ecaf7e683feae2d0a34998e197320d36020041feffffff010100000000000000015100000000",
			lock:    "512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451ae91",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000005: false, 0x000605: false, 0x000002: false, 0x000008: false, 0x00000e: false},
		},
		// ---- CPubKey::IsValid ----
		{
			name:    "PK prefix05-65 msig=false not=false",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100b4310f093dfe6b2cfaa5f1a90b056a875781d244fc05b107fd9ee5ded6cdc27a022056de7b6ac7b323d1538b7a01670899a4c6df9b93df9c7131184ce9ce06fce53901feffffff010100000000000000015100000000",
			lock:    "4105100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494dcc73dcc5816f1b580c5fefac269a3472580c9b4b615942c1f09471e68da5cdaac",
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000605: false, 0x000002: false},
		},
		{
			name:    "PK prefix05-65 msig=true not=false",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004900473044022047084980513e42bdcf85c695bcfd1bedcf80f15f20013eff6a870cc6b2ba37ed0220453f268b52c4ff85dd6fabc93093f40e98043af3576ed9272132b77508380e8501feffffff010100000000000000015100000000",
			lock:    "514105100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494dcc73dcc5816f1b580c5fefac269a3472580c9b4b615942c1f09471e68da5cda51ae",
			perWord: map[uint32]bool{0x000000: false, 0x000001: false, 0x000605: false, 0x000002: false},
		},
		{
			name:    "PK prefix05-65 msig=false not=true",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000048473044022007503d4b87c45eb852779d4783f83170a77019971dca9b1a7f342409efccfe93022052acd5e5abb8f805f647ebc4cccf2210cd45cebd29474e616ef8e702724b616801feffffff010100000000000000015100000000",
			lock:    "4105100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494dcc73dcc5816f1b580c5fefac269a3472580c9b4b615942c1f09471e68da5cdaac91",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000605: true, 0x000002: false},
		},
		{
			name:    "PK hybrid-right-parity msig=false not=false",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100d0cfe0c742245dbab5b4b0658176b077333086a4cdbcb630828a7babe20130a502200af1230882929f77a03892b5739081170ccbd5ffc9825d5859e12d27755256b001feffffff010100000000000000015100000000",
			lock:    "4106100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494dcc73dcc5816f1b580c5fefac269a3472580c9b4b615942c1f09471e68da5cdaac",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000605: true, 0x000002: false},
		},
		{
			name:    "PK hybrid-wrong-parity msig=false not=true",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100bc79c45529ef9b1cbe908843d0ec75449fec5291ccc42f50eb7084794fa59c4c02207f4768c1d661305ede99086de6cb884b6833454e894833603df42773aa6f207201feffffff010100000000000000015100000000",
			lock:    "4107100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494dcc73dcc5816f1b580c5fefac269a3472580c9b4b615942c1f09471e68da5cdaac91",
			perWord: map[uint32]bool{0x000000: true, 0x000001: true, 0x000605: true, 0x000002: false},
		},
		// ---- LOW_S after the lax parse (CPubKey::CheckLowS) ----
		{
			name:    "LOWS R>=N,S-high v=1",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a493046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364146022100b94dd21e811387924236fbbceaaa489c497a025bcad0d54e32962b0d4d6c2d4401feffffff010100000000000000015100000000",
			lock:    sig2P2PK + "91",
			perWord: map[uint32]bool{0x000008: true, 0x00000e: true, 0x004008: false, 0x00400e: false, 0x000000: true},
		},
		{
			name:    "LOWS R-ok,S=N v=1",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a4930460221008f6a97a9cfb281d68f156f918dc44e307151fd571059ad2ee706ed76614fab37022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414101feffffff010100000000000000015100000000",
			lock:    sig2P2PK + "91",
			perWord: map[uint32]bool{0x000008: true, 0x00000e: true, 0x004008: false, 0x00400e: false, 0x000000: true},
		},
		{
			name:    "LOWS R-ok,S=halfN+1 v=1",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000494830450221008f6a97a9cfb281d68f156f918dc44e307151fd571059ad2ee706ed76614fab3702207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a101feffffff010100000000000000015100000000",
			lock:    sig2P2PK + "91",
			perWord: map[uint32]bool{0x000008: false, 0x00000e: false, 0x004008: false, 0x00400e: false, 0x000000: true},
		},
		{
			name:    "LOWS R-ok,S=halfN v=1",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000494830450221008f6a97a9cfb281d68f156f918dc44e307151fd571059ad2ee706ed76614fab3702207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a001feffffff010100000000000000015100000000",
			lock:    sig2P2PK + "91",
			perWord: map[uint32]bool{0x000008: true, 0x00000e: true, 0x004008: false, 0x00400e: false, 0x000000: true},
		},
		{
			name:    "LOWS R=0,S-high v=1",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000002a293026020100022100b94dd21e811387924236fbbceaaa489c497a025bcad0d54e32962b0d4d6c2d4401feffffff010100000000000000015100000000",
			lock:    sig2P2PK + "91",
			perWord: map[uint32]bool{0x000008: false, 0x00000e: false, 0x004008: false, 0x00400e: false, 0x000000: true},
		},
		// ---- FindAndDelete / OP_CODESEPARATOR ----
		{
			name:    "FindAndDelete prefix PUSHDATA1-empty DROP sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a000047304402204da24e0df6377abad62d368d5e1dd0e5d17d4dfe8d3f91a7fdb88c6b02f9025102202beeac78d29dec6fd735904eeb04ac1cb194838f849f32a49b489a26eaa34ba241feffffff010100000000000000015100000000",
			lock:    "4c0075" + sig2Core2of4Gen,
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete prefix PUSHDATA1-empty DROP sig-over-alt-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0000483045022100b753befa68d0e4b8ce014bc639b8a642a3910e078daa2afb82d4a282f43de04302202e1c71beae700450279338849f17a0ad2a92e257d31315c23dd7028e9b5face741feffffff010100000000000000015100000000",
			lock:    "4c0075" + sig2Core2of4Gen,
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "FindAndDelete prefix OP_1NEGATE DROP sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b000048304502210094d56747b4704c2ea37c772e6565508e50b62ac1f6f4f88950b045cedfa6fdcf02202c9153f8059fe2837304a9aa39d40c826525c5e35d0cbb8597757029664d7a8841feffffff010100000000000000015100000000",
			lock:    "4f75" + sig2Core2of4Gen,
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete mid codesep sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a000047304402200323025e045ac4722ce9054ad19c8e5867e25dfe8e4956e516fd629398c1c35c02201e6175927e5fd97b2ebae02de8d60829c6db594ba9828f59dcc3e148ed3d01e541feffffff010100000000000000015100000000",
			lock:    "0075ab" + sig2Core2of4Gen,
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete mid codesep sig-over-alt-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0000483045022100b753befa68d0e4b8ce014bc639b8a642a3910e078daa2afb82d4a282f43de04302202e1c71beae700450279338849f17a0ad2a92e257d31315c23dd7028e9b5face741feffffff010100000000000000015100000000",
			lock:    "0075ab" + sig2Core2of4Gen,
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "FindAndDelete OP_RETURN tail 00 sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b00004830450221009d480613cccee39b8a6594e5ceda401d405b975181d3baa8e124ace0b04eedcf02207600b9c9232713453f326041a5fc98fbcd10cf2f36fd54f80c642a692b0f089641feffffff010100000000000000015100000000",
			lock:    sig2Core2of4Gen + "6a00",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete OP_RETURN tail 00 sig-over-alt-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0000483045022100fa918ed89bbd1560417346c3f77252005fc6daff423cae98636acb704e561c310220269a651452299224a7eed0b3151191211a244eb398612742dcffe2ed9b6b036941feffffff010100000000000000015100000000",
			lock:    sig2Core2of4Gen + "6a00",
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "FindAndDelete OP_RETURN tail 00 4c (malformed) sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a00004730440220305736a7635dbdde935a6269c308407de4da6fabde3f85f36dd3000185117e870220404d032800f1cd64d9c32d8c0df19ad50b3536ab25fff511eb981943ffe9490f41feffffff010100000000000000015100000000",
			lock:    sig2Core2of4Gen + "6a004c",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete OP_RETURN tail 00 4c (malformed) sig-over-alt-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a000047304402205e284f09728815a5e5d316c58f088b8cb31e8b9de7b1f1a2257e4bc8c3e8b3ea022021c1c2d22c7925bb3bf7a456d26eb3b6c1cea1567f00209adc9fb00d2ca2300841feffffff010100000000000000015100000000",
			lock:    sig2Core2of4Gen + "6a004c",
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "FindAndDelete OP_RETURN tail 4c 05 00 (truncated push) sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a0000473044022016b33267d26d17f4d5f3172ba922db7144d826ae38fafed1fbc2145e5a410f99022045da06f21d90e1c76d699de3f17eeb117687aa6383710eac30eaf481251ebc4841feffffff010100000000000000015100000000",
			lock:    sig2Core2of4Gen + "6a4c0500",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete OP_RETURN tail codesep 00 sig-over-node-code v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0000483045022100d6e8273d0c8ef959e4af4b0061b7812a13ce612ae716b43db70d225be22ee2c902204c40cd7b13cc445c098c4276e21128bd14b430768df2ce6144bdbd7405ec213d41feffffff010100000000000000015100000000",
			lock:    sig2Core2of4Gen + "6aab00",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete junk 1-byte 05 word=3d462f sig-over-node-code",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b000105473044022038610039c06ab0e1f38bfd197b0aa8a96d1d3733b814551bfa232ba0ee5ee26802200a5a80c3baa78f5bc20914027d5c7c5bd146f5c6eb595dde6a32128d91288f5941feffffff010100000000000000015100000000",
			lock:    "010575" + sig2Core2of2,
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete junk 1-byte 05 word=3d462f sig-over-alt-code",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004c00010548304502210097c9690f020f39b7fb370bd1738ca26b87ccc306d63f5d5d0acd73053aa6d76102206671c6cb73ddda84c9b05f1cef6d4233281de83381d1f053073a30fbd471e5bc41feffffff010100000000000000015100000000",
			lock:    "010575" + sig2Core2of2,
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "FindAndDelete junk 1-byte 05 PUSHDATA1-encoded in lock word=3d462f sig-over-lock",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b00010547304402204e24d7d2fcb8b3ee52488f408d8662579d982fe3d4ca562469f9fe07acd26e96022053a95391722398707d05f08ada2a0a25bf5da76a2b8ffa9b3968ba8d34459f6a41feffffff010100000000000000015100000000",
			lock:    "4c010575" + sig2Core2of2,
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete junk 1-byte 05 word=605 sig-over-node-code",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004c000105483045022100eaf506e081ec894855dd97a6c1edf238b8ae230777b8e68f922fcdba95da4d5602201f2414b126b8ec8c5bee5775eb86fc121d90719d6ea375de950106c32572376e01feffffff010100000000000000015100000000",
			lock:    "010575" + sig2Core2of2,
			perWord: map[uint32]bool{0x000605: false},
		},
		{
			name:    "FindAndDelete junk 1-byte 05 word=605 sig-over-alt-code",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b00010547304402205ebab0841648b645600b0442a0aa9b83788a2283a81b560168d0b63e01547bc602200a064a5e32886af04f5fe6cc6cdd1a5d8928922a6f72c0110ce69997d7d0468f01feffffff010100000000000000015100000000",
			lock:    "010575" + sig2Core2of2,
			perWord: map[uint32]bool{0x000605: true},
		},
		{
			name:    "FindAndDelete junk 9-byte nonDER ht41 word=3d462f sig-over-node-code",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000053000901020304050607084147304402204fa8565956e3433edaef61ea42e9155cd3124da635467aebc697f3ad5de8034b022017d19e4efd412c7788a66a7676b8cd62aaacda484addb6a496633f98567a56b441feffffff010100000000000000015100000000",
			lock:    "0901020304050607084175" + sig2Core2of2,
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "FindAndDelete legacy CHECKSIG self-push canonical",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100c40e614a4e607e197bf0e469c3da31a0b991001ba1d69b16766d595958c0eeb0022022648a24d83fd450e2fb0e79f394fd0693820171a14053d31ae997bd8a4a12f501feffffff010100000000000000015100000000",
			lock:    "483045022100c40e614a4e607e197bf0e469c3da31a0b991001ba1d69b16766d595958c0eeb0022022648a24d83fd450e2fb0e79f394fd0693820171a14053d31ae997bd8a4a12f50175210245d3b9ce0f54f4d6a17edfe3f9e0993b94d6b299c1a6e5a728ff036ecd9e139fac",
			perWord: map[uint32]bool{0x000605: true, 0x000000: true},
		},
		{
			name:    "FindAndDelete legacy CHECKSIG self-push codesep-before",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100c40e614a4e607e197bf0e469c3da31a0b991001ba1d69b16766d595958c0eeb0022022648a24d83fd450e2fb0e79f394fd0693820171a14053d31ae997bd8a4a12f501feffffff010100000000000000015100000000",
			lock:    "ab483045022100c40e614a4e607e197bf0e469c3da31a0b991001ba1d69b16766d595958c0eeb0022022648a24d83fd450e2fb0e79f394fd0693820171a14053d31ae997bd8a4a12f50175210245d3b9ce0f54f4d6a17edfe3f9e0993b94d6b299c1a6e5a728ff036ecd9e139fac",
			perWord: map[uint32]bool{0x000605: true, 0x000000: true},
		},
		// ---- CHECKMULTISIG in the unlocking script ----
		{
			name:    "SCRIPTSIG ms1 lock VERIFY 1 sig-over-node-code(sub+lock)",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000007000483045022100e5e0052917e0e181724d8e96cc79d982ebeb4931fc5c4584f9d7d7256a93e4e2022002e59d52b3e886a7dcf0ac43d7b0d8bfb1c5fbed5e09384e5182772a311d2040415121025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5751abaefeffffff010100000000000000015100000000",
			lock:    "6951",
			perWord: map[uint32]bool{0x3d462f: true, 0x3d47ff: true},
		},
		{
			name:    "SCRIPTSIG ms1 lock VERIFY 1 sig-over-sub-only",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000007000483045022100f526e617d69ba75ac1a67c10548903a3146707b615073989ca92e43960dc0a8402200b15f18565857d57cc5775fa590e1eb85c62817d1de5a96a3303bf6eb9631c1c415121025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5751abaefeffffff010100000000000000015100000000",
			lock:    "6951",
			perWord: map[uint32]bool{0x3d462f: false, 0x3d47ff: false},
		},
		{
			name:    "SCRIPTSIG ms2 empty+real badkey lock OP_0 DROP VERIFY 1 sig-over-op0-stripped(sub+lock)",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000930000473044022004967c7e8aaee8e5a2d8634ad3ad4914aa23a2bbd40ce7ef8ffb9acc07ef8dd902204afd06731aee68bea01a91941a48caa03280c0c1f3bbc9679a7e9c1360c0ade441522105000000000000000000000000000000000000000000000000000000000000000021025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5752abae91feffffff010100000000000000015100000000",
			lock:    "00756951",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "SCRIPTSIG ms2 empty+real badkey lock OP_0 DROP VERIFY 1 sig-over-unstripped(sub+lock)",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000940000483045022100d48a74b3e6b868b144338047f06ba521be469859ad90596d4cb2a93b191ef16d022067e9f28f63cb979c0e980b4ad6fae3d8183b2324649c63cb8ca2186b17c6a51b41522105000000000000000000000000000000000000000000000000000000000000000021025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5752abae91feffffff010100000000000000015100000000",
			lock:    "00756951",
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "SCRIPTSIG ms2 empty+real badkey lock OP_0 DROP VERIFY 1 sig-over-sub-only",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000940000483045022100e80899cb91ff9211a7bc5e96c55553364e06ce03546b71d52d84327b1f48defb022001666ab0397fa39e8760f868cb994523afd90104fc203f52d4918411210aedb641522105000000000000000000000000000000000000000000000000000000000000000021025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5752abae91feffffff010100000000000000015100000000",
			lock:    "00756951",
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "SCRIPTSIG ms2 empty+real badkey lock codesep VERIFY 1 sig-over-op0-stripped(sub+lock)",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000940000483045022100fcd3d37577b6c0a183d1d5051d7f0d0bc07c1ee200f5955d109f0baea63febd402202905b46b9549e137c8d6afe1f8069137356ea777e9f89086656347b6739fddf941522105000000000000000000000000000000000000000000000000000000000000000021025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5752abae91feffffff010100000000000000015100000000",
			lock:    "ab6951",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "SCRIPTSIG ms1 pre-Chronicle (no SIGPUSHONLY) sig-over-sub-only",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000007000483045022100f526e617d69ba75ac1a67c10548903a3146707b615073989ca92e43960dc0a8402200b15f18565857d57cc5775fa590e1eb85c62817d1de5a96a3303bf6eb9631c1c415121025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5751abaefeffffff010100000000000000015100000000",
			lock:    "6951",
			perWord: map[uint32]bool{0x0d460f: true},
		},
		{
			name:    "SCRIPTSIG ms1 pre-Chronicle (no SIGPUSHONLY) sig-over-sub+lock",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000007000483045022100e5e0052917e0e181724d8e96cc79d982ebeb4931fc5c4584f9d7d7256a93e4e2022002e59d52b3e886a7dcf0ac43d7b0d8bfb1c5fbed5e09384e5182772a311d2040415121025345693f0f7a41f1e99bd36cd3f8a563be20fe130bcdd8f0cecb3ce4ce478a5751abaefeffffff010100000000000000015100000000",
			lock:    "6951",
			perWord: map[uint32]bool{0x0d460f: false},
		},
		// ---- lax DER, CHECKMULTISIG key encoding and FindAndDelete ----
		{
			name:    "lax DER: long-form outer length (30 81 LL), pre-BIP66 word P2SH-only",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a49308145022100e9afd3d0d3aa3afe685df587d15e50655f13e6f2d9edf367733ae24e17defe200220764c1004947cc3303953b34c040bc6c233c69f325f4948d4b0525737d5579f5501ffffffff010100000000000000015100000000",
			lock:    "210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac",
			perWord: map[uint32]bool{0x000001: true},
		},
		{
			name:    "control: lax DER: R excessively padded, pre-BIP66 word",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a49304602220000e9afd3d0d3aa3afe685df587d15e50655f13e6f2d9edf367733ae24e17defe200220764c1004947cc3303953b34c040bc6c233c69f325f4948d4b0525737d5579f5501ffffffff010100000000000000015100000000",
			lock:    "210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac",
			perWord: map[uint32]bool{0x000001: true},
		},
		{
			name:    "CHECKMULTISIG 2-of-4 sigs [empty, real(pk4)], key1 bad encoding, OP_NOT, v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a00004730440220570764dc3857d59e96c43938663675ef433b7805b37742cd11d3be6bd07e3949022013cc091f06631217a9c86725cb088ca1fb169157bc24bf5868f3d7c23e73ccb641ffffffff010100000000000000015100000000",
			lock:    sig2Core2of4,
			perWord: map[uint32]bool{0x3d462f: false, 0x3d062f: false},
		},
		{
			name:    "CHECKMULTISIG 2-of-4 sigs [empty, real(pk4)], key1 bad encoding, OP_NOT, v1, words without NULLFAIL (UAHF-era block word / synthetic)",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a000047304402203d34b2d33e96558dbaf24f8244579f075cf485a1bf50b3b023db77600fe534fa022011b5addc7b008eb7edf0f33cadbbfe6671e43b6861cfbc6b5456a1ef9ed521ff41ffffffff010100000000000000015100000000",
			lock:    sig2Core2of4,
			perWord: map[uint32]bool{0x010607: false, 0x3d062f: false},
		},
		{
			name:    "lock has OP_0 OP_DROP prefix; real sig over OP_0-STRIPPED scriptCode (node FindAndDelete of empty sig), v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0000483045022100a576b4a37779a8dc81cd9061aada20ffe00a808c25327180af5c808287d7d5f8022077e4031e4c7c55bc3d6a938b2e438fd63b025aec9b238173900e03f20cde70be41ffffffff010100000000000000015100000000",
			lock:    "0075" + sig2Core2of4,
			perWord: map[uint32]bool{0x3d462f: false, 0x3d062f: false},
		},
		{
			name:    "same lock; real sig over UNSTRIPPED scriptCode, v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b0000483045022100d5d7ba69d65cfd4e033f8769910fd1d78500e180355b549b0127dbaef85761f70220579ca3605e3d879fd4abe3f4816dce188555e382262c80b6803e63be5b84401941ffffffff010100000000000000015100000000",
			lock:    "0075" + sig2Core2of4,
			perWord: map[uint32]bool{0x3d462f: true},
		},
		{
			name:    "CHECKMULTISIG 1-of-1 with DER-valid R=0 sig, bad key encoding, OP_NOT, v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000b0009300602010002010141ffffffff010100000000000000015100000000",
			lock:    "512105111111111111111111111111111111111111111111111111111111111111111151ae91",
			perWord: map[uint32]bool{0x3d462f: false, 0x3d062f: false},
		},
		{
			name:    "CHECKMULTISIG 1-of-1 with DER-valid R=0 sig, bad key encoding, OP_NOT, v1 without NULLFAIL word",
			tx:      "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000b0009300602010002010141ffffffff010100000000000000015100000000",
			lock:    "512105111111111111111111111111111111111111111111111111111111111111111151ae91",
			perWord: map[uint32]bool{0x010607: false},
		},
		{
			name:    "trailing OP_CODESEPARATOR after CHECKMULTISIG; sigs [empty, real]; real sig over FULL lock incl. trailing codesep, v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a00004730440220509bf2d61ca726dcfdea77e70d5e869fff58b8513ae1aa9ce0bf7d2d8b9812290220290a48d3eea65d2e4281598655a4108f9df806b85d5e29fe2d559cbce63a49ad41ffffffff010100000000000000015100000000",
			lock:    sig2Core2of4 + "ab",
			perWord: map[uint32]bool{0x3d462f: false},
		},
		{
			name:    "same; real sig over codesep-STRIPPED lock, v2",
			tx:      "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a00004730440220570764dc3857d59e96c43938663675ef433b7805b37742cd11d3be6bd07e3949022013cc091f06631217a9c86725cb088ca1fb169157bc24bf5868f3d7c23e73ccb641ffffffff010100000000000000015100000000",
			lock:    sig2Core2of4 + "ab",
			perWord: map[uint32]bool{0x3d462f: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			c.run(t)
		})
	}
}

// TestGHSASig2RemoveOpcodeByData pins removeOpcodeByData to node's
// scriptCode.FindAndDelete(CScript(data)) (script.h:200-222) on raw bytes.
func TestGHSASig2RemoveOpcodeByData(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, code, data, want string
	}{
		{"empty data removes OP_0 only", "0051004c004f76", "", "514c004f76"},
		{"empty data keeps pushes containing 00", "02000001007551", "", "0200000100" + "7551"},
		{"one-byte data matches its 01-prefixed push, not OP_N or PUSHDATA1", "010555" + "4c0105" + "0105", "05", "554c0105"},
		{"consecutive matches", "0105010501057601055f", "05", "765f"},
		{"no match leaves the script unchanged", "5176a9", "05", "5176a9"},
		{"the walk continues past a top-level OP_RETURN", "516a0001050000", "", "516a0105"},
		{"a malformed instruction stops the walk, the rest is kept", "00514c050000", "", "514c050000"},
		{"a truncated tail is kept", "00ab0200", "", "ab0200"},
		{"76-byte data matches its PUSHDATA1 push", "4c4c" + strings.Repeat("aa", 76) + "ac", strings.Repeat("aa", 76), "ac"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, err := hex.DecodeString(tc.code)
			require.NoError(t, err)
			data, err := hex.DecodeString(tc.data)
			require.NoError(t, err)
			require.Equal(t, tc.want, hex.EncodeToString(removeOpcodeByData(code, data)))
		})
	}
}

// TestGHSASig2CanonicalPush pins canonicalPush to CScript(vector)'s
// encoding (script.h:102-131) at every length-prefix boundary.
func TestGHSASig2CanonicalPush(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		size   int
		prefix string
	}{
		{0, "00"},
		{1, "01"},
		{75, "4b"},
		{76, "4c4c"},
		{255, "4cff"},
		{256, "4d0001"},
		{65535, "4dffff"},
		{65536, "4e00000100"},
	} {
		t.Run(fmt.Sprintf("len=%d", tc.size), func(t *testing.T) {
			t.Parallel()
			data := make([]byte, tc.size)
			got := canonicalPush(data)
			require.Equal(t, tc.prefix, hex.EncodeToString(got[:len(got)-tc.size]))
			require.Len(t, got, len(tc.prefix)/2+tc.size)
		})
	}
	// A single small value is never turned into OP_N.
	require.Equal(t, "0105", hex.EncodeToString(canonicalPush([]byte{0x05})))
}

// TestGHSASig2ExternalVerifierGetsStrictDER checks OP_CHECKSIG still hands
// the external verifier strict DER: the raw signature once the DER flags
// have validated it, else the low-S DER re-encoding of the lax-parsed R and
// S -- and that the verifier's answer decides the result. Not parallel: the
// hook is process-wide.
func TestGHSASig2ExternalVerifierGetsStrictDER(t *testing.T) {
	t.Cleanup(func() { InjectExternalVerifySignatureFn(nil) })

	const (
		// The lax DER "strict" and "outer-81" (30 81 45 ...) encodings of
		// one signature over sig2P2PK.
		strictTx = "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000"
		laxTx    = "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004a49308145022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc0501feffffff010100000000000000015100000000"
		wantDER  = "3045022100ee0fc41d865732d69ac56d225305a96cf0b44dba1eab8efb57b9d5fdfd4f96d102204e8929d28cc2216ea1bd1bdadaecba1e89ef4bdbb32d542997e0b29dd8a7fc05"
	)
	lockBytes, err := hex.DecodeString(sig2P2PK)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		tx   string
		word uint32
	}{
		{"strict signature under DERSIG", strictTx, 0x5},
		{"strict signature without DER flags", strictTx, 0x0},
		{"lax signature without DER flags", laxTx, 0x0},
	} {
		for _, verdict := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s verifier=%v", tc.name, verdict), func(t *testing.T) {
				tx, txErr := transaction.NewTransactionFromHex(tc.tx)
				require.NoError(t, txErr)
				prev := &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lockBytes), Satoshis: 1000}
				tx.Inputs[0].SetSourceTxOutput(prev)

				var got []string
				InjectExternalVerifySignatureFn(func(_, signature, _ []byte) bool {
					got = append(got, hex.EncodeToString(signature))
					return verdict
				})
				execErr := NewEngine().Execute(WithTx(tx, 0, prev), WithFlags(sig2WordFlags(tc.word)))
				require.Equal(t, []string{wantDER}, got)
				if verdict {
					require.NoError(t, execErr)
				} else {
					require.Error(t, execErr)
				}

				_, parseErr := ec.ParseDERSignature(sig2MustHex(t, got[0]))
				require.NoError(t, parseErr)
			})
		}
	}
}

func sig2MustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

package spv

import (
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker/headers_client"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

// BSV mainnet activation heights, for building test cases around them.
const (
	mainnetP2SHHeight      = 173_805
	mainnetBIP66Height     = 363_725
	mainnetBIP65Height     = 388_381
	mainnetCSVHeight       = 419_328
	mainnetUAHFHeight      = 478_558
	mainnetDAAHeight       = 504_031
	mainnetGenesisHeight   = 620_538
	mainnetChronicleHeight = 943_816
)

// mainnetFlags returns the mainnet flags for spending an output mined at
// coinHeight in the block at spendHeight.
func mainnetFlags(coinHeight, spendHeight uint32) scriptflag.Flag {
	return scriptflag.MainNetActivationHeights.BlockValidationFlags(coinHeight, spendHeight)
}

// The in-repo chain trackers that know their network say so.
var (
	_ ActivationHeightsProvider = (*chaintracker.WhatsOnChain)(nil)
	_ ActivationHeightsProvider = (*headers_client.Client)(nil)
)

// mainnetTracker is a GullibleHeadersClient that follows mainnet.
type mainnetTracker struct{ GullibleHeadersClient }

func (*mainnetTracker) ActivationHeights() scriptflag.ActivationHeights {
	return scriptflag.MainNetActivationHeights
}

// nodeFlagBits maps bitcoin-sv's script-verify flag bits (script_flags.h) to
// the SDK's flags, for comparing BlockValidationFlags with the node's words.
var nodeFlagBits = map[uint32]scriptflag.Flag{
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

func nodeWordFlags(t *testing.T, word uint32) scriptflag.Flag {
	t.Helper()
	var flags scriptflag.Flag
	for bit := uint32(1); bit != 0; bit <<= 1 {
		if word&bit == 0 {
			continue
		}
		f, ok := nodeFlagBits[bit]
		require.True(t, ok, "node flag bit 0x%x has no SDK counterpart", bit)
		flags |= f
	}
	return flags
}

// TestInputScriptFlagsMatchesNode compares inputScriptFlags with the flag
// words GoBDK's TxValidator("main").CalculateFlags(coinHeight, spendHeight,
// true) returned (gobdk v1.2.4, bitcoin-sv 879fc8b42) around every mainnet
// activation height.
func TestInputScriptFlagsMatchesNode(t *testing.T) {
	for _, tc := range []struct {
		coin, spend uint32
		word        uint32
	}{
		{0, 0, 0x0},
		{0, 1, 0x0},
		{173805, 173805, 0x0},
		{0, 173806, 0x1},
		{173806, 173806, 0x1},
		{0, 363724, 0x1},
		{0, 363725, 0x5},
		{0, 388380, 0x5},
		{0, 388381, 0x205},
		{0, 419327, 0x205},
		{0, 419328, 0x605},
		{0, 478558, 0x605},
		{0, 478559, 0x10607},
		{478559, 478559, 0x10607},
		{0, 504031, 0x10607},
		{0, 504032, 0x1460f},
		{100, 620537, 0x1460f},
		{620537, 620537, 0x1460f},
		{100, 620538, 0x5462f},
		{620537, 620538, 0x5462f},
		{620538, 620538, 0xd462f},
		{620537, 943815, 0x5462f},
		{620538, 943815, 0xd462f},
		{943815, 943815, 0xd462f},
		{100, 943816, 0x15462f},
		{620537, 943816, 0x15462f},
		{620538, 943816, 0x1d462f},
		{943815, 943816, 0x1d462f},
		{943816, 943816, 0x3d462f},
		{100, 967896, 0x15462f},
		{620538, 967896, 0x1d462f},
		{943816, 967896, 0x3d462f},
		{967896, 967896, 0x3d462f},
	} {
		require.Equal(t, nodeWordFlags(t, tc.word), mainnetFlags(tc.coin, tc.spend), "coin %d spend %d", tc.coin, tc.spend)
	}

	// An unmined spend of an unmined coin gets the current block word with
	// both UTXO flags, as CalculateFlags does for a MEMPOOL_HEIGHT coin.
	require.Equal(t, nodeWordFlags(t, 0x3d462f), mainnetFlags(unminedHeight, unminedHeight))
	require.Equal(t, nodeWordFlags(t, 0x15462f), mainnetFlags(100, unminedHeight))
}

// minedSource returns a transaction paying lock that is the only transaction
// of a block at height.
func minedSource(t *testing.T, lock *script.Script, height uint32) *transaction.Transaction {
	t.Helper()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
	mp, err := transaction.NewMerklePathFromCoinbaseTxid(src.TxID(), height)
	require.NoError(t, err)
	src.MerklePath = mp
	return src
}

// coinbaseSource returns a coinbase-shaped transaction (bitcoin-sv's
// CTransaction::IsCoinBase: one input spending the null outpoint) paying
// lock, the only transaction of a block at height.
func coinbaseSource(t *testing.T, lock *script.Script, height uint32) *transaction.Transaction {
	t.Helper()
	src := transaction.NewTransaction()
	src.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: transaction.DefaultSequenceNumber,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
	mp, err := transaction.NewMerklePathFromCoinbaseTxid(src.TxID(), height)
	require.NoError(t, err)
	src.MerklePath = mp
	return src
}

func spvKey(t *testing.T) (*ec.PrivateKey, *script.Script) {
	t.Helper()
	priv, err := ec.PrivateKeyFromWif(spvWIF)
	require.NoError(t, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(t, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	return priv, lock
}

// p2shOf returns the pre-Genesis pay-to-script-hash locking script for redeem.
func p2shOf(redeem []byte) *script.Script {
	lock := &script.Script{}
	_ = lock.AppendOpcodes(script.OpHASH160)
	_ = lock.AppendPushData(crypto.Hash160(redeem))
	_ = lock.AppendOpcodes(script.OpEQUAL)
	return lock
}

// p2shRedeem returns the redeem script <pubkey> OP_CHECKSIG for priv.
func p2shRedeem(t *testing.T, priv *ec.PrivateKey) *script.Script {
	t.Helper()
	redeem := &script.Script{}
	require.NoError(t, redeem.AppendPushData(priv.PubKey().Compressed()))
	require.NoError(t, redeem.AppendOpcodes(script.OpCHECKSIG))
	return redeem
}

// unlockP2SH sets the unlocking script of input vin of tx, which spends a
// P2SH output of redeem, to the redeem script, preceded when signed is true
// by priv's signature with the redeem script as its scriptCode.
func unlockP2SH(t *testing.T, tx *transaction.Transaction, vin uint32, priv *ec.PrivateKey, redeem *script.Script, signed bool) {
	t.Helper()
	in := tx.Inputs[vin]
	unlock := &script.Script{}
	if signed {
		src := in.SourceTransaction
		in.SourceTransaction = nil
		in.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: src.Outputs[in.SourceTxOutIndex].Satoshis, LockingScript: redeem})
		digest, err := tx.CalcInputSignatureHash(vin, sighash.AllForkID)
		require.NoError(t, err)
		in.SourceTransaction = src
		in.SetSourceTxOutput(nil)
		sig, err := priv.Sign(digest)
		require.NoError(t, err)
		require.NoError(t, unlock.AppendPushData(append(sig.Serialize(), byte(sighash.AllForkID))))
	}
	require.NoError(t, unlock.AppendPushData(*redeem))
	in.UnlockingScript = unlock
}

// p2shSpend returns a transaction spending a P2SH-shaped output, whose redeem
// script is <pubkey> OP_CHECKSIG, mined at height.
func p2shSpend(t *testing.T, height uint32, signed bool) *transaction.Transaction {
	t.Helper()
	priv, lock := spvKey(t)
	redeem := p2shRedeem(t, priv)
	src := minedSource(t, p2shOf(*redeem), height)
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(src, 0, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
	unlockP2SH(t, tx, 0, priv, redeem, signed)
	return tx
}

// p2shCoinbaseSpend returns a transaction spending a P2SH-shaped output of a
// coinbase mined at height, whose redeem script is <pubkey> OP_CHECKSIG.
// Unlike p2shSpend's source, this one lets a proven post-Genesis height keep
// its era: CheckCoinbase, unlike CheckRegularTransaction, does not forbid a
// P2SH output.
func p2shCoinbaseSpend(t *testing.T, height uint32, signed bool) *transaction.Transaction {
	t.Helper()
	priv, lock := spvKey(t)
	redeem := p2shRedeem(t, priv)
	src := coinbaseSource(t, p2shOf(*redeem), height)
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(src, 0, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
	unlockP2SH(t, tx, 0, priv, redeem, signed)
	return tx
}

// spvScenario is a transaction chain handed to Verify with the verdict
// bitcoin-sv reaches when it mines the unmined transactions in the next block.
type spvScenario struct {
	name  string
	tx    *transaction.Transaction
	valid bool
}

// spvScenarios builds the chains TestSPVVerifyScenarios verifies and
// TestSPVScenariosAgainstBDK replays through the node.
func spvScenarios(t *testing.T) []spvScenario {
	t.Helper()
	priv, lock := spvKey(t)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	p2pkhChain := func(height uint32) *transaction.Transaction {
		src := minedSource(t, lock, height)
		parent := transaction.NewTransaction()
		parent.AddInputFromTx(src, 0, unlocker)
		parent.AddOutput(&transaction.TransactionOutput{Satoshis: 50_000, LockingScript: lock})
		require.NoError(t, parent.Sign())
		child := transaction.NewTransaction()
		child.AddInputFromTx(parent, 0, unlocker)
		child.AddOutput(&transaction.TransactionOutput{Satoshis: 40_000, LockingScript: lock})
		require.NoError(t, child.Sign())
		return child
	}

	highS := func(version uint32) *transaction.Transaction {
		src := minedSource(t, lock, 800_000)
		tx := transaction.NewTransaction()
		tx.Version = version
		tx.AddInputFromTx(src, 0, nil)
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
		digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
		require.NoError(t, err)
		sig, err := priv.Sign(digest)
		require.NoError(t, err)
		s := sig.S
		if hs := new(big.Int).Sub(ec.S256().N, s); hs.Cmp(s) > 0 {
			s = hs
		}
		unlock := &script.Script{}
		require.NoError(t, unlock.AppendPushData(append(derSignature(sig.R, s), byte(sighash.AllForkID))))
		require.NoError(t, unlock.AppendPushData(priv.PubKey().Compressed()))
		tx.Inputs[0].UnlockingScript = unlock
		return tx
	}

	copies := newSourceCopies(t)
	noPath := copyOf(t, copies.src, nil)

	chainHeights := []uint32{100, 500_000, mainnetGenesisHeight - 1, mainnetGenesisHeight, 800_000, mainnetChronicleHeight - 1, mainnetChronicleHeight, 967_896}
	scenarios := make([]spvScenario, 0, 8+len(chainHeights))
	scenarios = append(
		scenarios,
		// A pre-Genesis P2SH output runs its redeem script, so pushing the
		// redeem script without a signature does not satisfy it (node
		// vector era/p2sh-pre-genesis-redeem-only).
		spvScenario{"pre-Genesis P2SH, no signature", p2shSpend(t, 100, false), false},
		spvScenario{"pre-Genesis P2SH, signed", p2shSpend(t, 100, true), true},
		// A coinbase can create a P2SH output after Genesis
		// (CheckCoinbase has no such restriction), so a coinbase's
		// P2SH-shaped output, once proven mined, keeps its real era: from
		// Genesis on, it is an ordinary hash puzzle.
		spvScenario{"post-Genesis P2SH-shaped output, coinbase source, no signature", p2shCoinbaseSpend(t, mainnetGenesisHeight, false), true},
		// LOW_S applies to version 1 spends; Chronicle exempts version 2.
		spvScenario{"high-S signature, version 1", highS(1), false},
		spvScenario{"high-S signature, version 2", highS(2), true},
		// A copy of a mined transaction without its merkle path does not
		// make its outputs unmined: the outputs of both copies were created
		// at the height the other copy's merkle path proves.
		spvScenario{"pre-Genesis P2SH, both inputs signed", copies.spend(t, copies.honest, copies.honest), true},
		spvScenario{"pre-Genesis P2SH, unsigned input spends a copy without a merkle path", copies.spend(t, copies.honest, noPath), false},
		spvScenario{"pre-Genesis P2SH, unsigned first input spends a copy without a merkle path", copies.spend(t, noPath, copies.honest), false},
	)
	for _, h := range chainHeights {
		scenarios = append(scenarios, spvScenario{fmt.Sprintf("P2PKH chain from a source mined at %d", h), p2pkhChain(h), true})
	}
	return scenarios
}

// TestSPVVerifyScenarios checks that Verify reaches the node's verdict on
// each scenario.
func TestSPVVerifyScenarios(t *testing.T) {
	for _, sc := range spvScenarios(t) {
		verified, err := Verify(t.Context(), sc.tx, &mainnetTracker{}, nil)
		require.Equal(t, sc.valid, verified, "%s: %v", sc.name, err)
		if sc.valid {
			require.NoError(t, err, sc.name)
		} else {
			require.ErrorIs(t, err, ErrScriptVerificationFailed, sc.name)
		}
	}
}

// derSignature DER-encodes r and s without normalising s.
func derSignature(r, s *big.Int) []byte {
	enc := func(v *big.Int) []byte {
		b := v.Bytes()
		if len(b) == 0 || b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...) //nolint:gosec // G115 -- a 256-bit integer is at most 33 bytes
	}
	body := append(enc(r), enc(s)...)
	return append([]byte{0x30, byte(len(body))}, body...) //nolint:gosec // G115 -- at most 70 bytes
}

// confirmingHeadersClient returns a headers_client.Client, built with opts,
// whose headers service confirms every merkle root and reports a current
// height comfortably past every coinbase-maturity check these tests need.
func confirmingHeadersClient(opts ...func(*headers_client.ClientOptions)) *headers_client.Client {
	mock := &tu.MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/chain/tip/longest") {
			return tu.StringResponse(http.StatusOK, `{"height":2000000}`), nil
		}
		return tu.StringResponse(http.StatusOK, `{"confirmationState":"CONFIRMED"}`), nil
	}}
	opts = append([]func(*headers_client.ClientOptions){headers_client.WithHTTPClient(mock)}, opts...)
	return headers_client.NewClient("https://headers.test", "", opts...)
}

// TestSPVVerifyDefaultsToMainNet checks that a chain tracker that does not
// say which network it follows, such as GullibleHeadersClient or a
// headers_client.Client built without WithActivationHeights, gets mainnet's
// activation heights: a P2SH output mined at height 100 still runs its redeem
// script, so pushing the redeem script without a signature does not spend it.
func TestSPVVerifyDefaultsToMainNet(t *testing.T) {
	require.Equal(t, scriptflag.MainNetActivationHeights, activationHeights(&GullibleHeadersClient{}))
	require.Equal(t, scriptflag.MainNetActivationHeights, activationHeights(skepticalHeaders{}))
	require.Equal(t, scriptflag.MainNetActivationHeights, activationHeights(&headers_client.Client{}))
	require.Equal(t, scriptflag.MainNetActivationHeights, activationHeights(confirmingHeadersClient()))
	require.Equal(t, scriptflag.MainNetActivationHeights, activationHeights(&mainnetTracker{}))

	unsigned := p2shSpend(t, 100, false)
	for name, tracker := range map[string]chaintracker.ChainTracker{
		"GullibleHeadersClient": &GullibleHeadersClient{},
		"headers_client.Client": confirmingHeadersClient(),
	} {
		verified, err := Verify(t.Context(), unsigned, tracker, nil)
		require.ErrorIs(t, err, ErrScriptVerificationFailed, name)
		require.False(t, verified, name)
	}
	verified, err := VerifyScripts(t.Context(), unsigned)
	require.ErrorIs(t, err, ErrScriptVerificationFailed)
	require.False(t, verified)

	verified, err = Verify(t.Context(), p2shSpend(t, 100, true), confirmingHeadersClient(), nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyWithActivationHeights checks that WithActivationHeights and
// headers_client.WithActivationHeights choose the network whose rules Verify
// applies. A coinbase output mined at height 700,000 was created after
// Genesis on mainnet, where a P2SH-shaped output is an ordinary hash puzzle,
// and before Genesis on testnet, where its redeem script runs. The zero
// value makes every rule active from the first block.
func TestSPVVerifyWithActivationHeights(t *testing.T) {
	testnet := scriptflag.TestNetActivationHeights
	for _, tc := range []struct {
		name    string
		tracker chaintracker.ChainTracker
		tx      *transaction.Transaction
		valid   bool
	}{
		{"mainnet, unsigned", &GullibleHeadersClient{}, p2shCoinbaseSpend(t, 700_000, false), true},
		{"testnet, unsigned", WithActivationHeights(&GullibleHeadersClient{}, testnet), p2shCoinbaseSpend(t, 700_000, false), false},
		{"testnet, signed", WithActivationHeights(&GullibleHeadersClient{}, testnet), p2shCoinbaseSpend(t, 700_000, true), true},
		{"headers_client testnet, unsigned", confirmingHeadersClient(headers_client.WithActivationHeights(testnet)), p2shCoinbaseSpend(t, 700_000, false), false},
		{"headers_client testnet, signed", confirmingHeadersClient(headers_client.WithActivationHeights(testnet)), p2shCoinbaseSpend(t, 700_000, true), true},
		{"every rule active, unsigned", WithActivationHeights(&GullibleHeadersClient{}, scriptflag.ActivationHeights{}), p2shSpend(t, 100, false), true},
	} {
		verified, err := Verify(t.Context(), tc.tx, tc.tracker, nil)
		require.Equal(t, tc.valid, verified, "%s: %v", tc.name, err)
		if !tc.valid {
			require.ErrorIs(t, err, ErrScriptVerificationFailed, tc.name)
		}
	}
	require.Equal(t, nodeWordFlags(t, 0x3d462f), scriptflag.ActivationHeights{}.BlockValidationFlags(100, unminedHeight))
}

// TestWithActivationHeightsDelegates checks that the tracker
// WithActivationHeights returns reports the heights it was given and answers
// merkle root and height queries from the tracker it wraps.
func TestWithActivationHeightsDelegates(t *testing.T) {
	tracker := WithActivationHeights(skepticalHeaders{}, scriptflag.TestNetActivationHeights)
	require.Equal(t, scriptflag.TestNetActivationHeights, activationHeights(tracker))

	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)
	verified, err := Verify(t.Context(), tx, tracker, nil)
	require.ErrorIs(t, err, ErrInvalidMerklePath)
	require.False(t, verified)

	height, err := WithActivationHeights(&GullibleHeadersClient{}, scriptflag.TestNetActivationHeights).CurrentHeight(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint32(800000), height)

	require.Panics(t, func() { WithActivationHeights(nil, scriptflag.MainNetActivationHeights) })
}

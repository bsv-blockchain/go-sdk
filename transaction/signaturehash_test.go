package transaction_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// Shared fixtures for the sighash preimage/digest golden tests. Defining the
// (long) transaction hexes and scripts once keeps the golden table below to a
// single, unique line per (fixture, flag).
const (
	sighashTx1In2Out = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
	sighashTx2In3Out = "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
	sighashScriptA   = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac"
	sighashScriptB   = "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac"
)

// sighashFixtures is the set of (transaction, signing input, spent output)
// triples shared by the preimage and digest golden tests.
var sighashFixtures = []struct {
	name       string
	unsignedTx string
	index      uint32
	sats       uint64
	srcScript  string
}{
	{"1 Input 2 Outputs", sighashTx1In2Out, 0, 100000000, sighashScriptA},
	{"2 Inputs 3 Outputs - Index 0", sighashTx2In3Out, 0, 2000000000, sighashScriptB},
	{"2 Inputs 3 Outputs - Index 1", sighashTx2In3Out, 1, 2000000000, sighashScriptB},
}

// sighashGolden pins, per fixture and SIGHASH flag, the preimage
// (CalcInputPreimage for FORKID flags, CalcInputPreimageLegacy otherwise) and the
// final CalcInputSignatureHash digest. The legacy None/Single/AnyOneCanPay
// vectors were captured from the implementation and independently confirmed
// byte-for-byte against go-bt's CalcInputPreimageLegacy.
var sighashGolden = []struct {
	fixture  int
	flagName string
	flag     sighash.Flag
	preimage string
	digest   string
}{
	{0, "AllForkID", sighash.AllForkID, "010000007ced5b2e5cf3ea407b005d8b18c393b6256ea2429b6ff409983e10adc61d0ae83bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504493a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac00e1f50500000000ffffffff87841ab2b7a4133af2c58256edb7c3c9edca765a852ebe2d0dc962604a30f1030000000041000000", "be9a42ef2e2dd7ef02cd631290667292cbbc5018f4e3f6843a8f4c302a2111b1"},
	{0, "All", sighash.All, "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac0000000001000000", "7bd029c36f5a950fe21989893bba45b657b217d62df9b1b49933b9cbe4aff389"},
	{0, "None", sighash.None, "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff000000000002000000", "40621e0bfd9b426227698d3f612f9aec0d8d89418fa221d06ac60ad58a6f43ca"},
	{0, "Single", sighash.Single, "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff01404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888ac0000000003000000", "6ccb2862929a416b10edba5a85d8ee1bb8978f53d8bc233d4660c66eda22be3e"},
	{0, "All|AnyOneCanPay", sighash.All | sighash.AnyOneCanPay, "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac0000000081000000", "e1b2cf25fa50144ec4824bbada59c60514c97b97b8b2e0d06fff28b980919e2c"},
	{0, "None|AnyOneCanPay", sighash.None | sighash.AnyOneCanPay, "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff000000000082000000", "9a4ba93872c715a606a114d74b3db882de807b21a87c17c96f1d1aa354e3b2d4"},
	{0, "Single|AnyOneCanPay", sighash.Single | sighash.AnyOneCanPay, "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88acffffffff01404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888ac0000000083000000", "ece108d9b44b1e087864b931c76fd12b0ff1dd4a70fda6bf35d6b6b636c273f5"},
	{1, "AllForkID", sighash.AllForkID, "01000000eaef7a1b82f72f4097e63b0173906d690cc137221d221fc4150bae88570fa356752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0094357700000000ffffffff0cf3246582f4b1b5fd150b942916c7d5c78e80259cbab1a761a9e4ac3a66e0a70000000041000000", "8b15eecfb6d5e727485e19797b5d1829e0630e8b43c806707685238e28a3194c"},
	{1, "All", sighash.All, "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0000000001000000", "66308491ca2e295f816fcc0cc88b4c46ba3fe58a69654f05833a4917d1102770"},
	{1, "None", sighash.None, "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000000000000000000000000002000000", "2cd6d4f0c1104098519f14443b8abe0603e8f7a96616f35fe80a895c82d57293"},
	{1, "Single", sighash.Single, "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000000000000100e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac0000000003000000", "7dde5c1672aa7aa22c4a282e8147146ef9b49458c1db003d1eb822f70c7ce920"},
	{1, "All|AnyOneCanPay", sighash.All | sighash.AnyOneCanPay, "01000000017e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0000000081000000", "cf418d0b9cdca83ea8bb23a5221d516dbab837ebe0006a5fb1e2684bcdf1809c"},
	{1, "None|AnyOneCanPay", sighash.None | sighash.AnyOneCanPay, "01000000017e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff000000000082000000", "e3150c70c49db73e540efc6b209a5065155dfe672caced63cf3b1a3d7df07ade"},
	{1, "Single|AnyOneCanPay", sighash.Single | sighash.AnyOneCanPay, "01000000017e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff0100e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac0000000083000000", "25cf0b78f2e60021224aaf31607d32a4ad6c436910e103cd4f1e55291b2f8ee1"},
	{2, "AllForkID", sighash.AllForkID, "01000000eaef7a1b82f72f4097e63b0173906d690cc137221d221fc4150bae88570fa356752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632addebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0094357700000000ffffffff0cf3246582f4b1b5fd150b942916c7d5c78e80259cbab1a761a9e4ac3a66e0a70000000041000000", "7b72c355a2714a5039d97fbd5eee792099b0eab4bf07d2e5bfcfc3309f81badb"},
	{2, "All", sighash.All, "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0000000001000000", "4c8ee5be8b0b4a822284248e3854bda603e6eca5e2db73498759cd3f7c25d329"},
	{2, "None", sighash.None, "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000000000000000debe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff000000000002000000", "f02ea7271ea0c25848ea845e56d80a0dad808bdb3b5aabcfe20a29a14769ec07"},
	{2, "Single", sighash.Single, "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000000000000000debe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff02ffffffffffffffff0000e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac0000000003000000", "087d03f8171e6f1865d528aad19ba738fbb6e145659e55d5b5fbc5fff64ed8c1"},
	{2, "All|AnyOneCanPay", sighash.All | sighash.AnyOneCanPay, "0100000001debe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0000000081000000", "f63eed36f3696d056cbd801419d17b6e3c50a5625ba922af9a79268281e891cb"},
	{2, "None|AnyOneCanPay", sighash.None | sighash.AnyOneCanPay, "0100000001debe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff000000000082000000", "d9b83968d6f3e204bbffa9435287b1994788371294fb7a0c3ef404d14f5dc2fe"},
	{2, "Single|AnyOneCanPay", sighash.Single | sighash.AnyOneCanPay, "0100000001debe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788acffffffff02ffffffffffffffff0000e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac0000000083000000", "c7adb9d41c1751beb7eb413590f3a1125754085e947679a95bdc5df6a9a8f538"},
}

// sighashFixtureTx builds the fixture transaction and attaches the spent output
// of the signing input, returning the transaction and the input index.
func sighashFixtureTx(t *testing.T, f int) (*transaction.Transaction, uint32) {
	t.Helper()
	fx := sighashFixtures[f]
	tx, err := transaction.NewTransactionFromHex(fx.unsignedTx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	prevScript, err := script.NewFromHex(fx.srcScript)
	require.NoError(t, err)
	tx.Inputs[fx.index].SetSourceTxOutput(&transaction.TransactionOutput{
		LockingScript: prevScript,
		Satoshis:      fx.sats,
	})
	return tx, fx.index
}

func TestTx_CalcInputPreimage(t *testing.T) {
	t.Parallel()
	for _, g := range sighashGolden {
		if !g.flag.Has(sighash.ForkID) {
			continue
		}
		t.Run(sighashFixtures[g.fixture].name+" - "+g.flagName, func(t *testing.T) {
			tx, index := sighashFixtureTx(t, g.fixture)
			actual, err := tx.CalcInputPreimage(index, g.flag)
			require.NoError(t, err)
			require.Equal(t, g.preimage, hex.EncodeToString(actual))
		})
	}
}

func TestTx_CalcInputPreimageLegacy(t *testing.T) {
	t.Parallel()
	for _, g := range sighashGolden {
		if g.flag.Has(sighash.ForkID) {
			continue
		}
		t.Run(sighashFixtures[g.fixture].name+" - "+g.flagName, func(t *testing.T) {
			tx, index := sighashFixtureTx(t, g.fixture)
			actual, err := tx.CalcInputPreimageLegacy(index, g.flag)
			require.NoError(t, err)
			require.Equal(t, g.preimage, hex.EncodeToString(actual))
		})
	}
}

func TestTx_CalcInputSignatureHash(t *testing.T) {
	t.Parallel()
	for _, g := range sighashGolden {
		t.Run(sighashFixtures[g.fixture].name+" - "+g.flagName, func(t *testing.T) {
			tx, index := sighashFixtureTx(t, g.fixture)
			actual, err := tx.CalcInputSignatureHash(index, g.flag)
			require.NoError(t, err)
			require.Equal(t, g.digest, hex.EncodeToString(actual))
		})
	}
}

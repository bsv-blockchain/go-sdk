package scriptflag

// ActivationHeights holds the block heights at which a network activated the
// protocol changes that alter script verification, as in bitcoin-sv's
// chainparams.cpp. The zero value treats every change as active from the
// first block.
type ActivationHeights struct {
	P2SH      uint32
	BIP66     uint32
	BIP65     uint32
	CSV       uint32
	UAHF      uint32
	DAA       uint32
	Genesis   uint32
	Chronicle uint32
}

var (
	// MainNetActivationHeights are the BSV mainnet activation heights.
	MainNetActivationHeights = ActivationHeights{
		P2SH:      173_805,
		BIP66:     363_725,
		BIP65:     388_381,
		CSV:       419_328,
		UAHF:      478_558,
		DAA:       504_031,
		Genesis:   620_538,
		Chronicle: 943_816,
	}

	// TestNetActivationHeights are the BSV testnet activation heights.
	TestNetActivationHeights = ActivationHeights{
		P2SH:      519,
		BIP66:     330_776,
		BIP65:     581_885,
		CSV:       770_112,
		UAHF:      1_155_875,
		DAA:       1_188_697,
		Genesis:   1_344_302,
		Chronicle: 1_713_168,
	}
)

// BlockValidationFlags returns the flags bitcoin-sv applies when a
// transaction in the block at spendHeight spends an output mined at
// coinHeight. It mirrors block validation: GetBlockScriptFlags evaluated for
// the block's parent (verify_script_flags.cpp, called with pindex->GetPrev()
// by ConnectBlock) combined with InputScriptVerifyFlags (policy/policy.h) for
// the eras of the spend and of the output. Pass math.MaxUint32 as spendHeight
// for a transaction that is not yet mined, and as coinHeight for an output of
// such a transaction.
func (h ActivationHeights) BlockValidationFlags(coinHeight, spendHeight uint32) Flag {
	var flags Flag
	// GetBlockScriptFlags compares the parent's height with the P2SH, UAHF
	// and DAA heights, and the parent's height + 1 with the BIP66, BIP65 and
	// CSV heights.
	parent := int64(spendHeight) - 1
	if parent >= int64(h.P2SH) {
		flags |= Bip16
	}
	if spendHeight >= h.BIP66 {
		flags |= VerifyDERSignatures
	}
	if spendHeight >= h.BIP65 {
		flags |= VerifyCheckLockTimeVerify
	}
	if spendHeight >= h.CSV {
		flags |= VerifyCheckSequenceVerify
	}
	if parent >= int64(h.UAHF) {
		flags |= VerifyStrictEncoding | EnableSighashForkID
	}
	if parent >= int64(h.DAA) {
		flags |= VerifyLowS | VerifyNullFail
	}
	// The protocol eras are those of the spending block and of the output's
	// block (GetProtocolEra: each era starts at its activation height).
	if spendHeight >= h.Genesis {
		flags |= Genesis | VerifySigPushOnly
	}
	if spendHeight >= h.Chronicle {
		flags |= Chronicle
	}
	if coinHeight >= h.Genesis {
		flags |= UTXOAfterGenesis
	}
	if coinHeight >= h.Chronicle {
		flags |= UTXOAfterChronicle
	}
	return flags
}

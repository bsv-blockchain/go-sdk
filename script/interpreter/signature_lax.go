package interpreter

import (
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// parseSignatureLax parses a signature (without its trailing hash type byte)
// exactly like bitcoin-sv's ecdsa_signature_parse_der_lax (pubkey.cpp:32-175),
// the parser CPubKey::Verify and CPubKey::CheckLowS use whatever the script
// flags are. It accepts every BER violation present in the chain before
// BIP66: long-form (and zero-prefixed) length descriptors, an ignored
// sequence length, negative and excessively padded integers, zero-length
// integers and trailing garbage after S.
//
// ok is false exactly where the node's parser returns 0. Where the node's
// parser succeeds but R or S does not fit a scalar (more than 32 significant
// bytes, or a value >= N) it substitutes the all-zero signature, which never
// verifies; parseSignatureLax then returns r = s = 0 likewise.
func parseSignatureLax(sig []byte) (r, s *big.Int, ok bool) {
	inputLen := uint64(len(sig))
	pos := uint64(0)

	// readLen reads an integer length descriptor at pos. A long-form
	// descriptor's leading zero bytes are skipped and it may carry at most
	// 7 significant bytes (lenbyte >= sizeof(size_t) fails).
	readLen := func() (uint64, bool) {
		if pos == inputLen {
			return 0, false
		}
		lenByte := uint64(sig[pos])
		pos++
		if lenByte&0x80 == 0 {
			return lenByte, true
		}
		lenByte -= 0x80
		if pos+lenByte > inputLen {
			return 0, false
		}
		for lenByte > 0 && sig[pos] == 0 {
			pos++
			lenByte--
		}
		if lenByte >= 8 {
			return 0, false
		}
		n := uint64(0)
		for ; lenByte > 0; lenByte-- {
			n = n<<8 + uint64(sig[pos])
			pos++
		}
		return n, true
	}

	// Sequence tag byte, then its length bytes, which are skipped unread.
	if pos == inputLen || sig[pos] != 0x30 {
		return nil, nil, false
	}
	pos++
	if pos == inputLen {
		return nil, nil, false
	}
	lenByte := uint64(sig[pos])
	pos++
	if lenByte&0x80 != 0 {
		lenByte -= 0x80
		if pos+lenByte > inputLen {
			return nil, nil, false
		}
		pos += lenByte
	}

	// Integer tag and length for R.
	if pos == inputLen || sig[pos] != 0x02 {
		return nil, nil, false
	}
	pos++
	rLen, lenOK := readLen()
	if !lenOK || rLen > inputLen-pos {
		return nil, nil, false
	}
	rPos := pos
	pos += rLen

	// Integer tag and length for S. Nothing requires S to end the input.
	if pos == inputLen || sig[pos] != 0x02 {
		return nil, nil, false
	}
	pos++
	sLen, lenOK := readLen()
	if !lenOK || sLen > inputLen-pos {
		return nil, nil, false
	}
	sPos := pos

	// Ignore leading zeroes; more than 32 remaining bytes, or a value >= N
	// (secp256k1_ecdsa_signature_parse_compact), overflows to the zero
	// signature.
	for rLen > 0 && sig[rPos] == 0 {
		rLen--
		rPos++
	}
	for sLen > 0 && sig[sPos] == 0 {
		sLen--
		sPos++
	}
	r, s = new(big.Int), new(big.Int)
	if rLen > 32 || sLen > 32 {
		return r, s, true
	}
	r.SetBytes(sig[rPos : rPos+rLen])
	s.SetBytes(sig[sPos : sPos+sLen])
	if n := ec.S256().N; r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return r.SetInt64(0), s.SetInt64(0), true
	}
	return r, s, true
}

// parseCheckSigSignature returns the signature CHECKSIG/CHECKMULTISIG verify
// sig (hash type already removed) as, or nil when it can never verify.
//
// The node always verifies through CPubKey::Verify: a lax DER parse
// followed by low-S normalisation (pubkey.cpp:183-213). When any of
// DERSIG/LOW_S/STRICTENC is set the signature has already passed
// IsValidSignatureEncoding, so the strict parser yields the same (R, S)
// whenever that verification could succeed.
func (t *thread) parseCheckSigSignature(sig []byte) *ec.Signature {
	if t.hasAny(scriptflag.VerifyStrictEncoding, scriptflag.VerifyDERSignatures, scriptflag.VerifyLowS) {
		signature, err := ec.ParseDERSignature(sig)
		if err != nil {
			return nil
		}
		return signature
	}

	r, s, ok := parseSignatureLax(sig)
	// secp256k1_ecdsa_sig_verify rejects a zero R or S, which is also what
	// an overflowing value was replaced with.
	if !ok || r.Sign() == 0 || s.Sign() == 0 {
		return nil
	}
	if s.Cmp(halfOrder) > 0 {
		s.Sub(ec.S256().N, s)
	}
	return &ec.Signature{R: r, S: s}
}

// isValidCheckSigPubKey mirrors CPubKey::IsValid (pubkey.h:54-78, 157): a
// key CheckSig will even try to parse is 33 bytes with a 0x02/0x03 prefix
// or 65 bytes with a 0x04/0x06/0x07 prefix. Any other key makes CheckSig
// return false (interpreter.cpp:2138-2140) -- notably a 65-byte key with
// prefix 0x05, which ec.ParsePubKey would read as uncompressed.
func isValidCheckSigPubKey(pubKey []byte) bool {
	if len(pubKey) == 0 {
		return false
	}
	switch pubKey[0] {
	case 0x02, 0x03:
		return len(pubKey) == 33
	case 0x04, 0x06, 0x07:
		return len(pubKey) == 65
	}
	return false
}

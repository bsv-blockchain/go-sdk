package script

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/pkg/errors"
)

// ScriptKey types.
const (
	// TODO: change to p2pk/p2pkh
	ScriptTypePubKey                = "pubkey"
	ScriptTypePubKeyHash            = "pubkeyhash"
	ScriptTypeNonStandard           = "nonstandard"
	ScriptTypeEmpty                 = "empty"
	ScriptTypeMultiSig              = "multisig"
	ScriptTypeNullData              = "nulldata"
	ScriptTypePubKeyHashInscription = "pubkeyhashinscription"
)

// Script type
type Script []byte

// NewFromHex creates a new script from a hex encoded string.
func NewFromHex(s string) (*Script, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(b), nil
}

// NewFromBytes wraps a byte slice with the Script type.
func NewFromBytes(b []byte) *Script {
	s := Script(b)
	return &s
}

// NewFromASM creates a new script from a BitCoin ASM formatted string.
func NewFromASM(str string) (*Script, error) {
	s := Script{}
	if len(str) == 0 {
		return &s, nil
	}

	for _, section := range strings.Split(str, " ") {
		if val, ok := OpCodeStrings[section]; ok {
			_ = s.AppendOpcodes(val)
		} else {
			if err := s.AppendPushDataHex(section); err != nil {
				return nil, ErrInvalidOpCode
			}
		}
	}

	return &s, nil
}

// AppendPushData takes data bytes and appends them to the script
// with proper PUSHDATA prefixes
func (s *Script) AppendPushData(d []byte) error {
	p, err := EncodePushDatas([][]byte{d})
	if err != nil {
		return err
	}

	*s = append(*s, p...)
	return nil
}

// AppendPushDataHex takes a hex string and appends them to the
// script with proper PUSHDATA prefixes
func (s *Script) AppendPushDataHex(str string) error {
	h, err := hex.DecodeString(str)
	if err != nil {
		return err
	}

	return s.AppendPushData(h)
}

// AppendPushDataString takes a string and appends its UTF-8 encoding
// to the script with proper PUSHDATA prefixes
func (s *Script) AppendPushDataString(str string) error {
	return s.AppendPushData([]byte(str))
}

// AppendPushDataArray takes an array of data bytes and appends them
// to the script with proper PUSHDATA prefixes
func (s *Script) AppendPushDataArray(d [][]byte) error {
	p, err := EncodePushDatas(d)
	if err != nil {
		return err
	}

	*s = append(*s, p...)
	return nil
}

func (s *Script) AppendBigInt(bInt big.Int) error {
	return s.AppendPushData(bInt.Bytes())
}

// AppendPushDataStrings takes an array of strings and appends their
// UTF-8 encoding to the script with proper PUSHDATA prefixes
func (s *Script) AppendPushDataStrings(pushDataStrings []string) error {
	dataBytes := make([][]byte, 0)
	for _, str := range pushDataStrings {
		strBytes := []byte(str)
		dataBytes = append(dataBytes, strBytes)
	}
	return s.AppendPushDataArray(dataBytes)
}

// AppendOpcodes appends opcodes type to the script.
// This does not support appending OP_PUSHDATA opcodes, so use `Script.AppendPushData` instead.
func (s *Script) AppendOpcodes(oo ...uint8) error {
	for _, o := range oo {
		if OpDATA1 <= o && o <= OpPUSHDATA4 {
			return fmt.Errorf("%w: %s", ErrInvalidOpcodeType, OpCodeValues[o])
		}
	}
	*s = append(*s, oo...)
	return nil
}

// Bytes implements the Byte interface and returns the byte slice of script.
func (s *Script) Bytes() []byte {
	return *s
}

// String implements the stringer interface and returns the hex string of script.
func (s *Script) String() string {
	return hex.EncodeToString(*s)
}

func (s *Script) ToASM() string {
	if s == nil || len(*s) == 0 {
		return ""
	}

	// var asm strings.Builder
	asm := make([]string, 0, len(*s))
	pos := 0
	for pos < len(*s) {
		op, err := s.ReadOp(&pos)
		if err != nil {
			// if err == ErrDataTooSmall {
			// 	asm = append(asm, "[error]")
			// 	break
			// }
			return ""
		}

		opStr := op.String()
		if len(opStr) > 0 {
			asm = append(asm, opStr)
		}
	}

	return strings.Join(asm, " ")
}

// IsP2PKH returns true if this is a pay to pubkey hash output script.
func (s *Script) IsP2PKH() bool {
	b := []byte(*s)
	return len(b) == 25 &&
		b[0] == OpDUP &&
		b[1] == OpHASH160 &&
		b[2] == OpDATA20 &&
		b[23] == OpEQUALVERIFY &&
		b[24] == OpCHECKSIG
}

// IsP2PK returns true if this is a public key output script.
func (s *Script) IsP2PK() bool {
	parts, err := DecodeScript(*s)
	if err != nil {
		return false
	}

	if len(parts) == 2 && len(parts[0].Data) > 0 && parts[1].Op == OpCHECKSIG {
		pubkey := parts[0].Data
		version := pubkey[0]

		if (version == 0x04 || version == 0x06 || version == 0x07) && len(pubkey) == 65 {
			return true
		} else if (version == 0x03 || version == 0x02) && len(pubkey) == 33 {
			return true
		}
	}
	return false
}

// IsP2SH returns true if this is a p2sh output script.
// TODO: remove all p2sh stuff from repo
func (s *Script) IsP2SH() bool {
	b := []byte(*s)

	return len(b) == 23 &&
		b[0] == OpHASH160 &&
		b[1] == OpDATA20 &&
		b[22] == OpEQUAL
}

// IsData returns true if this is a data output script. This
// means the script starts with OP_RETURN or OP_FALSE OP_RETURN.
func (s *Script) IsData() bool {
	b := []byte(*s)

	return (len(b) > 0 && b[0] == OpRETURN) ||
		(len(b) > 1 && b[0] == OpFALSE && b[1] == OpRETURN)
}

// Slice a script to get back a subset of that script.
func (s *Script) Slice(start, end uint64) *Script {
	ss := *s
	sss := ss[start:end]
	return &sss
}

// IsMultiSigOut returns true if this is a multisig output script.
func (s *Script) IsMultiSigOut() bool {
	parts, err := DecodeScript(*s)
	if err != nil {
		return false
	}

	if len(parts) < 3 {
		return false
	}

	if !IsSmallIntOp(parts[0].Op) {
		return false
	}

	for i := 1; i < len(parts)-2; i++ {
		if len(parts[i].Data) < 1 {
			return false
		}
	}

	return IsSmallIntOp(parts[len(parts)-2].Op) && parts[len(parts)-1].Op == OpCHECKMULTISIG
}

func IsSmallIntOp(opcode byte) bool {
	return opcode == OpZERO || (opcode >= OpONE && opcode <= Op16)
}

// PublicKeyHash returns a public key hash byte array if the script is a P2PKH script.
func (s *Script) PublicKeyHash() ([]byte, error) {
	if s == nil || len(*s) == 0 {
		return nil, ErrEmptyScript
	}

	if (*s)[0] != OpDUP || len(*s) <= 2 || (*s)[1] != OpHASH160 {
		return nil, ErrNotP2PKH
	}

	parts, err := DecodeScript((*s)[2:])
	if err != nil {
		return nil, err
	}

	return parts[0].Data, nil
}

// Addresses will return all addresses found in the script, if any.
func (s *Script) Addresses() ([]string, error) {
	addresses := make([]string, 0)
	if s.IsP2PKH() {
		pkh, err := s.PublicKeyHash()
		if err != nil {
			return nil, err
		}
		a, err := NewAddressFromPublicKeyHash(pkh, true)
		if err != nil {
			return nil, err
		}
		addresses = []string{a.AddressString}
	}
	return addresses, nil
}

// Equals will compare the script to b and return true if they match.
func (s *Script) Equals(b *Script) bool {
	return bytes.Equal(*s, *b)
}

// EqualsBytes will compare the script to a byte representation of a
// script, b, and return true if they match.
func (s *Script) EqualsBytes(b []byte) bool {
	return bytes.Equal(*s, b)
}

// EqualsHex will compare the script to a hex string h,
// if they match then true is returned otherwise false.
func (s *Script) EqualsHex(h string) bool {
	return s.String() == h
}

// MinPushSize returns the minimum size of a push operation of the given data.
func MinPushSize(bb []byte) int {
	l := len(bb)

	// data length is larger than max supported by the bitcoin protocol
	if bits.UintSize == 64 && int64(l) > 0xffffffff {
		return 0
	}

	if l == 0 {
		return 1
	}

	if l == 1 {
		// data can be represented as Op1 to Op16, or OpNegate
		if bb[0] <= 16 || bb[0] == 0x81 {
			// OpX
			return 1
		}
		// OP_DATA_1 + data
		return 2
	}

	// OP_DATA_X + data
	if l <= 75 {
		return l + 1
	}
	// OP_PUSHDATA1 + length byte + data
	if l <= 0xff {
		return l + 2
	}
	// OP_PUSHDATA2 + two length bytes + data
	if l <= 0xffff {
		return l + 3
	}

	// OP_PUSHDATA4 + four length bytes + data
	return l + 5
}

// Chunks extracts the decoded chunks from the script.
func (s *Script) Chunks() ([]*ScriptChunk, error) {
	return DecodeScript([]byte(*s))
}

// Address extracts the address from a P2PKH script.
func (s *Script) Address() (*Address, error) {
	if !s.IsP2PKH() {
		return nil, errors.New("script is not of type ScriptTypePubKeyHash")
	}
	parts, err := s.Chunks()
	if err != nil {
		return nil, err
	}
	return NewAddressFromPublicKeyHash(parts[2].Data, true)
}

// PubKey extracts the public key from a P2PK script.
func (s *Script) PubKey() (*ec.PublicKey, error) {
	if !s.IsP2PK() {
		return nil, errors.New("script is not of type ScriptTypePubKey")
	}

	parts, err := s.Chunks()
	if err != nil {
		return nil, err
	}

	if len(parts) == 0 || parts[0] == nil {
		return nil, errors.New("invalid script parts or missing public key part")
	}

	pubKey := parts[0].Data
	return ec.ParsePubKey(pubKey)
}

// PubKeyHex extracts the public key from a P2PK script.
func (s *Script) PubKeyHex() (string, error) {
	if !s.IsP2PK() {
		return "", errors.New("script is not of type ScriptTypePubKey")
	}

	parts, err := s.Chunks()
	if err != nil {
		return "", err
	}

	if len(parts) == 0 || parts[0] == nil {
		return "", errors.New("invalid script parts or missing public key part")
	}

	pubKey := parts[0].Data
	pubKeyHex := hex.EncodeToString(pubKey)

	return pubKeyHex, nil
}

// MarshalJSON convert script into json.
func (s *Script) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON covert from json into *script.Script.
func (s *Script) UnmarshalJSON(bb []byte) error {
	ss, err := NewFromHex(string(bytes.Trim(bb, `"`)))
	if err != nil {
		return err
	}

	*s = *ss
	return nil
}

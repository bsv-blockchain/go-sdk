package interpreter

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
)

// hexPreviewLen caps how many bytes of an oversized operand get rendered as
// hex in an error message. Post-Chronicle, a rejected operand can be up to
// 32,000,000 bytes long (see MaxScriptNumberLengthAfterChronicle); passing
// the full value straight to a %x verb would format and allocate a ~64MB
// string on every such rejection -- a wasteful, disproportionate cost for a
// script that need only be a few bytes long to trigger it. See
// GHSA-rh54-8fpg-8wwf.
const hexPreviewLen = 32

// hexPreview renders at most the first hexPreviewLen bytes of bb as hex,
// marking the result as truncated when bb is longer.
func hexPreview(bb []byte) string {
	if len(bb) <= hexPreviewLen {
		return fmt.Sprintf("%x", bb)
	}
	return fmt.Sprintf("%x...", bb[:hexPreviewLen])
}

// numberPreview formats v for an error message. Converting a big.Int to
// decimal is superlinear, so a value wider than 64 bits (a script number can
// be up to 32,000,000 bytes) is described by its bit length instead.
func numberPreview(v *big.Int) string {
	if v.BitLen() <= 64 {
		return v.String()
	}
	return fmt.Sprintf("of %d bits", v.BitLen())
}

// ScriptNumber represents a numeric value used in the scripting engine with
// special handling to deal with the subtle semantics required by consensus.
//
// All numbers are stored on the data and alternate stacks encoded as little
// endian with a sign bit.  All numeric opcodes such as OP_ADD, OP_SUB,
// and OP_MUL, are only allowed to operate on 4-byte integers in the range
// [-2^31 + 1, 2^31 - 1], however the results of numeric operations may overflow
// and remain valid so long as they are not used as inputs to other numeric
// operations or otherwise interpreted as an integer.
//
// For example, it is possible for OP_ADD to have 2^31 - 1 for its two operands
// resulting 2^32 - 2, which overflows, but is still pushed to the stack as the
// result of the addition.  That value can then be used as input to OP_VERIFY
// which will succeed because the data is being interpreted as a boolean.
// However, if that same value were to be used as input to another numeric
// opcode, such as OP_SUB, it must fail.
//
// This type handles the aforementioned requirements by storing all numeric
// operation results as an int64 to handle overflow and provides the Bytes
// method to get the serialized representation (including values that overflow).
//
// Then, whenever data is interpreted as an integer, it is converted to this
// type by using the NewNumber function which will return an error if the
// number is out of range or not minimally encoded depending on parameters.
// Since all numeric opcodes involve pulling data from the stack and
// interpreting it as an integer, it provides the required behavior.
type ScriptNumber struct {
	Val          *big.Int
	AfterGenesis bool
}

var (
	Zero = big.NewInt(0)
	One  = big.NewInt(1)
)

// MakeScriptNumber interprets the passed serialized bytes as an encoded integer
// and returns the result as a Number.
//
// Since the consensus rules dictate that serialized bytes interpreted as integers
// are only allowed to be in the range determined by a maximum number of bytes,
// on a per opcode basis, an error will be returned when the provided bytes
// would result in a number outside that range.  In particular, the range for
// the vast majority of opcodes dealing with numeric values are limited to 4
// bytes and therefore will pass that value to this function resulting in an
// allowed range of [-2^31 + 1, 2^31 - 1].
//
// The requireMinimal flag causes an error to be returned if additional checks
// on the encoding determine it is not represented with the smallest possible
// number of bytes or is the negative 0 encoding, [0x80].  For example, consider
// the number 127.  It could be encoded as [0x7f], [0x7f 0x00],
// [0x7f 0x00 0x00 ...], etc.  All forms except [0x7f] will return an error with
// requireMinimal enabled.
//
// The scriptNumLen is the maximum number of bytes the encoded value can be
// before an errs.ErrStackNumberTooBig is returned.  This effectively limits the
// range of allowed values.
// WARNING:  Great care should be taken if passing a value larger than
// defaultScriptNumLen, which could lead to addition and multiplication
// overflows.
//
// See the Bytes function documentation for example encodings.
func MakeScriptNumber(bb []byte, scriptNumLen int, requireMinimal, afterGenesis bool) (*ScriptNumber, error) {
	// Interpreting data requires that it is not larger than the passed scriptNumLen value.
	if len(bb) > scriptNumLen {
		return &ScriptNumber{Val: big.NewInt(0), AfterGenesis: false}, errs.NewError(
			errs.ErrNumberTooBig,
			"numeric value encoded as %s is %d bytes which exceeds the max allowed of %d",
			hexPreview(bb), len(bb), scriptNumLen,
		)
	}

	// Enforce minimal encoded if requested.
	if requireMinimal {
		if err := CheckMinimalDataEncoding(bb); err != nil {
			return &ScriptNumber{
				Val:          big.NewInt(0),
				AfterGenesis: false,
			}, err
		}
	}

	// Zero is encoded as an empty byte slice.
	if len(bb) == 0 {
		return &ScriptNumber{
			AfterGenesis: afterGenesis,
			Val:          big.NewInt(0),
		}, nil
	}

	// Decode from little endian.
	//
	// bb is little endian with a sign bit in the high bit of the last byte,
	// so reverse it into a big-endian buffer that big.Int.SetBytes can
	// consume directly, clearing the sign bit from what is now the first
	// byte first. This is O(len(bb)): a single reversal pass plus one
	// linear SetBytes, replacing the previous per-byte big.Int Lsh/Or loop
	// (O(len(bb)^2) since each iteration's Lsh/Or cost grows with the
	// output built so far -- see GHSA-rh54-8fpg-8wwf).
	be := make([]byte, len(bb))
	for i, b := range bb {
		be[len(bb)-1-i] = b
	}
	isNegative := be[0]&0x80 != 0
	if isNegative {
		be[0] &^= 0x80
	}
	v := new(big.Int).SetBytes(be)
	if isNegative {
		v.Neg(v)
	}
	return &ScriptNumber{
		Val:          v,
		AfterGenesis: afterGenesis,
	}, nil
}

// legacyDeserializeInt64 decodes bb the way node's bsv::deserialize<int64_t>
// (int_serialization.h:63-95) does for the OP_SUBSTR/OP_LEFT/OP_RIGHT operand
// path, where the CScriptNum is constructed with big_int=false. It must be
// used ONLY by those three opcodes (via stack.PopLegacyInt) -- OP_SPLIT and
// every other numeric opcode use the general, era-aware MakeScriptNumber
// path above and must not be routed through this function.
//
// For d := len(bb) in [1,8] this is the ordinary sign-magnitude little-endian
// decode, restricted to d bytes -- well-defined, since node's accumulation
// loop only ever shifts by less than 64 bits in this range.
//
// For d>=9, node's loop (int_serialization.h:72-79) ORs bytes[0:d-1] into a
// signed int64 via `tmp <<= 8*i` and returns at int_serialization.h:81-82
// BEFORE the sign handling runs: the last byte, including its sign bit, is
// discarded and the accumulated bit pattern is the raw two's-complement
// result. For d==9 that is simply bytes[0:8]. For d>=10 the shift count
// reaches 64, which is undefined behavior in C++. The linux-x86_64 and
// darwin-arm64 BDK builds compile the loop to a scalar variable shift that
// masks the count mod 64 (SHL r64,cl / LSLV), so byte i is ORed into byte
// slot i%8 -- e.g. 04 00x7 80 00 decodes to 0x84. This replicates those
// builds, verified against bitcoin-sv through GoBDK for d from 9 up to
// 100,001. The node's own result is platform-dependent:
// the darwin-x86_64 and linux-aarch64 builds vectorize the loop (PSLLQ /
// NEON SSHL give 0 for a count of 64 or more) and so drop some of the
// bytes this folds in once d>=17. Re-verify on each node release and
// follow upstream once the UB is fixed.
func legacyDeserializeInt64(bb []byte) int64 {
	d := len(bb)
	if d == 0 {
		return 0
	}
	if d >= 9 {
		var r uint64
		for i, b := range bb[:d-1] {
			r |= uint64(b) << (8 * (i % 8))
		}
		return int64(r) // raw two's-complement reinterpretation, as node returns it
	}

	var buf [8]byte
	copy(buf[:], bb)
	isNegative := bb[d-1]&0x80 != 0
	if isNegative {
		buf[d-1] &^= 0x80 //nolint:gosec // G602 -- d is provably in [1,8] here: d==0 returned above, d>=9 returned above
	}
	v := int64(binary.LittleEndian.Uint64(buf[:])) //nolint:gosec // G115 -- magnitude of a <=8-byte sign-magnitude value always fits int64
	if isNegative {
		v = -v
	}
	return v
}

// serializedSize returns len((&ScriptNumber{Val: v}).Bytes()) without
// materializing the encoding, i.e. node's bint::serialized_size()
// (big_int.cpp:570-575: BN_bn2mpi's length minus its 4-byte header). A
// non-zero magnitude of b bits needs ceil(b/8) bytes plus a sign byte when
// b%8 == 0, which is b/8+1 either way.
func serializedSize(v *big.Int) int {
	bits := v.BitLen()
	if bits == 0 {
		return 0
	}
	return bits/8 + 1
}

// bnMulFails reports whether OpenSSL's BN_mul, which node's OP_MUL uses for
// big numbers (big_int.cpp:226-236), fails -- SCRIPT_ERR_BIG_INT -- for
// operands a and b. OpenSSL 3.x bn_mul_fixed_top (bn_mul.c) takes its
// Karatsuba path when both operands have at least BN_MULL_SIZE_NORMAL (16)
// 64-bit words and their word counts differ by at most one; it then sizes
// its temporary and result at 8*j words (4*j when neither operand exceeds
// j), j being the largest power of two <= the longer word count, and
// bn_expand_internal (bn_lib.c) refuses more than INT_MAX/(4*BN_BITS2) =
// 8,388,607 words. The other paths only need len(a)+len(b) words, which the
// 32,000,000-byte number limit keeps below that bound. In effect it fails
// when the word counts are within one of each other and the longer exceeds
// 1,048,576 words (8 MiB).
func bnMulFails(a, b *big.Int) bool {
	const (
		bnMullSizeNormal = 16
		bnMaxWords       = math.MaxInt32 / (4 * 64)
	)
	al := (a.BitLen() + 63) / 64
	bl := (b.BitLen() + 63) / 64
	if al < bnMullSizeNormal || bl < bnMullSizeNormal || al-bl > 1 || bl-al > 1 {
		return false
	}
	j := 1 << (bits.Len(uint(max(al, bl))) - 1)
	need := 4 * j
	if al > j || bl > j {
		need = 8 * j
	}
	return need > bnMaxWords
}

// saturateInt32 clamps v to [math.MinInt32, math.MaxInt32], mirroring the
// int64 arm of node's CScriptNum::getint() (script_num.cpp:411-418).
func saturateInt32(v int64) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

// Add adds the receiver and the number, sets the result over the receiver and returns.
func (n *ScriptNumber) Add(o *ScriptNumber) *ScriptNumber {
	*n.Val = *new(big.Int).Add(n.Val, o.Val)
	return n
}

// Sub subtracts the number from the receiver, sets the result over the receiver and returns.
func (n *ScriptNumber) Sub(o *ScriptNumber) *ScriptNumber {
	*n.Val = *new(big.Int).Sub(n.Val, o.Val)
	return n
}

// Mul multiplies the receiver by the number, sets the result over the receiver and returns.
func (n *ScriptNumber) Mul(o *ScriptNumber) *ScriptNumber {
	*n.Val = *new(big.Int).Mul(n.Val, o.Val)
	return n
}

// Div divides the receiver by the number, sets the result over the receiver and returns.
func (n *ScriptNumber) Div(o *ScriptNumber) *ScriptNumber {
	*n.Val = *new(big.Int).Quo(n.Val, o.Val)
	return n
}

// Mod divides the receiver by the number, sets the remainder over the receiver and returns.
func (n *ScriptNumber) Mod(o *ScriptNumber) *ScriptNumber {
	*n.Val = *new(big.Int).Rem(n.Val, o.Val)
	return n
}

// LessThanInt returns true if the receiver is smaller than the integer passed.
func (n *ScriptNumber) LessThanInt(i int64) bool {
	return n.LessThan(&ScriptNumber{Val: big.NewInt(i)})
}

// LessThan returns true if the receiver is smaller than the number passed.
func (n *ScriptNumber) LessThan(o *ScriptNumber) bool {
	return n.Val.Cmp(o.Val) == -1
}

// LessThanOrEqual returns ture if the receiver is smaller or equal to the number passed.
func (n *ScriptNumber) LessThanOrEqual(o *ScriptNumber) bool {
	return n.Val.Cmp(o.Val) < 1
}

// GreaterThanInt returns true if the receiver is larger than the integer passed.
func (n *ScriptNumber) GreaterThanInt(i int64) bool {
	return n.GreaterThan(&ScriptNumber{Val: big.NewInt(i)})
}

// GreaterThan returns true if the receiver is larger than the number passed.
func (n *ScriptNumber) GreaterThan(o *ScriptNumber) bool {
	return n.Val.Cmp(o.Val) == 1
}

// GreaterThanOrEqual returns true if the receiver is larger or equal to the number passed.
func (n *ScriptNumber) GreaterThanOrEqual(o *ScriptNumber) bool {
	return n.Val.Cmp(o.Val) > -1
}

// EqualInt returns true if the receiver is equal to the integer passed.
func (n *ScriptNumber) EqualInt(i int64) bool {
	return n.Equal(&ScriptNumber{Val: big.NewInt(i)})
}

// Equal returns true if the receiver is equal to the number passed.
func (n *ScriptNumber) Equal(o *ScriptNumber) bool {
	return n.Val.Cmp(o.Val) == 0
}

// IsZero return strue if hte receiver equals zero.
func (n *ScriptNumber) IsZero() bool {
	return n.Val.Cmp(Zero) == 0
}

// Incr increment the receiver by one.
func (n *ScriptNumber) Incr() *ScriptNumber {
	*n.Val = *new(big.Int).Add(n.Val, One)
	return n
}

// Decr decrement the receiver by one.
func (n *ScriptNumber) Decr() *ScriptNumber {
	*n.Val = *new(big.Int).Sub(n.Val, One)
	return n
}

// Neg sets the receiver to the negative of the receiver.
func (n *ScriptNumber) Neg() *ScriptNumber {
	*n.Val = *new(big.Int).Neg(n.Val)
	return n
}

// Abs sets the receiver to the absolute value of hte receiver.
func (n *ScriptNumber) Abs() *ScriptNumber {
	*n.Val = *new(big.Int).Abs(n.Val)
	return n
}

// Int returns the receivers value as an int, saturating to math.MaxInt64 or
// math.MinInt64 when the receiver's magnitude is out of int64 range.
//
// This mirrors node's getint() (script_num.cpp:394-420), which compares
// against the target range via bigint comparison BEFORE ever narrowing,
// so a value far beyond int64 (reachable via a big-int-capable opcode's
// result, e.g. a 9+ byte push under a post-Genesis stack element) saturates
// instead of wrapping. It must NOT call n.Val.Int64() before checking range:
// math/big documents Int64() as undefined for out-of-range values, and in
// practice it silently truncates to the low 64 bits rather than erroring, so
// an unguarded cast would let callers such as
// OP_PICK/OP_ROLL treat "2^64" as "0".
func (n *ScriptNumber) Int() int {
	if n.GreaterThanInt(math.MaxInt) {
		return math.MaxInt
	}
	if n.LessThanInt(math.MinInt) {
		return math.MinInt
	}
	return int(n.Val.Int64())
}

// Int32 returns the Number clamped to a valid int32.  That is to say
// when the script number is higher than the max allowed int32, the max int32
// value is returned and vice versa for the minimum value.  Note that this
// behavior is different from a simple int32 cast because that truncates
// and the consensus rules dictate numbers which are directly cast to integers
// provide this behavior.
//
// In practice, for most opcodes, the number should never be out of range since
// it will have been created with makeScriptNumber using the defaultScriptLen
// value, which rejects them.  In case something in the future ends up calling
// this function against the result of some arithmetic, which IS allowed to be
// out of range before being reinterpreted as an integer, this will provide the
// correct behavior.
func (n *ScriptNumber) Int32() int32 {
	// As with Int(), the range check must happen via bigint comparison
	// BEFORE calling Val.Int64(): Int64() is undefined (and, in practice,
	// truncates to the low 64 bits) for a magnitude beyond int64, so a
	// value such as 2^64 would otherwise be misread as 0 -- see Int()'s
	// doc comment and GHSA-rh54-8fpg-8wwf (OP_PICK/OP_ROLL/OP_LSHIFT/
	// OP_RSHIFT all consume Int32()/Int() results).
	if n.GreaterThanInt(math.MaxInt32) {
		return math.MaxInt32
	}
	if n.LessThanInt(math.MinInt32) {
		return math.MinInt32
	}
	return int32(n.Val.Int64()) //nolint:gosec // G115 -- provably in [MinInt32,MaxInt32] per the two checks above
}

// Int64 returns the Number clamped to a valid int64.  That is to say
// when the script number is higher than the max allowed int64, the max int64
// value is returned and vice versa for the minimum value.  Note that this
// behavior is different from a simple int64 cast because that truncates
// and the consensus rules dictate numbers which are directly cast to integers
// provide this behavior.
//
// In practice, for most opcodes, the number should never be out of range since
// it will have been created with makeScriptNumber using the defaultScriptLen
// value, which rejects them.  In case something in the future ends up calling
// this function against the result of some arithmetic, which IS allowed to be
// out of range before being reinterpreted as an integer, this will provide the
// correct behavior.
func (n *ScriptNumber) Int64() int64 {
	if n.GreaterThanInt(math.MaxInt64) {
		return math.MaxInt64
	}
	if n.LessThanInt(math.MinInt64) {
		return math.MinInt64
	}
	return n.Val.Int64()
}

// Set the value of the receiver.
func (n *ScriptNumber) Set(i int64) *ScriptNumber {
	*n.Val = *new(big.Int).SetInt64(i)
	return n
}

// Bytes returns the number serialized as a little endian with a sign bit.
//
// Example encodings:
//
//	   127 -> [0x7f]
//	  -127 -> [0xff]
//	   128 -> [0x80 0x00]
//	  -128 -> [0x80 0x80]
//	   129 -> [0x81 0x00]
//	  -129 -> [0x81 0x80]
//	   256 -> [0x00 0x01]
//	  -256 -> [0x00 0x81]
//	 32767 -> [0xff 0x7f]
//	-32767 -> [0xff 0xff]
//	 32768 -> [0x00 0x80 0x00]
//	-32768 -> [0x00 0x80 0x80]
func (n *ScriptNumber) Bytes() []byte {
	// Zero encodes as an empty byte slice.
	if n.IsZero() {
		return []byte{}
	}

	// Take the absolute value and keep track of whether it was originally
	// negative.
	isNegative := n.Val.Cmp(Zero) == -1
	if isNegative {
		n.Neg()
	}

	// Encode to little endian by taking the big-endian magnitude bytes
	// (big.Int.Bytes() is already linear, and minimally sized) and
	// reversing them in one pass. This produces byte-for-byte identical
	// output to the previous implementation, which instead extracted one
	// little-endian byte at a time via a big.Int.Rsh per output byte --
	// each Rsh costs O(remaining magnitude), making the whole loop
	// O(len(result)^2). A single reversal is O(len(result)).
	//
	// Note: the pre-Genesis branch this replaced computed a would-be
	// int32-clamped magnitude into a local `bb` that was then used ONLY as
	// a capacity hint for `result` -- the actual bytes encoded always came
	// from n.Val itself, never from that clamped value, so dropping it
	// changes no observable output (verified against the old
	// implementation by a property test).
	//
	// The spare byte of capacity is for the sign byte below: appending it
	// would otherwise reallocate result at up to twice its length, memory
	// the stack memory limit never sees.
	mag := n.Val.Bytes()
	result := make([]byte, len(mag), len(mag)+1)
	for i, b := range mag {
		result[len(mag)-1-i] = b
	}

	// When the most significant byte already has the high bit set, an
	// additional high byte is required to indicate whether the number is
	// negative or positive.  The additional byte is removed when converting
	// back to an integral and its high bit is used to denote the sign.
	//
	// Otherwise, when the most significant byte does not already have the
	// high bit set, use it to indicate the value is negative, if needed.
	if result[len(result)-1]&0x80 != 0 {
		extraByte := byte(0x00)
		if isNegative {
			extraByte = 0x80
		}
		result = append(result, extraByte)
	} else if isNegative {
		result[len(result)-1] |= 0x80
	}

	return result
}

func MinimallyEncode(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	last := data[len(data)-1]
	if last&0x7f != 0 {
		return data
	}

	if len(data) == 1 {
		return []byte{}
	}

	if data[len(data)-2]&0x80 != 0 {
		return data
	}

	for i := len(data) - 1; i > 0; i-- {
		if data[i-1] != 0 {
			if data[i-1]&0x80 != 0 {
				data[i] = last
				i++
			} else {
				data[i-1] |= last
			}

			return data[:i]
		}
	}

	return []byte{}
}

// CheckMinimalDataEncoding returns whether the passed byte array adheres
// to the minimal encoding requirements.
func CheckMinimalDataEncoding(v []byte) error {
	if !isMinimallyEncoded(v) {
		return errs.NewError(errs.ErrMinimalData, "numeric value encoded as %s is not minimally encoded", hexPreview(v))
	}

	return nil
}

// isMinimallyEncoded reports whether v is a number encoded with the fewest
// bytes, that is whether MinimallyEncode would return it unchanged.
func isMinimallyEncoded(v []byte) bool {
	if len(v) == 0 {
		return true
	}

	// Check that the number is encoded with the minimum possible
	// number of bytes.
	//
	// If the most-significant-byte - excluding the sign bit - is zero
	// then we're not minimal.  Note how this test also rejects the
	// negative-zero encoding, [0x80].
	//
	// One exception: if there's more than one byte and the most
	// significant bit of the second-most-significant-byte is set
	// it would conflict with the sign bit.  An example of this case
	// is +-255, which encode to 0xff00 and 0xff80 respectively.
	// (big-endian).
	return v[len(v)-1]&0x7f != 0 || (len(v) > 1 && v[len(v)-2]&0x80 != 0)
}

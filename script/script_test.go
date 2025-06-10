package script_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/v2/chainhash"
	script "github.com/bsv-blockchain/go-sdk/v2/script"
	"github.com/bsv-blockchain/go-sdk/v2/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/v2/script/testdata"
	"github.com/bsv-blockchain/go-sdk/v2/transaction"
)

func TestNewFromHex(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t,
		"76a914e2a623699e81b291c0327f408fea765d534baa2a88ac",
		hex.EncodeToString(*s),
	)
}

func TestScript_ToASM(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		script string
		expASM string
	}{
		"valid script": {
			script: "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac",
			expASM: "OP_DUP OP_HASH160 e2a623699e81b291c0327f408fea765d534baa2a OP_EQUALVERIFY OP_CHECKSIG",
		},
		"empty script:": {
			script: "",
			expASM: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := script.NewFromHex(test.script)
			require.NoError(t, err)

			asm := s.ToASM()

			require.Equal(t, test.expASM, asm)
		})
	}
}

func TestNewFromASM(t *testing.T) {
	t.Parallel()

	s, err := script.NewFromASM("OP_DUP OP_HASH160 e2a623699e81b291c0327f408fea765d534baa2a OP_EQUALVERIFY OP_CHECKSIG")
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t,
		"76a914e2a623699e81b291c0327f408fea765d534baa2a88ac",
		hex.EncodeToString(*s),
	)
}

func TestScript_IsP2PKH(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
	require.NoError(t, err)

	scriptPub := script.NewFromBytes(b)
	require.NotNil(t, scriptPub)
	require.True(t, scriptPub.IsP2PKH())
}

func TestScript_IsP2PK(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("2102f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5ac")
	require.NoError(t, err)

	scriptPub := script.NewFromBytes(b)
	require.NotNil(t, scriptPub)
	require.True(t, scriptPub.IsP2PK())
}

func TestScript_IsP2SH(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87")
	require.NoError(t, err)

	scriptPub := script.NewFromBytes(b)
	require.NotNil(t, scriptPub)
	require.True(t, scriptPub.IsP2SH())
}

func TestScript_IsData(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("006a04ac1eed884d53027b2276657273696f6e223a22302e31222c22686569676874223a3634323436302c22707265764d696e65724964223a22303365393264336535633366376264393435646662663438653761393933393362316266623366313166333830616533306432383665376666326165633561323730222c22707265764d696e65724964536967223a2233303435303232313030643736333630653464323133333163613836663031386330343665353763393338663139373735303734373333333533363062653337303438636165316166333032323030626536363034353430323162663934363465393966356139353831613938633963663439353430373539386335396234373334623266646234383262663937222c226d696e65724964223a22303365393264336535633366376264393435646662663438653761393933393362316266623366313166333830616533306432383665376666326165633561323730222c2276637478223a7b2274784964223a2235373962343335393235613930656533396133376265336230306239303631653734633330633832343133663664306132303938653162656137613235313566222c22766f7574223a307d2c226d696e6572436f6e74616374223a7b22656d61696c223a22696e666f407461616c2e636f6d222c226e616d65223a225441414c20446973747269627574656420496e666f726d6174696f6e20546563686e6f6c6f67696573222c226d65726368616e74415049456e64506f696e74223a2268747470733a2f2f6d65726368616e746170692e7461616c2e636f6d2f227d7d46304402206fd1c6d6dd32cc85ddd2f30bc068445dd901c6bd85e394e45bb254716d2bb228022041f0f8b1b33c2e3702aee4ad47155548045ed945738b43dc0faed2e86faa12e4")
	require.NoError(t, err)

	scriptPub := script.NewFromBytes(b)
	require.NotNil(t, scriptPub)
	require.True(t, scriptPub.IsData())
}

func TestScript_IsMultisigOut(t *testing.T) {
	t.Parallel()

	t.Run("is multisig", func(t *testing.T) {
		b, err := hex.DecodeString("5201110122013353ae")
		require.NoError(t, err)

		scriptPub := script.NewFromBytes(b)
		require.NotNil(t, scriptPub)
		require.True(t, scriptPub.IsMultiSigOut())
	})

	t.Run("is not multisig and no error", func(t *testing.T) {
		//Test Txid:de22e20422dbba8e8eeab87d5532480499abb01d6619bb66fe374f4d4a7500ee, vout:1

		b, err := hex.DecodeString("5101400176018801a901ac615e7961007901687f7700005279517f75007f77007901fd8763615379537f75517f77007901007e81517a7561537a75527a527a5379535479937f75537f77527a75517a67007901fe8763615379557f75517f77007901007e81517a7561537a75527a527a5379555479937f75557f77527a75517a67007901ff8763615379597f75517f77007901007e81517a7561537a75527a527a5379595479937f75597f77527a75517a67615379517f75007f77007901007e81517a7561537a75527a527a5379515479937f75517f77527a75517a6868685179517a75517a75517a75517a7561517a7561007982770079011494527951797f77537952797f750001127900a063610113795a7959797e01147e51797e5a797e58797e517a7561610079011479007958806152790079827700517902fd009f63615179515179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd615279525179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe615279545179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff615279585179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a7561527951797e537a75527a527a527975757568607900a06351790112797e610079011279007958806152790079827700517902fd009f63615179515179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd615279525179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe615279545179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff615279585179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a7561527951797e537a75527a527a5279757575685e7900a063615f795a7959797e01147e51797e5a797e58797e517a75616100796079007958806152790079827700517902fd009f63615179515179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd615279525179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe615279545179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff615279585179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a7561527951797e537a75527a527a5279757575685c7900a063615d795a7959797e01147e51797e5a797e58797e517a75616100795e79007958806152790079827700517902fd009f63615179515179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd615279525179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe615279545179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff615279585179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a7561527951797e537a75527a527a5279757575680079aa007961011679007982775179517958947f7551790128947f77517a75517a75618769011679a954798769011779011779ac69610115796100792097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c011379011379855679aa616100790079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a756157795679567956795679537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff0061517951795179517997527a75517a5179009f635179517993527a75517a685179517a75517a7561527a75517a517951795296a0630079527994527a75517a68537982775279827754527993517993013051797e527e53797e57797e527e52797e5579517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7e56797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75617777777777777777777777777777777777777777777777776ae0cfa0c0930b63270459fe368d5ed31da74c00de")
		require.NoError(t, err)

		scriptPub := script.NewFromBytes(b)
		require.NotNil(t, scriptPub)
		require.False(t, scriptPub.IsMultiSigOut())
	})
}

func TestScript_PublicKeyHash(t *testing.T) {
	t.Parallel()

	t.Run("get as bytes", func(t *testing.T) {
		b, err := hex.DecodeString("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
		require.NoError(t, err)

		s := script.NewFromBytes(b)
		require.NotNil(t, s)

		var pkh []byte
		pkh, err = s.PublicKeyHash()
		require.NoError(t, err)
		require.Equal(t, "04d03f746652cfcb6cb55119ab473a045137d265", hex.EncodeToString(pkh))
	})

	t.Run("get as string", func(t *testing.T) {
		s, err := script.NewFromHex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
		require.NoError(t, err)
		require.NotNil(t, s)

		var pkh []byte
		pkh, err = s.PublicKeyHash()
		require.NoError(t, err)
		require.Equal(t, "04d03f746652cfcb6cb55119ab473a045137d265", hex.EncodeToString(pkh))
	})

	t.Run("empty script", func(t *testing.T) {
		s := &script.Script{}

		_, err := s.PublicKeyHash()
		require.Error(t, err)
		require.EqualError(t, err, "script is empty")
	})

	t.Run("nonstandard script", func(t *testing.T) {
		// example tx 37d4cc9f8a3b62e7f2e7c97c07a3282bfa924739c0e174733ff1b764ef8e3ebc
		s, err := script.NewFromHex("76")
		require.NoError(t, err)
		require.NotNil(t, s)

		_, err = s.PublicKeyHash()
		require.Error(t, err)
		require.EqualError(t, err, "not a P2PKH")
	})
}

func TestScript_AppendOpcodes(t *testing.T) {
	tests := map[string]struct {
		script    string
		appends   []byte
		expScript string
		expErr    error
	}{
		"successful single append": {
			script:    "OP_2 OP_2 OP_ADD",
			appends:   []byte{script.OpEQUALVERIFY},
			expScript: "OP_2 OP_2 OP_ADD OP_EQUALVERIFY",
		},
		"successful multiple append": {
			script:    "OP_2 OP_2 OP_ADD",
			appends:   []byte{script.OpEQUAL, script.OpVERIFY},
			expScript: "OP_2 OP_2 OP_ADD OP_EQUAL OP_VERIFY",
		},
		"unsuccessful push adata append": {
			script:  "OP_2 OP_2 OP_ADD",
			appends: []byte{script.OpEQUAL, script.OpPUSHDATA1, 0x44},
			expErr:  script.ErrInvalidOpcodeType,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			script, err := script.NewFromASM(test.script)
			require.NoError(t, err)

			err = script.AppendOpcodes(test.appends...)
			if test.expErr != nil {
				require.Error(t, err)
				require.EqualError(t, test.expErr, errors.Unwrap(err).Error())
			} else {
				require.NoError(t, err)
				asm := script.ToASM()
				require.Equal(t, test.expScript, asm)
			}
		})
	}
}

func TestScript_Equals(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		script1 *script.Script
		script2 *script.Script
		exp     bool
	}{
		"scripts from bytes equal should return true": {
			script1: func() *script.Script {
				b, err := hex.DecodeString("5201110122013353ae")
				require.NoError(t, err)

				return script.NewFromBytes(b)
			}(),
			script2: func() *script.Script {
				b, err := hex.DecodeString("5201110122013353ae")
				require.NoError(t, err)

				return script.NewFromBytes(b)
			}(),
			exp: true,
		}, "scripts from hex, equal should return true": {
			script1: func() *script.Script {
				s, err := script.NewFromHex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
				require.NoError(t, err)
				require.NotNil(t, s)
				return s
			}(),
			script2: func() *script.Script {
				s, err := script.NewFromHex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
				require.NoError(t, err)
				require.NotNil(t, s)
				return s
			}(),
			exp: true,
		}, "scripts from hex, not equal should return false": {
			script1: func() *script.Script {
				s, err := script.NewFromHex("76a91404d03f746652cfcb6cb55119ab473a045137d26566ac")
				require.NoError(t, err)
				require.NotNil(t, s)
				return s
			}(),
			script2: func() *script.Script {
				s, err := script.NewFromHex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
				require.NoError(t, err)
				require.NotNil(t, s)
				return s
			}(),
			exp: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.exp, test.script1.Equals(test.script2))
			require.Equal(t, test.exp, test.script1.EqualsBytes(*test.script2))
			require.Equal(t, test.exp, test.script1.EqualsHex(test.script2.String()))
		})
	}
}

func TestScript_MinPushSize(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data   [][]byte
		expLen int
	}{
		"OpX / OpNeg returns 1": {
			data: [][]byte{
				{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9},
				{10}, {11}, {12}, {13}, {14}, {15}, {16}, {0x81},
			},
			expLen: 1,
		},
		"OP_DATA_1 + data returns 2": {
			data: [][]byte{
				{0x17}, {0x18}, {0x19}, {0x20}, {0x21}, {0x22}, {0x23}, {0x24}, {0x25}, {0x26},
				{0x27}, {0x28}, {0x29}, {0x30}, {0x31}, {0x32}, {0x33}, {0x34}, {0x35}, {0x36},
				{0x37}, {0x38}, {0x39}, {0x40}, {0x41}, {0x42}, {0x43}, {0x44}, {0x45}, {0x46},
				{0x47}, {0x48}, {0x49}, {0x50}, {0x51}, {0x52}, {0x53}, {0x54}, {0x55}, {0x56},
				{0x57}, {0x58}, {0x59}, {0x60}, {0x61}, {0x62}, {0x63}, {0x64}, {0x65}, {0x66},
				{0x67}, {0x68}, {0x69}, {0x70}, {0x71}, {0x72}, {0x73}, {0x74}, {0x75}, {0x76},
				{0x78}, {0x79}, {0x7a}, {0x7b}, {0x7c}, {0x7d}, {0x7e}, {0x7f}, {0x80},
				{0x82}, {0x83}, {0x84}, {0x85}, {0x86}, {0x87}, {0x88}, {0x89}, {0x8a}, {0x8b},
				{0x8c}, {0x8d}, {0x8e}, {0x8f}, {0x90}, {0x91}, {0x92}, {0x93}, {0x94}, {0x95},
				{0x96}, {0x97}, {0x98}, {0x99}, {0x9a}, {0x9b}, {0x9c}, {0x9d}, {0x9e}, {0x9f},
				{0xa0}, {0xa1}, {0xa2}, {0xa3}, {0xa4}, {0xa5}, {0xa6}, {0xa7}, {0xa8}, {0xa9},
				{0xaa}, {0xab}, {0xac}, {0xad}, {0xae}, {0xaf}, {0xb0}, {0xb1}, {0xb2}, {0xb3},
				{0xb4}, {0xb5}, {0xb6}, {0xb7}, {0xb8}, {0xb9}, {0xba}, {0xbb}, {0xbc}, {0xbd},
				{0xbe}, {0xbf}, {0xc0}, {0xc1}, {0xc2}, {0xc3}, {0xc4}, {0xc5}, {0xc6}, {0xc7},
				{0xc8}, {0xc9}, {0xca}, {0xcb}, {0xcc}, {0xcd}, {0xce}, {0xcf}, {0xd0}, {0xd1},
				{0xd2}, {0xd3}, {0xd4}, {0xd5}, {0xd6}, {0xd7}, {0xd8}, {0xd9}, {0xda}, {0xdb},
				{0xdc}, {0xdd}, {0xde}, {0xdf}, {0xe0}, {0xe1}, {0xe2}, {0xe3}, {0xe4}, {0xe5},
				{0xe6}, {0xe7}, {0xe8}, {0xe9}, {0xea}, {0xeb}, {0xec}, {0xed}, {0xee}, {0xef},
				{0xf0}, {0xf1}, {0xf2}, {0xf3}, {0xf4}, {0xf5}, {0xf6}, {0xf7}, {0xf8}, {0xf9},
				{0xfa}, {0xfb}, {0xfc}, {0xfd}, {0xfe}, {0xff},
			},
			expLen: 2,
		},
		"OP_DATA_2 onward returns len(data)+1": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 23)
			}()},
			expLen: 23 + 1,
		},
		"OP_DATA_75 returns len(data)+1 (max)": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 75)
			}()},
			expLen: 75 + 1,
		},
		"OP_PUSHDATA1 + length byte + data returns len(data)+2": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 86)
			}()},
			expLen: 86 + 2,
		},
		"OP_PUSHDATA1 + length byte + data returns len(data)+2 (max)": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 255)
			}()},
			expLen: 255 + 2,
		},
		"OP_PUSHDATA2 + length byte + data returns len(data)+3": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 256)
			}()},
			expLen: 256 + 3,
		},
		"OP_PUSHDATA2 + length byte + data returns len(data)+3 (max)": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 65535)
			}()},
			expLen: 65535 + 3,
		},
		"OP_PUSHDATA4 + length byte + data returns len(data)+5": {
			data: [][]byte{func() []byte {
				return bytes.Repeat([]byte{0x00}, 65536)
			}()},
			expLen: 65536 + 5,
		},
		// These tests cause the CI to OOM due to the massive slices being created
		//"OP_PUSHDATA4 + length byte + data returns len(data)+5 (max)": {
		//	data: [][]byte{func() []byte {
		//		return bytes.Repeat([]byte{0x00}, 0xffffffff)
		//	}()},
		//	expLen: 0xffffffff + 5,
		//},
		//"data too large returns 0": {
		//	data: [][]byte{func() []byte {
		//		return bytes.Repeat([]byte{0x00}, 0xffffffff+1)
		//	}()},
		//	expLen: 0,
		//},
		"Op0 returns 1": {
			data:   [][]byte{},
			expLen: 1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for _, data := range test.data {
				require.Equal(t, test.expLen, script.MinPushSize(data), "data: %x", data)
			}
		})
	}
}

func TestScript_MarshalJSON(t *testing.T) {
	script, err := script.NewFromASM("OP_2 OP_2 OP_ADD OP_4 OP_EQUALVERIFY")
	require.NoError(t, err)

	bb, err := json.Marshal(script)
	require.NoError(t, err)

	require.Equal(t, `"5252935488"`, string(bb))
}

func TestScript_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		jsonString string
		exp        string
	}{
		"script with content": {
			jsonString: `"5252935488"`,
			exp:        "5252935488",
		},
		"empty script": {
			jsonString: `""`,
			exp:        "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var out *script.Script
			require.NoError(t, json.Unmarshal([]byte(test.jsonString), &out))
			require.Equal(t, test.exp, out.String())
		})
	}
}

func TestScriptToAsm(t *testing.T) {
	sbuf, _ := hex.DecodeString("006a2231394878696756345179427633744870515663554551797131707a5a56646f4175744d7301e4b8bbe381aa54574954544552e381a8425356e381ae547765746368e381a7e381aee98195e381840a547765746368e381a7e381afe887aae58886e381aee69bb8e38184e3819fe38384e382a8e383bce38388e381afe4b880e795aae69c80e5889de381bee381a70ae38195e3818be381aee381bce381a3e381a6e38184e381a4e381a7e38282e7a2bae8aa8de58fafe883bde381a7e8aaade381bfe8bebce381bfe381a7e995b7e69982e996930ae5819ce6ada2e381afe38182e3828ae381bee3819be38293e380825954e383aae383b3e382afe381aee58b95e794bbe38292e8a696e881b4e38197e3819fe5a0b4e590880ae99fb3e6a5bde381afe382b9e382afe383ade383bce383abe38197e381a6e38282e98094e58887e3828ce3819ae881b4e38193e38188e3819fe381bee381be0ae38384e382a4e38383e382bfe383bce381afe69c80e5889de381aee383ace382b9e381bee381a7e8a18ce38191e381aae38184e381a7e38197e38287e380820a746578742f706c61696e04746578741f7477657463685f7477746578745f313634343834393439353138332e747874017c223150755161374b36324d694b43747373534c4b79316b683536575755374d74555235035345540b7477646174615f6a736f6e046e756c6c0375726c046e756c6c07636f6d6d656e74046e756c6c076d625f757365720439373038057265706c794035366462363536376363306230663539316265363561396135313731663533396635316334333165643837356464326136373431643733353061353539363762047479706504706f73740974696d657374616d70046e756c6c036170700674776574636807696e766f6963652461366637336133312d336334342d346164612d393937352d386537386261666661623765017c22313550636948473232534e4c514a584d6f53556157566937575371633768436676610d424954434f494e5f454344534122314c6970354b335671677743415662674d7842536547434d344355364e344e6b75744c58494b4b554a35765a7753336b4c456e353749356a36485a2b43325733393834314e543532334a4c374534387655706d6f57306b4677613767392b51703246434f4d42776a556a7a76454150624252784d496a746c6b476b3d")
	s := script.Script(sbuf)

	asm := s.ToASM()

	expected := "OP_FALSE OP_RETURN 31394878696756345179427633744870515663554551797131707a5a56646f417574 e4b8bbe381aa54574954544552e381a8425356e381ae547765746368e381a7e381aee98195e381840a547765746368e381a7e381afe887aae58886e381aee69bb8e38184e3819fe38384e382a8e383bce38388e381afe4b880e795aae69c80e5889de381bee381a70ae38195e3818be381aee381bce381a3e381a6e38184e381a4e381a7e38282e7a2bae8aa8de58fafe883bde381a7e8aaade381bfe8bebce381bfe381a7e995b7e69982e996930ae5819ce6ada2e381afe38182e3828ae381bee3819be38293e380825954e383aae383b3e382afe381aee58b95e794bbe38292e8a696e881b4e38197e3819fe5a0b4e590880ae99fb3e6a5bde381afe382b9e382afe383ade383bce383abe38197e381a6e38282e98094e58887e3828ce3819ae881b4e38193e38188e3819fe381bee381be0ae38384e382a4e38383e382bfe383bce381afe69c80e5889de381aee383ace382b9e381bee381a7e8a18ce38191e381aae38184e381a7e38197e38287e38082 746578742f706c61696e 74657874 7477657463685f7477746578745f313634343834393439353138332e747874 7c 3150755161374b36324d694b43747373534c4b79316b683536575755374d74555235 534554 7477646174615f6a736f6e 6e756c6c 75726c 6e756c6c 636f6d6d656e74 6e756c6c 6d625f75736572 39373038 7265706c79 35366462363536376363306230663539316265363561396135313731663533396635316334333165643837356464326136373431643733353061353539363762 74797065 706f7374 74696d657374616d70 6e756c6c 617070 747765746368 696e766f696365 61366637336133312d336334342d346164612d393937352d386537386261666661623765 7c 313550636948473232534e4c514a584d6f5355615756693757537163376843667661 424954434f494e5f4543445341 314c6970354b335671677743415662674d7842536547434d344355364e344e6b7574 494b4b554a35765a7753336b4c456e353749356a36485a2b43325733393834314e543532334a4c374534387655706d6f57306b4677613767392b51703246434f4d42776a556a7a76454150624252784d496a746c6b476b3d"

	if asm != expected {
		t.Errorf("\nExpected %q\ngot      %q", expected, asm)
	}

}

func TestRunScriptExample2(t *testing.T) {
	sbuf, _ := hex.DecodeString("006a0372756e01050c63727970746f6669676874734d16057b22696e223a312c22726566223a5b22343561666530303862396634393663333130356663396132636234373234316565643566646531333531303532616339353938323531636666623939376136385f6f31222c22643335343933633964313266656538363134313663333366653336346662336566373531363234373532313833316264623232303933333731303330383663325f6f31222c22306338623636326339363862316537376164626535666161653566666436633033653537353965373833376132353534653438643561356535326335346634385f6f31222c22336136376365633363313662646238343762393732626565326663316330373137633539656463616537626635663438633931666563636661363335616633335f6f31222c22313465323738633638666635323165303931366164376337313361653461303135366537363336316462643362326233353764666236303238653064636137615f6f31222c22613738663561366437326637383731316536366336323131666262643061306266643135616439316264643030343034393238613966616363363364613664395f6f31222c22373535633932326336366363656533353766356265656437383164323631336634313739346230323839333963333435316466653438393032303238343263355f6f31222c22316661333532383030333363343534663465313263323134383333343436643335313734663031666565373064346639653633366664393462363237316436325f6f31222c22636233356534656361336635616334303561636261636464383632346366303835636333626535336639323633663531616565373037393234616265316237385f6f31222c22373166626133383633343162393332333830656335626665646333613430626365343364343937346465636463393463343139613934613863653564666332335f6f31222c22363161653132323165646438626431646438336332326461326232616237643131346139313239363439366365336664306562613737333236623638613238335f6f31222c22386462643166643638373934353131636364616338333938333136393638306662616338356233613961626439636166366361326666343839633862313633385f6f31222c22386564316564633665656439386135326635373234396333353032663266333764623561336666356233643135613930363732353063383465363035366531315f6f31222c22343062396534373865333766383733636532386364383162666635323532346631383063623538353837376331656139383636343933383039363363646237385f6f31225d2c226f7574223a5b2262633038643265323932623036313031323463313337656361356566393632383464363534363139616162366630313461333932353532613066336339666162225d2c2264656c223a5b5d2c22637265223a5b5d2c2265786563223a5b7b226f70223a2243414c4c222c2264617461223a5b7b22246a6967223a307d2c227265736f6c7665222c5b2263633031363466343332613563383635306331393731376430373161656561646261393065643761303939386234396464656535663537316430323139373032222c313634373630333734373833342c302c2230336339386161663266623237393930613130356364336362616462656461383536613064363238343262666564633430353730343966636232343163333563222c5b302c302c305d5d5d7d5d7d")
	s := script.Script(sbuf)

	asm := s.ToASM()

	expected := "OP_FALSE OP_RETURN 72756e 05 63727970746f666967687473 7b22696e223a312c22726566223a5b22343561666530303862396634393663333130356663396132636234373234316565643566646531333531303532616339353938323531636666623939376136385f6f31222c22643335343933633964313266656538363134313663333366653336346662336566373531363234373532313833316264623232303933333731303330383663325f6f31222c22306338623636326339363862316537376164626535666161653566666436633033653537353965373833376132353534653438643561356535326335346634385f6f31222c22336136376365633363313662646238343762393732626565326663316330373137633539656463616537626635663438633931666563636661363335616633335f6f31222c22313465323738633638666635323165303931366164376337313361653461303135366537363336316462643362326233353764666236303238653064636137615f6f31222c22613738663561366437326637383731316536366336323131666262643061306266643135616439316264643030343034393238613966616363363364613664395f6f31222c22373535633932326336366363656533353766356265656437383164323631336634313739346230323839333963333435316466653438393032303238343263355f6f31222c22316661333532383030333363343534663465313263323134383333343436643335313734663031666565373064346639653633366664393462363237316436325f6f31222c22636233356534656361336635616334303561636261636464383632346366303835636333626535336639323633663531616565373037393234616265316237385f6f31222c22373166626133383633343162393332333830656335626665646333613430626365343364343937346465636463393463343139613934613863653564666332335f6f31222c22363161653132323165646438626431646438336332326461326232616237643131346139313239363439366365336664306562613737333236623638613238335f6f31222c22386462643166643638373934353131636364616338333938333136393638306662616338356233613961626439636166366361326666343839633862313633385f6f31222c22386564316564633665656439386135326635373234396333353032663266333764623561336666356233643135613930363732353063383465363035366531315f6f31222c22343062396534373865333766383733636532386364383162666635323532346631383063623538353837376331656139383636343933383039363363646237385f6f31225d2c226f7574223a5b2262633038643265323932623036313031323463313337656361356566393632383464363534363139616162366630313461333932353532613066336339666162225d2c2264656c223a5b5d2c22637265223a5b5d2c2265786563223a5b7b226f70223a2243414c4c222c2264617461223a5b7b22246a6967223a307d2c227265736f6c7665222c5b2263633031363466343332613563383635306331393731376430373161656561646261393065643761303939386234396464656535663537316430323139373032222c313634373630333734373833342c302c2230336339386161663266623237393930613130356364336362616462656461383536613064363238343262666564633430353730343966636232343163333563222c5b302c302c305d5d5d7d5d7d"
	if asm != expected {
		t.Errorf("\nExpected %q\ngot      %q", expected, asm)
	}
}

func TestRunScriptExample3(t *testing.T) {
	sbuf, _ := hex.DecodeString("006a223139694733575459537362796f7333754a373333794b347a45696f69314665734e55010042666166383166326364346433663239383061623162363564616166656231656631333561626339643534386461633466366134656361623230653033656365362d300274780134")
	s := script.Script(sbuf)

	asm := s.ToASM()

	expected := "OP_FALSE OP_RETURN 3139694733575459537362796f7333754a373333794b347a45696f69314665734e55 00 666166383166326364346433663239383061623162363564616166656231656631333561626339643534386461633466366134656361623230653033656365362d30 7478 34"
	if asm != expected {
		t.Errorf("\nExpected %q\ngot      %q", expected, asm)
	}
}

// Test vectors from testdata/valid.go
func TestScriptInvalid(t *testing.T) {
	for i, v := range testdata.InvalidVectors {
		if len(v) == 1 {
			continue
		}
		t.Run(fmt.Sprintf("Test vector %d", i), func(t *testing.T) {
			// log.Println("Testing", i, v)
			// hydrate a script from the test vector
			for i := 0; i < 2; i++ {
				s, err := script.NewFromHex(v[i])
				if err != nil {
					log.Println("Faied NewFromHex:", v[0], v[1], v[2])
					t.Error(err)
					t.FailNow()
				}
				asm := s.ToASM()
				s, err = script.NewFromASM(asm)
				if err != nil {
					log.Println("Faied NewFromASM:", v[0], v[1], v[2])
					t.Error(err)
				}
				asm2 := s.ToASM()
				require.Equal(t, asm, asm2)
			}
		})
	}
}

// Test vectors from testdata/script.valid.vectors.json
func TestScriptValid(t *testing.T) {
	for i, v := range testdata.ValidVectors {
		if len(v) == 1 {
			continue
		}

		t.Run(fmt.Sprintf("Test vector %d", i), func(t *testing.T) {
			for i := 0; i < 2; i++ {
				s, err := script.NewFromHex(v[i])
				if err != nil {
					t.Error(err)
					t.FailNow()
				}
				// Test that no errors are thrown for the first item
				asm := s.ToASM()
				s, err = script.NewFromASM(asm)
				if err != nil {
					t.Error(err)
				}
				asm2 := s.ToASM()
				require.Equal(t, asm, asm2)
			}

		})
	}
}

func TestSpendValid(t *testing.T) {
	prevTxid := &chainhash.Hash{}
	prevIndex := uint32(0)
	for i, v := range testdata.ValidSpends {
		if len(v) == 1 {
			continue
		}

		t.Run(fmt.Sprintf("Spend vector %d", i), func(t *testing.T) {
			tx := transaction.NewTransaction()
			lockingScript, err := script.NewFromHex(v[1])
			if err != nil {
				t.Error(err)
			}
			_ = tx.AddInputsFromUTXOs(&transaction.UTXO{
				TxID:          prevTxid,
				Vout:          prevIndex,
				Satoshis:      1,
				LockingScript: lockingScript,
			})
			unlockingScript, err := script.NewFromHex(v[0])
			if err != nil {
				t.Error(err)
			}
			tx.Inputs[0].UnlockingScript = unlockingScript

			err = interpreter.NewEngine().Execute(
				interpreter.WithTx(tx, 0, &transaction.TransactionOutput{
					Satoshis:      1,
					LockingScript: lockingScript,
				}),
				// interpreter.WithAfterGenesis(),
				interpreter.WithForkID(),
			)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
func TestScriptChunks(t *testing.T) {
	t.Parallel()

	t.Run("simple", func(t *testing.T) {
		scriptHex := "05000102030401FF02ABCD"
		scriptBytes, err := hex.DecodeString(scriptHex)
		require.NoError(t, err)

		s := script.NewFromBytes(scriptBytes)
		parts, err := s.Chunks()
		require.NoError(t, err)
		require.Len(t, parts, 3)
	})

	t.Run("empty parts", func(t *testing.T) {
		scriptHex := ""
		scriptBytes, err := hex.DecodeString(scriptHex)
		require.NoError(t, err)

		s := script.NewFromBytes(scriptBytes)
		parts, err := s.Chunks()
		require.NoError(t, err)
		require.Empty(t, parts)
	})

	t.Run("complex parts", func(t *testing.T) {
		scriptHex := "524c53ff0488b21e000000000000000000362f7a9030543db8751401c387d6a71e870f1895b3a62569d455e8ee5f5f5e5f03036624c6df96984db6b4e625b6707c017eb0e0d137cd13a0c989bfa77a4473fd000000004c53ff0488b21e0000000000000000008b20425398995f3c866ea6ce5c1828a516b007379cf97b136bffbdc86f75df14036454bad23b019eae34f10aff8b8d6d8deb18cb31354e5a169ee09d8a4560e8250000000052ae"
		scriptBytes, err := hex.DecodeString(scriptHex)
		require.NoError(t, err)

		s := script.NewFromBytes(scriptBytes)
		parts, err := s.Chunks()
		require.NoError(t, err)
		require.Len(t, parts, 5)
	})

	t.Run("bad parts", func(t *testing.T) {
		scriptHex := "05000000"
		scriptBytes, err := hex.DecodeString(scriptHex)
		require.NoError(t, err)

		s := script.NewFromBytes(scriptBytes)
		_, err = s.Chunks()
		require.Error(t, err)
		require.EqualError(t, err, "not enough data")
	})

	t.Run("invalid script", func(t *testing.T) {
		scriptHex := "4c05000000"
		scriptBytes, err := hex.DecodeString(scriptHex)
		require.NoError(t, err)

		s := script.NewFromBytes(scriptBytes)
		_, err = s.Chunks()
		require.Error(t, err)
		require.EqualError(t, err, "not enough data")
	})

	t.Run("decode using PUSHDATA1", func(t *testing.T) {
		scriptHex := "testing"
		scriptBytes := append([]byte{script.OpPUSHDATA1}, byte(len(scriptHex)))
		scriptBytes = append(scriptBytes, []byte(scriptHex)...)

		s := script.NewFromBytes(scriptBytes)
		parts, err := s.Chunks()
		require.NoError(t, err)
		require.Len(t, parts, 1)
	})

	t.Run("invalid PUSHDATA1 - missing data payload", func(t *testing.T) {
		scriptBytes := []byte{script.OpPUSHDATA1}

		s := script.NewFromBytes(scriptBytes)
		_, err := s.Chunks()
		require.Error(t, err)
	})

	t.Run("invalid PUSHDATA2 - payload too small", func(t *testing.T) {
		scriptHex := "testing PUSHDATA2"
		scriptBytes := append([]byte{script.OpPUSHDATA2}, byte(len(scriptHex)))
		scriptBytes = append(scriptBytes, []byte(scriptHex)...)

		s := script.NewFromBytes(scriptBytes)
		_, err := s.Chunks()
		require.Error(t, err)
	})

	t.Run("invalid PUSHDATA2 - missing data payload", func(t *testing.T) {
		scriptBytes := []byte{script.OpPUSHDATA2}

		s := script.NewFromBytes(scriptBytes)
		_, err := s.Chunks()
		require.Error(t, err)
	})

	t.Run("invalid PUSHDATA4 - payload too small", func(t *testing.T) {
		scriptHex := "testing PUSHDATA4"
		scriptBytes := append([]byte{script.OpPUSHDATA4}, byte(len(scriptHex)))
		scriptBytes = append(scriptBytes, []byte(scriptHex)...)

		s := script.NewFromBytes(scriptBytes)
		_, err := s.Chunks()
		require.Error(t, err)
	})

	t.Run("invalid PUSHDATA4 - missing data payload", func(t *testing.T) {
		scriptBytes := []byte{script.OpPUSHDATA4}

		s := script.NewFromBytes(scriptBytes)
		_, err := s.Chunks()
		require.Error(t, err)
	})

	t.Run("panic case", func(t *testing.T) {
		scriptHex := "006a046d657461226e3465394d57576a416f576b727646344674724e783252507533584d53344d786570201ed64f8e4ddb6843121dc11e1db6d07c62e59c621f047e1be0a9dd910ca606d04cfe080000000b00045479706503070006706f7374616c000355736503070004686f6d650006526567696f6e030700057374617465000a506f7374616c436f64650307000432383238000b44617465437265617465640d070018323032302d30362d32325431323a32343a32362e3337315a00035f69640307002f302e34623836326165372d323533352d346136312d386461322d3962616231633336353038312e302e342e31332e30000443697479030700046369747900054c696e65300307000474657374000b436f756e747279436f646503070002414500054c696e653103070005746573743200084469737472696374030700086469737472696374"
		_, err := script.NewFromHex(scriptHex)
		require.NoError(t, err)
	})
}

func TestScriptPubKeyHex(t *testing.T) {
	tests := []struct {
		name           string
		scriptHex      string
		expectedPubKey string
		expectError    bool
	}{
		{
			name:           "Valid P2PK Script",
			scriptHex:      "2102f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5ac",
			expectedPubKey: "02f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5",
			expectError:    false,
		},
		{
			name:           "Invalid Data Script",
			scriptHex:      "006a04ac1eed884d53027b2276657273696f6e223a22302e31222c22686569676874223a3634323436302c22707265764d696e65724964223a22303365393264336535633366376264393435646662663438653761393933393362316266623366313166333830616533306432383665376666326165633561323730222c22707265764d696e65724964536967223a2233303435303232313030643736333630653464323133333163613836663031386330343665353763393338663139373735303734373333333533363062653337303438636165316166333032323030626536363034353430323162663934363465393966356139353831613938633963663439353430373539386335396234373334623266646234383262663937222c226d696e65724964223a22303365393264336535633366376264393435646662663438653761393933393362316266623366313166333830616533306432383665376666326165633561323730222c2276637478223a7b2274784964223a2235373962343335393235613930656533396133376265336230306239303631653734633330633832343133663664306132303938653162656137613235313566222c22766f7574223a307d2c226d696e6572436f6e74616374223a7b22656d61696c223a22696e666f407461616c2e636f6d222c226e616d65223a225441414c20446973747269627574656420496e666f726d6174696f6e20546563686e6f6c6f67696573222c226d65726368616e74415049456e64506f696e74223a2268747470733a2f2f6d65726368616e746170692e7461616c2e636f6d2f227d7d46304402206fd1c6d6dd32cc85ddd2f30bc068445dd901c6bd85e394e45bb254716d2bb228022041f0f8b1b33c2e3702aee4ad47155548045ed945738b43dc0faed2e86faa12e4",
			expectedPubKey: "",
			expectError:    true,
		},
		{
			name:           "Empty Script",
			scriptHex:      "",
			expectedPubKey: "",
			expectError:    true,
		},
		{
			name:           "Invalid Script (too short)",
			scriptHex:      "05000000",
			expectedPubKey: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := script.NewFromHex(tt.scriptHex)
			require.NoError(t, err)

			pubKeyHex, err := s.PubKeyHex()

			if tt.expectError {
				require.Error(t, err)
				require.Empty(t, pubKeyHex)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedPubKey, pubKeyHex)
			}
		})
	}
}

func TestScriptAddresses(t *testing.T) {
	tests := []struct {
		name              string
		scriptHex         string
		expectedAddresses []string
		expectError       bool
	}{
		{
			name:              "Valid P2PK Script",
			scriptHex:         "76a9149df0707f3f8e534441c055aca4bb816fbc1eadf488ac",
			expectedAddresses: []string{"1FQ789GuMRYki3t79XK3AWQ8gxzVNLzvXr"},
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := script.NewFromHex(tt.scriptHex)
			require.NoError(t, err)

			addresses, err := s.Addresses()

			if tt.expectError {
				require.Error(t, err)
				require.Empty(t, addresses)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedAddresses, addresses)
			}

			address, err := s.Address()
			require.NoError(t, err)
			require.Equal(t, tt.expectedAddresses[0], address.AddressString)
		})
	}
}

func TestScriptAppendPushDataString(t *testing.T) {
	t.Parallel()

	s := &script.Script{}

	// Test with a simple string
	err := s.AppendPushDataString("hello")
	require.NoError(t, err)

	// The script should contain the PUSHDATA opcode and the data
	expectedScriptHex := "0568656c6c6f"
	require.Equal(t, expectedScriptHex, s.String())

	// Test with an empty string
	s = &script.Script{}
	err = s.AppendPushDataString("")
	require.NoError(t, err)
	// Empty data should be represented as OP_0 (0x00)
	expectedScriptHex = "00"
	require.Equal(t, expectedScriptHex, s.String())

	// Test with a long string (>75 bytes to trigger PUSHDATA1)
	longStr := strings.Repeat("a", 80)
	s = &script.Script{}
	err = s.AppendPushDataString(longStr)
	require.NoError(t, err)

	// Since length is >75 and <=255, should use PUSHDATA1 (opcode 0x4c)
	expectedScriptBytes := append([]byte{script.OpPUSHDATA1, 0x50}, []byte(longStr)...)
	expectedScriptHex = hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())

	// Test with a very long string (>255 bytes to trigger PUSHDATA2)
	veryLongStr := strings.Repeat("b", 300)
	s = &script.Script{}
	err = s.AppendPushDataString(veryLongStr)
	require.NoError(t, err)

	// Should use PUSHDATA2 (opcode 0x4d)
	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, uint16(300))
	expectedScriptBytes = append([]byte{script.OpPUSHDATA2}, lengthBytes...)
	expectedScriptBytes = append(expectedScriptBytes, []byte(veryLongStr)...)
	expectedScriptHex = hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())
}

func TestScriptAppendPushDataArray(t *testing.T) {
	t.Parallel()

	s := &script.Script{}

	dataArray := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("test"),
	}

	err := s.AppendPushDataArray(dataArray)
	require.NoError(t, err)

	// The script should contain the correct PUSHDATA prefixes and data
	expectedScriptHex := "0568656c6c6f05776f726c640474657374"
	require.Equal(t, expectedScriptHex, s.String())

	// Test with an empty array
	s = &script.Script{}
	err = s.AppendPushDataArray([][]byte{})
	require.NoError(t, err)
	// Script should be empty
	require.Equal(t, "", s.String())

	// Test with data that requires PUSHDATA1
	longData := []byte(strings.Repeat("a", 80)) // 80 bytes
	dataArray = [][]byte{longData}
	s = &script.Script{}
	err = s.AppendPushDataArray(dataArray)
	require.NoError(t, err)

	expectedScriptBytes := append([]byte{script.OpPUSHDATA1, 0x50}, longData...)
	expectedScriptHex = hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())

	// Test with data that requires PUSHDATA2
	veryLongData := []byte(strings.Repeat("b", 300))
	dataArray = [][]byte{veryLongData}
	s = &script.Script{}
	err = s.AppendPushDataArray(dataArray)
	require.NoError(t, err)

	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, uint16(300))
	expectedScriptBytes = append([]byte{script.OpPUSHDATA2}, lengthBytes...)
	expectedScriptBytes = append(expectedScriptBytes, veryLongData...)
	expectedScriptHex = hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())
}

func TestScriptAppendBigInt(t *testing.T) {
	t.Parallel()

	s := &script.Script{}

	var bInt big.Int
	bInt.SetInt64(1234567890)

	err := s.AppendBigInt(bInt)
	require.NoError(t, err)

	// The script should contain the correct PUSHDATA prefix and data
	data := bInt.Bytes()
	dataLen := len(data)
	expectedScriptBytes := append([]byte{byte(dataLen)}, data...)
	expectedScriptHex := hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())

	// Test with zero
	bInt.SetInt64(0)
	s = &script.Script{}
	err = s.AppendBigInt(bInt)
	require.NoError(t, err)
	// Zero should be represented as OP_0 (0x00)
	require.Equal(t, "00", s.String())

	// Test with a negative big.Int
	bInt.SetInt64(-123456)
	s = &script.Script{}
	err = s.AppendBigInt(bInt)
	require.NoError(t, err)
	data = bInt.Bytes() // Negative numbers are represented in two's complement
	dataLen = len(data)
	expectedScriptBytes = append([]byte{byte(dataLen)}, data...)
	expectedScriptHex = hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())
}

func TestScriptAppendPushDataStrings(t *testing.T) {
	t.Parallel()

	s := &script.Script{}

	dataStrings := []string{"hello", "world", "test"}
	err := s.AppendPushDataStrings(dataStrings)
	require.NoError(t, err)

	// The script should contain the correct PUSHDATA prefixes and data
	expectedScriptHex := "0568656c6c6f05776f726c640474657374"
	require.Equal(t, expectedScriptHex, s.String())

	// Test with an empty array
	s = &script.Script{}
	err = s.AppendPushDataStrings([]string{})
	require.NoError(t, err)
	// Script should be empty
	require.Equal(t, "", s.String())

	// Test with strings that require PUSHDATA1
	longStrings := []string{strings.Repeat("a", 80), strings.Repeat("b", 80)}
	s = &script.Script{}
	err = s.AppendPushDataStrings(longStrings)
	require.NoError(t, err)

	expectedScriptBytes := []byte{}
	for _, str := range longStrings {
		data := []byte(str)
		dataLen := len(data)
		if dataLen <= 75 {
			expectedScriptBytes = append(expectedScriptBytes, byte(dataLen))
		} else if dataLen <= 255 {
			expectedScriptBytes = append(expectedScriptBytes, script.OpPUSHDATA1, byte(dataLen))
		}
		expectedScriptBytes = append(expectedScriptBytes, data...)
	}
	expectedScriptHex = hex.EncodeToString(expectedScriptBytes)
	require.Equal(t, expectedScriptHex, s.String())
}

func TestScriptPubKey(t *testing.T) {
	t.Parallel()

	// Valid P2PK script
	s, err := script.NewFromHex("2102f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5ac")
	require.NoError(t, err)
	require.NotNil(t, s)
	pubKey, err := s.PubKey()
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	// The public key bytes should match the expected value
	pubKeyBytes := pubKey.Compressed()
	expectedPubKeyHex := "02f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5"
	require.Equal(t, expectedPubKeyHex, hex.EncodeToString(pubKeyBytes))

	// Non-P2PK script
	s, err = script.NewFromHex("76a9149df0707f3f8e534441c055aca4bb816fbc1eadf488ac")
	require.NoError(t, err)
	require.NotNil(t, s)
	pubKey, err = s.PubKey()
	require.Error(t, err)
	require.EqualError(t, err, "script is not of type ScriptTypePubKey")
	require.Nil(t, pubKey)

	// Script with missing parts
	s = &script.Script{}
	err = s.AppendPushData([]byte{}) // Empty data
	require.NoError(t, err)
	pubKey, err = s.PubKey()
	require.Error(t, err)
	require.EqualError(t, err, "script is not of type ScriptTypePubKey")
	require.Nil(t, pubKey)

	// Create a P2PK script with an invalid public key (correct length but invalid content)
	s = &script.Script{}
	invalidPubKey := append([]byte{0x02}, bytes.Repeat([]byte{0x00}, 32)...) // 33 bytes, but invalid
	err = s.AppendPushData(invalidPubKey)
	require.NoError(t, err)
	err = s.AppendOpcodes(script.OpCHECKSIG)
	require.NoError(t, err)
	require.True(t, s.IsP2PK())
	pubKey, err = s.PubKey()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid square root")
	require.Nil(t, pubKey)
}

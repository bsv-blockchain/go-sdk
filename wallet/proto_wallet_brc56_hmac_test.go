package wallet

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// BRC-56 HMAC key vectors (bsv-blockchain/BRCs wallet/0056.md at d4ce811).
// The HMAC key is the shared point's X coordinate as a minimal-length unsigned
// big-endian byte array: leading zero octets are omitted. Creation and
// verification use only this encoding. paddedKeyTag is the tag a 32-byte
// zero-padded key produces for the rows with leading zero octets; it must be
// refused.
const (
	brc56RootKey        = "f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07"
	brc56RootPublicKey  = "035818cd7cc614fea816c8b39eebe6e43cafc635451ec5a873f8757b418aaae91a"
	brc56Counterparty   = "03458d551018414b8fe1adbcef2d0afc17e1074bfab3fdde3e1b0750bdde58a9a7"
	brc56DataHex        = "4252432d353620484d41432074657374"
	brc56ProtocolString = "hmac key vectors"
)

type brc56HMACVector struct {
	counterparty string
	keyID        string
	hmacKey      string
	hmac         string
	paddedKeyTag string
}

var brc56HMACVectors = []brc56HMACVector{
	{
		counterparty: "self",
		keyID:        "k0",
		hmacKey:      "b1273850ff41cee365a4d590e3c323822129f66c5a9b2eacb8b9e790e000e396",
		hmac:         "99455edf49ea2156f6109466fb344c3027d4c14485581a50bf5ff0850328a269",
	},
	{
		counterparty: "self",
		keyID:        "k95",
		hmacKey:      "0c82ac78dc853158f24883ccfda332be6ba34f821765357cc4ef2a190a28fd",
		hmac:         "3a968ebaa25eaa4b1cfad138f96105bb1eb738defc066d01e37b32595900d48b",
		paddedKeyTag: "054a0fc6a3b0e21b31dc627fb1d645f2eea4127dff71eac95b1f71b7cb13c787",
	},
	{
		counterparty: "self",
		keyID:        "k91538",
		hmacKey:      "9dc11102cc72eca3c6e4e232460eac581e9b2cee1bb35c395b635d3f6393",
		hmac:         "5a8b84fb2a7d9ce7b12feb8319f14dc6169e0be005a1a8e58d9b9b2d1ac29d47",
		paddedKeyTag: "ff43127cb1ddfbd19776d01ce34b8c3e83916b51fa55ac045a355b731e6999f5",
	},
	{
		counterparty: brc56Counterparty,
		keyID:        "k0",
		hmacKey:      "1896e0210afac8dbb4ca3bd4ea25c8377d0352ab83e62fe6ffabeca78c1a6113",
		hmac:         "986af579272261acf3e890bb1650124b0dfbc0b1edacda202f8ed0c3b876c072",
	},
	{
		counterparty: brc56Counterparty,
		keyID:        "k497",
		hmacKey:      "1829e1dd58fc2c45b6edcbb277eecdecbab1c884b42fd779e131fea5881b45",
		hmac:         "3a5ea2bf5bcc9bc1461041737384bf258b0a3e5a475fb281a19c2972cdb1cff6",
		paddedKeyTag: "aa39467c48a116ffb00fd7b56ff158bd9af37d1298df2f031c0125458c30f574",
	},
	{
		counterparty: brc56Counterparty,
		keyID:        "k29510",
		hmacKey:      "a52a35523175d6c181e90f463a27cdbf70f4ecf055e912d6fc24ac7d0e3c",
		hmac:         "ecca769bb17b1775ce8ae4326fe721ba0f7ba272300741bf4a5b068cf0cebd60",
		paddedKeyTag: "2677674035f1aaac3219b3405cf8569ec07922a3ceffbd4f7c8a7948b2d3c553",
	},
}

func decodeHMAC32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, b, 32)
	var out [32]byte
	copy(out[:], b)
	return out
}

func TestProtoWallet_BRC56_HMACKeyVectors(t *testing.T) {
	ctx := context.Background()

	rootKey, err := ec.PrivateKeyFromHex(brc56RootKey)
	require.NoError(t, err)
	require.Equal(t, brc56RootPublicKey, rootKey.PubKey().ToDERHex())

	pw, err := NewProtoWallet(ProtoWalletArgs{Type: ProtoWalletArgsTypePrivateKey, PrivateKey: rootKey})
	require.NoError(t, err)

	counterpartyKey, err := ec.PublicKeyFromString(brc56Counterparty)
	require.NoError(t, err)

	data, err := hex.DecodeString(brc56DataHex)
	require.NoError(t, err)

	protocol := Protocol{SecurityLevel: SecurityLevelEveryAppAndCounterparty, Protocol: brc56ProtocolString}

	for _, v := range brc56HMACVectors {
		name := "counterparty"
		counterparty := Counterparty{Type: CounterpartyTypeOther, Counterparty: counterpartyKey}
		if v.counterparty == "self" {
			name = "self"
			counterparty = Counterparty{Type: CounterpartyTypeSelf}
		}
		encArgs := EncryptionArgs{ProtocolID: protocol, KeyID: v.keyID, Counterparty: counterparty}

		t.Run(name+"_"+v.keyID, func(t *testing.T) {
			key, err := pw.keyDeriver.DeriveSymmetricKey(protocol, v.keyID, counterparty)
			require.NoError(t, err)
			require.Equal(t, v.hmacKey, hex.EncodeToString(minimalHMACKey(key.ToBytes())))

			created, err := pw.CreateHMAC(ctx, CreateHMACArgs{EncryptionArgs: encArgs, Data: data}, "")
			require.NoError(t, err)
			require.Equal(t, v.hmac, hex.EncodeToString(created.HMAC[:]))

			res, err := pw.VerifyHMAC(ctx, VerifyHMACArgs{EncryptionArgs: encArgs, Data: data, HMAC: decodeHMAC32(t, v.hmac)}, "")
			require.NoError(t, err)
			require.True(t, res.Valid)

			if v.paddedKeyTag != "" {
				_, err = pw.VerifyHMAC(ctx, VerifyHMACArgs{EncryptionArgs: encArgs, Data: data, HMAC: decodeHMAC32(t, v.paddedKeyTag)}, "")
				require.ErrorIs(t, err, ErrInvalidHMAC, "padded-key tag must be refused")
			}

			tampered := decodeHMAC32(t, v.hmac)
			tampered[31] ^= 1
			_, err = pw.VerifyHMAC(ctx, VerifyHMACArgs{EncryptionArgs: encArgs, Data: data, HMAC: tampered}, "")
			require.ErrorIs(t, err, ErrInvalidHMAC)
		})
	}
}

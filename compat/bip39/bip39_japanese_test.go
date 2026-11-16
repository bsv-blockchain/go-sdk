package bip39

import (
	_ "embed" // required so the embed directive loads the Japanese BIP-39 vectors
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/compat/bip39/wordlists"
)

// japaneseVectorFile is the BIP-39 Japanese test set. BIP-39 cites it for a
// passphrase that is not NFKD. The published sentences use ideographic spaces
// and composed kana; the wordlist and the seed are defined on the NFKD form.
//
// Source: https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json
//
//go:embed testdata/test_JP_BIP39.json
var japaneseVectorFile []byte

type japaneseVector struct {
	Entropy    string `json:"entropy"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
	Seed       string `json:"seed"`
}

func japaneseTestVectors(t *testing.T) []japaneseVector {
	t.Helper()

	var vectors []japaneseVector
	require.NoError(t, json.Unmarshal(japaneseVectorFile, &vectors))
	require.NotEmpty(t, vectors)

	return vectors
}

func TestNewSeedJapaneseVectors(t *testing.T) {
	for _, tt := range japaneseTestVectors(t) {
		t.Run(tt.Entropy, func(t *testing.T) {
			seed := NewSeed(tt.Mnemonic, tt.Passphrase)
			require.Equal(t, tt.Seed, hex.EncodeToString(seed))
		})
	}
}

func TestEntropyFromMnemonicJapaneseVectors(t *testing.T) {
	SetWordList(wordlists.Japanese)
	t.Cleanup(func() { SetWordList(wordlists.English) })

	for _, tt := range japaneseTestVectors(t) {
		t.Run(tt.Entropy, func(t *testing.T) {
			require.True(t, IsMnemonicValid(tt.Mnemonic))

			entropy, err := EntropyFromMnemonic(tt.Mnemonic)
			require.NoError(t, err)
			require.Equal(t, tt.Entropy, hex.EncodeToString(entropy))

			seed, err := NewSeedWithErrorChecking(tt.Mnemonic, tt.Passphrase)
			require.NoError(t, err)
			require.Equal(t, tt.Seed, hex.EncodeToString(seed))
		})
	}
}

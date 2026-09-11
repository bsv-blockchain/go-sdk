package wallet_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func kdProtocol() wallet.Protocol {
	return wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "testprotocol"}
}

func kdBadProtocol() wallet.Protocol {
	return wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "ab"}
}

func TestKeyDeriverDerivePublicKeyBranches(t *testing.T) {
	t.Parallel()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	kd := wallet.NewKeyDeriver(pk)

	t.Run("forSelf true", func(t *testing.T) {
		t.Parallel()
		pub, err := kd.DerivePublicKey(kdProtocol(), "k1", wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, true)
		require.NoError(t, err)
		require.NotNil(t, pub)
	})

	t.Run("counterparty other with nil key", func(t *testing.T) {
		t.Parallel()
		_, err := kd.DerivePublicKey(kdProtocol(), "k1", wallet.Counterparty{Type: wallet.CounterpartyTypeOther}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty public key required for other")
	})

	t.Run("uninitialized counterparty", func(t *testing.T) {
		t.Parallel()
		_, err := kd.DerivePublicKey(kdProtocol(), "k1", wallet.Counterparty{Type: wallet.CounterpartyUninitialized}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid counterparty")
	})

	t.Run("compute invoice number failure", func(t *testing.T) {
		t.Parallel()
		_, err := kd.DerivePublicKey(kdBadProtocol(), "k1", wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invoice number")
	})
}

func TestKeyDeriverDerivePrivateKeyBranches(t *testing.T) {
	t.Parallel()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	kd := wallet.NewKeyDeriver(pk)

	t.Run("counterparty other with nil key", func(t *testing.T) {
		t.Parallel()
		_, err := kd.DerivePrivateKey(kdProtocol(), "k1", wallet.Counterparty{Type: wallet.CounterpartyTypeOther})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty public key required for other")
	})

	t.Run("compute invoice number failure", func(t *testing.T) {
		t.Parallel()
		_, err := kd.DerivePrivateKey(kdBadProtocol(), "k1", wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
		require.Error(t, err)
	})
}

func TestKeyDeriverDeriveSymmetricKeyError(t *testing.T) {
	t.Parallel()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	other, err := ec.NewPrivateKey()
	require.NoError(t, err)
	kd := wallet.NewKeyDeriver(pk)

	_, err = kd.DeriveSymmetricKey(kdBadProtocol(), "k1", wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: other.PubKey(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to derive public key")
}

func TestKeyDeriverRevealSpecificSecretErrors(t *testing.T) {
	t.Parallel()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	other, err := ec.NewPrivateKey()
	require.NoError(t, err)
	kd := wallet.NewKeyDeriver(pk)

	t.Run("normalize counterparty failure", func(t *testing.T) {
		t.Parallel()
		_, err := kd.RevealSpecificSecret(wallet.Counterparty{Type: wallet.CounterpartyTypeOther}, kdProtocol(), "k1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to normalize counterparty")
	})

	t.Run("compute invoice number failure", func(t *testing.T) {
		t.Parallel()
		_, err := kd.RevealSpecificSecret(
			wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: other.PubKey()},
			kdBadProtocol(), "k1",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invoice number")
	})
}

func TestKeyDeriverRevealCounterpartySecretNormalizeError(t *testing.T) {
	t.Parallel()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	kd := wallet.NewKeyDeriver(pk)

	_, err = kd.RevealCounterpartySecret(wallet.Counterparty{Type: wallet.CounterpartyUninitialized})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to normalize counterparty")
}

// TestRevealSpecificKeyLinkageCounterpartyBranches covers getCounterpartyPublicKey's
// "other with nil key" and "uninitialized" branches via RevealSpecificKeyLinkage.
func TestRevealSpecificKeyLinkageCounterpartyBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifier, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
		Type:       wallet.ProtoWalletArgsTypePrivateKey,
		PrivateKey: pk,
	})
	require.NoError(t, err)

	t.Run("other with nil key", func(t *testing.T) {
		t.Parallel()
		_, err := w.RevealSpecificKeyLinkage(ctx, wallet.RevealSpecificKeyLinkageArgs{
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther},
			Verifier:     verifier.PubKey(),
			ProtocolID:   kdProtocol(),
			KeyID:        "k1",
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "counterparty public key is required")
	})

	t.Run("uninitialized", func(t *testing.T) {
		t.Parallel()
		_, err := w.RevealSpecificKeyLinkage(ctx, wallet.RevealSpecificKeyLinkageArgs{
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyUninitialized},
			Verifier:     verifier.PubKey(),
			ProtocolID:   kdProtocol(),
			KeyID:        "k1",
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid counterparty type")
	})
}

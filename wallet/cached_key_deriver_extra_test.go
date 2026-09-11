package wallet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestCachedKeyDeriverDeriveErrors verifies that derivation errors from the
// underlying KeyDeriver are propagated (and wrapped) by CachedKeyDeriver.
func TestCachedKeyDeriverDeriveErrors(t *testing.T) {
	t.Parallel()

	rootKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	other, err := ec.NewPrivateKey()
	require.NoError(t, err)

	cached := NewCachedKeyDeriver(rootKey, 0)

	// A protocol name shorter than 5 characters makes computeInvoiceNumber fail.
	badProtocol := Protocol{SecurityLevel: SecurityLevelSilent, Protocol: "ab"}
	self := Counterparty{Type: CounterpartyTypeSelf}
	otherCP := Counterparty{Type: CounterpartyTypeOther, Counterparty: other.PubKey()}

	t.Run("DerivePublicKey error", func(t *testing.T) {
		t.Parallel()
		_, err := cached.DerivePublicKey(badProtocol, "k1", self, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive public key")
	})

	t.Run("DerivePrivateKey error", func(t *testing.T) {
		t.Parallel()
		_, err := cached.DerivePrivateKey(badProtocol, "k1", self)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive private key")
	})

	t.Run("RevealSpecificSecret error", func(t *testing.T) {
		t.Parallel()
		_, err := cached.RevealSpecificSecret(otherCP, badProtocol, "k1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to reveal specific secret")
	})
}

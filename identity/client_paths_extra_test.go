package identity

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
)

// issueRealCert creates a subject wallet and issues a real, verifiable
// certificate so PubliclyRevealAttributes gets past certificate verification.
func issueRealCert(t *testing.T) (*wallet.TestWallet, *wallet.Certificate, []CertificateFieldNameUnder50Bytes) {
	t.Helper()
	subjectPrivKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	subjectWallet := wallet.NewTestWallet(t, subjectPrivKey)

	certMgr := testcertificates.NewManager(t, subjectWallet)
	issued := certMgr.CertificateForTest().
		WithType("identity-broadcast-cert").
		WithFieldValue("userName", "Alice").
		Issue()
	require.NotNil(t, issued.WalletCert)

	return subjectWallet, issued.WalletCert, []CertificateFieldNameUnder50Bytes{"userName"}
}

// TestPubliclyRevealAttributesReachesBroadcast drives the real client all the
// way through transaction creation, network detection, and broadcast. The
// broadcast itself fails because outbound HTTP is disabled, exercising the
// mainnet/testnet broadcaster branches and the Broadcast call.
func TestPubliclyRevealAttributesReachesBroadcast(t *testing.T) {
	tests := []struct {
		name    string
		network string
	}{
		{"testnet", "testnet"},
		{"mainnet", "mainnet"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tu.WithUnreachableTransport(t)
			subjectWallet, cert, fields := issueRealCert(t)
			subjectWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
				Tx: tu.SingleOutputBeef(t, &script.Script{}),
			})
			subjectWallet.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{Network: wallet.Network(tc.network)})

			client, err := NewClient(subjectWallet, nil, "")
			require.NoError(t, err)

			success, failure, err := client.PubliclyRevealAttributes(context.Background(), cert, fields)
			require.NoError(t, err)
			require.Nil(t, success)
			require.NotNil(t, failure)
		})
	}
}

// TestPubliclyRevealAttributesSimpleBroadcastFailure covers the Simple wrapper's
// broadcast-failure return branch.
func TestPubliclyRevealAttributesSimpleBroadcastFailure(t *testing.T) {
	tu.WithUnreachableTransport(t)
	subjectWallet, cert, fields := issueRealCert(t)
	subjectWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Tx: tu.SingleOutputBeef(t, &script.Script{}),
	})
	subjectWallet.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{Network: "testnet"})

	client, err := NewClient(subjectWallet, nil, "")
	require.NoError(t, err)

	txid, err := client.PubliclyRevealAttributesSimple(context.Background(), cert, fields)
	require.Error(t, err)
	require.Empty(t, txid)
	require.Contains(t, err.Error(), "broadcast failed")
}

// TestPubliclyRevealAttributesNilTx covers the branch where CreateAction returns
// a result without a transaction.
func TestPubliclyRevealAttributesNilTx(t *testing.T) {
	subjectWallet, cert, fields := issueRealCert(t)
	subjectWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{Tx: nil})

	client, err := NewClient(subjectWallet, nil, "")
	require.NoError(t, err)

	_, _, err = client.PubliclyRevealAttributes(context.Background(), cert, fields)
	require.Error(t, err)
	require.Contains(t, err.Error(), "public reveal failed")
}

// TestPubliclyRevealAttributesInvalidBEEF covers the branch where the created
// transaction bytes cannot be parsed as BEEF.
func TestPubliclyRevealAttributesInvalidBEEF(t *testing.T) {
	subjectWallet, cert, fields := issueRealCert(t)
	subjectWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{Tx: []byte("invalid-beef")})

	client, err := NewClient(subjectWallet, nil, "")
	require.NoError(t, err)

	_, _, err = client.PubliclyRevealAttributes(context.Background(), cert, fields)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create transaction from BEEF")
}

// TestPubliclyRevealAttributesGetNetworkError covers the branch where network
// detection fails after a transaction is created.
func TestPubliclyRevealAttributesGetNetworkError(t *testing.T) {
	subjectWallet, cert, fields := issueRealCert(t)
	subjectWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Tx: tu.SingleOutputBeef(t, &script.Script{}),
	})
	subjectWallet.OnGetNetwork().ReturnError(fmt.Errorf("network unavailable"))

	client, err := NewClient(subjectWallet, nil, "")
	require.NoError(t, err)

	_, _, err = client.PubliclyRevealAttributes(context.Background(), cert, fields)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to get network")
}

// TestPubliclyRevealAttributesVerifyFailure covers the branch where a tampered
// certificate fails verification.
func TestPubliclyRevealAttributesVerifyFailure(t *testing.T) {
	subjectWallet, cert, fields := issueRealCert(t)
	// Replace the valid signature with an unrelated one so verification fails.
	cert.Signature = &ec.Signature{R: big.NewInt(2), S: big.NewInt(3)}

	client, err := NewClient(subjectWallet, nil, "")
	require.NoError(t, err)

	_, _, err = client.PubliclyRevealAttributes(context.Background(), cert, fields)
	require.Error(t, err)
}

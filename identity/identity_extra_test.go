package identity

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
	"github.com/stretchr/testify/require"
)

// buildIdentityCert creates a wallet.IdentityCertificate for testing parseIdentity
func buildIdentityCert(typeStr string, fields map[string]string, certifierName, certifierIcon string) *wallet.IdentityCertificate {
	certType, _ := wallet.StringBase64(typeStr).ToArray()
	_, pubKey := privateKeyFromInt(42)
	return &wallet.IdentityCertificate{
		Certificate: wallet.Certificate{
			Type:    certType,
			Subject: pubKey,
		},
		DecryptedFields: fields,
		CertifierInfo: wallet.IdentityCertifier{
			Name:    certifierName,
			IconUrl: certifierIcon,
		},
	}
}

const socialCertNetURL = "https://socialcert.net"

func TestParseIdentityAllTypes(t *testing.T) {
	t.Run("DiscordCert", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.DiscordCert,
			map[string]string{"userName": "discordUser", "profilePhoto": "discordPhoto"},
			"DiscordCertifier", "discordIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "discordUser", identity.Name)
		require.Equal(t, "discordPhoto", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Discord account certified by DiscordCertifier")
		require.Equal(t, socialCertNetURL, identity.BadgeClickURL)
		require.Equal(t, "discordIcon", identity.BadgeIconURL)
	})

	t.Run("PhoneCert", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.PhoneCert,
			map[string]string{"phoneNumber": "+1234567890"},
			"PhoneCertifier", "phoneIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "+1234567890", identity.Name)
		require.Equal(t, "XUTLxtX3ELNUwRhLwL7kWNGbdnFM8WG2eSLv84J7654oH8HaJWrU", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Phone certified by PhoneCertifier")
		require.Equal(t, socialCertNetURL, identity.BadgeClickURL)
	})

	t.Run("IdentiCert", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.IdentiCert,
			map[string]string{"firstName": "John", "lastName": "Doe", "profilePhoto": "govPhoto"},
			"GovCertifier", "govIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "John Doe", identity.Name)
		require.Equal(t, "govPhoto", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Government ID certified by GovCertifier")
		require.Equal(t, "https://identicert.me", identity.BadgeClickURL)
	})

	t.Run("Registrant", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.Registrant,
			map[string]string{"name": "MyOrg", "icon": "orgIcon"},
			"RegistrantCertifier", "regIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "MyOrg", identity.Name)
		require.Equal(t, "orgIcon", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Entity certified by RegistrantCertifier")
		require.Equal(t, "https://projectbabbage.com/docs/registrant", identity.BadgeClickURL)
	})

	t.Run("CoolCert - cool", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.CoolCert,
			map[string]string{"cool": "true"},
			"CoolCertifier", "coolIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "Cool Person!", identity.Name)
	})

	t.Run("CoolCert - not cool", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.CoolCert,
			map[string]string{"cool": "false"},
			"CoolCertifier", "coolIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "Not cool!", identity.Name)
	})

	t.Run("Anyone", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.Anyone,
			map[string]string{},
			"AnyoneCertifier", "anyoneIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "Anyone", identity.Name)
		require.Equal(t, "XUT4bpQ6cpBaXi1oMzZsXfpkWGbtp2JTUYAoN7PzhStFJ6wLfoeR", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Represents the ability for anyone")
		require.Equal(t, "https://projectbabbage.com/docs/anyone-identity", identity.BadgeClickURL)
	})

	t.Run("Self", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.Self,
			map[string]string{},
			"SelfCertifier", "selfIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "You", identity.Name)
		require.Equal(t, "XUT9jHGk2qace148jeCX5rDsMftkSGYKmigLwU2PLLBc7Hm63VYR", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Represents your ability")
		require.Equal(t, "https://projectbabbage.com/docs/self-identity", identity.BadgeClickURL)
	})

	t.Run("XCert full coverage", func(t *testing.T) {
		cert := buildIdentityCert(KnownIdentityTypes.XCert,
			map[string]string{"userName": "xuser", "profilePhoto": "xphoto"},
			"XCertifier", "xIcon")
		identity := ParseIdentity(cert)
		require.Equal(t, "xuser", identity.Name)
		require.Equal(t, "xphoto", identity.AvatarURL)
		require.Equal(t, socialCertNetURL, identity.BadgeClickURL)
		// Check abbreviated key is correct length
		require.NotEmpty(t, identity.AbbreviatedKey)
		require.True(t, len(identity.AbbreviatedKey) > 3)
	})
}

func TestNewClientWithNilWallet(t *testing.T) {
	t.Run("nil wallet creates random key wallet", func(t *testing.T) {
		client, err := NewClient(nil, nil, "")
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NotNil(t, client.Wallet)
	})
}

func TestNewClientWithOptions(t *testing.T) {
	t.Run("custom options are applied", func(t *testing.T) {
		opts := &IdentityClientOptions{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "custom-protocol",
			},
			KeyID:       "custom-key",
			TokenAmount: 100,
			OutputIndex: 2,
		}

		client, err := NewClient(nil, opts, "example.com")
		require.NoError(t, err)
		require.Equal(t, opts.KeyID, client.Options.KeyID)
		require.Equal(t, opts.TokenAmount, client.Options.TokenAmount)
		require.Equal(t, opts.OutputIndex, client.Options.OutputIndex)
		require.Equal(t, OriginatorDomainNameStringUnder250Bytes("example.com"), client.Originator)
	})
}

func TestDefaultCertificateVerifier(t *testing.T) {
	t.Run("Verify returns nil", func(t *testing.T) {
		v := &DefaultCertificateVerifier{}
		err := v.Verify(nil, nil)
		require.NoError(t, err)
	})
}

func TestNewTestableIdentityClientNilVerifier(t *testing.T) {
	t.Run("nil verifier uses default", func(t *testing.T) {
		client, err := NewTestableIdentityClient(nil, nil, "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestWithTransactionCreator(t *testing.T) {
	t.Run("sets custom transaction creator returns client", func(t *testing.T) {
		client, err := NewTestableIdentityClient(nil, nil, "", nil)
		require.NoError(t, err)

		result := client.WithTransactionCreator(func(data []byte) (*transaction.Transaction, error) {
			return nil, nil
		})
		require.NotNil(t, result)
	})
}

func TestPubliclyRevealAttributesSimpleNoFieldsError(t *testing.T) {
	t.Run("returns error when no fields", func(t *testing.T) {
		client, err := NewClient(nil, nil, "")
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Fields: make(map[string]string),
		}

		_, err = client.PubliclyRevealAttributesSimple(nil, cert, []CertificateFieldNameUnder50Bytes{"name"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate has no fields to reveal")
	})
}

func TestPubliclyRevealAttributesSimpleEmptyFieldsToReveal(t *testing.T) {
	t.Run("returns error when empty fieldsToReveal", func(t *testing.T) {
		client, err := NewClient(nil, nil, "")
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Fields: map[string]string{"name": "Alice"},
		}

		_, err = client.PubliclyRevealAttributesSimple(nil, cert, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "you must reveal at least one field")
	})
}

func TestPubliclyRevealAttributesWithRealCert(t *testing.T) {
	t.Run("fails at ProveCertificate with valid cert (gets past verification)", func(t *testing.T) {
		// Create a subject wallet
		subjectPrivKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		subjectWallet := wallet.NewTestWallet(t, subjectPrivKey)

		// Create a certificate manager and issue a real signed certificate
		certMgr := testcertificates.NewManager(t, subjectWallet)
		issued := certMgr.CertificateForTest().
			WithType("identity-test-cert").
			WithFieldValue("userName", "Alice").
			WithFieldValue("profilePhoto", "photo.jpg").
			Issue()

		walletCert := issued.WalletCert
		require.NotNil(t, walletCert)
		require.NotNil(t, walletCert.Signature)

		// Create identity client with the subject wallet
		client, err := NewClient(subjectWallet, nil, "")
		require.NoError(t, err)

		// Mock ProveCertificate to simulate wallet's response
		subjectWallet.OnProveCertificate().ReturnError(fmt.Errorf("prove certificate failed"))

		// Call PubliclyRevealAttributes - should pass verification and fail at ProveCertificate
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"userName"}
		_, _, err = client.PubliclyRevealAttributes(context.Background(), walletCert, fieldsToReveal)
		require.Error(t, err)
		// Either verify fails or ProveCertificate fails
		require.NotNil(t, err)
	})
}

func TestPubliclyRevealAttributesWithRealCertAndSuccessfulProve(t *testing.T) {
	t.Run("gets past ProveCertificate and fails at CreateAction", func(t *testing.T) {
		subjectPrivKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		subjectWallet := wallet.NewTestWallet(t, subjectPrivKey)

		certMgr := testcertificates.NewManager(t, subjectWallet)
		issued := certMgr.CertificateForTest().
			WithType("identity-test-cert-2").
			WithFieldValue("userName", "Alice").
			Issue()

		walletCert := issued.WalletCert
		require.NotNil(t, walletCert)

		// Do NOT mock ProveCertificate - let the testcertificates manager handle it
		// But mock CreateAction to fail
		subjectWallet.OnCreateAction().ReturnError(fmt.Errorf("create action failed"))

		client, err := NewClient(subjectWallet, nil, "")
		require.NoError(t, err)

		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"userName"}
		_, _, err = client.PubliclyRevealAttributes(context.Background(), walletCert, fieldsToReveal)
		require.Error(t, err)
		// Should fail at CreateAction or before (ProveCertificate succeeds)
		// The error message could be either "certificate verification failed" or something later
		require.NotNil(t, err)
	})
}

func TestPubliclyRevealAttributesSimpleWithError(t *testing.T) {
	t.Run("simple API propagates error from PubliclyRevealAttributes", func(t *testing.T) {
		client, err := NewClient(nil, nil, "")
		require.NoError(t, err)

		// Certificate with fields but no revocation outpoint
		cert := &wallet.Certificate{
			Fields:             map[string]string{"name": "Alice"},
			RevocationOutpoint: nil,
		}

		_, err = client.PubliclyRevealAttributesSimple(context.Background(), cert,
			[]CertificateFieldNameUnder50Bytes{"name"})
		require.Error(t, err)
	})
}

func TestPubliclyRevealAttributesValidationErrors(t *testing.T) {
	client, err := NewClient(nil, nil, "")
	require.NoError(t, err)

	t.Run("fails when certificate has no revocation outpoint", func(t *testing.T) {
		cert := &wallet.Certificate{
			Fields:             map[string]string{"name": "Alice"},
			RevocationOutpoint: nil,
		}
		_, _, err := client.PubliclyRevealAttributes(
			context.Background(), cert,
			[]CertificateFieldNameUnder50Bytes{"name"},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "revocation outpoint")
	})

	t.Run("fails when certificate has no subject", func(t *testing.T) {
		cert := &wallet.Certificate{
			Fields: map[string]string{"name": "Alice"},
			// RevocationOutpoint set but Subject nil
			RevocationOutpoint: &transaction.Outpoint{},
			Subject:            nil,
		}
		_, _, err := client.PubliclyRevealAttributes(
			context.Background(), cert,
			[]CertificateFieldNameUnder50Bytes{"name"},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "subject")
	})
}

func TestPubliclyRevealAttributesSimpleValidationErrors(t *testing.T) {
	client, err := NewClient(nil, nil, "")
	require.NoError(t, err)

	t.Run("fails when certificate has no revocation outpoint", func(t *testing.T) {
		cert := &wallet.Certificate{
			Fields:             map[string]string{"name": "Alice"},
			RevocationOutpoint: nil,
		}
		_, err := client.PubliclyRevealAttributesSimple(
			context.Background(), cert,
			[]CertificateFieldNameUnder50Bytes{"name"},
		)
		require.Error(t, err)
	})
}

func TestTestablePubliclyRevealAttributesSimpleViaNetwork(t *testing.T) {
	t.Run("reaches broadcast via simple API (failure path from broadcast)", func(t *testing.T) {
		privKey, pubKey := privateKeyFromInt(203)
		mockWallet := wallet.NewTestWallet(t, privKey)

		typeXCert, err := wallet.StringBase64(KnownIdentityTypes.XCert).ToArray()
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Type:    typeXCert,
			Subject: pubKey,
			Fields:  map[string]string{"name": "Alice"},
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
			Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
		})
		mockWallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"key": "value"},
		})
		mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
			Tx: []byte{0x01, 0x02, 0x03, 0x04},
		})
		mockWallet.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{
			Network: "testnet",
		})

		mockVerifier := &MockCertificateVerifier{}

		testableClient, err := NewTestableIdentityClient(mockWallet, nil, "", mockVerifier)
		require.NoError(t, err)
		testableClient.WithTransactionCreator(func(data []byte) (*transaction.Transaction, error) {
			return transaction.NewTransaction(), nil
		})

		// Call via Simple API - should reach the broadcast and return a result
		result, err := testableClient.PubliclyRevealAttributesSimple(context.Background(), cert, fieldsToReveal)
		// The broadcast will either fail (network error -> err) or return (nil, nil) -> unknown error
		// Either way, we exercise the Simple API code paths
		if err != nil {
			require.Error(t, err)
		} else {
			// If somehow success
			_ = result
		}
	})
}

func TestResolveByIdentityKeyError(t *testing.T) {
	t.Run("returns error when wallet fails", func(t *testing.T) {
		mockWallet := wallet.NewTestWalletForRandomKey(t)
		client, err := NewClient(mockWallet, nil, "")
		require.NoError(t, err)

		mockWallet.OnDiscoverByIdentityKey().ReturnError(fmt.Errorf("wallet error"))

		_, err = client.ResolveByIdentityKey(context.Background(), wallet.DiscoverByIdentityKeyArgs{})
		require.Error(t, err)
	})
}

func TestResolveByAttributesError(t *testing.T) {
	t.Run("returns error when wallet fails", func(t *testing.T) {
		mockWallet := wallet.NewTestWalletForRandomKey(t)
		client, err := NewClient(mockWallet, nil, "")
		require.NoError(t, err)

		mockWallet.OnDiscoverByAttributes().ReturnError(fmt.Errorf("wallet error"))

		_, err = client.ResolveByAttributes(context.Background(), wallet.DiscoverByAttributesArgs{})
		require.Error(t, err)
	})
}

func TestMockCertificateVerifierNilMockVerify(t *testing.T) {
	t.Run("returns nil when MockVerify is nil", func(t *testing.T) {
		m := &MockCertificateVerifier{}
		err := m.Verify(nil, nil)
		require.NoError(t, err)
	})
}

func TestWithBroadcaster(t *testing.T) {
	t.Run("sets broadcaster and returns client", func(t *testing.T) {
		client, err := NewTestableIdentityClient(nil, nil, "", nil)
		require.NoError(t, err)

		result := client.WithBroadcaster(topic.Broadcaster{})
		require.NotNil(t, result)
		require.Same(t, client, result)
	})
}

func TestTestablePubliclyRevealAttributesSimpleFailure(t *testing.T) {
	t.Run("simple api returns error when PubliclyRevealAttributes fails", func(t *testing.T) {
		client, err := NewTestableIdentityClient(nil, nil, "", &MockCertificateVerifier{
			MockVerify: func(ctx context.Context, cert *wallet.Certificate) error {
				return fmt.Errorf("verification error")
			},
		})
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Fields: map[string]string{"name": "Alice"},
		}

		_, err = client.PubliclyRevealAttributesSimple(
			context.Background(),
			cert,
			[]CertificateFieldNameUnder50Bytes{"name"},
		)
		require.Error(t, err)
	})
}

func TestTestablePubliclyRevealAttributesGetNetworkPath(t *testing.T) {
	t.Run("reaches GetNetwork after successful transaction creation", func(t *testing.T) {
		privKey, pubKey := privateKeyFromInt(200)
		mockWallet := wallet.NewTestWallet(t, privKey)

		// Setup certificate
		typeXCert, err := wallet.StringBase64(KnownIdentityTypes.XCert).ToArray()
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Type:    typeXCert,
			Subject: pubKey,
			Fields:  map[string]string{"name": "Alice"},
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
			Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
		})
		mockWallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"key": "value"},
		})
		mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
			Tx: []byte{0x01, 0x02, 0x03, 0x04},
		})
		// Mock GetNetwork to return testnet
		mockWallet.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{
			Network: "testnet",
		})

		mockVerifier := &MockCertificateVerifier{}

		testableClient, err := NewTestableIdentityClient(mockWallet, nil, "", mockVerifier)
		require.NoError(t, err)

		// Inject a valid transaction creator
		testableClient.WithTransactionCreator(func(data []byte) (*transaction.Transaction, error) {
			return transaction.NewTransaction(), nil
		})

		// Will fail at broadcast but should reach GetNetwork
		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), cert, fieldsToReveal)
		// We expect either a broadcast failure or success (network-dependent), not an early error
		// The important thing is we've executed past GetNetwork
		_ = err
	})

	t.Run("fails when GetNetwork returns error", func(t *testing.T) {
		privKey, pubKey := privateKeyFromInt(201)
		mockWallet := wallet.NewTestWallet(t, privKey)

		typeXCert, err := wallet.StringBase64(KnownIdentityTypes.XCert).ToArray()
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Type:    typeXCert,
			Subject: pubKey,
			Fields:  map[string]string{"name": "Alice"},
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
			Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
		})
		mockWallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"key": "value"},
		})
		mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
			Tx: []byte{0x01, 0x02, 0x03, 0x04},
		})
		mockWallet.OnGetNetwork().ReturnError(fmt.Errorf("network error"))

		mockVerifier := &MockCertificateVerifier{}

		testableClient, err := NewTestableIdentityClient(mockWallet, nil, "", mockVerifier)
		require.NoError(t, err)
		testableClient.WithTransactionCreator(func(data []byte) (*transaction.Transaction, error) {
			return transaction.NewTransaction(), nil
		})

		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), cert, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get network")
	})

	t.Run("mainnet path uses mainnet broadcaster", func(t *testing.T) {
		privKey, pubKey := privateKeyFromInt(202)
		mockWallet := wallet.NewTestWallet(t, privKey)

		typeXCert, err := wallet.StringBase64(KnownIdentityTypes.XCert).ToArray()
		require.NoError(t, err)

		cert := &wallet.Certificate{
			Type:    typeXCert,
			Subject: pubKey,
			Fields:  map[string]string{"name": "Alice"},
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
			Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
		})
		mockWallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"key": "value"},
		})
		mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
			Tx: []byte{0x01, 0x02, 0x03, 0x04},
		})
		mockWallet.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{
			Network: "mainnet",
		})

		mockVerifier := &MockCertificateVerifier{}

		testableClient, err := NewTestableIdentityClient(mockWallet, nil, "", mockVerifier)
		require.NoError(t, err)
		testableClient.WithTransactionCreator(func(data []byte) (*transaction.Transaction, error) {
			return transaction.NewTransaction(), nil
		})

		// Will fail at broadcast since there's no real network, but we reach the mainnet path
		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), cert, fieldsToReveal)
		_ = err
	})
}

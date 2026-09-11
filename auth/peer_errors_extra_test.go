package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
)

var errBoom = errors.New("boom")

// failingOnDataTransport is a transport whose OnData always fails, used to
// exercise the peer's Start error handling.
type failingOnDataTransport struct{}

func (failingOnDataTransport) Send(context.Context, *auth.AuthMessage) error { return nil }

func (failingOnDataTransport) OnData(func(context.Context, *auth.AuthMessage) error) error {
	return errBoom
}

func (failingOnDataTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return nil, errBoom
}

// acceptTransport accepts every Send without ever delivering a response, so a
// peer that initiates a handshake over it will time out waiting for a reply.
type acceptTransport struct {
	handler func(context.Context, *auth.AuthMessage) error
}

func (a *acceptTransport) Send(context.Context, *auth.AuthMessage) error { return nil }

func (a *acceptTransport) OnData(cb func(context.Context, *auth.AuthMessage) error) error {
	a.handler = cb
	return nil
}

func (a *acceptTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return a.handler, nil
}

// newHandlerPeer builds a peer wired to a plain MockTransport and returns the
// registered incoming-message handler so tests can feed it crafted messages
// directly, exercising the internal message handlers.
func newHandlerPeer(t *testing.T) (*wallet.TestWallet, auth.SessionManager, func(context.Context, *auth.AuthMessage) error) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(bobPrivKeyHex)
	require.NoError(t, err)

	w := wallet.NewTestWallet(t, priv, wallet.WithTestWalletName("receiver"))
	tr := NewMockTransport("receiver")
	sm := auth.NewSessionManager()
	// The registered handler closes over the peer, keeping it alive.
	auth.NewPeer(&auth.PeerOptions{
		Wallet:         w,
		Transport:      tr,
		SessionManager: sm,
	})

	handler, err := tr.GetRegisteredOnData()
	require.NoError(t, err)
	return w, sm, handler
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestNewPeerAndStartErrorPaths(t *testing.T) {
	t.Run("NewPeer applies configured CertificatesToRequest", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)

		certReq := &utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{priv.PubKey()},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				wallet.CertificateType{}: []string{emailField},
			},
		}

		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:                w,
			Transport:             NewMockTransport("test"),
			CertificatesToRequest: certReq,
		})
		assert.Same(t, certReq, peer.CertificatesToRequest)
	})

	t.Run("NewPeer tolerates transport that fails to register handler", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)

		// Must not panic even though Start fails internally.
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:    w,
			Transport: failingOnDataTransport{},
		})
		require.NotNil(t, peer)
	})

	t.Run("Start returns error when transport OnData fails", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)

		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:    w,
			Transport: failingOnDataTransport{},
		})
		err = peer.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to register message handler")
	})
}

func TestHandleIncomingMessageBranches(t *testing.T) {
	_, _, handler := newHandlerPeer(t)
	ctx := t.Context()

	priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
	require.NoError(t, err)

	t.Run("nil message is rejected", func(t *testing.T) {
		err := handler(ctx, nil)
		require.ErrorIs(t, err, auth.ErrInvalidMessage)
	})

	t.Run("unsupported version is rejected", func(t *testing.T) {
		err := handler(ctx, &auth.AuthMessage{
			Version:     "9.9",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: priv.PubKey(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid or unsupported message auth version")
	})

	t.Run("unknown message type is rejected", func(t *testing.T) {
		err := handler(ctx, &auth.AuthMessage{
			Version:     auth.AUTH_VERSION,
			MessageType: auth.MessageType("bogus"),
			IdentityKey: priv.PubKey(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown message type")
	})
}

func TestHandleInitialRequestErrorPaths(t *testing.T) {
	sender, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
	require.NoError(t, err)
	senderPub := sender.PubKey()

	validNonce := string(utils.RandomBase64(32))

	t.Run("empty initial nonce is rejected", func(t *testing.T) {
		_, _, handler := newHandlerPeer(t)
		err := handler(t.Context(), &auth.AuthMessage{
			Version:      auth.AUTH_VERSION,
			MessageType:  auth.MessageTypeInitialRequest,
			IdentityKey:  senderPub,
			InitialNonce: "",
		})
		require.ErrorIs(t, err, auth.ErrInvalidNonce)
	})

	t.Run("create session nonce failure", func(t *testing.T) {
		w, _, handler := newHandlerPeer(t)
		w.OnCreateHMAC().ReturnError(errBoom)
		err := handler(t.Context(), &auth.AuthMessage{
			Version:      auth.AUTH_VERSION,
			MessageType:  auth.MessageTypeInitialRequest,
			IdentityKey:  senderPub,
			InitialNonce: validNonce,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create session nonce")
	})

	t.Run("get identity key failure", func(t *testing.T) {
		w, _, handler := newHandlerPeer(t)
		w.OnGetPublicKey().ReturnError(errBoom)
		err := handler(t.Context(), &auth.AuthMessage{
			Version:      auth.AUTH_VERSION,
			MessageType:  auth.MessageTypeInitialRequest,
			IdentityKey:  senderPub,
			InitialNonce: validNonce,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get identity key")
	})

	t.Run("undecodable initial nonce is rejected", func(t *testing.T) {
		_, _, handler := newHandlerPeer(t)
		err := handler(t.Context(), &auth.AuthMessage{
			Version:      auth.AUTH_VERSION,
			MessageType:  auth.MessageTypeInitialRequest,
			IdentityKey:  senderPub,
			InitialNonce: "@@@not-base64@@@",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode initial nonce")
	})

	t.Run("sign initial response failure", func(t *testing.T) {
		w, _, handler := newHandlerPeer(t)
		w.OnCreateSignature().ReturnError(errBoom)
		err := handler(t.Context(), &auth.AuthMessage{
			Version:      auth.AUTH_VERSION,
			MessageType:  auth.MessageTypeInitialRequest,
			IdentityKey:  senderPub,
			InitialNonce: validNonce,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign initial response")
	})
}

// nonGeneralOrInitialResponse groups the message types whose handlers share the
// nonce-verify / session-lookup / signature-parse error scaffolding.
func authMessageTypesForErrors() []auth.MessageType {
	return []auth.MessageType{
		auth.MessageTypeInitialResponse,
		auth.MessageTypeCertificateRequest,
		auth.MessageTypeCertificateResponse,
		auth.MessageTypeGeneral,
	}
}

func TestHandleMessageNonceErrors(t *testing.T) {
	sender, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
	require.NoError(t, err)
	senderPub := sender.PubKey()

	t.Run("undecodable your-nonce fails validation", func(t *testing.T) {
		_, _, handler := newHandlerPeer(t)
		for _, mt := range authMessageTypesForErrors() {
			t.Run(string(mt), func(t *testing.T) {
				err := handler(t.Context(), &auth.AuthMessage{
					Version:     auth.AUTH_VERSION,
					MessageType: mt,
					IdentityKey: senderPub,
					YourNonce:   "@@@not-base64@@@",
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to validate nonce")
			})
		}
	})

	t.Run("well-formed but foreign nonce is invalid", func(t *testing.T) {
		w, _, handler := newHandlerPeer(t)
		// Force VerifyHMAC to report a mismatch without error.
		w.OnVerifyHMAC().ReturnSuccess(&wallet.VerifyHMACResult{Valid: false})
		for _, mt := range authMessageTypesForErrors() {
			t.Run(string(mt), func(t *testing.T) {
				err := handler(t.Context(), &auth.AuthMessage{
					Version:     auth.AUTH_VERSION,
					MessageType: mt,
					IdentityKey: senderPub,
					YourNonce:   string(utils.RandomBase64(32)),
				})
				require.ErrorIs(t, err, auth.ErrInvalidNonce)
			})
		}
	})

	t.Run("missing session is rejected", func(t *testing.T) {
		w, _, handler := newHandlerPeer(t)
		// A nonce created by this wallet passes verification but no session exists.
		yourNonce, err := utils.CreateNonce(t.Context(), w, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
		require.NoError(t, err)
		for _, mt := range authMessageTypesForErrors() {
			t.Run(string(mt), func(t *testing.T) {
				err := handler(t.Context(), &auth.AuthMessage{
					Version:     auth.AUTH_VERSION,
					MessageType: mt,
					IdentityKey: senderPub,
					YourNonce:   yourNonce,
				})
				require.ErrorIs(t, err, auth.ErrSessionNotFound)
			})
		}
	})
}

func TestHandleMessageSignatureErrors(t *testing.T) {
	sender, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
	require.NoError(t, err)
	senderPub := sender.PubKey()

	t.Run("unparseable signature is rejected", func(t *testing.T) {
		w, sm, handler := newHandlerPeer(t)
		ctx := t.Context()
		sessionNonce, err := utils.CreateNonce(ctx, w, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
		require.NoError(t, err)
		require.NoError(t, sm.AddSession(&auth.PeerSession{
			SessionNonce:    sessionNonce,
			PeerNonce:       string(utils.RandomBase64(32)),
			PeerIdentityKey: senderPub,
			IsAuthenticated: true,
			LastUpdate:      time.Now().UnixMilli(),
		}))

		for _, mt := range authMessageTypesForErrors() {
			t.Run(string(mt), func(t *testing.T) {
				err := handler(ctx, &auth.AuthMessage{
					Version:      auth.AUTH_VERSION,
					MessageType:  mt,
					IdentityKey:  senderPub,
					YourNonce:    sessionNonce,
					InitialNonce: string(utils.RandomBase64(32)),
					Signature:    []byte("not-a-signature"),
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to parse signature")
			})
		}
	})

	// Helper that builds a peer with a session and a parseable signature, then
	// applies a VerifySignature override to exercise the verify branches.
	setup := func(t *testing.T) (auth.SessionManager, string, []byte, *wallet.TestWallet, func(context.Context, *auth.AuthMessage) error) {
		t.Helper()
		w, sm, handler := newHandlerPeer(t)
		ctx := t.Context()
		sessionNonce, err := utils.CreateNonce(ctx, w, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
		require.NoError(t, err)
		require.NoError(t, sm.AddSession(&auth.PeerSession{
			SessionNonce:    sessionNonce,
			PeerNonce:       string(utils.RandomBase64(32)),
			PeerIdentityKey: senderPub,
			IsAuthenticated: true,
			LastUpdate:      time.Now().UnixMilli(),
		}))

		sigRes, err := w.CreateSignature(ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: auth.AUTH_PROTOCOL_ID},
				KeyID:        "x",
				Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
			},
			Data: []byte("dummy"),
		}, "")
		require.NoError(t, err)
		return sm, sessionNonce, sigRes.Signature.Serialize(), w, handler
	}

	t.Run("verify signature error", func(t *testing.T) {
		_, sessionNonce, validSig, w, handler := setup(t)
		ctx := t.Context()
		w.OnVerifySignature().ReturnError(errBoom)
		for _, mt := range authMessageTypesForErrors() {
			t.Run(string(mt), func(t *testing.T) {
				err := handler(ctx, &auth.AuthMessage{
					Version:      auth.AUTH_VERSION,
					MessageType:  mt,
					IdentityKey:  senderPub,
					YourNonce:    sessionNonce,
					InitialNonce: string(utils.RandomBase64(32)),
					Signature:    validSig,
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), "unable to verify signature")
			})
		}
	})

	t.Run("invalid signature is rejected", func(t *testing.T) {
		_, sessionNonce, validSig, w, handler := setup(t)
		ctx := t.Context()
		w.OnVerifySignature().ReturnSuccess(&wallet.VerifySignatureResult{Valid: false})
		for _, mt := range authMessageTypesForErrors() {
			t.Run(string(mt), func(t *testing.T) {
				err := handler(ctx, &auth.AuthMessage{
					Version:      auth.AUTH_VERSION,
					MessageType:  mt,
					IdentityKey:  senderPub,
					YourNonce:    sessionNonce,
					InitialNonce: string(utils.RandomBase64(32)),
					Signature:    validSig,
				})
				require.ErrorIs(t, err, auth.ErrInvalidSignature)
			})
		}
	})
}

// buildInitialResponseWithCerts constructs a valid initial-response message from
// bob to alice carrying the supplied certificates, signed by bob's wallet so
// alice accepts it. It mirrors what a spec-compliant peer embeds in an initial
// response.
func buildInitialResponseWithCerts(
	t *testing.T,
	ctx context.Context,
	aliceWallet *wallet.TestWallet,
	aliceSM auth.SessionManager,
	alicePub *ec.PublicKey,
	bob *Actor,
	certs []*certificates.VerifiableCertificate,
) *auth.AuthMessage {
	t.Helper()

	aliceNonce, err := utils.CreateNonce(ctx, aliceWallet, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	require.NoError(t, err)
	bobNonce, err := utils.CreateNonce(ctx, bob.Wallet, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	require.NoError(t, err)

	require.NoError(t, aliceSM.AddSession(&auth.PeerSession{
		SessionNonce:    aliceNonce,
		PeerIdentityKey: bob.IdentityKey,
		LastUpdate:      time.Now().UnixMilli(),
	}))

	sigData := append(mustDecodeB64(t, aliceNonce), mustDecodeB64(t, bobNonce)...)
	// Bob signs the concatenated nonces addressed to Alice, matching what a peer
	// produces for an initial response.
	sigRes, err := bob.Wallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: auth.AUTH_PROTOCOL_ID},
			KeyID:        fmt.Sprintf("%s %s", aliceNonce, bobNonce),
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: alicePub},
		},
		Data: sigData,
	}, "")
	require.NoError(t, err)

	return &auth.AuthMessage{
		Version:      auth.AUTH_VERSION,
		MessageType:  auth.MessageTypeInitialResponse,
		IdentityKey:  bob.IdentityKey,
		Nonce:        bobNonce,
		YourNonce:    aliceNonce,
		InitialNonce: bobNonce,
		Signature:    sigRes.Signature.Serialize(),
		Certificates: certs,
	}
}

func TestHandleInitialResponseWithCertificates(t *testing.T) {
	// Bob only needs a wallet + certificate manager; his peer/transport are unused.
	bob := NewActor(t, bobName, bobPrivKeyHex)
	bobCertManager := testcertificates.NewManager(t, bob.Wallet)
	bobsCert := bobCertManager.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, bobName+"@example.com").
		Issue()

	certReq := &utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{bobsCert.WalletCert.Certifier},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			bobsCert.WalletCert.Type: []string{emailField},
		},
	}

	t.Run("valid embedded certificates authenticate the session", func(t *testing.T) {
		alicePriv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		aliceWallet := wallet.NewTestWallet(t, alicePriv, wallet.WithTestWalletName(aliceName))
		aliceTr := NewMockTransport(aliceName)
		aliceSM := auth.NewSessionManager()
		alice := auth.NewPeer(&auth.PeerOptions{
			Wallet:                aliceWallet,
			Transport:             aliceTr,
			SessionManager:        aliceSM,
			CertificatesToRequest: certReq,
		})
		handler, err := aliceTr.GetRegisteredOnData()
		require.NoError(t, err)

		var received bool
		alice.ListenForCertificatesReceived(func(_ context.Context, _ *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
			received = true
			assert.Len(t, certs, 1)
			return nil
		})

		verifiableCert := bobsCert.ToVerifiableCertificate(alicePriv.PubKey())
		ctx := t.Context()
		msg := buildInitialResponseWithCerts(t, ctx, aliceWallet, aliceSM, alicePriv.PubKey(), bob, []*certificates.VerifiableCertificate{verifiableCert})

		err = handler(ctx, msg)
		require.NoError(t, err)
		require.True(t, received, "certificate-received callback must fire")

		session, err := aliceSM.GetSession(msg.YourNonce)
		require.NoError(t, err)
		require.True(t, session.IsAuthenticated)
	})

	t.Run("invalid embedded certificates are rejected", func(t *testing.T) {
		alicePriv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		aliceWallet := wallet.NewTestWallet(t, alicePriv, wallet.WithTestWalletName(aliceName))
		aliceTr := NewMockTransport(aliceName)
		aliceSM := auth.NewSessionManager()
		auth.NewPeer(&auth.PeerOptions{
			Wallet:                aliceWallet,
			Transport:             aliceTr,
			SessionManager:        aliceSM,
			CertificatesToRequest: certReq,
		})
		handler, err := aliceTr.GetRegisteredOnData()
		require.NoError(t, err)

		verifiableCert := bobsCert.ToVerifiableCertificate(alicePriv.PubKey())
		verifiableCert.Signature = nil // break the certificate signature
		ctx := t.Context()
		msg := buildInitialResponseWithCerts(t, ctx, aliceWallet, aliceSM, alicePriv.PubKey(), bob, []*certificates.VerifiableCertificate{verifiableCert})

		err = handler(ctx, msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid certificates")
	})
}

func TestToPeerErrorPaths(t *testing.T) {
	t.Run("uses last interacted peer when identity key is nil", func(t *testing.T) {
		alice, bob := CreateActorsPair(t)
		bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })

		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000))

		// Second send with a nil identity key must reuse the last peer.
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, nil, 5000))
	})

	t.Run("get identity key failure", func(t *testing.T) {
		alice, bob := CreateActorsPair(t)
		bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000))

		alice.Wallet.OnGetPublicKey().ReturnError(errBoom)
		err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get identity key")
	})

	t.Run("sign message failure", func(t *testing.T) {
		alice, bob := CreateActorsPair(t)
		bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000))

		alice.Wallet.OnCreateSignature().ReturnError(errBoom)
		err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign message")
	})
}

func TestInitiateHandshakeErrorPaths(t *testing.T) {
	bob, err := ec.PrivateKeyFromHex(bobPrivKeyHex)
	require.NoError(t, err)
	bobPub := bob.PubKey()

	newAcceptPeer := func(t *testing.T) *auth.Peer {
		t.Helper()
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)
		return auth.NewPeer(&auth.PeerOptions{
			Wallet:         w,
			Transport:      &acceptTransport{},
			SessionManager: auth.NewSessionManager(),
		})
	}

	t.Run("create session nonce failure", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)
		w.OnCreateHMAC().ReturnError(errBoom)
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:         w,
			Transport:      &acceptTransport{},
			SessionManager: auth.NewSessionManager(),
		})
		err = peer.ToPeer(t.Context(), anyMessage, bobPub, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create session nonce")
	})

	t.Run("get identity key failure", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)
		w.OnGetPublicKey().ReturnError(errBoom)
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:         w,
			Transport:      &acceptTransport{},
			SessionManager: auth.NewSessionManager(),
		})
		err = peer.ToPeer(t.Context(), anyMessage, bobPub, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get identity key")
	})

	t.Run("handshake times out without response", func(t *testing.T) {
		peer := newAcceptPeer(t)
		err := peer.ToPeer(t.Context(), anyMessage, bobPub, 10)
		require.Error(t, err)
		require.ErrorIs(t, err, auth.ErrTimeout)
	})
}

func TestRequestCertificatesErrorPaths(t *testing.T) {
	bob, err := ec.PrivateKeyFromHex(bobPrivKeyHex)
	require.NoError(t, err)
	bobPub := bob.PubKey()

	reqSet := utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{bobPub},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			wallet.CertificateType{}: []string{emailField},
		},
	}

	t.Run("authenticated session failure", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:         w,
			Transport:      &acceptTransport{},
			SessionManager: auth.NewSessionManager(),
		})
		err = peer.RequestCertificates(t.Context(), bobPub, reqSet, 10)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get authenticated session")
	})

	t.Run("create nonce failure", func(t *testing.T) {
		alice, bobActor := CreateActorsPair(t)
		bobActor.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bobActor.IdentityKey, 5000))

		alice.Wallet.OnCreateHMAC().ReturnError(errBoom)
		err := alice.RequestCertificates(t.Context(), bobActor.IdentityKey, reqSet, 5000)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create nonce")
	})

	t.Run("get identity key failure", func(t *testing.T) {
		alice, bobActor := CreateActorsPair(t)
		bobActor.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bobActor.IdentityKey, 5000))

		alice.Wallet.OnGetPublicKey().ReturnError(errBoom)
		err := alice.RequestCertificates(t.Context(), bobActor.IdentityKey, reqSet, 5000)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get identity key")
	})

	t.Run("sign request failure", func(t *testing.T) {
		alice, bobActor := CreateActorsPair(t)
		bobActor.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bobActor.IdentityKey, 5000))

		alice.Wallet.OnCreateSignature().ReturnError(errBoom)
		err := alice.RequestCertificates(t.Context(), bobActor.IdentityKey, reqSet, 5000)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign certificate request")
	})
}

func TestSendCertificateResponseErrorPaths(t *testing.T) {
	bob, err := ec.PrivateKeyFromHex(bobPrivKeyHex)
	require.NoError(t, err)
	bobPub := bob.PubKey()

	noCerts := []*certificates.VerifiableCertificate{}

	t.Run("authenticated session failure", func(t *testing.T) {
		priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w := wallet.NewTestWallet(t, priv)
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:         w,
			Transport:      &acceptTransport{},
			SessionManager: auth.NewSessionManager(),
		})
		err = peer.SendCertificateResponse(t.Context(), bobPub, noCerts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get authenticated session")
	})

	t.Run("create nonce failure", func(t *testing.T) {
		alice, bobActor := CreateActorsPair(t)
		bobActor.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bobActor.IdentityKey, 5000))

		alice.Wallet.OnCreateHMAC().ReturnError(errBoom)
		err := alice.SendCertificateResponse(t.Context(), bobActor.IdentityKey, noCerts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create nonce")
	})

	t.Run("get identity key failure", func(t *testing.T) {
		alice, bobActor := CreateActorsPair(t)
		bobActor.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bobActor.IdentityKey, 5000))

		alice.Wallet.OnGetPublicKey().ReturnError(errBoom)
		err := alice.SendCertificateResponse(t.Context(), bobActor.IdentityKey, noCerts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get identity key")
	})

	t.Run("sign response failure", func(t *testing.T) {
		alice, bobActor := CreateActorsPair(t)
		bobActor.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error { return nil })
		require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bobActor.IdentityKey, 5000))

		alice.Wallet.OnCreateSignature().ReturnError(errBoom)
		err := alice.SendCertificateResponse(t.Context(), bobActor.IdentityKey, noCerts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign certificate response")
	})
}

func TestHandleGeneralMessageCallbackError(t *testing.T) {
	// A callback returning an error is logged but does not fail delivery.
	alice, bob := CreateActorsPair(t)
	bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		return errBoom
	})
	err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
	require.NoError(t, err)
}

func TestAuthMessageCertificateSignatureRoundTrip(t *testing.T) {
	// Build a message whose certificate carries a base64-encoded signature so
	// both MarshalJSON and UnmarshalJSON exercise their signature-normalisation
	// loops.
	priv, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
	require.NoError(t, err)
	tw := wallet.NewTestWallet(t, priv)
	mgr := testcertificates.NewManager(t, tw)
	issued := mgr.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, "a@example.com").
		Issue()

	verifierPriv, err := ec.PrivateKeyFromHex(bobPrivKeyHex)
	require.NoError(t, err)
	vc := issued.ToVerifiableCertificate(verifierPriv.PubKey())

	// A base64 string ("some") whose raw bytes are not a valid DER signature.
	vc.Signature = []byte("c29tZQ==")

	msg := &auth.AuthMessage{
		Version:      auth.AUTH_VERSION,
		MessageType:  auth.MessageTypeCertificateResponse,
		IdentityKey:  priv.PubKey(),
		Certificates: []*certificates.VerifiableCertificate{vc},
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var restored auth.AuthMessage
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)
	require.Len(t, restored.Certificates, 1)
	require.NotEmpty(t, restored.Certificates[0].Signature)
}

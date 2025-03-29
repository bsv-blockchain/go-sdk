package auth

import (
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type OnGeneralMessageReceivedCallback func(senderPublicKey string, payload []byte) error
type OnCertificateReceivedCallback func(senderPublicKey string, certs []*certificates.VerifiableCertificate) error
type OnCertificateRequestReceivedCallback func(senderPublicKey string, requestedCertificates RequesredCertificateSet) error

type Peer struct {
	sessionManager                        *sessionManager
	transport                             Transport
	wallet                                wallet.Wallet
	CertificatesToRequest                 RequesredCertificateSet
	onGeneralMessageReceivedCallbacks     map[int]OnGeneralMessageReceivedCallback
	onCertificateReceivedCallbacks        map[int]OnCertificateReceivedCallback
	onCertificateRequestReceivedCallbacks map[int]OnCertificateRequestReceivedCallback
	onInitialResponseReceivedCallbacks    map[int]struct {
		Callback     func(sessionNonce string) error
		SessionNonce string
	}
	callbackIdCounter      int
	autoPersistLastSession bool
	lastInteractedWithPeer string
}

type PeerOptions struct {
	Wallet                 wallet.Wallet
	Transport              Transport
	CertificatesToRequest  *RequesredCertificateSet
	SessionManager         *sessionManager
	AutoPersistLastSession *bool
}

func NewPeer(cfg *PeerOptions) *Peer {
	peer := &Peer{
		wallet:         cfg.Wallet,
		transport:      cfg.Transport,
		sessionManager: cfg.SessionManager,
	}
	// peer.transport
	if peer.sessionManager == nil {
		peer.sessionManager = NewSessionManager()
	}
	if cfg.AutoPersistLastSession == nil || *cfg.AutoPersistLastSession {
		peer.autoPersistLastSession = true
	}
	return peer
}

// func (p *Peer)

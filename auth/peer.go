package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// AUTH_VERSION is the version of the auth protocol
const AUTH_VERSION = "0.1"

type OnGeneralMessageReceivedCallback func(senderPublicKey *ec.PublicKey, payload []byte) error
type OnCertificateReceivedCallback func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error
type OnCertificateRequestReceivedCallback func(senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error

type Peer struct {
	sessionManager                        SessionManager
	transport                             Transport
	wallet                                wallet.Interface
	CertificatesToRequest                 utils.RequestedCertificateSet
	onGeneralMessageReceivedCallbacks     map[int]OnGeneralMessageReceivedCallback
	onCertificateReceivedCallbacks        map[int]OnCertificateReceivedCallback
	onCertificateRequestReceivedCallbacks map[int]OnCertificateRequestReceivedCallback
	onInitialResponseReceivedCallbacks    map[int]struct {
		Callback     func(sessionNonce string) error
		SessionNonce string
	}
	callbackIdCounter      int
	autoPersistLastSession bool
	lastInteractedWithPeer *ec.PublicKey
	logger                 *log.Logger // Logger for debug messages
}

type PeerOptions struct {
	Wallet                 wallet.Interface
	Transport              Transport
	CertificatesToRequest  *utils.RequestedCertificateSet
	SessionManager         SessionManager
	AutoPersistLastSession *bool
	Logger                 *log.Logger // Optional logger for debug messages
}

// NewPeer creates a new peer instance
func NewPeer(cfg *PeerOptions) *Peer {
	peer := &Peer{
		wallet:                                cfg.Wallet,
		transport:                             cfg.Transport,
		sessionManager:                        cfg.SessionManager,
		onGeneralMessageReceivedCallbacks:     make(map[int]OnGeneralMessageReceivedCallback),
		onCertificateReceivedCallbacks:        make(map[int]OnCertificateReceivedCallback),
		onCertificateRequestReceivedCallbacks: make(map[int]OnCertificateRequestReceivedCallback),
		onInitialResponseReceivedCallbacks: make(map[int]struct {
			Callback     func(sessionNonce string) error
			SessionNonce string
		}),
		logger: cfg.Logger,
	}

	// Use a discard logger if none provided
	if peer.logger == nil {
		peer.logger = log.New(log.Writer(), "[Auth Peer] ", log.LstdFlags)
	}

	if peer.sessionManager == nil {
		peer.sessionManager = NewSessionManager()
	}

	if cfg.AutoPersistLastSession == nil || *cfg.AutoPersistLastSession {
		peer.autoPersistLastSession = true
	}

	if cfg.CertificatesToRequest != nil {
		peer.CertificatesToRequest = *cfg.CertificatesToRequest
	} else {
		peer.CertificatesToRequest = utils.RequestedCertificateSet{
			Certifiers:       []string{},
			CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
		}
	}

	// Start the peer
	err := peer.Start(context.TODO())
	if err != nil {
		peer.logger.Printf("Warning: Failed to start peer: %v", err)
	}

	return peer
}

// Start initializes the peer by setting up the transport's message handler
func (p *Peer) Start(ctx context.Context) error {
	// Register the message handler with the transport
	err := p.transport.OnData(func(message *AuthMessage) error {
		err := p.handleIncomingMessage(ctx, message)
		if err != nil {
			p.logger.Printf("Error handling incoming message: %v", err)
			return err
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to register message handler with transport: %w", err)
	}

	return nil
}

// Stop cleans up any resources used by the peer
func (p *Peer) Stop() error {
	// Clean up any resources if needed
	return nil
}

// ListenForGeneralMessages registers a callback for general messages
func (p *Peer) ListenForGeneralMessages(callback OnGeneralMessageReceivedCallback) int {
	callbackID := p.callbackIdCounter
	p.callbackIdCounter++
	p.onGeneralMessageReceivedCallbacks[callbackID] = callback
	return callbackID
}

// StopListeningForGeneralMessages removes a general message listener
func (p *Peer) StopListeningForGeneralMessages(callbackID int) {
	delete(p.onGeneralMessageReceivedCallbacks, callbackID)
}

// ListenForCertificatesReceived registers a callback for certificate reception
func (p *Peer) ListenForCertificatesReceived(callback OnCertificateReceivedCallback) int {
	callbackID := p.callbackIdCounter
	p.callbackIdCounter++
	p.onCertificateReceivedCallbacks[callbackID] = callback
	return callbackID
}

// StopListeningForCertificatesReceived removes a certificate reception listener
func (p *Peer) StopListeningForCertificatesReceived(callbackID int) {
	delete(p.onCertificateReceivedCallbacks, callbackID)
}

// ListenForCertificatesRequested registers a callback for certificate requests
func (p *Peer) ListenForCertificatesRequested(callback OnCertificateRequestReceivedCallback) int {
	callbackID := p.callbackIdCounter
	p.callbackIdCounter++
	p.onCertificateRequestReceivedCallbacks[callbackID] = callback
	return callbackID
}

// StopListeningForCertificatesRequested removes a certificate request listener
func (p *Peer) StopListeningForCertificatesRequested(callbackID int) {
	delete(p.onCertificateRequestReceivedCallbacks, callbackID)
}

// ToPeer sends a message to a peer, initiating authentication if needed
func (p *Peer) ToPeer(ctx context.Context, message []byte, identityKey *ec.PublicKey, maxWaitTime int) error {
	if p.autoPersistLastSession && p.lastInteractedWithPeer != nil && identityKey == nil {
		identityKey = p.lastInteractedWithPeer
	}

	peerSession, err := p.GetAuthenticatedSession(ctx, identityKey, maxWaitTime)
	if err != nil {
		return fmt.Errorf("failed to get authenticated session: %w", err)
	}

	// Create a nonce for this request
	requestNonce := utils.RandomBase64(32)

	// Get identity key
	identityKeyResult, err := p.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey:    true,
		EncryptionArgs: wallet.EncryptionArgs{},
	}, "auth-peer")
	if err != nil {
		return fmt.Errorf("failed to get identity key: %w", err)
	}

	// Create general message
	generalMessage := &AuthMessage{
		Version:     AUTH_VERSION,
		MessageType: MessageTypeGeneral,
		IdentityKey: identityKeyResult.PublicKey,
		Nonce:       string(requestNonce),
		YourNonce:   peerSession.PeerNonce,
		Payload:     message,
	}

	// Sign the message
	sigResult, err := p.wallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", requestNonce, peerSession.PeerNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: peerSession.PeerIdentityKey,
			},
		},
		Data: message,
	}, "auth-peer")

	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	generalMessage.Signature = sigResult.Signature.Serialize()

	// Update session timestamp
	now := time.Now().UnixNano() / int64(time.Millisecond)
	peerSession.LastUpdate = now
	p.sessionManager.UpdateSession(peerSession)

	// Update last interacted peer if auto-persist is enabled
	if p.autoPersistLastSession {
		p.lastInteractedWithPeer = peerSession.PeerIdentityKey
	}

	// Send the message
	err = p.transport.Send(generalMessage)
	if err != nil {
		return fmt.Errorf("failed to send message to peer %s: %w", peerSession.PeerIdentityKey, err)
	}

	return nil
}

// GetAuthenticatedSession retrieves or creates an authenticated session with a peer
func (p *Peer) GetAuthenticatedSession(ctx context.Context, identityKey *ec.PublicKey, maxWaitTimeMs int) (*PeerSession, error) {
	// If we have an existing authenticated session, return it
	if identityKey != nil {
		session, _ := p.sessionManager.GetSession(identityKey.ToDERHex())
		if session != nil && session.IsAuthenticated {
			if p.autoPersistLastSession {
				p.lastInteractedWithPeer = identityKey
			}
			return session, nil
		}
	}

	// No valid session, initiate handshake
	session, err := p.initiateHandshake(ctx, identityKey, maxWaitTimeMs)
	if err != nil {
		return nil, err
	}

	if p.autoPersistLastSession {
		p.lastInteractedWithPeer = identityKey
	}

	return session, nil
}

// initiateHandshake starts the mutual authentication handshake with a peer
func (p *Peer) initiateHandshake(ctx context.Context, peerIdentityKey *ec.PublicKey, maxWaitTimeMs int) (*PeerSession, error) {
	// Create a session nonce
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return nil, NewAuthError("failed to generate nonce", err)
	}

	sessionNonce := base64.StdEncoding.EncodeToString(nonceBytes)

	// Add a preliminary session entry (not yet authenticated)
	session := &PeerSession{
		IsAuthenticated: false,
		SessionNonce:    sessionNonce,
		PeerIdentityKey: peerIdentityKey,
		LastUpdate:      time.Now().UnixMilli(),
	}

	err = p.sessionManager.AddSession(session)
	if err != nil {
		return nil, NewAuthError("failed to add session", err)
	}

	// Get our identity key to include in the initial request
	pubKey, err := p.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey:    true,
		EncryptionArgs: wallet.EncryptionArgs{
			// No specific protocol or key ID needed for identity key
		},
	}, "auth-peer")
	if err != nil {
		return nil, NewAuthError("failed to get identity key", err)
	}

	// Create and send the initial request message
	initialRequest := &AuthMessage{
		Version:               AUTH_VERSION,
		MessageType:           MessageTypeInitialRequest,
		IdentityKey:           pubKey.PublicKey,
		Nonce:                 "", // No nonce for initial request
		InitialNonce:          sessionNonce,
		RequestedCertificates: p.CertificatesToRequest,
	}

	// Set up channels for async response handling
	responseChan := make(chan error)
	timeoutChan := make(chan bool)

	// Register a callback for the response
	callbackID := p.callbackIdCounter
	p.callbackIdCounter++

	p.onInitialResponseReceivedCallbacks[callbackID] = struct {
		Callback     func(sessionNonce string) error
		SessionNonce string
	}{
		Callback: func(peerNonce string) error {
			// The initial response was received
			// Update our session with the peer's nonce
			session.PeerNonce = peerNonce
			session.IsAuthenticated = true
			p.sessionManager.UpdateSession(session)
			responseChan <- nil
			return nil
		},
		SessionNonce: sessionNonce,
	}

	// Set up a timeout
	go func() {
		time.Sleep(time.Duration(maxWaitTimeMs) * time.Millisecond)
		timeoutChan <- true
	}()

	// Send the initial request
	err = p.transport.Send(initialRequest)
	if err != nil {
		delete(p.onInitialResponseReceivedCallbacks, callbackID)
		return nil, NewAuthError("failed to send initial request", err)
	}

	// Wait for response or timeout
	select {
	case err := <-responseChan:
		delete(p.onInitialResponseReceivedCallbacks, callbackID)
		if err != nil {
			return nil, err
		}
		return session, nil
	case <-timeoutChan:
		delete(p.onInitialResponseReceivedCallbacks, callbackID)
		return nil, ErrTimeout
	}
}

// handleIncomingMessage processes incoming authentication messages
func (p *Peer) handleIncomingMessage(ctx context.Context, message *AuthMessage) error {
	if message == nil {
		return ErrInvalidMessage
	}

	if message.Version != AUTH_VERSION {
		return fmt.Errorf("invalid or unsupported message auth version! Received: %s, expected: %s", message.Version, AUTH_VERSION)
	}

	// Extract the sender's identity key
	// Handle different message types
	switch message.MessageType {
	case MessageTypeInitialRequest:
		if err := p.handleInitialRequest(ctx, message, message.IdentityKey); err != nil {
			p.logger.Printf("Error handling initial request: %v", err)
			return err
		}
		return nil
	case MessageTypeInitialResponse:
		if err := p.handleInitialResponse(ctx, message, message.IdentityKey); err != nil {
			p.logger.Printf("Error handling initial response: %v", err)
			return err
		}
		return nil
	case MessageTypeCertificateRequest:
		if err := p.handleCertificateRequest(ctx, message, message.IdentityKey); err != nil {
			p.logger.Printf("Error handling certificate request: %v", err)
			return err
		}
		return nil
	case MessageTypeCertificateResponse:
		if err := p.handleCertificateResponse(ctx, message, message.IdentityKey); err != nil {
			p.logger.Printf("Error handling certificate response: %v", err)
			return err
		}
		return nil
	case MessageTypeGeneral:
		if err := p.handleGeneralMessage(ctx, message, message.IdentityKey); err != nil {
			p.logger.Printf("Error handling general message: %v", err)
			return err
		}
		return nil
	default:
		errMsg := fmt.Sprintf("unknown message type: %s", message.MessageType)
		p.logger.Println(errMsg)
		return fmt.Errorf("%s", errMsg)
	}
}

// handleInitialRequest processes an initial authentication request
func (p *Peer) handleInitialRequest(ctx context.Context, message *AuthMessage, senderPublicKey *ec.PublicKey) error {
	// Validate the request has an initial nonce
	if message.InitialNonce == "" {
		return ErrInvalidNonce
	}

	// Create our session nonce
	ourNonce, err := utils.CreateNonce(ctx, p.wallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	if err != nil {
		return NewAuthError("failed to create session nonce", err)
	}

	// Add a new authenticated session
	session := &PeerSession{
		IsAuthenticated: true,
		SessionNonce:    ourNonce,
		PeerNonce:       message.InitialNonce,
		PeerIdentityKey: senderPublicKey,
		LastUpdate:      time.Now().UnixMilli(),
	}
	err = p.sessionManager.AddSession(session)
	if err != nil {
		return NewAuthError("failed to add session", err)
	}

	// Get our identity key for the response
	identityKeyResult, err := p.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey:    true,
		EncryptionArgs: wallet.EncryptionArgs{},
	}, "auth-peer")
	if err != nil {
		return NewAuthError("failed to get identity key", err)
	}

	// Create certificates if requested
	var certs []*certificates.VerifiableCertificate
	if len(message.RequestedCertificates.Certifiers) > 0 || len(message.RequestedCertificates.CertificateTypes) > 0 {
		certs, err = utils.GetVerifiableCertificates(
			p.wallet,
			message.RequestedCertificates,
			senderPublicKey,
		)
		if err != nil {
			// Log the error but continue - certificate error shouldn't stop auth
			p.logger.Printf("Warning: Failed to get certificates: %v", err)
		}
	}

	// Create and send initial response
	response := &AuthMessage{
		Version:      AUTH_VERSION,
		MessageType:  MessageTypeInitialResponse,
		IdentityKey:  identityKeyResult.PublicKey,
		Nonce:        ourNonce,
		YourNonce:    message.InitialNonce,
		InitialNonce: message.InitialNonce,
		Certificates: certs,
	}

	// Send the response
	return p.transport.Send(response)
}

// handleInitialResponse processes the response to our initial authentication request
func (p *Peer) handleInitialResponse(ctx context.Context, message *AuthMessage, senderPublicKey *ec.PublicKey) error {
	// Validate the response has required nonces
	if message.YourNonce == "" || message.InitialNonce == "" {
		return ErrInvalidNonce
	}

	// Find corresponding initial request callback by the initial nonce
	for id, callback := range p.onInitialResponseReceivedCallbacks {
		if callback.SessionNonce == message.InitialNonce {
			// Process certificates if included
			if len(message.Certificates) > 0 {
				// Create utils.AuthMessage from our message
				utilsMessage := &AuthMessage{
					IdentityKey:  message.IdentityKey,
					Certificates: message.Certificates,
				}

				// Convert our RequestedCertificateSet to utils.RequestedCertificateSet
				utilsRequestedCerts := &utils.RequestedCertificateSet{
					Certifiers: p.CertificatesToRequest.Certifiers,
				}

				// Convert map type
				certTypes := make(utils.RequestedCertificateTypeIDAndFieldList)
				for k, v := range p.CertificatesToRequest.CertificateTypes {
					certTypes[k] = v
				}
				utilsRequestedCerts.CertificateTypes = certTypes

				// Call ValidateCertificates with proper types
				err := ValidateCertificates(
					ctx,
					p.wallet,
					utilsMessage,
					utilsRequestedCerts,
				)
				if err != nil {
					// Log the error but continue - certificate error shouldn't stop auth
					p.logger.Printf("Warning: Certificate validation failed: %v", err)
				}

				// Notify certificate listeners
				for _, callback := range p.onCertificateReceivedCallbacks {
					err := callback(senderPublicKey, message.Certificates)
					if err != nil {
						// Log callback error but continue
						p.logger.Printf("Warning: Certificate callback error: %v", err)
					}
				}
			}

			// Call the initial response callback with the peer's nonce
			err := callback.Callback(message.Nonce)
			delete(p.onInitialResponseReceivedCallbacks, id)
			return err
		}
	}

	// No matching callback found
	return fmt.Errorf("no matching initial request found for response with nonce %s", message.InitialNonce)
}

// handleCertificateRequest processes a certificate request message
func (p *Peer) handleCertificateRequest(ctx context.Context, message *AuthMessage, senderPublicKey *ec.PublicKey) error {
	// Validate the session exists and is authenticated
	session, err := p.sessionManager.GetSession(senderPublicKey.ToDERHex())
	if err != nil || session == nil {
		return ErrSessionNotFound
	}
	if !session.IsAuthenticated {
		return ErrNotAuthenticated
	}

	// Verify nonces match
	if message.YourNonce != session.SessionNonce {
		return ErrInvalidNonce
	}

	// Update session timestamp
	session.LastUpdate = time.Now().UnixMilli()
	p.sessionManager.UpdateSession(session)

	// // Verify message signature
	// senderPubKey, err := publicKeyFromString(senderPublicKey)
	// if err != nil {
	// 	return fmt.Errorf("failed to parse sender public key: %w", err)
	// }

	// Convert json of requested certificates to bytes for verification
	certRequestData, err := json.Marshal(message.RequestedCertificates)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate request data: %w", err)
	}

	// Try to parse the signature
	sig, err := ec.ParseSignature(message.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify signature
	verifyResult, err := p.wallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", message.Nonce, session.SessionNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: senderPublicKey,
			},
		},
		Data:      certRequestData,
		Signature: *sig,
	}, "")

	if err != nil || !verifyResult.Valid {
		return fmt.Errorf("invalid signature in certificate request: %w", err)
	}

	// Notify certificate request listeners
	for _, callback := range p.onCertificateRequestReceivedCallbacks {
		err := callback(senderPublicKey, message.RequestedCertificates)
		if err != nil {
			// Log callback error but continue
			p.logger.Printf("Warning: Certificate request callback error: %v", err)
		}
	}

	// If we have auto-response enabled, automatically send certificates
	if len(message.RequestedCertificates.Certifiers) > 0 || len(message.RequestedCertificates.CertificateTypes) > 0 {
		certs, err := utils.GetVerifiableCertificates(
			p.wallet,
			message.RequestedCertificates,
			senderPublicKey,
		)
		if err == nil && len(certs) > 0 {
			// Auto-respond with available certificates
			err = p.SendCertificateResponse(ctx, senderPublicKey, certs)
			if err != nil {
				p.logger.Printf("Warning: Failed to auto-respond with certificates: %v", err)
			}
		}
	}

	return nil
}

// handleCertificateResponse processes a certificate response message
func (p *Peer) handleCertificateResponse(ctx context.Context, message *AuthMessage, senderPublicKey *ec.PublicKey) error {
	// Validate the session exists and is authenticated
	session, err := p.sessionManager.GetSession(senderPublicKey.ToDERHex())
	if err != nil || session == nil {
		return ErrSessionNotFound
	}
	if !session.IsAuthenticated {
		return ErrNotAuthenticated
	}

	// Verify nonces match
	if message.YourNonce != session.SessionNonce {
		return ErrInvalidNonce
	}

	// Update session timestamp
	session.LastUpdate = time.Now().UnixMilli()
	p.sessionManager.UpdateSession(session)

	// Convert json of certificates to bytes for verification
	certData, err := json.Marshal(message.Certificates)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate data: %w", err)
	}

	// Try to parse the signature
	sig, err := ec.ParseSignature(message.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify signature
	verifyResult, err := p.wallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", message.Nonce, session.SessionNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: senderPublicKey,
			},
		},
		Data:      certData,
		Signature: *sig,
	}, "")

	if err != nil || !verifyResult.Valid {
		return fmt.Errorf("invalid signature in certificate response: %w", err)
	}

	// Process certificates if included
	if len(message.Certificates) > 0 {
		// Create utils.AuthMessage from our message
		utilsMessage := &AuthMessage{
			IdentityKey:  message.IdentityKey,
			Certificates: message.Certificates,
		}

		// Convert our RequestedCertificateSet to utils.RequestedCertificateSet
		utilsRequestedCerts := &utils.RequestedCertificateSet{
			Certifiers: p.CertificatesToRequest.Certifiers,
		}

		// Convert map type
		certTypes := make(utils.RequestedCertificateTypeIDAndFieldList)
		for k, v := range p.CertificatesToRequest.CertificateTypes {
			certTypes[k] = v
		}
		utilsRequestedCerts.CertificateTypes = certTypes

		// Call ValidateCertificates with proper types
		err := ValidateCertificates(
			ctx,
			p.wallet, // Type assertion to wallet.Interface
			utilsMessage,
			utilsRequestedCerts,
		)
		if err != nil {
			// Log the error but continue - certificate error shouldn't stop auth
			p.logger.Printf("Warning: Certificate validation failed: %v", err)
		}

		// Notify certificate listeners
		for _, callback := range p.onCertificateReceivedCallbacks {
			err := callback(senderPublicKey, message.Certificates)
			if err != nil {
				// Log callback error but continue
				p.logger.Printf("Warning: Certificate callback error: %v", err)
			}
		}
	}

	return nil
}

// handleGeneralMessage processes a general message
func (p *Peer) handleGeneralMessage(ctx context.Context, message *AuthMessage, senderPublicKey *ec.PublicKey) error {
	// Validate the session exists and is authenticated
	session, err := p.sessionManager.GetSession(senderPublicKey.ToDERHex())
	if err != nil || session == nil {
		return ErrSessionNotFound
	}
	if !session.IsAuthenticated {
		return ErrNotAuthenticated
	}

	// Verify nonces match
	if message.YourNonce != session.SessionNonce {
		return ErrInvalidNonce
	}

	// Update session timestamp
	session.LastUpdate = time.Now().UnixMilli()
	p.sessionManager.UpdateSession(session)

	// Try to parse the signature
	sig, err := ec.ParseSignature(message.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify signature
	verifyResult, err := p.wallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", message.Nonce, session.SessionNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: senderPublicKey,
			},
		},
		Data:      message.Payload,
		Signature: *sig,
	}, "")

	if err != nil || !verifyResult.Valid {
		return fmt.Errorf("invalid signature in general message: %w", err)
	}

	// Update last interacted peer
	if p.autoPersistLastSession {
		p.lastInteractedWithPeer = senderPublicKey
	}

	// Notify general message listeners
	for _, callback := range p.onGeneralMessageReceivedCallbacks {
		err := callback(senderPublicKey, message.Payload)
		if err != nil {
			// Log callback error but continue
			p.logger.Printf("Warning: General message callback error: %v", err)
		}
	}

	return nil
}

// RequestCertificates sends a certificate request to a peer
func (p *Peer) RequestCertificates(ctx context.Context, identityKey *ec.PublicKey, certificateRequirements utils.RequestedCertificateSet, maxWaitTime int) error {
	peerSession, err := p.GetAuthenticatedSession(ctx, identityKey, maxWaitTime)
	if err != nil {
		return fmt.Errorf("failed to get authenticated session: %w", err)
	}

	// Create a nonce for this request
	requestNonce, err := utils.CreateNonce(ctx, p.wallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	if err != nil {
		return fmt.Errorf("failed to create nonce: %w", err)
	}

	// Get identity key
	identityKeyResult, err := p.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "")
	if err != nil {
		return fmt.Errorf("failed to get identity key: %w", err)
	}

	// Create certificate request message
	certRequest := &AuthMessage{
		Version:               AUTH_VERSION,
		MessageType:           MessageTypeCertificateRequest,
		IdentityKey:           identityKeyResult.PublicKey,
		Nonce:                 requestNonce,
		YourNonce:             peerSession.PeerNonce,
		RequestedCertificates: certificateRequirements,
	}

	// Marshal the certificate requirements to match TypeScript
	certRequestData, err := json.Marshal(certificateRequirements)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate request data: %w", err)
	}

	// Sign the request
	sigResult, err := p.wallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", requestNonce, peerSession.PeerNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: nil, // We can't add the peer's public key here due to type issues
			},
		},
		// Sign the certificate request data, as in TypeScript
		Data: certRequestData,
	}, "")

	if err != nil {
		return fmt.Errorf("failed to sign certificate request: %w", err)
	}

	certRequest.Signature = sigResult.Signature.Serialize()

	// Send the request
	err = p.transport.Send(certRequest)
	if err != nil {
		return fmt.Errorf("failed to send certificate request: %w", err)
	}

	// Update session timestamp
	now := time.Now().UnixNano() / int64(time.Millisecond)
	peerSession.LastUpdate = now
	p.sessionManager.UpdateSession(peerSession)

	// Update last interacted peer
	if p.autoPersistLastSession {
		p.lastInteractedWithPeer = identityKey
	}

	return nil
}

// SendCertificateResponse sends certificates back to a peer in response to a request
func (p *Peer) SendCertificateResponse(ctx context.Context, identityKey *ec.PublicKey, certificates []*certificates.VerifiableCertificate) error {
	peerSession, err := p.GetAuthenticatedSession(ctx, identityKey, 0)
	if err != nil {
		return fmt.Errorf("failed to get authenticated session: %w", err)
	}

	// Create a nonce for this response
	responseNonce, err := utils.CreateNonce(ctx, p.wallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	if err != nil {
		return fmt.Errorf("failed to create nonce: %w", err)
	}

	// Get identity key
	identityKeyResult, err := p.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "")
	if err != nil {
		return fmt.Errorf("failed to get identity key: %w", err)
	}

	// Create certificate response message
	certResponse := &AuthMessage{
		Version:      AUTH_VERSION,
		MessageType:  MessageTypeCertificateResponse,
		IdentityKey:  identityKeyResult.PublicKey,
		Nonce:        responseNonce,
		YourNonce:    peerSession.PeerNonce,
		Certificates: certificates,
	}

	// Marshal the certificates data to match TypeScript
	certData, err := json.Marshal(certificates)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate data: %w", err)
	}

	// Sign the response
	sigResult, err := p.wallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", responseNonce, peerSession.PeerNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: nil, // We can't add the peer's public key here due to type issues
			},
		},
		// Sign the certificate data, as in TypeScript
		Data: certData,
	}, "")

	if err != nil {
		return fmt.Errorf("failed to sign certificate response: %w", err)
	}

	certResponse.Signature = sigResult.Signature.Serialize()

	// Send the response
	err = p.transport.Send(certResponse)
	if err != nil {
		return fmt.Errorf("failed to send certificate response: %w", err)
	}

	// Update session timestamp
	now := time.Now().UnixNano() / int64(time.Millisecond)
	peerSession.LastUpdate = now
	p.sessionManager.UpdateSession(peerSession)

	// Update last interacted peer
	if p.autoPersistLastSession {
		p.lastInteractedWithPeer = identityKey
	}

	return nil
}

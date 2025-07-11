package admintoken

import (
	"context"
	"encoding/hex"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// OverlayAdminTokenData represents the data contained within a SHIP or SLAP administration token
type OverlayAdminTokenData struct {
	Protocol       overlay.Protocol
	IdentityKey    string
	Domain         string
	TopicOrService string
}

// OverlayAdminToken is a script template for creating, unlocking, and decoding SHIP and SLAP advertisements
type OverlayAdminToken struct {
	PushDrop *pushdrop.PushDrop
}

// NewOverlayAdminToken creates a new overlay admin token instance
func NewOverlayAdminToken(wallet wallet.Interface, originator ...string) *OverlayAdminToken {
	pd := &pushdrop.PushDrop{
		Wallet: wallet,
	}
	if len(originator) > 0 {
		pd.Originator = originator[0]
	}
	return &OverlayAdminToken{
		PushDrop: pd,
	}
}

// Decode extracts overlay admin token data from a locking script
func Decode(s *script.Script) *OverlayAdminTokenData {
	if result := pushdrop.Decode(s); result != nil {
		if len(result.Fields) < 4 {
			return nil
		}
		protocol := overlay.Protocol(string(result.Fields[0]))
		if protocol != overlay.ProtocolSHIP && protocol != overlay.ProtocolSLAP {
			return nil
		}
		// Convert fields to strings, handling the case where empty strings
		// are encoded as OP_0 and decoded as [0]
		domain := string(result.Fields[2])
		topicOrService := string(result.Fields[3])

		// If the field is a single null byte, treat it as an empty string
		// This matches the expected behavior in the TypeScript tests
		if domain == "\x00" {
			domain = ""
		}
		if topicOrService == "\x00" {
			topicOrService = ""
		}

		return &OverlayAdminTokenData{
			Protocol:       protocol,
			IdentityKey:    hex.EncodeToString(result.Fields[1]),
			Domain:         domain,
			TopicOrService: topicOrService,
		}
	}
	return nil
}

// Lock creates a new overlay admin token locking script for the specified protocol, domain, and topic/service
func (o *OverlayAdminToken) Lock(
	ctx context.Context,
	protocol overlay.Protocol,
	domain string,
	topicOrService string,
) (*script.Script, error) {
	// Get the identity key first, matching TypeScript behavior
	pub, err := o.PushDrop.Wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, o.PushDrop.Originator)
	if err != nil {
		return nil, err
	}

	protocolID := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	}
	if protocol == overlay.ProtocolSHIP {
		protocolID.Protocol = "Service Host Interconnect"
	} else {
		protocolID.Protocol = "Service Lookup Availability"
	}

	return o.PushDrop.Lock(
		ctx,
		[][]byte{
			[]byte(protocol),
			pub.PublicKey.Compressed(),
			[]byte(domain),
			[]byte(topicOrService),
		},
		protocolID,
		"1",
		wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		},
		false,               // forSelf
		true,                // includeSignature
		pushdrop.LockBefore, // lockPosition
	)
}

// Unlock creates an unlocker for overlay admin tokens of the specified protocol
func (o *OverlayAdminToken) Unlock(
	ctx context.Context,
	protocol overlay.Protocol,
) *pushdrop.Unlocker {
	protocolID := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	}
	if protocol == overlay.ProtocolSHIP {
		protocolID.Protocol = "Service Host Interconnect"
	} else {
		protocolID.Protocol = "Service Lookup Availability"
	}
	return o.PushDrop.Unlock(
		ctx,
		protocolID,
		"1",
		wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		},
		wallet.SignOutputsAll,
		false, // anyoneCanPay
	)
}

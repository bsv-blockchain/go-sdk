package admintoken

import (
	"context"
	"encoding/hex"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type OverlayAdminTokenData struct {
	Protocol       overlay.Protocol
	IdentityKey    string
	Domain         string
	TopicOrService string
}

type OverlayAdminTokenTemplate struct {
	PushDrop pushdrop.PushDropTemplate
}

func Decode(s *script.Script) *OverlayAdminTokenData {
	if result := pushdrop.Decode(s); result != nil {
		return &OverlayAdminTokenData{
			Protocol:       overlay.Protocol(string(result.Fields[0])),
			IdentityKey:    hex.EncodeToString(result.Fields[0]),
			Domain:         string(result.Fields[1]),
			TopicOrService: string(result.Fields[2]),
		}
	}
	return nil
}

func (o *OverlayAdminTokenTemplate) Lock(
	ctx context.Context,
	protocol overlay.Protocol,
	domain string,
	topicOrService string,
) (*script.Script, error) {
	pub, err := o.PushDrop.Wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, o.PushDrop.Originator)
	if err != nil {
		return nil, err
	}

	protocolId := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	}
	if protocol == overlay.ProtocolSHIP {
		protocolId.Protocol = "Service Host Interconnect"
	} else {
		protocolId.Protocol = "Service Lookup Availability"
	}

	return o.PushDrop.Lock(
		ctx,
		[][]byte{
			[]byte(protocol),
			pub.PublicKey.Compressed(),
			[]byte(domain),
			[]byte(topicOrService),
		},
		protocolId,
		"1",
		wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		},
		false,
		true,
		true,
	)
}

func (o *OverlayAdminTokenTemplate) Unlock(
	ctx context.Context,
	protocol overlay.Protocol,
) *pushdrop.PushDropUnlocker {
	protocolId := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	}
	if protocol == overlay.ProtocolSHIP {
		protocolId.Protocol = "Service Host Interconnect"
	} else {
		protocolId.Protocol = "Service Lookup Availability"
	}
	return o.PushDrop.Unlock(
		ctx,
		protocolId,
		"1",
		wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		},
		wallet.SignOutputsAll,
		false,
	)
}

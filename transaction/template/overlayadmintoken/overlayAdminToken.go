package overlayadmintoken

import (
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

func Decode(s *script.Script) (*OverlayAdminTokenData, error) {
	if restult, err := pushdrop.Decode(s); err != nil {
		return nil, err
	} else {
		return &OverlayAdminTokenData{
			Protocol:       overlay.Protocol(string(restult.Fields[0])),
			IdentityKey:    hex.EncodeToString(restult.Fields[0]),
			Domain:         string(restult.Fields[1]),
			TopicOrService: string(restult.Fields[2]),
		}, nil
	}
}

func (o *OverlayAdminTokenTemplate) Lock(
	protocol overlay.Protocol,
	domain string,
	topicOrService string,
) (*script.Script, error) {
	pub := o.PushDrop.Wallet.GetPublicKey(&wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, o.PushDrop.Originator)

	protocolId := wallet.WalletProtocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	}
	if protocol == overlay.ProtocolSHIP {
		protocolId.Protocol = "Service Host Interconnect"
	} else {
		protocolId.Protocol = "Service Lookup Availability"
	}

	return o.PushDrop.Lock(
		[][]byte{
			[]byte(protocol),
			pub.PublicKey.Compressed(),
			[]byte(domain),
			[]byte(topicOrService),
		},
		protocolId,
		"1",
		wallet.WalletCounterparty{
			Type: wallet.CounterpartyTypeSelf,
		},
		false,
		true,
		true,
	)
}

func (o *OverlayAdminTokenTemplate) Unlock(
	protocol overlay.Protocol,
) *pushdrop.PushDropUnlocker {
	protocolId := wallet.WalletProtocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	}
	if protocol == overlay.ProtocolSHIP {
		protocolId.Protocol = "Service Host Interconnect"
	} else {
		protocolId.Protocol = "Service Lookup Availability"
	}
	return o.PushDrop.Unlock(
		protocolId,
		"1",
		wallet.WalletCounterparty{
			Type: wallet.CounterpartyTypeSelf,
		},
		wallet.SignOutputsAll,
		false,
	)
}

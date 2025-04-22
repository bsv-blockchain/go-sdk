package registry

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	// RegistrantTokenAmount is the satoshi value of registry entry tokens
	RegistrantTokenAmount uint64 = 1
)

// RegistryClient manages on-chain registry definitions for three types:
// - basket (basket-based items)
// - protocol (protocol-based items)
// - certificate (certificate-based items)
//
// It provides methods to:
// - Register new definitions using pushdrop-based UTXOs.
// - Resolve existing definitions using a lookup service.
// - List registry entries associated with the operator's wallet.
// - Revoke an existing registry entry by spending its UTXO.
type RegistryClient struct {
	wallet        wallet.Interface
	originator    string
	network       overlay.Network
	lookupFactory func() *lookup.LookupResolver
}

// NewRegistryClient creates a new registry client with the provided wallet.
func NewRegistryClient(walletInstance wallet.Interface, originator string) *RegistryClient {
	return &RegistryClient{
		wallet:     walletInstance,
		originator: originator,
		network:    overlay.NetworkMainnet, // Default to mainnet, will be updated on first use if needed
		lookupFactory: func() *lookup.LookupResolver {
			return lookup.NewLookupResolver(&lookup.LookupResolver{})
		},
	}
}

// SetNetwork explicitly sets the network for the client.
func (c *RegistryClient) SetNetwork(network overlay.Network) {
	c.network = network
}

// mapDefinitionTypeToWalletProtocol converts our definitionType to the wallet protocol format.
func mapDefinitionTypeToWalletProtocol(definitionType DefinitionType) wallet.Protocol {
	switch definitionType {
	case DefinitionTypeBasket:
		return wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "basketmap",
		}
	case DefinitionTypeProtocol:
		return wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "protomap",
		}
	case DefinitionTypeCertificate:
		return wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "certmap",
		}
	default:
		panic(fmt.Sprintf("Unknown definition type: %s", definitionType))
	}
}

// mapDefinitionTypeToBasketName converts definition type to the basket name used by the wallet.
func mapDefinitionTypeToBasketName(definitionType DefinitionType) string {
	switch definitionType {
	case DefinitionTypeBasket:
		return "basketmap"
	case DefinitionTypeProtocol:
		return "protomap"
	case DefinitionTypeCertificate:
		return "certmap"
	default:
		panic(fmt.Sprintf("Unknown definition type: %s", definitionType))
	}
}

// mapDefinitionTypeToTopic converts definition type to the broadcast topic name.
func mapDefinitionTypeToTopic(definitionType DefinitionType) string {
	switch definitionType {
	case DefinitionTypeBasket:
		return "tm_basketmap"
	case DefinitionTypeProtocol:
		return "tm_protomap"
	case DefinitionTypeCertificate:
		return "tm_certmap"
	default:
		panic(fmt.Sprintf("Unknown definition type: %s", definitionType))
	}
}

// mapDefinitionTypeToServiceName converts definition type to the lookup service name.
func mapDefinitionTypeToServiceName(definitionType DefinitionType) string {
	switch definitionType {
	case DefinitionTypeBasket:
		return "ls_basketmap"
	case DefinitionTypeProtocol:
		return "ls_protomap"
	case DefinitionTypeCertificate:
		return "ls_certmap"
	default:
		panic(fmt.Sprintf("Unknown definition type: %s", definitionType))
	}
}

// buildPushDropFields converts definition data into an array of pushdrop fields.
// Each definition type has a slightly different shape.
func buildPushDropFields(data DefinitionData, registryOperator string) ([][]byte, error) {
	var fields []string

	switch d := data.(type) {
	case *BasketDefinitionData:
		fields = []string{
			d.BasketID,
			d.Name,
			d.IconURL,
			d.Description,
			d.DocumentationURL,
		}
	case *ProtocolDefinitionData:
		protocolIDJSON, err := json.Marshal(d.ProtocolID)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal protocol ID: %w", err)
		}
		fields = []string{
			string(protocolIDJSON),
			d.Name,
			d.IconURL,
			d.Description,
			d.DocumentationURL,
		}
	case *CertificateDefinitionData:
		fieldsJSON, err := json.Marshal(d.Fields)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificate fields: %w", err)
		}
		fields = []string{
			d.Type,
			d.Name,
			d.IconURL,
			d.Description,
			d.DocumentationURL,
			string(fieldsJSON),
		}
	default:
		return nil, errors.New("unsupported definition type")
	}

	// Append the operator's public identity key last
	fields = append(fields, registryOperator)

	// Convert string array to byte array slices
	result := make([][]byte, len(fields))
	for i, field := range fields {
		result[i] = []byte(field)
	}

	return result, nil
}

// deserializeWalletProtocol converts a JSON string to a wallet.Protocol object.
func deserializeWalletProtocol(str string) (wallet.Protocol, error) {
	var protocolData []interface{}
	if err := json.Unmarshal([]byte(str), &protocolData); err != nil {
		return wallet.Protocol{}, fmt.Errorf("invalid wallet protocol format: %w", err)
	}

	// Validate that the parsed value is an array with exactly two elements
	if len(protocolData) != 2 {
		return wallet.Protocol{}, errors.New("invalid wallet protocol format, expected array of length 2")
	}

	// Extract security level
	securityLevel, ok := protocolData[0].(float64)
	if !ok || securityLevel < 0 || securityLevel > 2 {
		return wallet.Protocol{}, errors.New("invalid security level")
	}

	// Extract protocol string
	protocolString, ok := protocolData[1].(string)
	if !ok {
		return wallet.Protocol{}, errors.New("invalid protocol ID")
	}

	return wallet.Protocol{
		SecurityLevel: wallet.SecurityLevel(int(securityLevel)),
		Protocol:      protocolString,
	}, nil
}

// parseLockingScript decodes a pushdrop locking script for a given definition type,
// returning a typed record with the appropriate fields.
func parseLockingScript(definitionType DefinitionType, lockingScript *script.Script) (DefinitionData, error) {
	decoded := pushdrop.Decode(lockingScript)
	if decoded == nil || len(decoded.Fields) == 0 {
		return nil, errors.New("not a valid registry pushdrop script")
	}

	var data DefinitionData
	var registryOperator string

	switch definitionType {
	case DefinitionTypeBasket:
		if len(decoded.Fields) != 6 {
			return nil, errors.New("unexpected field count for basket type")
		}
		basketID := string(decoded.Fields[0])
		name := string(decoded.Fields[1])
		iconURL := string(decoded.Fields[2])
		description := string(decoded.Fields[3])
		docURL := string(decoded.Fields[4])
		registryOperator = string(decoded.Fields[5])

		data = &BasketDefinitionData{
			DefinitionType:   definitionType,
			BasketID:         basketID,
			Name:             name,
			IconURL:          iconURL,
			Description:      description,
			DocumentationURL: docURL,
			RegistryOperator: registryOperator,
		}

	case DefinitionTypeProtocol:
		if len(decoded.Fields) != 6 {
			return nil, errors.New("unexpected field count for protocol type")
		}
		protocolIDJson := string(decoded.Fields[0])
		name := string(decoded.Fields[1])
		iconURL := string(decoded.Fields[2])
		description := string(decoded.Fields[3])
		docURL := string(decoded.Fields[4])
		registryOperator = string(decoded.Fields[5])

		protocolID, err := deserializeWalletProtocol(protocolIDJson)
		if err != nil {
			return nil, fmt.Errorf("error deserializing protocol ID: %w", err)
		}

		data = &ProtocolDefinitionData{
			DefinitionType:   definitionType,
			ProtocolID:       protocolID,
			Name:             name,
			IconURL:          iconURL,
			Description:      description,
			DocumentationURL: docURL,
			RegistryOperator: registryOperator,
		}

	case DefinitionTypeCertificate:
		if len(decoded.Fields) != 7 {
			return nil, errors.New("unexpected field count for certificate type")
		}
		certType := string(decoded.Fields[0])
		name := string(decoded.Fields[1])
		iconURL := string(decoded.Fields[2])
		description := string(decoded.Fields[3])
		docURL := string(decoded.Fields[4])
		fieldsJSON := string(decoded.Fields[5])
		registryOperator = string(decoded.Fields[6])

		var fields map[string]CertificateFieldDescriptor
		if err := json.Unmarshal([]byte(fieldsJSON), &fields); err != nil {
			fields = make(map[string]CertificateFieldDescriptor) // Use empty map if parse fails
		}

		data = &CertificateDefinitionData{
			DefinitionType:   definitionType,
			Type:             certType,
			Name:             name,
			IconURL:          iconURL,
			Description:      description,
			DocumentationURL: docURL,
			Fields:           fields,
			RegistryOperator: registryOperator,
		}

	default:
		return nil, fmt.Errorf("unsupported definition type: %s", definitionType)
	}

	return data, nil
}

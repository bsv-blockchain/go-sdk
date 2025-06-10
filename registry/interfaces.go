// Package registry provides functionality for managing on-chain definitions
// for baskets, protocols, and certificates.
package registry

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

// DefinitionType represents the three types of registry entries.
type DefinitionType string

const (
	// DefinitionTypeBasket represents a basket definition in the registry.
	DefinitionTypeBasket DefinitionType = "basket"

	// DefinitionTypeProtocol represents a protocol definition in the registry.
	DefinitionTypeProtocol DefinitionType = "protocol"

	// DefinitionTypeCertificate represents a certificate definition in the registry.
	DefinitionTypeCertificate DefinitionType = "certificate"
)

// CertificateFieldDescriptor describes the structure and metadata for a certificate field.
type CertificateFieldDescriptor struct {
	FriendlyName string `json:"friendlyName"`
	Description  string `json:"description"`
	Type         string `json:"type"` // "text", "imageURL", or "other"
	FieldIcon    string `json:"fieldIcon"`
}

// BasketDefinitionData contains information about a basket registry entry.
type BasketDefinitionData struct {
	DefinitionType   DefinitionType `json:"definitionType"`
	BasketID         string         `json:"basketID"`
	Name             string         `json:"name"`
	IconURL          string         `json:"iconURL"`
	Description      string         `json:"description"`
	DocumentationURL string         `json:"documentationURL"`
	RegistryOperator string         `json:"registryOperator,omitempty"`
}

// ProtocolDefinitionData contains information about a protocol registry entry.
type ProtocolDefinitionData struct {
	DefinitionType   DefinitionType  `json:"definitionType"`
	ProtocolID       wallet.Protocol `json:"protocolID"`
	Name             string          `json:"name"`
	IconURL          string          `json:"iconURL"`
	Description      string          `json:"description"`
	DocumentationURL string          `json:"documentationURL"`
	RegistryOperator string          `json:"registryOperator,omitempty"`
}

// CertificateDefinitionData contains information about a certificate registry entry.
type CertificateDefinitionData struct {
	DefinitionType   DefinitionType                        `json:"definitionType"`
	Type             string                                `json:"type"`
	Name             string                                `json:"name"`
	IconURL          string                                `json:"iconURL"`
	Description      string                                `json:"description"`
	DocumentationURL string                                `json:"documentationURL"`
	Fields           map[string]CertificateFieldDescriptor `json:"fields"`
	RegistryOperator string                                `json:"registryOperator,omitempty"`
}

// DefinitionData is an interface for the different types of registry data.
type DefinitionData interface {
	GetDefinitionType() DefinitionType
	GetRegistryOperator() string
}

// Ensure all definition data types implement the DefinitionData interface
var (
	_ DefinitionData = &BasketDefinitionData{}
	_ DefinitionData = &ProtocolDefinitionData{}
	_ DefinitionData = &CertificateDefinitionData{}
)

// GetDefinitionType returns the type of definition for BasketDefinitionData.
func (b *BasketDefinitionData) GetDefinitionType() DefinitionType {
	return DefinitionTypeBasket
}

// GetRegistryOperator returns the registry operator for BasketDefinitionData.
func (b *BasketDefinitionData) GetRegistryOperator() string {
	return b.RegistryOperator
}

// GetDefinitionType returns the type of definition for ProtocolDefinitionData.
func (p *ProtocolDefinitionData) GetDefinitionType() DefinitionType {
	return DefinitionTypeProtocol
}

// GetRegistryOperator returns the registry operator for ProtocolDefinitionData.
func (p *ProtocolDefinitionData) GetRegistryOperator() string {
	return p.RegistryOperator
}

// GetDefinitionType returns the type of definition for CertificateDefinitionData.
func (c *CertificateDefinitionData) GetDefinitionType() DefinitionType {
	return DefinitionTypeCertificate
}

// GetRegistryOperator returns the registry operator for CertificateDefinitionData.
func (c *CertificateDefinitionData) GetRegistryOperator() string {
	return c.RegistryOperator
}

// TokenData contains information about the on-chain token/UTXO for a registry entry.
type TokenData struct {
	TxID          string `json:"txid"`
	OutputIndex   uint32 `json:"outputIndex"`
	Satoshis      uint64 `json:"satoshis"`
	LockingScript string `json:"lockingScript"`
	BEEF          []byte `json:"beef"`
}

// RegistryRecord combines definition data with on-chain token data.
type RegistryRecord struct {
	DefinitionData
	TokenData
}

// BasketQuery is used to filter basket registry entries.
type BasketQuery struct {
	BasketID          *string  `json:"basketID,omitempty"`
	RegistryOperators []string `json:"registryOperators,omitempty"`
	Name              *string  `json:"name,omitempty"`
}

// ProtocolQuery is used to filter protocol registry entries.
type ProtocolQuery struct {
	Name              *string          `json:"name,omitempty"`
	RegistryOperators []string         `json:"registryOperators,omitempty"`
	ProtocolID        *wallet.Protocol `json:"protocolID,omitempty"`
}

// CertificateQuery is used to filter certificate registry entries.
type CertificateQuery struct {
	Type              *string  `json:"type,omitempty"`
	Name              *string  `json:"name,omitempty"`
	RegistryOperators []string `json:"registryOperators,omitempty"`
}

// RegisterDefinitionResult represents the result of registering a definition.
type RegisterDefinitionResult struct {
	Success *transaction.BroadcastSuccess
	Failure *transaction.BroadcastFailure
}

// RevokeDefinitionResult represents the result of revoking a definition.
type RevokeDefinitionResult struct {
	Success *transaction.BroadcastSuccess
	Failure *transaction.BroadcastFailure
}

// RegistryClientInterface defines the interface for registry operations.
type RegistryClientInterface interface {
	// RegisterDefinition publishes a new on-chain definition for baskets, protocols, or certificates.
	RegisterDefinition(ctx context.Context, data DefinitionData) (*RegisterDefinitionResult, error)

	// Resolve resolves registrant tokens of a particular type using a lookup service.
	ResolveBasket(ctx context.Context, query BasketQuery) ([]*BasketDefinitionData, error)
	ResolveProtocol(ctx context.Context, query ProtocolQuery) ([]*ProtocolDefinitionData, error)
	ResolveCertificate(ctx context.Context, query CertificateQuery) ([]*CertificateDefinitionData, error)

	// ListOwnRegistryEntries lists the registry operator's published definitions for the given type.
	ListOwnRegistryEntries(ctx context.Context, definitionType DefinitionType) ([]*RegistryRecord, error)

	// RevokeOwnRegistryEntry revokes a registry record by spending its associated UTXO.
	RevokeOwnRegistryEntry(ctx context.Context, record *RegistryRecord) (*RevokeDefinitionResult, error)
}

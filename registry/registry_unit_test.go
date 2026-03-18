package registry

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- DefinitionData interface implementations ----

func TestBasketDefinitionData_GetDefinitionType(t *testing.T) {
	b := &BasketDefinitionData{DefinitionType: DefinitionTypeBasket}
	assert.Equal(t, DefinitionTypeBasket, b.GetDefinitionType())
}

func TestBasketDefinitionData_GetRegistryOperator(t *testing.T) {
	b := &BasketDefinitionData{RegistryOperator: "operator123"}
	assert.Equal(t, "operator123", b.GetRegistryOperator())
}

func TestProtocolDefinitionData_GetDefinitionType(t *testing.T) {
	p := &ProtocolDefinitionData{DefinitionType: DefinitionTypeProtocol}
	assert.Equal(t, DefinitionTypeProtocol, p.GetDefinitionType())
}

func TestProtocolDefinitionData_GetRegistryOperator(t *testing.T) {
	p := &ProtocolDefinitionData{RegistryOperator: "operator456"}
	assert.Equal(t, "operator456", p.GetRegistryOperator())
}

func TestCertificateDefinitionData_GetDefinitionType(t *testing.T) {
	c := &CertificateDefinitionData{DefinitionType: DefinitionTypeCertificate}
	assert.Equal(t, DefinitionTypeCertificate, c.GetDefinitionType())
}

func TestCertificateDefinitionData_GetRegistryOperator(t *testing.T) {
	c := &CertificateDefinitionData{RegistryOperator: "certop"}
	assert.Equal(t, "certop", c.GetRegistryOperator())
}

// ---- mapDefinitionTypeToWalletProtocol ----

func TestMapDefinitionTypeToWalletProtocol(t *testing.T) {
	tests := []struct {
		dt       DefinitionType
		expected string
	}{
		{DefinitionTypeBasket, "basketmap"},
		{DefinitionTypeProtocol, "protomap"},
		{DefinitionTypeCertificate, "certmap"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dt), func(t *testing.T) {
			p := mapDefinitionTypeToWalletProtocol(tt.dt)
			assert.Equal(t, tt.expected, p.Protocol)
		})
	}
}

func TestMapDefinitionTypeToWalletProtocol_Panic(t *testing.T) {
	assert.Panics(t, func() {
		mapDefinitionTypeToWalletProtocol("unknown")
	})
}

// ---- mapDefinitionTypeToBasketName ----

func TestMapDefinitionTypeToBasketName(t *testing.T) {
	tests := []struct {
		dt   DefinitionType
		want string
	}{
		{DefinitionTypeBasket, "basketmap"},
		{DefinitionTypeProtocol, "protomap"},
		{DefinitionTypeCertificate, "certmap"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dt), func(t *testing.T) {
			assert.Equal(t, tt.want, mapDefinitionTypeToBasketName(tt.dt))
		})
	}
}

func TestMapDefinitionTypeToBasketName_Panic(t *testing.T) {
	assert.Panics(t, func() {
		mapDefinitionTypeToBasketName("unknown")
	})
}

// ---- mapDefinitionTypeToTopic ----

func TestMapDefinitionTypeToTopic(t *testing.T) {
	tests := []struct {
		dt   DefinitionType
		want string
	}{
		{DefinitionTypeBasket, "tm_basketmap"},
		{DefinitionTypeProtocol, "tm_protomap"},
		{DefinitionTypeCertificate, "tm_certmap"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dt), func(t *testing.T) {
			assert.Equal(t, tt.want, mapDefinitionTypeToTopic(tt.dt))
		})
	}
}

func TestMapDefinitionTypeToTopic_Panic(t *testing.T) {
	assert.Panics(t, func() {
		mapDefinitionTypeToTopic("unknown")
	})
}

// ---- mapDefinitionTypeToServiceName ----

func TestMapDefinitionTypeToServiceName(t *testing.T) {
	tests := []struct {
		dt   DefinitionType
		want string
	}{
		{DefinitionTypeBasket, "ls_basketmap"},
		{DefinitionTypeProtocol, "ls_protomap"},
		{DefinitionTypeCertificate, "ls_certmap"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dt), func(t *testing.T) {
			assert.Equal(t, tt.want, mapDefinitionTypeToServiceName(tt.dt))
		})
	}
}

func TestMapDefinitionTypeToServiceName_Panic(t *testing.T) {
	assert.Panics(t, func() {
		mapDefinitionTypeToServiceName("unknown")
	})
}

// ---- buildPushDropFields ----

func TestBuildPushDropFields_Basket(t *testing.T) {
	data := &BasketDefinitionData{
		BasketID:         "basket1",
		Name:             "Test Basket",
		IconURL:          "https://example.com/icon.png",
		Description:      "A test basket",
		DocumentationURL: "https://example.com/docs",
	}

	fields, err := buildPushDropFields(data, "operator123")
	require.NoError(t, err)
	assert.Len(t, fields, 6)
	assert.Equal(t, []byte("basket1"), fields[0])
	assert.Equal(t, []byte("Test Basket"), fields[1])
	assert.Equal(t, []byte("operator123"), fields[5])
}

func TestBuildPushDropFields_Protocol(t *testing.T) {
	data := &ProtocolDefinitionData{
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		Name:             "Test Protocol",
		IconURL:          "https://example.com/icon.png",
		Description:      "A test protocol",
		DocumentationURL: "https://example.com/docs",
	}

	fields, err := buildPushDropFields(data, "operator123")
	require.NoError(t, err)
	assert.Len(t, fields, 6)
	assert.Equal(t, []byte("Test Protocol"), fields[1])
	assert.Equal(t, []byte("operator123"), fields[5])
}

func TestBuildPushDropFields_Certificate(t *testing.T) {
	data := &CertificateDefinitionData{
		Type:             "cert-type-1",
		Name:             "Test Cert",
		IconURL:          "https://example.com/icon.png",
		Description:      "A test cert",
		DocumentationURL: "https://example.com/docs",
		Fields: map[string]CertificateFieldDescriptor{
			"name": {FriendlyName: "Full Name", Type: "text"},
		},
	}

	fields, err := buildPushDropFields(data, "operator123")
	require.NoError(t, err)
	assert.Len(t, fields, 7)
	assert.Equal(t, []byte("cert-type-1"), fields[0])
	assert.Equal(t, []byte("operator123"), fields[6])
}

func TestBuildPushDropFields_Unsupported(t *testing.T) {
	// Pass a type that doesn't match any case
	fields, err := buildPushDropFields(&unsupportedData{}, "operator")
	assert.Error(t, err)
	assert.Nil(t, fields)
}

// unsupportedData is a fake DefinitionData for testing the unsupported case
type unsupportedData struct{}

func (u *unsupportedData) GetDefinitionType() DefinitionType { return "unsupported" }
func (u *unsupportedData) GetRegistryOperator() string       { return "" }

// ---- deserializeWalletProtocol ----

func TestDeserializeWalletProtocol(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantProto string
		wantLevel wallet.SecurityLevel
		wantErr   bool
	}{
		{
			name:      "valid protocol",
			input:     `[2, "myprotocol"]`,
			wantProto: "myprotocol",
			wantLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			wantErr:   false,
		},
		{
			name:    "invalid JSON",
			input:   `not-json`,
			wantErr: true,
		},
		{
			name:    "wrong array length",
			input:   `[2]`,
			wantErr: true,
		},
		{
			name:    "invalid security level type",
			input:   `["notanumber", "protocol"]`,
			wantErr: true,
		},
		{
			name:    "security level too high",
			input:   `[5, "protocol"]`,
			wantErr: true,
		},
		{
			name:    "invalid protocol type",
			input:   `[1, 123]`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := deserializeWalletProtocol(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantProto, p.Protocol)
				assert.Equal(t, tt.wantLevel, p.SecurityLevel)
			}
		})
	}
}

// ---- NewRegistryClient ----

func TestNewRegistryClient(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, "test-originator")
	assert.NotNil(t, client)
}

func TestRegistryClient_SetNetwork(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, "test-originator")
	client.SetNetwork(2) // Local
	// No assertion needed; just verify no panic
}

func TestRegistryClient_SetBroadcasterFactory(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, "test-originator")
	// Verify SetBroadcasterFactory accepts a nil factory without panicking
	client.SetBroadcasterFactory(nil)
}

package registry

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIconURL        = "https://example.com/icon.png"
	testDocsURL        = "https://example.com/docs"
	testUnitOriginator = "test-originator"
)

// ---- DefinitionData interface implementations ----

func TestBasketDefinitionDataGetDefinitionType(t *testing.T) {
	b := &BasketDefinitionData{DefinitionType: DefinitionTypeBasket}
	assert.Equal(t, DefinitionTypeBasket, b.GetDefinitionType())
}

func TestBasketDefinitionDataGetRegistryOperator(t *testing.T) {
	b := &BasketDefinitionData{RegistryOperator: "operator123"}
	assert.Equal(t, "operator123", b.GetRegistryOperator())
}

func TestProtocolDefinitionDataGetDefinitionType(t *testing.T) {
	p := &ProtocolDefinitionData{DefinitionType: DefinitionTypeProtocol}
	assert.Equal(t, DefinitionTypeProtocol, p.GetDefinitionType())
}

func TestProtocolDefinitionDataGetRegistryOperator(t *testing.T) {
	p := &ProtocolDefinitionData{RegistryOperator: "operator456"}
	assert.Equal(t, "operator456", p.GetRegistryOperator())
}

func TestCertificateDefinitionDataGetDefinitionType(t *testing.T) {
	c := &CertificateDefinitionData{DefinitionType: DefinitionTypeCertificate}
	assert.Equal(t, DefinitionTypeCertificate, c.GetDefinitionType())
}

func TestCertificateDefinitionDataGetRegistryOperator(t *testing.T) {
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

func TestMapDefinitionTypeToWalletProtocolPanic(t *testing.T) {
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

func TestMapDefinitionTypeToBasketNamePanic(t *testing.T) {
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

func TestMapDefinitionTypeToTopicPanic(t *testing.T) {
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

func TestMapDefinitionTypeToServiceNamePanic(t *testing.T) {
	assert.Panics(t, func() {
		mapDefinitionTypeToServiceName("unknown")
	})
}

// ---- buildPushDropFields ----

func TestBuildPushDropFieldsBasket(t *testing.T) {
	data := &BasketDefinitionData{
		BasketID:         "basket1",
		Name:             "Test Basket",
		IconURL:          testIconURL,
		Description:      "A test basket",
		DocumentationURL: testDocsURL,
	}

	fields, err := buildPushDropFields(data, "operator123")
	require.NoError(t, err)
	assert.Len(t, fields, 6)
	assert.Equal(t, []byte("basket1"), fields[0])
	assert.Equal(t, []byte("Test Basket"), fields[1])
	assert.Equal(t, []byte("operator123"), fields[5])
}

func TestBuildPushDropFieldsProtocol(t *testing.T) {
	data := &ProtocolDefinitionData{
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		Name:             "Test Protocol",
		IconURL:          testIconURL,
		Description:      "A test protocol",
		DocumentationURL: testDocsURL,
	}

	fields, err := buildPushDropFields(data, "operator123")
	require.NoError(t, err)
	assert.Len(t, fields, 6)
	assert.Equal(t, []byte("Test Protocol"), fields[1])
	assert.Equal(t, []byte("operator123"), fields[5])
}

func TestBuildPushDropFieldsCertificate(t *testing.T) {
	data := &CertificateDefinitionData{
		Type:             "cert-type-1",
		Name:             "Test Cert",
		IconURL:          testIconURL,
		Description:      "A test cert",
		DocumentationURL: testDocsURL,
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

func TestBuildPushDropFieldsUnsupported(t *testing.T) {
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
	client := NewRegistryClient(mockWallet, testUnitOriginator)
	assert.NotNil(t, client)
}

func TestRegistryClientSetNetwork(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, testUnitOriginator)
	client.SetNetwork(2) // Local
	// No assertion needed; just verify no panic
}

func TestRegistryClientSetBroadcasterFactory(t *testing.T) {
	mockWallet := NewMockRegistry(t)
	client := NewRegistryClient(mockWallet, testUnitOriginator)
	// Verify SetBroadcasterFactory accepts a nil factory without panicking
	client.SetBroadcasterFactory(nil)
}

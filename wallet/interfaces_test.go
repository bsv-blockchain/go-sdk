package wallet_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- CertificateType helpers ----

func TestCertificateTypeFromString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errContains string
	}{
		{"valid short", "test", false, ""},
		{"valid 32 chars", "12345678901234567890123456789012", false, ""},
		{"too long", "123456789012345678901234567890123", true, "longer then 32 bytes"},
		{"empty", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := wallet.CertificateTypeFromString(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.Contains(t, string(ct.Bytes()), tt.input)
			}
		})
	}
}

func TestCertificateTypeFromBase64(t *testing.T) {
	import64 := "dGVzdA==" // "test" in base64

	ct, err := wallet.CertificateTypeFromBase64(import64)
	require.NoError(t, err)
	assert.Equal(t, "test", ct.String()[:4])
}

func TestCertificateTypeFromBase64Invalid(t *testing.T) {
	_, err := wallet.CertificateTypeFromBase64("not-valid-base64!!!")
	assert.Error(t, err)
}

func TestCertificateTypeBytes(t *testing.T) {
	ct, _ := wallet.CertificateTypeFromString("hello")
	b := ct.Bytes()
	assert.Equal(t, 32, len(b))
	assert.Equal(t, byte('h'), b[0])
}

func TestCertificateTypeString(t *testing.T) {
	ct, _ := wallet.CertificateTypeFromString("hello")
	s := ct.String()
	assert.Contains(t, s, "hello")
}

func TestCertificateTypeBase64(t *testing.T) {
	ct, _ := wallet.CertificateTypeFromString("hello")
	b64 := ct.Base64()
	assert.NotEmpty(t, b64)
}

// ---- QueryMode ----

func TestQueryModeFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    wallet.QueryMode
		wantErr bool
	}{
		{"any", wallet.QueryModeAny, false},
		{"all", wallet.QueryModeAll, false},
		{"", "", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			qm, err := wallet.QueryModeFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, qm)
			}
		})
	}
}

// ---- OutputInclude ----

func TestOutputIncludeFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    wallet.OutputInclude
		wantErr bool
	}{
		{"locking scripts", wallet.OutputIncludeLockingScripts, false},
		{"entire transactions", wallet.OutputIncludeEntireTransactions, false},
		{"", "", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			oi, err := wallet.OutputIncludeFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, oi)
			}
		})
	}
}

// ---- InternalizeProtocol ----

func TestInternalizeProtocolFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    wallet.InternalizeProtocol
		wantErr bool
	}{
		{"wallet payment", wallet.InternalizeProtocolWalletPayment, false},
		{"basket insertion", wallet.InternalizeProtocolBasketInsertion, false},
		{"", "", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip, err := wallet.InternalizeProtocolFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, ip)
			}
		})
	}
}

// ---- AcquisitionProtocol ----

func TestAcquisitionProtocolFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    wallet.AcquisitionProtocol
		wantErr bool
	}{
		{"direct", wallet.AcquisitionProtocolDirect, false},
		{"issuance", wallet.AcquisitionProtocolIssuance, false},
		{"", "", false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ap, err := wallet.AcquisitionProtocolFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, ap)
			}
		})
	}
}

// ---- Network ----

func TestNetworkFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    wallet.Network
		wantErr bool
	}{
		{"mainnet", wallet.NetworkMainnet, false},
		{"testnet", wallet.NetworkTestnet, false},
		{"", "", false},
		{"localnet", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			n, err := wallet.NetworkFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, n)
			}
		})
	}
}

// ---- Error ----

func TestWalletError(t *testing.T) {
	e := &wallet.Error{
		Code:    42,
		Message: "something went wrong",
		Stack:   "at main.go:10",
	}
	assert.Contains(t, e.Error(), "42")
	assert.Contains(t, e.Error(), "something went wrong")
}

package utils_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestRequestedCertificateSetMarshalJSON pins the BRC-103 wire shape
// (lowercase "certifiers"/"types") that @bsv/sdk 2.8's AuthMessageValidation
// strictly requires. Before this fix, the zero-value RequestedCertificateSet
// marshaled as {"Certifiers":[],"CertificateTypes":{}} (capitalized, and
// null instead of [] once JSON round-tripped through a struct with omitempty
// on the container), which a strict TS peer rejects.
func TestRequestedCertificateSetMarshalJSON(t *testing.T) {
	t.Run("zero value marshals to lowercase empty array and object, never null", func(t *testing.T) {
		var set utils.RequestedCertificateSet
		data, err := json.Marshal(set)
		require.NoError(t, err)
		assert.JSONEq(t, `{"certifiers":[],"types":{}}`, string(data))
	})

	t.Run("populated set marshals with lowercase keys", func(t *testing.T) {
		priv, err := ec.NewPrivateKey()
		require.NoError(t, err)
		certType, err := wallet.CertificateTypeFromString("contact")
		require.NoError(t, err)

		set := utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{priv.PubKey()},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				certType: {"name", "email"},
			},
		}
		data, err := json.Marshal(set)
		require.NoError(t, err)

		var decoded map[string]any
		require.NoError(t, json.Unmarshal(data, &decoded))
		if _, ok := decoded["Certifiers"]; ok {
			t.Errorf("marshaled output still has the legacy capitalized \"Certifiers\" key: %s", data)
		}
		if _, ok := decoded["CertificateTypes"]; ok {
			t.Errorf("marshaled output still has the legacy capitalized \"CertificateTypes\" key: %s", data)
		}
		certifiers, ok := decoded["certifiers"].([]any)
		require.True(t, ok, "certifiers must be an array")
		require.Len(t, certifiers, 1)
		assert.Equal(t, priv.PubKey().ToDERHex(), certifiers[0])

		types, ok := decoded["types"].(map[string]any)
		require.True(t, ok, "types must be an object")
		fields, ok := types[base64.StdEncoding.EncodeToString(certType[:])].([]any)
		require.True(t, ok)
		assert.ElementsMatch(t, []any{"name", "email"}, fields)
	})
}

// TestRequestedCertificateSetUnmarshalJSON checks both the current wire
// shape and the legacy pre-fix Go field names decode correctly, so an older
// Go peer's persisted or in-flight data keeps working against this version.
func TestRequestedCertificateSetUnmarshalJSON(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certType, err := wallet.CertificateTypeFromString("contact")
	require.NoError(t, err)
	typeKeyB64 := base64.StdEncoding.EncodeToString(certType[:])

	t.Run("current wire shape (lowercase)", func(t *testing.T) {
		wire := `{"certifiers":["` + priv.PubKey().ToDERHex() + `"],"types":{"` + typeKeyB64 + `":["name"]}}`
		var set utils.RequestedCertificateSet
		require.NoError(t, json.Unmarshal([]byte(wire), &set))
		require.Len(t, set.Certifiers, 1)
		assert.True(t, set.Certifiers[0].IsEqual(priv.PubKey()))
		assert.Equal(t, []string{"name"}, set.CertificateTypes[certType])
	})

	t.Run("legacy Go field names", func(t *testing.T) {
		wire := `{"Certifiers":["` + priv.PubKey().ToDERHex() + `"],"CertificateTypes":{"` + typeKeyB64 + `":["name"]}}`
		var set utils.RequestedCertificateSet
		require.NoError(t, json.Unmarshal([]byte(wire), &set))
		require.Len(t, set.Certifiers, 1)
		assert.True(t, set.Certifiers[0].IsEqual(priv.PubKey()))
		assert.Equal(t, []string{"name"}, set.CertificateTypes[certType])
	})

	t.Run("absent fields decode to nil, not a panic", func(t *testing.T) {
		var set utils.RequestedCertificateSet
		require.NoError(t, json.Unmarshal([]byte(`{}`), &set))
		assert.Nil(t, set.Certifiers)
		assert.Nil(t, set.CertificateTypes)
	})

	t.Run("round trip preserves content through the new shape", func(t *testing.T) {
		original := utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{priv.PubKey()},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				certType: {"name"},
			},
		}
		data, err := json.Marshal(original)
		require.NoError(t, err)

		var roundTripped utils.RequestedCertificateSet
		require.NoError(t, json.Unmarshal(data, &roundTripped))
		require.Len(t, roundTripped.Certifiers, 1)
		assert.True(t, roundTripped.Certifiers[0].IsEqual(priv.PubKey()))
		assert.Equal(t, original.CertificateTypes, roundTripped.CertificateTypes)
	})
}

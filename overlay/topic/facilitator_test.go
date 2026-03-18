package topic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/stretchr/testify/require"
)

func TestHTTPSOverlayBroadcastFacilitator_Success(t *testing.T) {
	expectedSteak := &overlay.Steak{
		"tm_test": &overlay.AdmittanceInstructions{
			OutputsToAdmit: []uint32{0},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/submit", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
		require.NotEmpty(t, r.Header.Get("X-Topics"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedSteak)
	}))
	defer server.Close()

	f := &HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}
	taggedBEEF := &overlay.TaggedBEEF{
		Beef:   []byte{0x01, 0x02, 0x03},
		Topics: []string{"tm_test"},
	}

	steak, err := f.Send(server.URL, taggedBEEF)
	require.NoError(t, err)
	require.NotNil(t, steak)

	admittance, ok := (*steak)["tm_test"]
	require.True(t, ok)
	require.Equal(t, []uint32{0}, admittance.OutputsToAdmit)
}

func TestHTTPSOverlayBroadcastFacilitator_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	f := &HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}
	taggedBEEF := &overlay.TaggedBEEF{
		Beef:   []byte{0xDE, 0xAD},
		Topics: []string{"tm_test"},
	}

	_, err := f.Send(server.URL, taggedBEEF)
	require.Error(t, err)
}

func TestHTTPSOverlayBroadcastFacilitator_InvalidURL(t *testing.T) {
	f := &HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}
	taggedBEEF := &overlay.TaggedBEEF{
		Beef:   []byte{0x01},
		Topics: []string{"tm_test"},
	}

	_, err := f.Send("http://127.0.0.1:0", taggedBEEF)
	require.Error(t, err)
}

func TestHTTPSOverlayBroadcastFacilitator_InvalidResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-valid-json"))
	}))
	defer server.Close()

	f := &HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}
	taggedBEEF := &overlay.TaggedBEEF{
		Beef:   []byte{0x01},
		Topics: []string{"tm_test"},
	}

	_, err := f.Send(server.URL, taggedBEEF)
	require.Error(t, err)
}

func TestHTTPSOverlayBroadcastFacilitator_EmptySteak(t *testing.T) {
	emptySteak := &overlay.Steak{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(emptySteak)
	}))
	defer server.Close()

	f := &HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}
	taggedBEEF := &overlay.TaggedBEEF{
		Beef:   []byte{0x01},
		Topics: []string{"tm_test"},
	}

	steak, err := f.Send(server.URL, taggedBEEF)
	require.NoError(t, err)
	require.NotNil(t, steak)
	require.Empty(t, *steak)
}

package serializer

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
)

// These tests feed each deserializer a short message whose declared element
// count is larger than the bytes that follow, and expect an error rather than
// a slice sized from the count. Any panic is recovered and reported as a
// failure. Each case runs with a count far beyond any real message, with a
// count that fits a uint32 field but still exceeds the remaining bytes, and
// with the all-ones "absent" sentinel, which the count reader passes through:
// sites that treat it as an absent slice must accept it, and every other site
// must reject it rather than loop on it.
// Any new deserializer that reads an element count should get a row here.

// oversizedCount is far larger than any real message, and is not the all-ones
// sentinel some readers treat as "absent".
const oversizedCount = uint64(math.MaxUint64 - 1)

// smallOversizedCount fits in a uint32 field but exceeds the bytes that follow
// the count in every message these tests build. It exercises the bound at
// sites that store the count as a uint32, where oversizedCount already failed
// the range check before this change.
const smallOversizedCount = uint64(1000)

// countBoundError is the message the count reader returns when a count
// exceeds the remaining bytes.
const countBoundError = "elements declared but only"

// writeActionHeader writes the fixed leading fields of one serialized action, up
// to but not including its input count, so a caller can append a crafted count.
func writeActionHeader(w *util.Writer) {
	w.WriteBytesReverse(make([]byte, chainhash.HashSize)) // txid
	w.WriteVarInt(0)                                      // satoshis
	w.WriteByteValue(byte(actionStatusCodeCompleted))     // status
	w.WriteByteValue(0)                                   // not outgoing
	w.WriteString("")                                     // description
	w.WriteStringSlice(nil)                               // labels
	w.WriteVarInt(0)                                      // version
	w.WriteVarInt(0)                                      // lock time
}

// compressedPubKey returns a valid 33-byte compressed public key, needed where a
// deserializer parses a key before reaching the count under test.
func compressedPubKey(t *testing.T) []byte {
	t.Helper()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	return pk.PubKey().Compressed()
}

// writeProveCertificatePrefix writes the leading fields of ProveCertificateArgs
// up to but not including the certificate's field count: type, subject, serial
// number, certifier, revocation outpoint and an empty signature.
func writeProveCertificatePrefix(t *testing.T, w *util.Writer) {
	t.Helper()
	w.WriteBytes(make([]byte, sizeType))   // certificate type
	w.WriteBytes(compressedPubKey(t))      // subject
	w.WriteBytes(make([]byte, sizeSerial)) // serial number
	w.WriteBytes(compressedPubKey(t))      // certifier
	w.WriteBytes(make([]byte, 32))         // revocation outpoint txid
	w.WriteVarInt(0)                       // revocation outpoint index
	w.WriteVarInt(0)                       // empty signature
}

// writeIdentityCertificatePrefix writes one DiscoverCertificatesResult entry up
// to but not including its publicly revealed keyring count.
func writeIdentityCertificatePrefix(t *testing.T, w *util.Writer) {
	t.Helper()
	w.WriteIntBytes(certificateBytes(t))
	w.WriteString("")   // certifier name
	w.WriteString("")   // certifier icon url
	w.WriteString("")   // certifier description
	w.WriteByteValue(0) // trust
}

// certificateBytes returns a minimal valid serialized certificate with no
// fields and no signature, for deserializers that embed one before the count
// under test.
func certificateBytes(t *testing.T) []byte {
	t.Helper()
	w := util.NewWriter()
	w.WriteBytes(make([]byte, sizeType))   // type
	w.WriteBytes(make([]byte, sizeSerial)) // serial number
	w.WriteBytes(compressedPubKey(t))      // subject
	w.WriteBytes(compressedPubKey(t))      // certifier
	w.WriteBytes(make([]byte, 32))         // revocation outpoint txid
	w.WriteVarInt(0)                       // revocation outpoint index
	w.WriteVarInt(0)                       // no fields
	return w.Buf
}

func TestDeserializersRejectOversizedCounts(t *testing.T) {
	cases := []struct {
		name string
		// optional marks a site that reads the all-ones sentinel as an absent
		// slice. Its message is complete once the count is written, so the
		// sentinel must deserialize without error.
		optional bool
		call     func(t *testing.T, count uint64) error
	}{
		{
			name:     "ListActionsResult input count",
			optional: true,
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(1) // one action
				writeActionHeader(w)
				w.WriteVarInt(count) // input count, no inputs follow
				w.WriteNegativeOne() // outputs absent
				_, err := DeserializeListActionsResult(w.Buf)
				return err
			},
		},
		{
			name:     "ListActionsResult output count",
			optional: true,
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(1) // one action
				writeActionHeader(w)
				w.WriteVarInt(0)     // no inputs
				w.WriteVarInt(count) // output count, no outputs follow
				_, err := DeserializeListActionsResult(w.Buf)
				return err
			},
		},
		{
			name:     "outpoint slice count",
			optional: true,
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // outpoint count, no outpoints follow
				_, err := decodeOutpoints(w.Buf)
				return err
			},
		},
		{
			name: "sendWith result count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // result count, no results follow
				_, err := readTxidSliceWithStatus(util.NewReader(w.Buf))
				return err
			},
		},
		{
			name: "ListCertificatesArgs certifiers count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // certifiers count, none follow
				_, err := DeserializeListCertificatesArgs(w.Buf)
				return err
			},
		},
		{
			name: "ListCertificatesArgs types count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(0)     // no certifiers
				w.WriteVarInt(count) // types count, none follow
				_, err := DeserializeListCertificatesArgs(w.Buf)
				return err
			},
		},
		{
			name: "InternalizeActionArgs output count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(0)     // empty tx
				w.WriteVarInt(count) // output count, none follow
				_, err := DeserializeInternalizeActionArgs(w.Buf)
				return err
			},
		},
		{
			name:     "CreateActionArgs output count",
			optional: true,
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // output count, none follow
				_, err := deserializeCreateActionOutputs(util.NewReaderHoldError(w.Buf))
				return err
			},
		},
		{
			name: "ProveCertificateArgs fieldsToReveal count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				writeProveCertificatePrefix(t, w)
				w.WriteVarInt(0)     // no fields
				w.WriteVarInt(count) // fieldsToReveal count, none follow
				_, err := DeserializeProveCertificateArgs(w.Buf)
				return err
			},
		},
		{
			name: "ProveCertificateArgs fields count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				writeProveCertificatePrefix(t, w)
				w.WriteVarInt(count) // fields count, none follow
				_, err := DeserializeProveCertificateArgs(w.Buf)
				return err
			},
		},
		{
			name: "ProveCertificateResult keyring count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // keyring count, none follow
				_, err := DeserializeProveCertificateResult(w.Buf)
				return err
			},
		},
		{
			name: "Certificate fields count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteBytes(make([]byte, sizeType))   // type
				w.WriteBytes(make([]byte, sizeSerial)) // serial number
				w.WriteBytes(compressedPubKey(t))      // subject
				w.WriteBytes(compressedPubKey(t))      // certifier
				w.WriteBytes(make([]byte, 32))         // revocation outpoint txid
				w.WriteVarInt(0)                       // revocation outpoint index
				w.WriteVarInt(count)                   // fields count, none follow
				_, err := DeserializeCertificate(w.Buf)
				return err
			},
		},
		{
			name: "AcquireCertificateArgs fields count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteBytes(make([]byte, sizeType)) // type
				w.WriteBytes(compressedPubKey(t))    // certifier
				w.WriteVarInt(count)                 // fields count, none follow
				_, err := DeserializeAcquireCertificateArgs(w.Buf)
				return err
			},
		},
		{
			name: "AcquireCertificateArgs keyringForSubject count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteBytes(make([]byte, sizeType))          // type
				w.WriteBytes(compressedPubKey(t))             // certifier
				w.WriteVarInt(0)                              // no fields
				w.WriteBytes(encodePrivilegedParams(nil, "")) // privileged absent
				w.WriteByteValue(acquisitionProtocolDirect)   // acquisition protocol
				w.WriteBytes(make([]byte, sizeSerial))        // serial number
				w.WriteBytes(make([]byte, 32))                // revocation outpoint txid
				w.WriteVarInt(0)                              // revocation outpoint index
				w.WriteVarInt(0)                              // empty signature
				w.WriteByteValue(keyRingRevealerCertifier)    // keyring revealer
				w.WriteVarInt(count)                          // keyring count, none follow
				_, err := DeserializeAcquireCertificateArgs(w.Buf)
				return err
			},
		},
		{
			name: "DiscoverByAttributesArgs attributes count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // attributes count, none follow
				_, err := DeserializeDiscoverByAttributesArgs(w.Buf)
				return err
			},
		},
		{
			name: "SignActionArgs spends count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // spends count, none follow
				_, err := DeserializeSignActionArgs(w.Buf)
				return err
			},
		},
		{
			name:     "CreateActionArgs input count",
			optional: true,
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // input count, none follow
				_, err := deserializeCreateActionInputs(util.NewReaderHoldError(w.Buf))
				return err
			},
		},
		{
			name: "ListOutputsResult total outputs",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // total outputs, none follow
				_, err := DeserializeListOutputsResult(w.Buf)
				return err
			},
		},
		{
			name: "ListActionsResult total actions",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // total actions, none follow
				_, err := DeserializeListActionsResult(w.Buf)
				return err
			},
		},
		{
			name: "ListCertificatesResult total certificates",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // total certificates, none follow
				_, err := DeserializeListCertificatesResult(w.Buf)
				return err
			},
		},
		{
			name: "DiscoverCertificatesResult total certificates",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(count) // total certificates, none follow
				_, err := DeserializeDiscoverCertificatesResult(w.Buf)
				return err
			},
		},
		{
			name: "IdentityCertificate publicly revealed keyring count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(1) // one certificate
				writeIdentityCertificatePrefix(t, w)
				w.WriteVarInt(count) // keyring count, none follow
				_, err := DeserializeDiscoverCertificatesResult(w.Buf)
				return err
			},
		},
		{
			name: "IdentityCertificate decrypted fields count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(1) // one certificate
				writeIdentityCertificatePrefix(t, w)
				w.WriteVarInt(0)     // empty keyring
				w.WriteVarInt(count) // decrypted fields count, none follow
				_, err := DeserializeDiscoverCertificatesResult(w.Buf)
				return err
			},
		},
		{
			name: "ListCertificatesResult keyring count",
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(1) // one certificate
				w.WriteIntBytes(certificateBytes(t))
				w.WriteByteValue(1)  // keyring present
				w.WriteVarInt(count) // keyring count, none follow
				_, err := DeserializeListCertificatesResult(w.Buf)
				return err
			},
		},
		{
			name:     "InternalizeActionArgs labels count",
			optional: true,
			call: func(t *testing.T, count uint64) error {
				w := util.NewWriter()
				w.WriteVarInt(0)         // empty tx
				w.WriteVarInt(0)         // no outputs
				w.WriteVarInt(count)     // labels count, none follow
				w.WriteString("")        // description
				w.WriteOptionalBool(nil) // seek permission absent
				_, err := DeserializeInternalizeActionArgs(w.Buf)
				return err
			},
		},
	}

	// callNoPanic runs tc.call and converts a panic into a test failure.
	callNoPanic := func(t *testing.T, call func(t *testing.T, count uint64) error, count uint64) (err error) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("expected an error, got panic: %v", r)
			}
		}()
		return call(t, count)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("oversized", func(t *testing.T) {
				err := callNoPanic(t, tc.call, oversizedCount)
				require.Error(t, err, "an oversized count must be rejected")
			})
			t.Run("exceeds remaining bytes", func(t *testing.T) {
				err := callNoPanic(t, tc.call, smallOversizedCount)
				require.ErrorContains(t, err, countBoundError, "a count past the end of the message must fail the bound check")
			})
			t.Run("absent sentinel", func(t *testing.T) {
				err := callNoPanic(t, tc.call, math.MaxUint64)
				if tc.optional {
					require.NoError(t, err, "the sentinel marks an absent slice here")
				} else {
					require.Error(t, err, "a required count must reject the sentinel")
				}
			})
		})
	}
}

package auth_test

import (
	"encoding/base64"
	"testing"
)

// This file is a compact Go port of the structural rules in
// /packages/sdk/src/auth/AuthMessageValidation.ts (@bsv/sdk >= 2.8), applied
// as a test-only check against every AuthMessage Go's Peer emits, decoded
// exactly as a wire receiver would (json.Marshal -> map[string]any). It
// intentionally covers field presence, exact-case field names, and byte/size
// shape rather than the byte-budget/depth/cycle DoS guards in the TS source
// (walkAuthData / MAX_AUTH_MESSAGE_*), which police a JSON parser's input
// and are not meaningful to re-check against Go's own successful encoding of
// a well-formed struct.

const (
	assertMaxSignatureBytes      = 1024
	assertMaxCertificates        = 100
	assertMaxCertificateTypes    = 100
	assertMaxCertificateFields   = 100
	assertMaxCertificateFieldLen = 50
)

// assertIdentityKeyField mirrors assertAuthIdentityKey: a canonical
// compressed public key hex string (lowercase, 66 chars, 02/03 prefix).
func assertIdentityKeyField(t *testing.T, vectorLabel, field string, v any) {
	t.Helper()
	s, ok := v.(string)
	if !ok || !pubKeyHexPattern.MatchString(s) {
		t.Errorf("%s: %s must be a canonical compressed public key hex string, got %v", vectorLabel, field, v)
	}
}

// assertCanonicalBase64Field mirrors assertCanonicalBase64: a base64 string
// that decodes to exactly decodedBytes bytes and re-encodes back to itself.
func assertCanonicalBase64Field(t *testing.T, vectorLabel, field string, v any, decodedBytes int) {
	t.Helper()
	s, ok := v.(string)
	if !ok || len(s) > 128 {
		t.Errorf("%s: %s must be a base64 string, got %v", vectorLabel, field, v)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Errorf("%s: %s is not valid base64: %v", vectorLabel, field, err)
		return
	}
	if len(decoded) != decodedBytes {
		t.Errorf("%s: %s must encode exactly %d bytes, got %d", vectorLabel, field, decodedBytes, len(decoded))
	}
	if base64.StdEncoding.EncodeToString(decoded) != s {
		t.Errorf("%s: %s is not canonical base64: %q", vectorLabel, field, s)
	}
}

// assertDenseByteArrayField mirrors assertAuthByteArray: a JSON array of
// integers in [0,255], within maxBytes, non-empty unless allowEmpty.
func assertDenseByteArrayField(t *testing.T, vectorLabel, field string, v any, maxBytes int, allowEmpty bool) {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Errorf("%s: %s must be an array, got %T", vectorLabel, field, v)
		return
	}
	if !allowEmpty && len(arr) == 0 {
		t.Errorf("%s: %s must not be empty", vectorLabel, field)
	}
	if len(arr) > maxBytes {
		t.Errorf("%s: %s exceeds %d bytes", vectorLabel, field, maxBytes)
	}
	for i, el := range arr {
		n, ok := el.(float64)
		if !ok || n != float64(int(n)) || n < 0 || n > 255 {
			t.Errorf("%s: %s[%d] is not a byte value: %v", vectorLabel, field, i, el)
		}
	}
}

// assertRequestedCertificateSetField mirrors assertRequestedCertificateSet:
// {"certifiers": [...unique identity keys], "types": {<32-byte-base64
// key>: [...unique non-empty field names]}}, both present, never null.
func assertRequestedCertificateSetField(t *testing.T, vectorLabel, field string, v any) {
	t.Helper()
	obj, ok := v.(map[string]any)
	if !ok {
		t.Errorf("%s: %s must be an object, got %T", vectorLabel, field, v)
		return
	}

	certifiers, ok := obj["certifiers"].([]any)
	if !ok {
		t.Errorf("%s: %s.certifiers must be an array (present, never null)", vectorLabel, field)
	} else if len(certifiers) > assertMaxCertificates {
		t.Errorf("%s: %s.certifiers exceeds its limit", vectorLabel, field)
	} else {
		seen := make(map[string]bool, len(certifiers))
		for _, c := range certifiers {
			s, isString := c.(string)
			if !isString {
				t.Errorf("%s: %s.certifiers contains a non-string entry: %v", vectorLabel, field, c)
				continue
			}
			assertIdentityKeyField(t, vectorLabel, field+".certifiers[]", s)
			if seen[s] {
				t.Errorf("%s: %s.certifiers has a duplicate entry: %s", vectorLabel, field, s)
			}
			seen[s] = true
		}
	}

	types, ok := obj["types"].(map[string]any)
	if !ok {
		t.Errorf("%s: %s.types must be an object (present, never null)", vectorLabel, field)
		return
	}
	if len(types) > assertMaxCertificateTypes {
		t.Errorf("%s: %s.types exceeds its limit", vectorLabel, field)
	}
	for typeKey, fieldsRaw := range types {
		assertCanonicalBase64Field(t, vectorLabel, field+".types key", typeKey, 32)
		fields, ok := fieldsRaw.([]any)
		if !ok || len(fields) > assertMaxCertificateFields {
			t.Errorf("%s: %s.types[%q] must be a field-name array within its limit", vectorLabel, field, typeKey)
			continue
		}
		seen := make(map[string]bool, len(fields))
		for _, f := range fields {
			name, ok := f.(string)
			if !ok || name == "" || len(name) > assertMaxCertificateFieldLen || seen[name] {
				t.Errorf("%s: %s.types[%q] has an invalid or duplicate field name: %v", vectorLabel, field, typeKey, f)
				continue
			}
			seen[name] = true
		}
	}
}

// assertValidAuthMessageShape is a compact Go port of
// AuthMessageValidation.ts's assertValidAuthMessageShape: it checks the
// fields required for msg["messageType"], by exact (TS camelCase) key name.
// msg is a decoded map[string]any, i.e. exactly what a receiver gets from
// json.Unmarshal of the bytes Go put on the wire.
func assertValidAuthMessageShape(t *testing.T, vectorLabel string, msg map[string]any) {
	t.Helper()

	if msg["version"] != "0.1" {
		t.Errorf("%s: version = %v, want \"0.1\"", vectorLabel, msg["version"])
	}
	assertIdentityKeyField(t, vectorLabel, "identityKey", msg["identityKey"])

	if rc, ok := msg["requestedCertificates"]; ok {
		assertRequestedCertificateSetField(t, vectorLabel, "requestedCertificates", rc)
	}
	if certsRaw, ok := msg["certificates"]; ok {
		if _, ok := certsRaw.([]any); !ok {
			t.Errorf("%s: certificates must be an array when present, got %T", vectorLabel, certsRaw)
		}
	}

	messageType, _ := msg["messageType"].(string)
	switch messageType {
	case "initialRequest":
		assertCanonicalBase64Field(t, vectorLabel, "initialRequest.initialNonce", msg["initialNonce"], 48)

	case "initialResponse":
		assertCanonicalBase64Field(t, vectorLabel, "initialResponse.initialNonce", msg["initialNonce"], 48)
		assertCanonicalBase64Field(t, vectorLabel, "initialResponse.yourNonce", msg["yourNonce"], 48)
		assertDenseByteArrayField(t, vectorLabel, "initialResponse.signature", msg["signature"], assertMaxSignatureBytes, false)

	case "certificateRequest":
		assertCanonicalBase64Field(t, vectorLabel, "certificateRequest.nonce", msg["nonce"], 32)
		assertCanonicalBase64Field(t, vectorLabel, "certificateRequest.initialNonce", msg["initialNonce"], 48)
		assertCanonicalBase64Field(t, vectorLabel, "certificateRequest.yourNonce", msg["yourNonce"], 48)
		assertRequestedCertificateSetField(t, vectorLabel, "requestedCertificates", msg["requestedCertificates"])
		assertDenseByteArrayField(t, vectorLabel, "certificateRequest.signature", msg["signature"], assertMaxSignatureBytes, false)

	case "certificateResponse":
		assertCanonicalBase64Field(t, vectorLabel, "certificateResponse.nonce", msg["nonce"], 32)
		assertCanonicalBase64Field(t, vectorLabel, "certificateResponse.initialNonce", msg["initialNonce"], 48)
		assertCanonicalBase64Field(t, vectorLabel, "certificateResponse.yourNonce", msg["yourNonce"], 48)
		if _, ok := msg["certificates"].([]any); !ok {
			t.Errorf("%s: certificateResponse.certificates must be an array", vectorLabel)
		}
		assertDenseByteArrayField(t, vectorLabel, "certificateResponse.signature", msg["signature"], assertMaxSignatureBytes, false)

	case "general":
		assertCanonicalBase64Field(t, vectorLabel, "general.nonce", msg["nonce"], 32)
		assertCanonicalBase64Field(t, vectorLabel, "general.yourNonce", msg["yourNonce"], 48)
		assertDenseByteArrayField(t, vectorLabel, "general.payload", msg["payload"], 16*1024*1024, true)
		assertDenseByteArrayField(t, vectorLabel, "general.signature", msg["signature"], assertMaxSignatureBytes, false)

	default:
		t.Errorf("%s: unknown messageType %q", vectorLabel, messageType)
	}
}

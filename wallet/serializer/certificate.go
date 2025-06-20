package serializer

import (
	"fmt"
	"sort"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	sizeType    = 32
	sizeSubject = 33
	sizeSerial  = 32
	sizePubKey  = 33
)

func SerializeCertificateNoSignature(cert *wallet.Certificate) ([]byte, error) {
	return serializeCertificate(cert, false)
}

func SerializeCertificate(cert *wallet.Certificate) ([]byte, error) {
	return serializeCertificate(cert, true)
}

func serializeCertificate(cert *wallet.Certificate, includeSignature bool) ([]byte, error) {
	w := util.NewWriter()

	// Type (base64)
	if cert.Type == [32]byte{} {
		return nil, fmt.Errorf("cert type is empty")
	}
	w.WriteBytes(cert.Type[:])
	w.WriteBytes(cert.SerialNumber[:])
	w.WriteBytes(cert.Subject.Compressed())
	w.WriteBytes(cert.Certifier.Compressed())

	// Revocation outpoint
	w.WriteBytes(encodeOutpoint(cert.RevocationOutpoint))

	// Fields (sorted lexicographically with specific encoding) - matches original format
	fieldNames := make([]string, 0, len(cert.Fields))
	for fieldName := range cert.Fields {
		fieldNames = append(fieldNames, fieldName)
	}
	// Sort field names lexicographically to match original implementation
	sort.Strings(fieldNames)

	w.WriteVarInt(uint64(len(fieldNames)))
	for _, fieldName := range fieldNames {
		fieldValue := cert.Fields[fieldName]
		// Field name length + name
		fieldNameBytes := []byte(fieldName)
		w.WriteVarInt(uint64(len(fieldNameBytes)))
		w.WriteBytes(fieldNameBytes)
		// Field value length + value
		fieldValueBytes := []byte(fieldValue)
		w.WriteVarInt(uint64(len(fieldValueBytes)))
		w.WriteBytes(fieldValueBytes)
	}

	// Signature if included - matches original format
	if includeSignature && cert.Signature != nil {
		w.WriteBytes(cert.Signature.Serialize())
	}

	return w.Buf, nil
}

func DeserializeCertificate(data []byte) (cert *wallet.Certificate, err error) {
	r := util.NewReaderHoldError(data)
	cert = &wallet.Certificate{}

	// Read type (base64)
	copy(cert.Type[:], r.ReadBytes(sizeType))

	// Read serial number (base64)
	copy(cert.SerialNumber[:], r.ReadBytes(sizeSerial))

	// Read subject (hex)
	cert.Subject, err = ec.PublicKeyFromBytes(r.ReadBytes(sizeSubject))
	if err != nil {
		return nil, fmt.Errorf("error reading subject public key: %w", err)
	}

	// Read certifier (hex)
	cert.Certifier, err = ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing certifier key: %w", err)
	}

	// Read revocation outpoint
	cert.RevocationOutpoint, err = decodeOutpoint(&r.Reader)
	if err != nil {
		return nil, fmt.Errorf("error decoding revocation outpoint: %w", err)
	}

	// Read fields
	fieldsLength := r.ReadVarInt()
	if fieldsLength > 0 {
		cert.Fields = make(map[string]string, fieldsLength)
	}
	for i := uint64(0); i < fieldsLength; i++ {
		fieldName := string(r.ReadIntBytes())
		fieldValue := string(r.ReadIntBytes())

		if r.Err != nil {
			return nil, fmt.Errorf("error reading field %s: %w", fieldName, r.Err)
		}

		cert.Fields[fieldName] = fieldValue
	}

	// Read signature
	sigBytes := r.ReadRemaining()
	if len(sigBytes) > 0 {
		cert.Signature, err = ec.ParseSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing signature: %w", err)
		}
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing certificate: %w", r.Err)
	}

	return cert, nil
}

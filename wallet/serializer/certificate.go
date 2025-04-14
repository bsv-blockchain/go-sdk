package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	SizeType      = 32
	SizeSubject   = 33
	SizeCertifier = 33
	SizeRevealer  = 33
	SizeSerial    = 32
)

func SerializeCertificate(cert *wallet.Certificate) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)

	// Type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(cert.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != SizeType {
		return nil, fmt.Errorf("type must be %d bytes long", SizeType)
	}
	w.writeBytes(typeBytes)

	// Subject (hex)
	subjectBytes, err := hex.DecodeString(cert.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid subject hex: %w", err)
	}
	if len(subjectBytes) != SizeSubject {
		return nil, fmt.Errorf("subject must be %d bytes long", SizeSubject)
	}
	w.writeBytes(subjectBytes)

	// Serial number (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	if len(serialBytes) != SizeSerial {
		return nil, fmt.Errorf("serialNumber must be %d bytes long", SizeSerial)
	}
	w.writeBytes(serialBytes)

	// Certifier (hex)
	certifierBytes, err := hex.DecodeString(cert.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(certifierBytes) != SizeCertifier {
		return nil, fmt.Errorf("certifier must be %d bytes long", SizeCertifier)
	}
	w.writeBytes(certifierBytes)

	// Revocation outpoint
	outpointBytes, err := encodeOutpoint(cert.RevocationOutpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
	}
	if len(outpointBytes) != OutpointSize {
		return nil, fmt.Errorf("revocationOutpoint must be %d bytes long", OutpointSize)
	}
	w.writeBytes(outpointBytes)

	// Signature (hex)
	sigBytes, err := hex.DecodeString(cert.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	w.writeIntBytes(sigBytes)

	// Fields
	fieldEntries := make([]string, 0, len(cert.Fields))
	for k := range cert.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.writeVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		w.writeIntBytes([]byte(key))
		w.writeIntBytes([]byte(cert.Fields[key]))
	}

	return w.buf, nil
}

func DeserializeCertificate(data []byte) (*wallet.Certificate, error) {
	r := newReaderHoldError(data)
	cert := &wallet.Certificate{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("certificate deserialization failed with error byte %d", errorByte)
	}

	// Read type (base64)
	typeBytes := r.readBytes(SizeType)
	cert.Type = base64.StdEncoding.EncodeToString(typeBytes)

	if r.err != nil {
		return nil, fmt.Errorf("error 1: %w", r.err)
	}

	// Read subject (hex)
	subjectBytes := r.readBytes(SizeSubject)
	cert.Subject = hex.EncodeToString(subjectBytes)

	if r.err != nil {
		return nil, fmt.Errorf("error 2: %w", r.err)
	}

	// Read serial number (base64)
	cert.SerialNumber = base64.StdEncoding.EncodeToString(r.readBytes(SizeSerial))

	// Read certifier (hex)
	cert.Certifier = hex.EncodeToString(r.readBytes(SizeCertifier))

	if r.err != nil {
		return nil, fmt.Errorf("error 3: %w", r.err)
	}

	// Read revocation outpoint
	outpoint, err := decodeOutpoint(r.readBytes(OutpointSize))
	if err != nil {
		return nil, fmt.Errorf("error decoding revocation outpoint: %w", r.err)
	}
	cert.RevocationOutpoint = outpoint

	// Read signature
	cert.Signature = hex.EncodeToString(r.readIntBytes())

	// Read fields
	fieldsLength := r.readVarInt()
	if fieldsLength > 0 {
		cert.Fields = make(map[string]string, fieldsLength)
	}
	for i := uint64(0); i < fieldsLength; i++ {
		fieldName := string(r.readIntBytes())
		fieldValue := string(r.readIntBytes())

		if r.err != nil {
			return nil, fmt.Errorf("error reading field %s: %w", fieldName, r.err)
		}

		cert.Fields[fieldName] = fieldValue
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing certificate: %w", r.err)
	}

	return cert, nil
}

package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
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
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)

	// Type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(cert.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != SizeType {
		return nil, fmt.Errorf("type must be %d bytes long", SizeType)
	}
	w.WriteBytes(typeBytes)

	w.WriteBytes(cert.Subject.Compressed())

	// Serial number (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	if len(serialBytes) != SizeSerial {
		return nil, fmt.Errorf("serialNumber must be %d bytes long", SizeSerial)
	}
	w.WriteBytes(serialBytes)

	w.WriteBytes(cert.Certifier.Compressed())

	// Revocation outpoint
	outpointBytes, err := encodeOutpoint(cert.RevocationOutpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
	}
	if len(outpointBytes) != OutpointSize {
		return nil, fmt.Errorf("revocationOutpoint must be %d bytes long", OutpointSize)
	}
	w.WriteBytes(outpointBytes)

	// Signature (hex)
	sigBytes, err := hex.DecodeString(cert.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	w.WriteIntBytes(sigBytes)

	// Fields
	fieldEntries := make([]string, 0, len(cert.Fields))
	for k := range cert.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.WriteVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		w.WriteIntBytes([]byte(key))
		w.WriteIntBytes([]byte(cert.Fields[key]))
	}

	return w.Buf, nil
}

func DeserializeCertificate(data []byte) (cert *wallet.Certificate, err error) {
	r := util.NewReaderHoldError(data)
	cert = &wallet.Certificate{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("certificate deserialization failed with error byte %d", errorByte)
	}

	// Read type (base64)
	typeBytes := r.ReadBytes(SizeType)
	cert.Type = base64.StdEncoding.EncodeToString(typeBytes)

	if r.Err != nil {
		return nil, fmt.Errorf("error 1: %w", r.Err)
	}

	// Read subject (hex)
	subjectBytes := r.ReadBytes(SizeSubject)
	cert.Subject, err = ec.PublicKeyFromBytes(subjectBytes)
	if r.Err != nil {
		return nil, fmt.Errorf("error 2: %w", r.Err)
	}

	// Read serial number (base64)
	cert.SerialNumber = base64.StdEncoding.EncodeToString(r.ReadBytes(SizeSerial))

	// Read certifier (hex)
	cert.Certifier, err = ec.PublicKeyFromBytes(r.ReadBytes(SizeCertifier))
	if r.Err != nil {
		return nil, fmt.Errorf("error 3: %w", r.Err)
	}

	// Read revocation outpoint
	outpoint, err := decodeOutpoint(r.ReadBytes(OutpointSize))
	if err != nil {
		return nil, fmt.Errorf("error decoding revocation outpoint: %w", r.Err)
	}
	cert.RevocationOutpoint = outpoint

	// Read signature
	cert.Signature = hex.EncodeToString(r.ReadIntBytes())

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

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing certificate: %w", r.Err)
	}

	return cert, nil
}

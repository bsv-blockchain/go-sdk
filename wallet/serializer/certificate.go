package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	sizeType      = 32
	sizeSubject   = 33
	sizeCertifier = 33
	sizeRevealer  = 33
	sizeSerial    = 32
	sizeIdentity  = 33
)

func SerializeCertificate(cert *wallet.Certificate) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)

	// Type (base64)
	if err := w.WriteSizeFromBase64(cert.Type, sizeType); err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}

	w.WriteBytes(cert.Subject.Compressed())

	// Serial number (base64)
	if err := w.WriteSizeFromBase64(cert.SerialNumber, sizeSerial); err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}

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
	if err := w.WriteIntFromHex(cert.Signature); err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

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
	cert.Type = r.ReadBase64(sizeType)

	// Read subject (hex)
	subjectBytes := r.ReadBytes(sizeSubject)
	cert.Subject, err = ec.PublicKeyFromBytes(subjectBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading subject public key: %w", err)
	}

	// Read serial number (base64)
	cert.SerialNumber = r.ReadBase64(sizeSerial)

	// Read certifier (hex)
	cert.Certifier, err = ec.PublicKeyFromBytes(r.ReadBytes(sizeCertifier))
	if err != nil {
		return nil, fmt.Errorf("error parsing certifier key: %w", err)
	}

	// Read revocation outpoint
	outpoint, err := decodeOutpoint(r.ReadBytes(OutpointSize))
	if err != nil {
		return nil, fmt.Errorf("error decoding revocation outpoint: %w", err)
	}
	cert.RevocationOutpoint = outpoint

	// Read signature
	cert.Signature = r.ReadIntBytesHex()

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

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing certificate: %w", r.Err)
	}

	return cert, nil
}

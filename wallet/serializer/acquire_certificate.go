package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	SizeType      = 32
	SizeCertifier = 33
	SizeRevealer  = 33
)

func SerializeAcquireCertificateArgs(args *wallet.AcquireCertificateArgs) ([]byte, error) {
	w := newWriter()

	// Encode type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(args.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != SizeType {
		return nil, fmt.Errorf("type must be %d bytes long", SizeType)
	}
	w.writeBytes(typeBytes)

	// Encode certifier (hex)
	certifierBytes, err := hex.DecodeString(args.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(certifierBytes) != SizeCertifier {
		return nil, fmt.Errorf("certifier must be %d bytes long", SizeCertifier)
	}
	w.writeBytes(certifierBytes)

	// Encode fields
	fieldEntries := make([]string, 0, len(args.Fields))
	for k, _ := range args.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.writeVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		keyBytes := []byte(key)
		w.writeVarInt(uint64(len(keyBytes)))
		w.writeBytes(keyBytes)
		valueBytes := []byte(args.Fields[key])
		w.writeVarInt(uint64(len(valueBytes)))
		w.writeBytes(valueBytes)
	}

	// Encode privileged params
	w.writeBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	// Encode acquisition protocol (1 = direct, 2 = issuance)
	if args.AcquisitionProtocol == "direct" {
		w.writeByte(1)
	} else {
		w.writeByte(2)
	}

	if args.AcquisitionProtocol == "direct" {
		// Serial number (base64)
		serialBytes, err := base64.StdEncoding.DecodeString(args.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
		}
		w.writeBytes(serialBytes)

		// Revocation outpoint
		outpointBytes, err := encodeOutpoint(args.RevocationOutpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
		}
		w.writeBytes(outpointBytes)

		// Signature (hex)
		sigBytes, err := hex.DecodeString(args.Signature)
		if err != nil {
			return nil, fmt.Errorf("invalid signature hex: %w", err)
		}
		w.writeIntBytes(sigBytes)

		// Keyring revealer
		if args.KeyringRevealer == "certifier" {
			w.writeByte(11)
		} else {
			revealerBytes, err := hex.DecodeString(args.KeyringRevealer)
			if err != nil {
				return nil, fmt.Errorf("invalid keyringRevealer hex: %w", err)
			}
			if len(revealerBytes) != SizeRevealer {
				return nil, fmt.Errorf("keyringRevealer must be %d bytes long", SizeRevealer)
			}
			w.writeBytes(revealerBytes)
		}

		// Keyring for subject
		keyringKeys := make([]string, 0, len(args.KeyringForSubject))
		for k := range args.KeyringForSubject {
			keyringKeys = append(keyringKeys, k)
		}
		w.writeVarInt(uint64(len(keyringKeys)))
		for _, key := range keyringKeys {
			keyBytes := []byte(key)
			w.writeVarInt(uint64(len(keyBytes)))
			w.writeBytes(keyBytes)
			valueBytes, err := base64.StdEncoding.DecodeString(args.KeyringForSubject[key])
			if err != nil {
				return nil, fmt.Errorf("invalid keyringForSubject value base64: %w", err)
			}
			w.writeVarInt(uint64(len(valueBytes)))
			w.writeBytes(valueBytes)
		}
	} else {
		// Certifier URL
		urlBytes := []byte(args.CertifierUrl)
		w.writeVarInt(uint64(len(urlBytes)))
		w.writeBytes(urlBytes)
	}

	return w.buf, nil
}

func DeserializeAcquireCertificateArgs(data []byte) (*wallet.AcquireCertificateArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.AcquireCertificateArgs{}

	// Read type (base64)
	typeBytes := r.readBytes(SizeType)
	args.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read certifier (hex)
	certifierBytes := r.readBytes(SizeCertifier)
	args.Certifier = hex.EncodeToString(certifierBytes)

	// Read fields
	fieldsLength := r.readVarInt()
	if fieldsLength > 0 {
		args.Fields = make(map[string]string, fieldsLength)
	}
	for i := uint64(0); i < fieldsLength; i++ {
		fieldName := string(r.readIntBytes())
		fieldValue := string(r.readIntBytes())

		if r.err != nil {
			return nil, fmt.Errorf("error reading field %s: %w", fieldName, r.err)
		}

		args.Fields[fieldName] = fieldValue
	}

	// Read privileged parameters
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	// Read acquisition protocol
	acquisitionProtocolFlag := r.readByte()
	switch acquisitionProtocolFlag {
	case 1:
		args.AcquisitionProtocol = "direct"
	case 2:
		args.AcquisitionProtocol = "issuance"
	default:
		return nil, fmt.Errorf("invalid acquisition protocol flag: %d", acquisitionProtocolFlag)
	}

	if args.AcquisitionProtocol == "direct" {
		// Read serial number
		serialNumberBytes := r.readBytes(32)
		args.SerialNumber = base64.StdEncoding.EncodeToString(serialNumberBytes)

		// Read revocation outpoint
		outpointBytes := r.readBytes(OutpointSize)
		args.RevocationOutpoint, r.err = decodeOutpoint(outpointBytes)
		if r.err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", r.err)
		}

		// Read signature
		args.Signature = hex.EncodeToString(r.readIntBytes())

		// Read keyring revealer
		keyringRevealerIdentifier := r.readByte()
		if keyringRevealerIdentifier == 11 {
			args.KeyringRevealer = "certifier"
		} else {
			keyringRevealerBytes := append([]byte{keyringRevealerIdentifier}, r.readBytes(SizeRevealer-1)...)
			args.KeyringRevealer = hex.EncodeToString(keyringRevealerBytes)
		}

		// Read keyring for subject
		keyringEntriesLength := r.readVarInt()
		if keyringEntriesLength > 0 {
			args.KeyringForSubject = make(map[string]string, keyringEntriesLength)
		}

		for i := uint64(0); i < keyringEntriesLength; i++ {
			fieldKeyLength := r.readVarInt()
			fieldKeyBytes := r.readBytes(int(fieldKeyLength))
			fieldKey := string(fieldKeyBytes)

			fieldValueLength := r.readVarInt()
			fieldValueBytes := r.readBytes(int(fieldValueLength))
			fieldValue := base64.StdEncoding.EncodeToString(fieldValueBytes)

			args.KeyringForSubject[fieldKey] = fieldValue
			if r.err != nil {
				return nil, fmt.Errorf("error reading keyring for subject %s: %w", fieldKey, r.err)
			}
		}
	} else {
		// Read certifier URL
		certifierUrlLength := r.readVarInt()
		certifierUrlBytes := r.readBytes(int(certifierUrlLength))
		args.CertifierUrl = string(certifierUrlBytes)
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing acquireCertificate args: %w", r.err)
	}

	return args, nil
}

func SerializeCertificate(cert *wallet.Certificate) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)

	// Type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(cert.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	w.writeBytes(typeBytes)

	// Subject (hex)
	subjectBytes, err := hex.DecodeString(cert.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid subject hex: %w", err)
	}
	w.writeBytes(subjectBytes)

	// Serial number (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	w.writeBytes(serialBytes)

	// Certifier (hex)
	certifierBytes, err := hex.DecodeString(cert.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	w.writeBytes(certifierBytes)

	// Revocation outpoint
	outpointBytes, err := encodeOutpoint(cert.RevocationOutpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
	}
	w.writeBytes(outpointBytes)

	// Signature (hex)
	sigBytes, err := hex.DecodeString(cert.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	w.writeVarInt(uint64(len(sigBytes)))
	w.writeBytes(sigBytes)

	// Fields
	fieldEntries := make([]string, 0, len(cert.Fields))
	for k := range cert.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.writeVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		keyBytes := []byte(key)
		w.writeVarInt(uint64(len(keyBytes)))
		w.writeBytes(keyBytes)
		valueBytes := []byte(cert.Fields[key])
		w.writeVarInt(uint64(len(valueBytes)))
		w.writeBytes(valueBytes)
	}

	return w.buf, nil
}

func DeserializeCertificate(data []byte) (*wallet.Certificate, error) {
	r := newReaderHoldError(data)
	cert := &wallet.Certificate{
		Fields: make(map[string]string),
	}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("certificate deserialization failed with error byte %d", errorByte)
	}

	// Read type (base64)
	typeBytes := r.readBytes(32)
	cert.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read subject (hex)
	subjectBytes := r.readBytes(33)
	cert.Subject = hex.EncodeToString(subjectBytes)

	// Read serial number (base64)
	serialBytes := r.readBytes(32)
	cert.SerialNumber = base64.StdEncoding.EncodeToString(serialBytes)

	// Read certifier (hex)
	certifierBytes := r.readBytes(33)
	cert.Certifier = hex.EncodeToString(certifierBytes)

	// Read revocation outpoint
	outpointBytes := r.readBytes(OutpointSize)
	cert.RevocationOutpoint, r.err = decodeOutpoint(outpointBytes)
	if r.err != nil {
		return nil, fmt.Errorf("error decoding outpoint: %w", r.err)
	}

	// Read signature
	signatureLength := r.readVarInt()
	signatureBytes := r.readBytes(int(signatureLength))
	cert.Signature = hex.EncodeToString(signatureBytes)

	// Read fields
	fieldsLength := r.readVarInt()
	for i := uint64(0); i < fieldsLength; i++ {
		fieldNameLength := r.readVarInt()
		fieldNameBytes := r.readBytes(int(fieldNameLength))
		fieldName := string(fieldNameBytes)

		fieldValueLength := r.readVarInt()
		fieldValueBytes := r.readBytes(int(fieldValueLength))
		fieldValue := string(fieldValueBytes)

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

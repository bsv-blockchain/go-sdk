package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeProveCertificateArgs(args *wallet.ProveCertificateArgs) ([]byte, error) {
	w := newWriter()

	// Encode certificate type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(args.Certificate.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != SizeType {
		return nil, fmt.Errorf("type must be %d bytes", SizeType)
	}
	w.writeBytes(typeBytes)

	// Encode subject (hex)
	subjectBytes, err := hex.DecodeString(args.Certificate.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid subject hex: %w", err)
	}
	if len(subjectBytes) != SizeCertifier {
		return nil, fmt.Errorf("subject must be %d bytes", SizeCertifier)
	}
	w.writeBytes(subjectBytes)

	// Encode serialNumber (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(args.Certificate.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	if len(serialBytes) != SizeType {
		return nil, fmt.Errorf("serialNumber must be %d bytes", SizeType)
	}
	w.writeBytes(serialBytes)

	// Encode certifier (hex)
	certifierBytes, err := hex.DecodeString(args.Certificate.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(certifierBytes) != SizeCertifier {
		return nil, fmt.Errorf("certifier must be %d bytes", SizeCertifier)
	}
	w.writeBytes(certifierBytes)

	// Encode revocationOutpoint
	outpointBytes, err := encodeOutpoint(args.Certificate.RevocationOutpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
	}
	w.writeBytes(outpointBytes)

	// Encode signature (hex)
	sigBytes, err := hex.DecodeString(args.Certificate.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	w.writeVarInt(uint64(len(sigBytes)))
	w.writeBytes(sigBytes)

	// Encode fields
	fieldEntries := make([]string, 0, len(args.Certificate.Fields))
	for k := range args.Certificate.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.writeVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		keyBytes := []byte(key)
		w.writeVarInt(uint64(len(keyBytes)))
		w.writeBytes(keyBytes)
		valueBytes := []byte(args.Certificate.Fields[key])
		w.writeVarInt(uint64(len(valueBytes)))
		w.writeBytes(valueBytes)
	}

	// Encode fieldsToReveal
	w.writeVarInt(uint64(len(args.FieldsToReveal)))
	for _, field := range args.FieldsToReveal {
		fieldBytes := []byte(field)
		w.writeVarInt(uint64(len(fieldBytes)))
		w.writeBytes(fieldBytes)
	}

	// Encode verifier (hex)
	verifierBytes, err := hex.DecodeString(args.Verifier)
	if err != nil {
		return nil, fmt.Errorf("invalid verifier hex: %w", err)
	}
	if len(verifierBytes) != SizeCertifier {
		return nil, fmt.Errorf("verifier must be %d bytes", SizeCertifier)
	}
	w.writeBytes(verifierBytes)

	// Encode privileged params
	w.writeBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	return w.buf, nil
}

func DeserializeProveCertificateArgs(data []byte) (*wallet.ProveCertificateArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.ProveCertificateArgs{}

	// Read certificate type (base64)
	typeBytes := r.readBytes(SizeType)
	args.Certificate.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read subject (hex)
	subjectBytes := r.readBytes(SizeCertifier)
	args.Certificate.Subject = hex.EncodeToString(subjectBytes)

	// Read serialNumber (base64)
	serialBytes := r.readBytes(SizeType)
	args.Certificate.SerialNumber = base64.StdEncoding.EncodeToString(serialBytes)

	// Read certifier (hex)
	certifierBytes := r.readBytes(SizeCertifier)
	args.Certificate.Certifier = hex.EncodeToString(certifierBytes)

	// Read revocationOutpoint
	outpointBytes := r.readBytes(OutpointSize)
	args.Certificate.RevocationOutpoint, r.err = decodeOutpoint(outpointBytes)
	if r.err != nil {
		return nil, fmt.Errorf("error decoding outpoint: %w", r.err)
	}

	// Read signature (hex)
	sigLen := r.readVarInt()
	sigBytes := r.readBytes(int(sigLen))
	args.Certificate.Signature = hex.EncodeToString(sigBytes)

	// Read fields
	fieldsLen := r.readVarInt()
	if fieldsLen > 0 {
		args.Certificate.Fields = make(map[string]string, fieldsLen)
	}
	for i := uint64(0); i < fieldsLen; i++ {
		keyLen := r.readVarInt()
		keyBytes := r.readBytes(int(keyLen))
		key := string(keyBytes)

		valueLen := r.readVarInt()
		valueBytes := r.readBytes(int(valueLen))
		value := string(valueBytes)

		args.Certificate.Fields[key] = value
		if r.err != nil {
			return nil, fmt.Errorf("error reading field %s: %w", key, r.err)
		}
	}

	// Read fieldsToReveal
	fieldsToRevealLen := r.readVarInt()
	args.FieldsToReveal = make([]string, 0, fieldsToRevealLen)
	for i := uint64(0); i < fieldsToRevealLen; i++ {
		fieldLen := r.readVarInt()
		fieldBytes := r.readBytes(int(fieldLen))
		args.FieldsToReveal = append(args.FieldsToReveal, string(fieldBytes))
	}

	// Read verifier (hex)
	verifierBytes := r.readBytes(SizeCertifier)
	args.Verifier = hex.EncodeToString(verifierBytes)

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing ProveCertificate args: %w", r.err)
	}

	return args, nil
}

func SerializeProveCertificateResult(result *wallet.ProveCertificateResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)

	// Write keyringForVerifier
	w.writeVarInt(uint64(len(result.KeyringForVerifier)))
	for k, v := range result.KeyringForVerifier {
		keyBytes := []byte(k)
		w.writeVarInt(uint64(len(keyBytes)))
		w.writeBytes(keyBytes)

		valueBytes, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid keyring value base64: %w", err)
		}
		w.writeVarInt(uint64(len(valueBytes)))
		w.writeBytes(valueBytes)
	}

	return w.buf, nil
}

func DeserializeProveCertificateResult(data []byte) (*wallet.ProveCertificateResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.ProveCertificateResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("proveCertificate failed with error byte %d", errorByte)
	}

	// Read keyringForVerifier
	keyringLen := r.readVarInt()
	if keyringLen > 0 {
		result.KeyringForVerifier = make(map[string]string, keyringLen)
	}
	for i := uint64(0); i < keyringLen; i++ {
		keyLen := r.readVarInt()
		keyBytes := r.readBytes(int(keyLen))
		key := string(keyBytes)

		valueLen := r.readVarInt()
		valueBytes := r.readBytes(int(valueLen))
		value := base64.StdEncoding.EncodeToString(valueBytes)

		result.KeyringForVerifier[key] = value
		if r.err != nil {
			return nil, fmt.Errorf("error reading keyring entry %s: %w", key, r.err)
		}
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing ProveCertificate result: %w", r.err)
	}

	return result, nil
}

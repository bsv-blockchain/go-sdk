package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeProveCertificateArgs(args *wallet.ProveCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode certificate type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(args.Certificate.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != SizeType {
		return nil, fmt.Errorf("type must be %d bytes", SizeType)
	}
	w.WriteBytes(typeBytes)
	w.WriteBytes(args.Certificate.Subject.Compressed())

	// Encode serialNumber (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(args.Certificate.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	if len(serialBytes) != SizeType {
		return nil, fmt.Errorf("serialNumber must be %d bytes", SizeType)
	}
	w.WriteBytes(serialBytes)

	w.WriteBytes(args.Certificate.Certifier.Compressed())

	// Encode revocationOutpoint
	outpointBytes, err := encodeOutpoint(args.Certificate.RevocationOutpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
	}
	w.WriteBytes(outpointBytes)

	// Encode signature (hex)
	sigBytes, err := hex.DecodeString(args.Certificate.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	w.WriteVarInt(uint64(len(sigBytes)))
	w.WriteBytes(sigBytes)

	// Encode fields
	fieldEntries := make([]string, 0, len(args.Certificate.Fields))
	for k := range args.Certificate.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.WriteVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		keyBytes := []byte(key)
		w.WriteVarInt(uint64(len(keyBytes)))
		w.WriteBytes(keyBytes)
		valueBytes := []byte(args.Certificate.Fields[key])
		w.WriteVarInt(uint64(len(valueBytes)))
		w.WriteBytes(valueBytes)
	}

	// Encode fieldsToReveal
	w.WriteVarInt(uint64(len(args.FieldsToReveal)))
	for _, field := range args.FieldsToReveal {
		fieldBytes := []byte(field)
		w.WriteVarInt(uint64(len(fieldBytes)))
		w.WriteBytes(fieldBytes)
	}

	// Encode verifier (hex)
	verifierBytes, err := hex.DecodeString(args.Verifier)
	if err != nil {
		return nil, fmt.Errorf("invalid verifier hex: %w", err)
	}
	if len(verifierBytes) != SizeCertifier {
		return nil, fmt.Errorf("verifier must be %d bytes", SizeCertifier)
	}
	w.WriteBytes(verifierBytes)

	// Encode privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	return w.Buf, nil
}

func DeserializeProveCertificateArgs(data []byte) (args *wallet.ProveCertificateArgs, err error) {
	r := util.NewReaderHoldError(data)
	args = &wallet.ProveCertificateArgs{}

	// Read certificate type (base64)
	typeBytes := r.ReadBytes(SizeType)
	args.Certificate.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read subject (hex)
	subjectBytes := r.ReadBytes(SizeCertifier)
	if args.Certificate.Subject, err = ec.PublicKeyFromBytes(subjectBytes); err != nil {
		return nil, err
	}

	// Read serialNumber (base64)
	serialBytes := r.ReadBytes(SizeType)
	args.Certificate.SerialNumber = base64.StdEncoding.EncodeToString(serialBytes)

	// Read certifier (hex)
	certifierBytes := r.ReadBytes(SizeCertifier)
	if args.Certificate.Certifier, err = ec.PublicKeyFromBytes(certifierBytes); err != nil {
		return nil, err
	}

	// Read revocationOutpoint
	outpointBytes := r.ReadBytes(OutpointSize)
	args.Certificate.RevocationOutpoint, err = decodeOutpoint(outpointBytes)
	if err != nil {
		return nil, fmt.Errorf("error decoding outpoint: %w", err)
	}

	// Read signature (hex)
	sigLen := r.ReadVarInt()
	sigBytes := r.ReadBytes(int(sigLen))
	args.Certificate.Signature = hex.EncodeToString(sigBytes)

	// Read fields
	fieldsLen := r.ReadVarInt()
	if fieldsLen > 0 {
		args.Certificate.Fields = make(map[string]string, fieldsLen)
	}
	for i := uint64(0); i < fieldsLen; i++ {
		keyLen := r.ReadVarInt()
		keyBytes := r.ReadBytes(int(keyLen))
		key := string(keyBytes)

		valueLen := r.ReadVarInt()
		valueBytes := r.ReadBytes(int(valueLen))
		value := string(valueBytes)

		args.Certificate.Fields[key] = value
		if r.Err != nil {
			return nil, fmt.Errorf("error reading field %s: %w", key, r.Err)
		}
	}

	// Read fieldsToReveal
	fieldsToRevealLen := r.ReadVarInt()
	args.FieldsToReveal = make([]string, 0, fieldsToRevealLen)
	for i := uint64(0); i < fieldsToRevealLen; i++ {
		fieldLen := r.ReadVarInt()
		fieldBytes := r.ReadBytes(int(fieldLen))
		args.FieldsToReveal = append(args.FieldsToReveal, string(fieldBytes))
	}

	// Read verifier (hex)
	verifierBytes := r.ReadBytes(SizeCertifier)
	args.Verifier = hex.EncodeToString(verifierBytes)

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing ProveCertificate args: %w", r.Err)
	}

	return args, nil
}

func SerializeProveCertificateResult(result *wallet.ProveCertificateResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)

	// Write keyringForVerifier
	w.WriteVarInt(uint64(len(result.KeyringForVerifier)))
	for k, v := range result.KeyringForVerifier {
		keyBytes := []byte(k)
		w.WriteVarInt(uint64(len(keyBytes)))
		w.WriteBytes(keyBytes)

		valueBytes, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid keyring value base64: %w", err)
		}
		w.WriteVarInt(uint64(len(valueBytes)))
		w.WriteBytes(valueBytes)
	}

	return w.Buf, nil
}

func DeserializeProveCertificateResult(data []byte) (*wallet.ProveCertificateResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ProveCertificateResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("proveCertificate failed with error byte %d", errorByte)
	}

	// Read keyringForVerifier
	keyringLen := r.ReadVarInt()
	if keyringLen > 0 {
		result.KeyringForVerifier = make(map[string]string, keyringLen)
	}
	for i := uint64(0); i < keyringLen; i++ {
		keyLen := r.ReadVarInt()
		keyBytes := r.ReadBytes(int(keyLen))
		key := string(keyBytes)

		valueLen := r.ReadVarInt()
		valueBytes := r.ReadBytes(int(valueLen))
		value := base64.StdEncoding.EncodeToString(valueBytes)

		result.KeyringForVerifier[key] = value
		if r.Err != nil {
			return nil, fmt.Errorf("error reading keyring entry %s: %w", key, r.Err)
		}
	}

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing ProveCertificate result: %w", r.Err)
	}

	return result, nil
}

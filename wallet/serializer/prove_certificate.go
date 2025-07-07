package serializer

import (
	"fmt"
	"sort"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeProveCertificateArgs(args *wallet.ProveCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode certificate type (base64)
	if args.Certificate.Type == [32]byte{} {
		return nil, fmt.Errorf("certificate type is empty")
	}
	w.WriteBytes(args.Certificate.Type[:])
	w.WriteBytes(args.Certificate.Subject.Compressed())
	w.WriteBytes(args.Certificate.SerialNumber[:])
	w.WriteBytes(args.Certificate.Certifier.Compressed())

	// Encode revocationOutpoint
	w.WriteBytes(encodeOutpoint(args.Certificate.RevocationOutpoint))

	// Encode signature (hex)
	if args.Certificate.Signature != nil {
		w.WriteIntBytes(args.Certificate.Signature.Serialize())
	} else {
		w.WriteIntBytes(nil)
	}

	// Encode fields
	fieldEntries := make([]string, 0, len(args.Certificate.Fields))
	for k := range args.Certificate.Fields {
		fieldEntries = append(fieldEntries, k)
	}

	// Sort field entries for consistent serialization
	sort.Strings(fieldEntries)

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
	w.WriteBytes(args.Verifier.Compressed())

	// Encode privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	return w.Buf, nil
}

func DeserializeProveCertificateArgs(data []byte) (args *wallet.ProveCertificateArgs, err error) {
	r := util.NewReaderHoldError(data)
	args = &wallet.ProveCertificateArgs{}

	// Read certificate type (base64)
	copy(args.Certificate.Type[:], r.ReadBytes(sizeType))

	// Read subject (hex)
	subjectBytes := r.ReadBytes(sizePubKey)
	if args.Certificate.Subject, err = ec.PublicKeyFromBytes(subjectBytes); err != nil {
		return nil, err
	}

	// Read serialNumber (base64)
	copy(args.Certificate.SerialNumber[:], r.ReadBytes(sizeSerial))

	// Read certifier (hex)
	certifierBytes := r.ReadBytes(sizePubKey)
	if args.Certificate.Certifier, err = ec.PublicKeyFromBytes(certifierBytes); err != nil {
		return nil, err
	}

	// Read revocationOutpoint
	args.Certificate.RevocationOutpoint, err = decodeOutpoint(&r.Reader)
	if err != nil {
		return nil, fmt.Errorf("error decoding outpoint: %w", err)
	}

	// Read signature (hex)
	sigBytes := r.ReadIntBytes()
	if len(sigBytes) > 0 {
		args.Certificate.Signature, err = ec.ParseSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing signature: %w", err)
		}
	}

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

	// Read verifier
	verifierBytes := r.ReadBytes(sizePubKey)
	if r.Err != nil {
		return nil, fmt.Errorf("error reading verifier: %w", r.Err)
	}
	parsedVerifier, err := ec.PublicKeyFromBytes(verifierBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing verifier public key: %w", err)
	}
	args.Verifier = parsedVerifier

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing ProveCertificate args: %w", r.Err)
	}

	return args, nil
}

func SerializeProveCertificateResult(result *wallet.ProveCertificateResult) ([]byte, error) {
	w := util.NewWriter()

	// Write keyringForVerifier
	w.WriteVarInt(uint64(len(result.KeyringForVerifier)))
	for k, v := range result.KeyringForVerifier {
		keyBytes := []byte(k)
		w.WriteVarInt(uint64(len(keyBytes)))
		w.WriteBytes(keyBytes)

		if err := w.WriteIntFromBase64(v); err != nil {
			return nil, fmt.Errorf("invalid keyring value base64: %w", err)
		}
	}

	return w.Buf, nil
}

func DeserializeProveCertificateResult(data []byte) (*wallet.ProveCertificateResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ProveCertificateResult{}

	// Read keyringForVerifier
	keyringLen := r.ReadVarInt()
	if keyringLen > 0 {
		result.KeyringForVerifier = make(map[string]string, keyringLen)
	}
	for i := uint64(0); i < keyringLen; i++ {
		keyLen := r.ReadVarInt()
		keyBytes := r.ReadBytes(int(keyLen))
		key := string(keyBytes)

		result.KeyringForVerifier[key] = r.ReadBase64Int()

		if r.Err != nil {
			return nil, fmt.Errorf("error reading keyring entry %s: %w", key, r.Err)
		}
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing ProveCertificate result: %w", r.Err)
	}

	return result, nil
}

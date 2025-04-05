package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"math"
)

func SerializeListCertificatesArgs(args *wallet.ListCertificatesArgs) ([]byte, error) {
	w := newWriter()

	// Write certifiers
	w.writeVarInt(uint64(len(args.Certifiers)))
	for _, certifier := range args.Certifiers {
		certifierBytes, err := hex.DecodeString(certifier)
		if err != nil {
			return nil, fmt.Errorf("invalid certifier hex: %w", err)
		}
		if len(certifierBytes) != SizeCertifier {
			return nil, fmt.Errorf("certifier should be %d bytes, got %d", SizeCertifier, len(certifierBytes))
		}
		w.writeBytes(certifierBytes)
	}

	// Write types
	w.writeVarInt(uint64(len(args.Types)))
	for _, typ := range args.Types {
		typeBytes, err := base64.StdEncoding.DecodeString(typ)
		if err != nil {
			return nil, fmt.Errorf("invalid type base64: %w", err)
		}
		if len(typeBytes) != SizeType {
			return nil, fmt.Errorf("type should be %d bytes, got %d", SizeType, len(typeBytes))
		}
		w.writeBytes(typeBytes)
	}

	// Write limit (or max uint64 if undefined)
	if args.Limit > 0 {
		w.writeVarInt(uint64(args.Limit))
	} else {
		w.writeVarInt(math.MaxUint64)
	}

	// Write offset (or max uint64 if undefined)
	if args.Offset > 0 {
		w.writeVarInt(uint64(args.Offset))
	} else {
		w.writeVarInt(math.MaxUint64)
	}

	// Write privileged params
	w.writeBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	return w.buf, nil
}

func DeserializeListCertificatesArgs(data []byte) (*wallet.ListCertificatesArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.ListCertificatesArgs{}

	// Read certifiers
	certifiersLength := r.readVarInt()
	args.Certifiers = make([]string, 0, certifiersLength)
	for i := uint64(0); i < certifiersLength; i++ {
		certifierBytes := r.readBytes(SizeCertifier)
		if r.err != nil {
			return nil, fmt.Errorf("error deserializing certifier: %w", r.err)
		}
		args.Certifiers = append(args.Certifiers, hex.EncodeToString(certifierBytes))
	}

	// Read types
	typesLength := r.readVarInt()
	args.Types = make([]string, 0, typesLength)
	for i := uint64(0); i < typesLength; i++ {
		typeBytes := r.readBytes(SizeType)
		if r.err != nil {
			return nil, fmt.Errorf("error deserializing type: %w", r.err)
		}
		args.Types = append(args.Types, base64.StdEncoding.EncodeToString(typeBytes))
	}

	// Read limit
	limit := r.readVarInt()
	if limit != math.MaxUint64 {
		args.Limit = uint32(limit)
	}

	// Read offset
	offset := r.readVarInt()
	if offset != math.MaxUint64 {
		args.Offset = uint32(offset)
	}

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing ListCertificates args: %w", r.err)
	}

	return args, nil
}

func SerializeListCertificatesResult(result *wallet.ListCertificatesResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)

	// Write total certificates
	w.writeVarInt(uint64(result.TotalCertificates))

	// Write certificates
	w.writeVarInt(uint64(len(result.Certificates)))
	for _, cert := range result.Certificates {
		certBytes, err := SerializeCertificate(&cert.Certificate)
		if err != nil {
			return nil, fmt.Errorf("error serializing certificate: %w", err)
		}
		w.writeIntBytes(certBytes)

		// Write keyring if present
		if cert.Keyring != nil {
			w.writeByte(1) // present
			w.writeVarInt(uint64(len(cert.Keyring)))
			for k, v := range cert.Keyring {
				w.writeString(k)
				w.writeString(v)
			}
		} else {
			w.writeByte(0) // not present
		}

		// Write verifier if present
		if cert.Verifier != "" {
			w.writeByte(1) // present
			w.writeString(cert.Verifier)
		} else {
			w.writeByte(0) // not present
		}
	}

	return w.buf, nil
}

func DeserializeListCertificatesResult(data []byte) (*wallet.ListCertificatesResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.ListCertificatesResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("listCertificates failed with error byte %d", errorByte)
	}

	// Read total certificates
	result.TotalCertificates = uint32(r.readVarInt())

	// Read certificates
	certCount := r.readVarInt()
	if certCount > 0 {
		result.Certificates = make([]wallet.CertificateResult, 0, certCount)
	}
	for i := uint64(0); i < certCount; i++ {
		cert, err := DeserializeCertificate(r.readIntBytes())
		if err != nil {
			return nil, fmt.Errorf("error deserializing certificate: %w", err)
		}

		certResult := wallet.CertificateResult{Certificate: *cert}

		// Read keyring if present
		if r.readByte() == 1 {
			keyringLen := r.readVarInt()
			if keyringLen > 0 {
				certResult.Keyring = make(map[string]string, keyringLen)
			}
			for j := uint64(0); j < keyringLen; j++ {
				key := r.readString()
				value := r.readString()
				certResult.Keyring[key] = value
			}
		}

		// Read verifier if present
		if r.readByte() == 1 {
			certResult.Verifier = r.readString()
		}

		result.Certificates = append(result.Certificates, certResult)
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing ListCertificates result: %w", r.err)
	}

	return result, nil
}

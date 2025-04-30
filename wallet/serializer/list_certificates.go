package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeListCertificatesArgs(args *wallet.ListCertificatesArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write certifiers
	w.WriteVarInt(uint64(len(args.Certifiers)))
	for _, certifier := range args.Certifiers {
		certifierBytes, err := hex.DecodeString(certifier)
		if err != nil {
			return nil, fmt.Errorf("invalid certifier hex: %w", err)
		}
		if len(certifierBytes) != sizeCertifier {
			return nil, fmt.Errorf("certifier should be %d bytes, got %d", sizeCertifier, len(certifierBytes))
		}
		w.WriteBytes(certifierBytes)
	}

	// Write types
	w.WriteVarInt(uint64(len(args.Types)))
	for _, typ := range args.Types {
		typeBytes, err := base64.StdEncoding.DecodeString(typ)
		if err != nil {
			return nil, fmt.Errorf("invalid type base64: %w", err)
		}
		if len(typeBytes) != sizeType {
			return nil, fmt.Errorf("type should be %d bytes, got %d", sizeType, len(typeBytes))
		}
		w.WriteBytes(typeBytes)
	}

	// Write limit (or max uint64 if undefined)
	if args.Limit > 0 {
		w.WriteVarInt(uint64(args.Limit))
	} else {
		w.WriteVarInt(math.MaxUint64)
	}

	// Write offset (or max uint64 if undefined)
	if args.Offset > 0 {
		w.WriteVarInt(uint64(args.Offset))
	} else {
		w.WriteVarInt(math.MaxUint64)
	}

	// Write privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	return w.Buf, nil
}

func DeserializeListCertificatesArgs(data []byte) (*wallet.ListCertificatesArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.ListCertificatesArgs{}

	// Read certifiers
	certifiersLength := r.ReadVarInt()
	args.Certifiers = make([]string, 0, certifiersLength)
	for i := uint64(0); i < certifiersLength; i++ {
		certifierBytes := r.ReadBytes(sizeCertifier)
		if r.Err != nil {
			return nil, fmt.Errorf("error deserializing certifier: %w", r.Err)
		}
		args.Certifiers = append(args.Certifiers, hex.EncodeToString(certifierBytes))
	}

	// Read types
	typesLength := r.ReadVarInt()
	args.Types = make([]string, 0, typesLength)
	for i := uint64(0); i < typesLength; i++ {
		typeBytes := r.ReadBytes(sizeType)
		if r.Err != nil {
			return nil, fmt.Errorf("error deserializing type: %w", r.Err)
		}
		args.Types = append(args.Types, base64.StdEncoding.EncodeToString(typeBytes))
	}

	// Read limit
	limit := r.ReadVarInt()
	if limit != math.MaxUint64 {
		args.Limit = uint32(limit)
	}

	// Read offset
	offset := r.ReadVarInt()
	if offset != math.MaxUint64 {
		args.Offset = uint32(offset)
	}

	// Read privileged params
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing ListCertificates args: %w", r.Err)
	}

	return args, nil
}

func SerializeListCertificatesResult(result *wallet.ListCertificatesResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)

	// Write total certificates
	w.WriteVarInt(uint64(result.TotalCertificates))

	// Write certificates
	w.WriteVarInt(uint64(len(result.Certificates)))
	for _, cert := range result.Certificates {
		certBytes, err := SerializeCertificate(&cert.Certificate)
		if err != nil {
			return nil, fmt.Errorf("error serializing certificate: %w", err)
		}
		w.WriteIntBytes(certBytes)

		// Write keyring if present
		if cert.Keyring != nil {
			w.WriteByte(1) // present
			w.WriteVarInt(uint64(len(cert.Keyring)))
			for k, v := range cert.Keyring {
				w.WriteString(k)
				w.WriteString(v)
			}
		} else {
			w.WriteByte(0) // not present
		}

		// Write verifier if present
		if cert.Verifier != "" {
			w.WriteByte(1) // present
			w.WriteString(cert.Verifier)
		} else {
			w.WriteByte(0) // not present
		}
	}

	return w.Buf, nil
}

func DeserializeListCertificatesResult(data []byte) (*wallet.ListCertificatesResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.ListCertificatesResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("listCertificates failed with error byte %d", errorByte)
	}

	// Read total certificates
	result.TotalCertificates = uint32(r.ReadVarInt())

	// Read certificates
	certCount := r.ReadVarInt()
	if certCount > 0 {
		result.Certificates = make([]wallet.CertificateResult, 0, certCount)
	}
	for i := uint64(0); i < certCount; i++ {
		cert, err := DeserializeCertificate(r.ReadIntBytes())
		if err != nil {
			return nil, fmt.Errorf("error deserializing certificate: %w", err)
		}

		certResult := wallet.CertificateResult{Certificate: *cert}

		// Read keyring if present
		if r.ReadByte() == 1 {
			keyringLen := r.ReadVarInt()
			if keyringLen > 0 {
				certResult.Keyring = make(map[string]string, keyringLen)
			}
			for j := uint64(0); j < keyringLen; j++ {
				key := r.ReadString()
				value := r.ReadString()
				certResult.Keyring[key] = value
			}
		}

		// Read verifier if present
		if r.ReadByte() == 1 {
			certResult.Verifier = r.ReadString()
		}

		result.Certificates = append(result.Certificates, certResult)
	}

	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing ListCertificates result: %w", r.Err)
	}

	return result, nil
}

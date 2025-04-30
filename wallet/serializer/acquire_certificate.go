package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	AcquisitionProtocolDirect   = 1
	AcquisitionProtocolIssuance = 2

	KeyRingRevealerCertifier = 11
)

func SerializeAcquireCertificateArgs(args *wallet.AcquireCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(args.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != sizeType {
		return nil, fmt.Errorf("type must be %d bytes long", sizeType)
	}
	w.WriteBytes(typeBytes)

	// Encode certifier (hex)
	certifierBytes, err := hex.DecodeString(args.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(certifierBytes) != sizeCertifier {
		return nil, fmt.Errorf("certifier must be %d bytes long", sizeCertifier)
	}
	w.WriteBytes(certifierBytes)

	// Encode fields
	fieldEntries := make([]string, 0, len(args.Fields))
	// TODO: Iterating over maps doesn't guarantee order to be consistent
	for k := range args.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	w.WriteVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		keyBytes := []byte(key)
		w.WriteVarInt(uint64(len(keyBytes)))
		w.WriteBytes(keyBytes)
		valueBytes := []byte(args.Fields[key])
		w.WriteVarInt(uint64(len(valueBytes)))
		w.WriteBytes(valueBytes)
	}

	// Encode privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	// Encode acquisition protocol (1 = direct, 2 = issuance)
	if args.AcquisitionProtocol == "direct" {
		w.WriteByte(AcquisitionProtocolDirect)
	} else {
		w.WriteByte(AcquisitionProtocolIssuance)
	}

	if args.AcquisitionProtocol == "direct" {
		// Serial number (base64)
		serialBytes, err := base64.StdEncoding.DecodeString(args.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
		}
		if len(serialBytes) != sizeSerial {
			return nil, fmt.Errorf("serialNumber must be %d bytes long", sizeSerial)
		}
		w.WriteBytes(serialBytes)

		// Revocation outpoint
		outpointBytes, err := encodeOutpoint(args.RevocationOutpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid revocationOutpoint: %w", err)
		}
		w.WriteBytes(outpointBytes)

		// Signature (hex)
		sigBytes, err := hex.DecodeString(args.Signature)
		if err != nil {
			return nil, fmt.Errorf("invalid signature hex: %w", err)
		}
		w.WriteIntBytes(sigBytes)

		// Keyring revealer
		if args.KeyringRevealer == "certifier" {
			w.WriteByte(KeyRingRevealerCertifier)
		} else {
			revealerBytes, err := hex.DecodeString(args.KeyringRevealer)
			if err != nil {
				return nil, fmt.Errorf("invalid keyringRevealer hex: %w", err)
			}
			if len(revealerBytes) != sizeRevealer {
				return nil, fmt.Errorf("keyringRevealer must be %d bytes long", sizeRevealer)
			}
			w.WriteBytes(revealerBytes)
		}

		// Keyring for subject
		keyringKeys := make([]string, 0, len(args.KeyringForSubject))
		for k := range args.KeyringForSubject {
			keyringKeys = append(keyringKeys, k)
		}
		w.WriteVarInt(uint64(len(keyringKeys)))
		for _, key := range keyringKeys {
			keyBytes := []byte(key)
			w.WriteVarInt(uint64(len(keyBytes)))
			w.WriteBytes(keyBytes)
			valueBytes, err := base64.StdEncoding.DecodeString(args.KeyringForSubject[key])
			if err != nil {
				return nil, fmt.Errorf("invalid keyringForSubject value base64: %w", err)
			}
			w.WriteVarInt(uint64(len(valueBytes)))
			w.WriteBytes(valueBytes)
		}
	} else {
		// Certifier URL
		urlBytes := []byte(args.CertifierUrl)
		w.WriteVarInt(uint64(len(urlBytes)))
		w.WriteBytes(urlBytes)
	}

	return w.Buf, nil
}

func DeserializeAcquireCertificateArgs(data []byte) (*wallet.AcquireCertificateArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.AcquireCertificateArgs{}

	// Read type (base64)
	typeBytes := r.ReadBytes(sizeType)
	args.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read certifier (hex)
	certifierBytes := r.ReadBytes(sizeCertifier)
	args.Certifier = hex.EncodeToString(certifierBytes)

	// Read fields
	fieldsLength := r.ReadVarInt()
	if fieldsLength > 0 {
		args.Fields = make(map[string]string, fieldsLength)
	}
	for i := uint64(0); i < fieldsLength; i++ {
		fieldName := string(r.ReadIntBytes())
		fieldValue := string(r.ReadIntBytes())

		if r.Err != nil {
			return nil, fmt.Errorf("error reading field %s: %w", fieldName, r.Err)
		}

		args.Fields[fieldName] = fieldValue
	}

	// Read privileged parameters
	args.Privileged, args.PrivilegedReason = decodePrivilegedParams(r)

	// Read acquisition protocol
	acquisitionProtocolFlag := r.ReadByte()
	switch acquisitionProtocolFlag {
	case AcquisitionProtocolDirect:
		args.AcquisitionProtocol = "direct"
	case AcquisitionProtocolIssuance:
		args.AcquisitionProtocol = "issuance"
	default:
		return nil, fmt.Errorf("invalid acquisition protocol flag: %d", acquisitionProtocolFlag)
	}

	if args.AcquisitionProtocol == "direct" {
		// Read serial number
		serialNumberBytes := r.ReadBytes(sizeSerial)
		args.SerialNumber = base64.StdEncoding.EncodeToString(serialNumberBytes)

		// Read revocation outpoint
		outpointBytes := r.ReadBytes(OutpointSize)
		args.RevocationOutpoint, r.Err = decodeOutpoint(outpointBytes)
		if r.Err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", r.Err)
		}

		// Read signature
		args.Signature = hex.EncodeToString(r.ReadIntBytes())

		// Read keyring revealer
		keyringRevealerIdentifier := r.ReadByte()
		if keyringRevealerIdentifier == KeyRingRevealerCertifier {
			args.KeyringRevealer = "certifier"
		} else {
			keyringRevealerBytes := append([]byte{keyringRevealerIdentifier}, r.ReadBytes(sizeRevealer-1)...)
			args.KeyringRevealer = hex.EncodeToString(keyringRevealerBytes)
		}

		// Read keyring for subject
		keyringEntriesLength := r.ReadVarInt()
		if keyringEntriesLength > 0 {
			args.KeyringForSubject = make(map[string]string, keyringEntriesLength)
		}

		for i := uint64(0); i < keyringEntriesLength; i++ {
			fieldKeyLength := r.ReadVarInt()
			fieldKeyBytes := r.ReadBytes(int(fieldKeyLength))
			fieldKey := string(fieldKeyBytes)

			fieldValueLength := r.ReadVarInt()
			fieldValueBytes := r.ReadBytes(int(fieldValueLength))
			fieldValue := base64.StdEncoding.EncodeToString(fieldValueBytes)

			args.KeyringForSubject[fieldKey] = fieldValue
			if r.Err != nil {
				return nil, fmt.Errorf("error reading keyring for subject %s: %w", fieldKey, r.Err)
			}
		}
	} else {
		// Read certifier URL
		certifierUrlLength := r.ReadVarInt()
		certifierUrlBytes := r.ReadBytes(int(certifierUrlLength))
		args.CertifierUrl = string(certifierUrlBytes)
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing acquireCertificate args: %w", r.Err)
	}

	return args, nil
}

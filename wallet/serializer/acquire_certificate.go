package serializer

import (
	"fmt"
	"sort"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	acquisitionProtocolDirect   = 1
	acquisitionProtocolIssuance = 2

	keyRingRevealerCertifier = 11
)

func SerializeAcquireCertificateArgs(args *wallet.AcquireCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode type (base64)
	w.WriteBytes(args.Type[:])

	// Encode certifier (hex)
	w.WriteBytes(args.Certifier.Compressed())

	// Encode fields
	fieldEntries := make([]string, 0, len(args.Fields))
	// TODO: Iterating over maps doesn't guarantee order to be consistent
	for k := range args.Fields {
		fieldEntries = append(fieldEntries, k)
	}
	sort.Slice(fieldEntries, func(i, j int) bool {
		return fieldEntries[i] < fieldEntries[j]
	})
	w.WriteVarInt(uint64(len(fieldEntries)))
	for _, key := range fieldEntries {
		w.WriteString(key)
		w.WriteString(args.Fields[key])
	}

	// Encode privileged params
	w.WriteBytes(encodePrivilegedParams(args.Privileged, args.PrivilegedReason))

	// Encode acquisition protocol (1 = direct, 2 = issuance)
	switch args.AcquisitionProtocol {
	case wallet.AcquisitionProtocolDirect:
		w.WriteByte(acquisitionProtocolDirect)
		// Serial number (base64)
		if args.SerialNumber == nil {
			return nil, fmt.Errorf("serialNumber is empty")
		}
		w.WriteBytes(args.SerialNumber[:])

		// Revocation outpoint
		w.WriteBytes(encodeOutpoint(args.RevocationOutpoint))

		// Signature (hex)
		var sigBytes []byte
		if args.Signature != nil {
			sigBytes = args.Signature.Serialize()
		}
		w.WriteIntBytes(sigBytes)

		// Keyring revealer
		if args.KeyringRevealer == nil {
			return nil, fmt.Errorf("keyringRevealer cannot be nil")
		}
		if args.KeyringRevealer.Certifier {
			w.WriteByte(keyRingRevealerCertifier)
		} else {
			if args.KeyringRevealer.PubKey == nil {
				return nil, fmt.Errorf("keyringRevealer PubKey cannot be nil if not certifier")
			}
			w.WriteBytes(args.KeyringRevealer.PubKey.Compressed())
		}

		// Keyring for subject
		keyringKeys := make([]string, 0, len(args.KeyringForSubject))
		for k := range args.KeyringForSubject {
			keyringKeys = append(keyringKeys, k)
		}
		w.WriteVarInt(uint64(len(keyringKeys)))
		for _, key := range keyringKeys {
			w.WriteIntBytes([]byte(key))
			if err := w.WriteIntFromBase64(args.KeyringForSubject[key]); err != nil {
				return nil, fmt.Errorf("invalid keyringForSubject value base64: %w", err)
			}
		}
	case wallet.AcquisitionProtocolIssuance:
		w.WriteByte(acquisitionProtocolIssuance)
		// Certifier URL
		w.WriteString(args.CertifierUrl)
	default:
		return nil, fmt.Errorf("invalid acquisition protocol: %s", args.AcquisitionProtocol)
	}

	return w.Buf, nil
}

func DeserializeAcquireCertificateArgs(data []byte) (*wallet.AcquireCertificateArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.AcquireCertificateArgs{}

	// Read type (base64) and certifier (hex)
	copy(args.Type[:], r.ReadBytes(sizeType))
	parsedCertifier, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing certifier public key: %w", err)
	}
	args.Certifier = parsedCertifier

	// Read fields
	fieldsLength := r.ReadVarInt()
	if fieldsLength > 0 {
		args.Fields = make(map[string]string, fieldsLength)
	}
	for i := uint64(0); i < fieldsLength; i++ {
		fieldName := r.ReadString()
		fieldValue := r.ReadString()

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
	case acquisitionProtocolDirect:
		args.AcquisitionProtocol = wallet.AcquisitionProtocolDirect
	case acquisitionProtocolIssuance:
		args.AcquisitionProtocol = wallet.AcquisitionProtocolIssuance
	default:
		return nil, fmt.Errorf("invalid acquisition protocol flag: %d", acquisitionProtocolFlag)
	}

	if args.AcquisitionProtocol == wallet.AcquisitionProtocolDirect {
		// Read serial number
		args.SerialNumber = new(wallet.SerialNumber)
		copy(args.SerialNumber[:], r.ReadBytes(sizeSerial))

		// Read revocation outpoint
		revocationOutpoint, err := decodeOutpoint(&r.Reader)
		if err != nil {
			return nil, fmt.Errorf("error decoding outpoint: %w", err)
		}
		args.RevocationOutpoint = revocationOutpoint

		// Read signature
		sigBytes := r.ReadIntBytes()
		if len(sigBytes) > 0 {
			sig, err := ec.ParseSignature(sigBytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing signature: %w", err)
			}
			args.Signature = sig
		}

		// Read keyring revealer
		keyringRevealerIdentifier := r.ReadByte()
		if keyringRevealerIdentifier == keyRingRevealerCertifier {
			args.KeyringRevealer = &wallet.KeyringRevealer{
				Certifier: true,
			}
		} else {
			// The keyringRevealerIdentifier is the first byte of the PubKey
			keyringRevealerFullBytes := append([]byte{keyringRevealerIdentifier}, r.ReadBytes(sizePubKey-1)...)
			parsedKeyringPubKey, err := ec.PublicKeyFromBytes(keyringRevealerFullBytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing keyring revealer public key: %w", err)
			}
			args.KeyringRevealer = &wallet.KeyringRevealer{PubKey: parsedKeyringPubKey}
		}

		// Read keyring for subject
		keyringEntriesLength := r.ReadVarInt()
		if keyringEntriesLength > 0 {
			args.KeyringForSubject = make(map[string]string, keyringEntriesLength)
		}

		for i := uint64(0); i < keyringEntriesLength; i++ {
			fieldKey := r.ReadString()
			args.KeyringForSubject[fieldKey] = r.ReadBase64Int()
			if r.Err != nil {
				return nil, fmt.Errorf("error reading keyring for subject %s: %w", fieldKey, r.Err)
			}
		}
	} else {
		// Read certifier URL
		args.CertifierUrl = r.ReadString()
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing acquireCertificate args: %w", r.Err)
	}

	return args, nil
}

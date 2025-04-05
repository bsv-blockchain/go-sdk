package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverByIdentityKeyArgs(args *wallet.DiscoverByIdentityKeyArgs) ([]byte, error) {
	w := newWriter()

	// Write identity key (33 bytes)
	identityKeyBytes, err := hex.DecodeString(args.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identityKey hex: %w", err)
	}
	if len(identityKeyBytes) != 33 {
		return nil, fmt.Errorf("identityKey must be 33 bytes")
	}
	w.writeBytes(identityKeyBytes)

	// Write limit, offset, seek permission
	w.writeOptionalUint32(args.Limit)
	w.writeOptionalUint32(args.Offset)
	w.writeOptionalBool(args.SeekPermission)

	return w.buf, nil
}

func DeserializeDiscoverByIdentityKeyArgs(data []byte) (*wallet.DiscoverByIdentityKeyArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.DiscoverByIdentityKeyArgs{}

	// Read identity key (33 bytes)
	identityKeyBytes := r.readBytes(33)
	args.IdentityKey = hex.EncodeToString(identityKeyBytes)

	// Read limit (varint) or 9 bytes of 0xFF if undefined
	args.Limit = r.readOptionalUint32()
	args.Offset = r.readOptionalUint32()
	args.SeekPermission = r.readOptionalBool()

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverByIdentityKey args: %w", r.err)
	}

	return args, nil
}

func SerializeDiscoverCertificatesResult(result *wallet.DiscoverCertificatesResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)

	// Write total certificates
	w.writeVarInt(uint64(result.TotalCertificates))

	// Write certificates
	w.writeVarInt(uint64(len(result.Certificates)))
	for _, cert := range result.Certificates {
		certBytes, err := SerializeIdentityCertificate(&cert)
		if err != nil {
			return nil, fmt.Errorf("error serializing certificate: %w", err)
		}
		w.writeIntBytes(certBytes)
	}

	return w.buf, nil
}

func DeserializeDiscoverCertificatesResult(data []byte) (*wallet.DiscoverCertificatesResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.DiscoverCertificatesResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("discoverByIdentityKey failed with error byte %d", errorByte)
	}

	// Read total certificates
	result.TotalCertificates = uint32(r.readVarInt())

	// Read certificates
	certCount := r.readVarInt()
	if certCount > 0 {
		result.Certificates = make([]wallet.IdentityCertificate, 0, certCount)
	}
	for i := uint64(0); i < certCount; i++ {
		certBytes := r.readIntBytes()
		cert, err := DeserializeIdentityCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("error deserializing certificate: %w", err)
		}
		result.Certificates = append(result.Certificates, *cert)
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverCertificates result: %w", r.err)
	}

	return result, nil
}

package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

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

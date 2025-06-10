package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverCertificatesResult(result *wallet.DiscoverCertificatesResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)

	// Write total certificates
	w.WriteVarInt(uint64(result.TotalCertificates))

	// Write certificates
	w.WriteVarInt(uint64(len(result.Certificates)))
	for _, cert := range result.Certificates {
		certBytes, err := SerializeIdentityCertificate(&cert)
		if err != nil {
			return nil, fmt.Errorf("error serializing certificate: %w", err)
		}
		w.WriteIntBytes(certBytes)
	}

	return w.Buf, nil
}

func DeserializeDiscoverCertificatesResult(data []byte) (*wallet.DiscoverCertificatesResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.DiscoverCertificatesResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("discoverByIdentityKey failed with error byte %d", errorByte)
	}

	// Read total certificates
	result.TotalCertificates = uint32(r.ReadVarInt())

	// Read certificates
	certCount := r.ReadVarInt()
	if certCount > 0 {
		result.Certificates = make([]wallet.IdentityCertificate, 0, certCount)
	}
	for i := uint64(0); i < certCount; i++ {
		certBytes := r.ReadIntBytes()
		cert, err := DeserializeIdentityCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("error deserializing certificate: %w", err)
		}
		result.Certificates = append(result.Certificates, *cert)
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing DiscoverCertificates result: %w", r.Err)
	}

	return result, nil
}

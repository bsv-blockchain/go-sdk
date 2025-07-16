package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeDiscoverCertificatesResult(result *wallet.DiscoverCertificatesResult) ([]byte, error) {
	w := util.NewWriter()

	if result.TotalCertificates != uint32(len(result.Certificates)) {
		return nil, fmt.Errorf("total certificates %d does not match length of certificates slice %d", result.TotalCertificates, len(result.Certificates))
	}

	// Write total certificates
	w.WriteVarInt(uint64(result.TotalCertificates))

	// Write certificates
	for _, cert := range result.Certificates {
		certBytes, err := SerializeIdentityCertificate(&cert)
		if err != nil {
			return nil, fmt.Errorf("error serializing certificate: %w", err)
		}
		w.WriteBytes(certBytes)
	}

	return w.Buf, nil
}

func DeserializeDiscoverCertificatesResult(data []byte) (*wallet.DiscoverCertificatesResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.DiscoverCertificatesResult{}

	// Read total certificates
	result.TotalCertificates = uint32(r.ReadVarInt())

	// Read certificates
	if result.TotalCertificates > 0 {
		result.Certificates = make([]wallet.IdentityCertificate, 0, result.TotalCertificates)
	}
	for i := uint32(0); i < result.TotalCertificates; i++ {
		cert, err := DeserializeIdentityCertificate(r)
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

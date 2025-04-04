package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeAcquireCertificateArgs(args *wallet.AcquireCertificateArgs) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func DeserializeAcquireCertificateArgs(data []byte) (*wallet.AcquireCertificateArgs, error) {
	return nil, fmt.Errorf("not implemented")
}

func SerializeCertificate(result *wallet.Certificate) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func DeserializeCertificate(data []byte) (*wallet.Certificate, error) {
	return nil, fmt.Errorf("not implemented")
}

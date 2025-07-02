package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRelinquishCertificateArgs(args *wallet.RelinquishCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode type (base64)
	if args.Type == [32]byte{} {
		return nil, fmt.Errorf("type is empty")
	}
	w.WriteBytes(args.Type[:])

	// Encode serialNumber (base64)
	if args.SerialNumber == [32]byte{} {
		return nil, fmt.Errorf("serialNumber is empty")
	}
	w.WriteBytes(args.SerialNumber[:])

	// Encode certifier (hex)
	if args.Certifier == nil {
		return nil, fmt.Errorf("certifier is empty")
	}
	w.WriteBytes(args.Certifier.Compressed())

	return w.Buf, nil
}

func DeserializeRelinquishCertificateArgs(data []byte) (*wallet.RelinquishCertificateArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RelinquishCertificateArgs{}

	// Read type (base64), serialNumber (base64), certifier (hex)
	copy(args.Type[:], r.ReadBytes(sizeType))
	copy(args.SerialNumber[:], r.ReadBytes(sizeSerial))

	parsedCertifier, err := ec.PublicKeyFromBytes(r.ReadBytes(sizePubKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing certifier public key: %w", err)
	}
	args.Certifier = parsedCertifier

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing RelinquishCertificate args: %w", r.Err)
	}

	return args, nil
}

func SerializeRelinquishCertificateResult(_ *wallet.RelinquishCertificateResult) ([]byte, error) {
	return nil, nil
}

func DeserializeRelinquishCertificateResult(_ []byte) (*wallet.RelinquishCertificateResult, error) {
	return &wallet.RelinquishCertificateResult{
		Relinquished: true,
	}, nil
}

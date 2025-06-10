package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
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

func SerializeRelinquishCertificateResult(result *wallet.RelinquishCertificateResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	w.WriteByte(1) // relinquished = true
	return w.Buf, nil
}

func DeserializeRelinquishCertificateResult(data []byte) (*wallet.RelinquishCertificateResult, error) {
	r := util.NewReaderHoldError(data)
	result := &wallet.RelinquishCertificateResult{}

	// Read error byte (0 = success)
	errorByte := r.ReadByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("relinquishCertificate failed with error byte %d", errorByte)
	}

	// Read relinquished flag
	relinquished := r.ReadByte()
	result.Relinquished = relinquished == 1

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing RelinquishCertificate result: %w", r.Err)
	}

	return result, nil
}

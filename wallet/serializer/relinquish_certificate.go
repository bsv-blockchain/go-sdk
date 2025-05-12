package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRelinquishCertificateArgs(args *wallet.RelinquishCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode type (base64)
	if err := w.WriteSizeFromBase64(args.Type, sizeType); err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}

	// Encode serialNumber (base64)
	if err := w.WriteSizeFromBase64(args.SerialNumber, sizeSerial); err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}

	// Encode certifier (hex)
	if err := w.WriteSizeFromHex(args.Certifier, sizeCertifier); err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}

	return w.Buf, nil
}

func DeserializeRelinquishCertificateArgs(data []byte) (*wallet.RelinquishCertificateArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RelinquishCertificateArgs{}

	// Read type (base64), serialNumber (base64), certifier (hex)
	args.Type = r.ReadBase64(sizeType)
	args.SerialNumber = r.ReadBase64(sizeSerial)
	args.Certifier = r.ReadHex(sizeCertifier)

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

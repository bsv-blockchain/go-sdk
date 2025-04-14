package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRelinquishCertificateArgs(args *wallet.RelinquishCertificateArgs) ([]byte, error) {
	w := newWriter()

	// Encode type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(args.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != SizeType {
		return nil, fmt.Errorf("type must be %d bytes long", SizeType)
	}
	w.writeBytes(typeBytes)

	// Encode serialNumber (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(args.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	if len(serialBytes) != SizeSerial {
		return nil, fmt.Errorf("serialNumber must be %d bytes long", SizeSerial)
	}
	w.writeBytes(serialBytes)

	// Encode certifier (hex)
	certifierBytes, err := hex.DecodeString(args.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(certifierBytes) != SizeCertifier {
		return nil, fmt.Errorf("certifier must be %d bytes long", SizeCertifier)
	}
	w.writeBytes(certifierBytes)

	return w.buf, nil
}

func DeserializeRelinquishCertificateArgs(data []byte) (*wallet.RelinquishCertificateArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.RelinquishCertificateArgs{}

	// Read type (base64)
	typeBytes := r.readBytes(SizeType)
	args.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read serialNumber (base64)
	serialBytes := r.readBytes(SizeSerial)
	args.SerialNumber = base64.StdEncoding.EncodeToString(serialBytes)

	// Read certifier (hex)
	certifierBytes := r.readBytes(SizeCertifier)
	args.Certifier = hex.EncodeToString(certifierBytes)

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing RelinquishCertificate args: %w", r.err)
	}

	return args, nil
}

func SerializeRelinquishCertificateResult(result *wallet.RelinquishCertificateResult) ([]byte, error) {
	w := newWriter()
	w.writeByte(0) // errorByte = 0 (success)
	w.writeByte(1) // relinquished = true
	return w.buf, nil
}

func DeserializeRelinquishCertificateResult(data []byte) (*wallet.RelinquishCertificateResult, error) {
	r := newReaderHoldError(data)
	result := &wallet.RelinquishCertificateResult{}

	// Read error byte (0 = success)
	errorByte := r.readByte()
	if errorByte != 0 {
		return nil, fmt.Errorf("relinquishCertificate failed with error byte %d", errorByte)
	}

	// Read relinquished flag
	relinquished := r.readByte()
	result.Relinquished = relinquished == 1

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing RelinquishCertificate result: %w", r.err)
	}

	return result, nil
}

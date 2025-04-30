package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRelinquishCertificateArgs(args *wallet.RelinquishCertificateArgs) ([]byte, error) {
	w := util.NewWriter()

	// Encode type (base64)
	typeBytes, err := base64.StdEncoding.DecodeString(args.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type base64: %w", err)
	}
	if len(typeBytes) != sizeType {
		return nil, fmt.Errorf("type must be %d bytes long", sizeType)
	}
	w.WriteBytes(typeBytes)

	// Encode serialNumber (base64)
	serialBytes, err := base64.StdEncoding.DecodeString(args.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serialNumber base64: %w", err)
	}
	if len(serialBytes) != sizeSerial {
		return nil, fmt.Errorf("serialNumber must be %d bytes long", sizeSerial)
	}
	w.WriteBytes(serialBytes)

	// Encode certifier (hex)
	certifierBytes, err := hex.DecodeString(args.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(certifierBytes) != sizeCertifier {
		return nil, fmt.Errorf("certifier must be %d bytes long", sizeCertifier)
	}
	w.WriteBytes(certifierBytes)

	return w.Buf, nil
}

func DeserializeRelinquishCertificateArgs(data []byte) (*wallet.RelinquishCertificateArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RelinquishCertificateArgs{}

	// Read type (base64)
	typeBytes := r.ReadBytes(sizeType)
	args.Type = base64.StdEncoding.EncodeToString(typeBytes)

	// Read serialNumber (base64)
	serialBytes := r.ReadBytes(sizeSerial)
	args.SerialNumber = base64.StdEncoding.EncodeToString(serialBytes)

	// Read certifier (hex)
	certifierBytes := r.ReadBytes(sizeCertifier)
	args.Certifier = hex.EncodeToString(certifierBytes)

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

package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeIdentityCertificate(cert *wallet.IdentityCertificate) ([]byte, error) {
	w := newWriter()

	// Serialize base Certificate fields
	certBytes, err := SerializeCertificate(&cert.Certificate)
	if err != nil {
		return nil, fmt.Errorf("error serializing base certificate: %w", err)
	}
	w.writeIntBytes(certBytes)

	// Serialize CertifierInfo
	w.writeString(cert.CertifierInfo.Name)
	w.writeString(cert.CertifierInfo.IconUrl)
	w.writeString(cert.CertifierInfo.Description)
	w.writeByte(cert.CertifierInfo.Trust)

	// Serialize PubliclyRevealedKeyring
	w.writeVarInt(uint64(len(cert.PubliclyRevealedKeyring)))
	for k, v := range cert.PubliclyRevealedKeyring {
		w.writeString(k)
		w.writeString(v)
	}

	// Serialize DecryptedFields
	w.writeVarInt(uint64(len(cert.DecryptedFields)))
	for k, v := range cert.DecryptedFields {
		w.writeString(k)
		w.writeString(v)
	}

	return w.buf, nil
}

func DeserializeIdentityCertificate(data []byte) (*wallet.IdentityCertificate, error) {
	r := newReaderHoldError(data)
	cert := &wallet.IdentityCertificate{}

	// Deserialize base Certificate
	certBytes := r.readIntBytes()
	baseCert, err := DeserializeCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("error deserializing base certificate: %w", err)
	}
	cert.Certificate = *baseCert

	// Deserialize CertifierInfo
	cert.CertifierInfo.Name = r.readString()
	cert.CertifierInfo.IconUrl = r.readString()
	cert.CertifierInfo.Description = r.readString()
	cert.CertifierInfo.Trust = r.readByte()

	// Deserialize PubliclyRevealedKeyring
	keyringLen := r.readVarInt()
	if keyringLen > 0 {
		cert.PubliclyRevealedKeyring = make(map[string]string, keyringLen)
		for i := uint64(0); i < keyringLen; i++ {
			key := r.readString()
			value := r.readString()
			cert.PubliclyRevealedKeyring[key] = value
		}
	}

	// Deserialize DecryptedFields
	fieldsLen := r.readVarInt()
	if fieldsLen > 0 {
		cert.DecryptedFields = make(map[string]string, fieldsLen)
		for i := uint64(0); i < fieldsLen; i++ {
			key := r.readString()
			value := r.readString()
			cert.DecryptedFields[key] = value
		}
	}

	if r.err != nil {
		return nil, fmt.Errorf("error deserializing identity certificate: %w", r.err)
	}

	return cert, nil
}

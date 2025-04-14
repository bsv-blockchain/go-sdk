package serializer

import (
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// SerializeGetPublicKeyArgs serializes the wallet.GetPublicKeyArgs structure into a byte array.
func SerializeGetPublicKeyArgs(args *wallet.GetPublicKeyArgs) ([]byte, error) {
	w := newWriter()

	// Write identity key flag
	// Write identity key flag
	if args.IdentityKey {
		w.writeByte(1)
	} else {
		w.writeByte(0)
	}

	if !args.IdentityKey {
		// Encode key related params
		keyParams, err := encodeKeyRelatedParams(KeyRelatedParams{
			ProtocolID:       args.ProtocolID,
			KeyID:            args.KeyID,
			Counterparty:     args.Counterparty,
			Privileged:       &args.Privileged,
			PrivilegedReason: args.PrivilegedReason,
		})
		if err != nil {
			return nil, fmt.Errorf("error encoding key params: %w", err)
		}
		w.writeBytes(keyParams)

		// Write forSelf flag
		w.writeOptionalBool(&args.ForSelf)
	} else {
		// Write privileged params for identity key case
		w.writeBytes(encodePrivilegedParams(&args.Privileged, args.PrivilegedReason))
	}

	// Write seekPermission
	w.writeOptionalBool(&args.SeekPermission)

	return w.buf, nil
}

// DeserializeGetPublicKeyArgs deserializes a byte array into the wallet.GetPublicKeyArgs structure.
func DeserializeGetPublicKeyArgs(data []byte) (*wallet.GetPublicKeyArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.GetPublicKeyArgs{}

	// Read identity key flag
	identityKeyFlag := r.readByte()
	if identityKeyFlag == 1 {
		args.IdentityKey = true
	}

	if !args.IdentityKey {
		// Decode key related params
		keyParams, err := decodeKeyRelatedParams(r)
		if err != nil {
			return nil, fmt.Errorf("error decoding key params: %w", err)
		}
		args.ProtocolID = keyParams.ProtocolID
		args.KeyID = keyParams.KeyID
		args.Counterparty = keyParams.Counterparty
		args.Privileged = keyParams.Privileged != nil && *keyParams.Privileged
		args.PrivilegedReason = keyParams.PrivilegedReason

		// Read forSelf flag
		args.ForSelf = readOptionalBoolAsBool(r.readOptionalBool())
	} else {
		// Read privileged params for identity key case
		privileged, privilegedReason := decodePrivilegedParams(r)
		args.Privileged = privileged != nil && *privileged
		args.PrivilegedReason = privilegedReason
	}

	// Read seekPermission
	args.SeekPermission = readOptionalBoolAsBool(r.readOptionalBool())

	if r.err != nil {
		return nil, fmt.Errorf("error reading getPublicKey args: %w", r.err)
	}

	return args, nil
}

// SerializeGetPublicKeyResult serializes the wallet.GetPublicKeyResult structure into a byte array.
func SerializeGetPublicKeyResult(result *wallet.GetPublicKeyResult) ([]byte, error) {
	w := newWriter()
	w.writeBytes(result.PublicKey.ToDER())
	return w.buf, nil
}

// DeserializeGetPublicKeyResult deserializes a byte array into the wallet.GetPublicKeyResult structure.
func DeserializeGetPublicKeyResult(data []byte) (*wallet.GetPublicKeyResult, error) {
	pubKey, err := ec.PublicKeyFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing result public key: %w", err)
	}
	result := &wallet.GetPublicKeyResult{
		PublicKey: pubKey,
	}
	return result, nil
}

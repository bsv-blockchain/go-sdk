package serializer

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const identityKeyFlag = 1

// SerializeGetPublicKeyArgs serializes the wallet.GetPublicKeyArgs structure into a byte array.
func SerializeGetPublicKeyArgs(args *wallet.GetPublicKeyArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write identity key flag
	if args.IdentityKey {
		w.WriteByte(identityKeyFlag)
	} else {
		w.WriteByte(0)
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
		w.WriteBytes(keyParams)

		// Write forSelf flag
		w.WriteOptionalBool(&args.ForSelf)
	} else {
		// Write privileged params for identity key case
		w.WriteBytes(encodePrivilegedParams(&args.Privileged, args.PrivilegedReason))
	}

	// Write seekPermission
	w.WriteOptionalBool(&args.SeekPermission)

	return w.Buf, nil
}

// DeserializeGetPublicKeyArgs deserializes a byte array into the wallet.GetPublicKeyArgs structure.
func DeserializeGetPublicKeyArgs(data []byte) (*wallet.GetPublicKeyArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.GetPublicKeyArgs{}

	// Read identity key flag
	if r.ReadByte() == identityKeyFlag {
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
		args.ForSelf = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())
	} else {
		// Read privileged params for identity key case
		privileged, privilegedReason := decodePrivilegedParams(r)
		args.Privileged = privileged != nil && *privileged
		args.PrivilegedReason = privilegedReason
	}

	// Read seekPermission
	args.SeekPermission = util.ReadOptionalBoolAsBool(r.ReadOptionalBool())

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading getPublicKey args: %w", r.Err)
	}

	return args, nil
}

// SerializeGetPublicKeyResult serializes the wallet.GetPublicKeyResult structure into a byte array.
func SerializeGetPublicKeyResult(result *wallet.GetPublicKeyResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteBytes(result.PublicKey.ToDER())
	return w.Buf, nil
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

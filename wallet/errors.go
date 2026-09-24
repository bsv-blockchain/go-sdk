package wallet

import "errors"

// Sentinel errors returned by ProtoWallet's cryptographic verification
// methods (and any other wallet.Interface implementation that mirrors their
// behaviour).
//
// These match the TS reference SDK's ProtoWallet (see @bsv/sdk's
// wallet/ProtoWallet.ts verifySignature/verifyHmac), which throws an Error
// carrying a `code` of ERR_INVALID_SIGNATURE / ERR_INVALID_HMAC rather than
// returning {valid: false} when verification fails. Go mirrors that by
// returning a non-nil error wrapping one of these sentinels instead of a
// {Valid: false} result, so callers can use errors.Is to tell "the
// signature/HMAC was cryptographically invalid" apart from any other failure
// (a malformed argument, a key-derivation error, an unreachable backend,
// etc), exactly as they could switch on the TS reference's `err.code`.
var (
	// ErrInvalidSignature is returned when a signature fails verification.
	// Equivalent to the TS reference's ERR_INVALID_SIGNATURE.
	ErrInvalidSignature = errors.New("signature is not valid")

	// ErrInvalidHMAC is returned when an HMAC fails verification.
	// Equivalent to the TS reference's ERR_INVALID_HMAC.
	ErrInvalidHMAC = errors.New("hmac is not valid")
)

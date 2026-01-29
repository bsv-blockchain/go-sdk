package spv

import "errors"

var (
	ErrFeeTooLow                = errors.New("fee is too low")
	ErrInvalidMerklePath        = errors.New("invalid merkle path")
	ErrMissingSourceTransaction = errors.New("missing source transaction")
	ErrScriptVerificationFailed = errors.New("script verification failed")
)

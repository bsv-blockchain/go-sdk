package wallet

import "fmt"

// Error represents a wallet-specific error with a code, message and stack trace.
// It implements the standard error interface and provides structured error information
// for wallet operations that can fail.
type Error struct {
	Code    byte
	Message string
	Stack   string
}

// Error returns a formatted string representation of the wallet error.
// It implements the standard error interface by combining the error code and message.
func (e *Error) Error() string {
	return fmt.Sprintf("WalletError %d: %s", e.Code, e.Message)
}

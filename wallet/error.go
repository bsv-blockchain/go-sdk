package wallet

import "fmt"

type Error struct {
	Code    byte
	Message string
	Stack   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("WalletError %d: %s", e.Code, e.Message)
}

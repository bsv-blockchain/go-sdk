package feemodel

import "errors"

var ErrNoUnlockingScript = errors.New("inputs must have an unlocking script or an unlocker")

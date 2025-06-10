package transaction

import (
	"encoding/json"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/pkg/errors"
)

type txJSON struct {
	TxID     string               `json:"txid"`
	Hex      string               `json:"hex"`
	Inputs   []*TransactionInput  `json:"inputs"`
	Outputs  []*TransactionOutput `json:"outputs"`
	Version  uint32               `json:"version"`
	LockTime uint32               `json:"lockTime"`
}

type inputJSON struct {
	UnlockingScript string `json:"unlockingScript"`
	TxID            string `json:"txid"`
	Vout            uint32 `json:"vout"`
	Sequence        uint32 `json:"sequence"`
}

type outputJSON struct {
	Satoshis      uint64 `json:"satoshis"`
	LockingScript string `json:"lockingScript"`
}

// MarshalJSON will serialize a transaction to json.
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	if tx == nil {
		return nil, errors.Wrap(ErrTxNil, "cannot marshal tx")
	}
	return json.Marshal(txJSON{
		TxID:     tx.TxID().String(),
		Hex:      tx.String(),
		Inputs:   tx.Inputs,
		Outputs:  tx.Outputs,
		LockTime: tx.LockTime,
		Version:  tx.Version,
	})
}

// UnmarshalJSON will unmarshall a transaction that has been marshaled with this library.
func (tx *Transaction) UnmarshalJSON(b []byte) error {
	var txj txJSON
	if err := json.Unmarshal(b, &txj); err != nil {
		return err
	}
	// quick convert
	if txj.Hex != "" {
		t, err := NewTransactionFromHex(txj.Hex)
		if err != nil {
			return err
		}
		*tx = *t
		return nil
	}
	tx.LockTime = txj.LockTime
	tx.Version = txj.Version
	return nil
}

// MarshalJSON will convert an input to json, expanding upon the
// input struct to add additional fields.
func (i *TransactionInput) MarshalJSON() ([]byte, error) {
	return json.Marshal(&inputJSON{
		TxID:            i.SourceTXID.String(),
		Vout:            i.SourceTxOutIndex,
		UnlockingScript: i.UnlockingScript.String(),
		Sequence:        i.SequenceNumber,
	})
}

// UnmarshalJSON will convert a JSON input to an input.
func (i *TransactionInput) UnmarshalJSON(b []byte) error {
	var ij inputJSON
	if err := json.Unmarshal(b, &ij); err != nil {
		return err
	}
	ptxID, err := chainhash.NewHashFromHex(ij.TxID)
	if err != nil {
		return err
	}
	s, err := script.NewFromHex(ij.UnlockingScript)
	if err != nil {
		return err
	}
	i.UnlockingScript = s
	i.SourceTXID = ptxID
	i.SourceTxOutIndex = ij.Vout
	i.SequenceNumber = ij.Sequence
	return nil
}

// MarshalJSON will serialize an output to json.
func (o *TransactionOutput) MarshalJSON() ([]byte, error) {
	return json.Marshal(&outputJSON{
		Satoshis:      o.Satoshis,
		LockingScript: o.LockingScriptHex(),
	})
}

// UnmarshalJSON will convert a json serialized output to a bt Output.
func (o *TransactionOutput) UnmarshalJSON(b []byte) error {
	var oj outputJSON
	if err := json.Unmarshal(b, &oj); err != nil {
		return err
	}
	s, err := script.NewFromHex(oj.LockingScript)
	if err != nil {
		return err
	}
	o.Satoshis = oj.Satoshis
	o.LockingScript = s
	return nil
}

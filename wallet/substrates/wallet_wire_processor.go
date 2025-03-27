package substrates

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"strings"
)

// WalletWireProcessor implements the WalletWire interface
type WalletWireProcessor struct {
	Wallet wallet.Interface
}

func NewWalletWireProcessor(wallet wallet.Interface) *WalletWireProcessor {
	return &WalletWireProcessor{Wallet: wallet}
}

// decodeOutpoint converts binary outpoint data to string format "txid.index"
func (w *WalletWireProcessor) decodeOutpoint(data []byte) (string, error) {
	if len(data) < 32 {
		return "", errors.New("invalid outpoint data length")
	}

	txid := hex.EncodeToString(data[:32])
	index := binary.BigEndian.Uint32(data[32:36])
	return fmt.Sprintf("%s.%d", txid, index), nil
}

// encodeOutpoint converts outpoint string "txid.index" to binary format
func (w *WalletWireProcessor) encodeOutpoint(outpoint string) ([]byte, error) {
	parts := strings.Split(outpoint, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid outpoint format")
	}

	txid, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid txid: %v", err)
	}

	var index uint32
	if _, err := fmt.Sscanf(parts[1], "%d", &index); err != nil {
		return nil, fmt.Errorf("invalid index: %v", err)
	}

	buf := make([]byte, 36)
	copy(buf[:32], txid)
	binary.BigEndian.PutUint32(buf[32:36], index)

	return buf, nil
}

// TransmitToWallet processes incoming wallet messages
func (w *WalletWireProcessor) TransmitToWallet(message []byte) ([]byte, error) {
	// TODO: Implement message processing
	return nil, errors.New("not implemented")
}

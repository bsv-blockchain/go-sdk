package transaction

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/bsv-blockchain/go-sdk/util"
)

// Beef is a set of Transactions and their MerklePaths.
// Each Transaction can be RawTx, RawTxAndBumpIndex, or TxIDOnly.
// It's useful when transporting multiple transactions all at once.
// Txid only can be used in the case that the recipient already has that tx.
type Beef struct {
	Version      uint32
	BUMPs        []*MerklePath
	Transactions map[chainhash.Hash]*BeefTx
}

func NewBeef() *Beef {
	return &Beef{
		Version:      BEEF_V2,
		BUMPs:        []*MerklePath{},
		Transactions: make(map[chainhash.Hash]*BeefTx),
	}
}

const BEEF_V1 = uint32(4022206465)     // BRC-64
const BEEF_V2 = uint32(4022206466)     // BRC-96
const ATOMIC_BEEF = uint32(0x01010101) // BRC-95

func (t *Transaction) FromBEEF(beef []byte) error {
	tx, err := NewTransactionFromBEEF(beef)
	if err != nil {
		return fmt.Errorf("failed to parse BEEF bytes: %w", err)
	}
	*t = *tx
	return nil
}

func NewBeefV1() *Beef {
	return newEmptyBeef(BEEF_V1)
}

func NewBeefV2() *Beef {
	return newEmptyBeef(BEEF_V2)
}

func newEmptyBeef(version uint32) *Beef {
	return &Beef{
		Version:      version,
		BUMPs:        []*MerklePath{},
		Transactions: make(map[chainhash.Hash]*BeefTx),
	}
}

func readBeefTx(reader *bytes.Reader, BUMPs []*MerklePath) (*map[chainhash.Hash]*BeefTx, error) {
	var numberOfTransactions util.VarInt
	_, err := numberOfTransactions.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	txs := make(map[chainhash.Hash]*BeefTx, 0)
	for i := 0; i < int(numberOfTransactions); i++ {
		formatByte, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		var beefTx BeefTx
		beefTx.DataFormat = DataFormat(formatByte)
		beefTx.Transaction = &Transaction{}

		if beefTx.DataFormat > TxIDOnly {
			return nil, fmt.Errorf("invalid data format: %d", formatByte)
		}

		if beefTx.DataFormat == TxIDOnly {
			var txid chainhash.Hash
			_, err = reader.Read(txid[:])
			beefTx.KnownTxID = &txid
			if err != nil {
				return nil, err
			}
			txs[txid] = &beefTx
		} else {
			bump := beefTx.DataFormat == RawTxAndBumpIndex
			// read the index of the bump
			var bumpIndex util.VarInt
			if bump {
				_, err := bumpIndex.ReadFrom(reader)
				if err != nil {
					return nil, err
				}
				beefTx.BumpIndex = int(bumpIndex)
			}
			// read the transaction data
			_, err = beefTx.Transaction.ReadFrom(reader)
			if err != nil {
				return nil, err
			}
			// attach the bump
			if bump {
				beefTx.Transaction.MerklePath = BUMPs[int(bumpIndex)]
			}

			for _, input := range beefTx.Transaction.Inputs {
				if sourceObj, ok := txs[*input.SourceTXID]; ok {
					input.SourceTransaction = sourceObj.Transaction
				}
			}

			txs[*beefTx.Transaction.TxID()] = &beefTx
		}

	}

	return &txs, nil
}

func NewBeefFromHex(beefHex string) (*Beef, error) {
	beef, err := hex.DecodeString(beefHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode beef hex: %w", err)
	}
	return NewBeefFromBytes(beef)
}

func NewBeefFromBytes(beef []byte) (*Beef, error) {
	var reader *bytes.Reader
	if binary.LittleEndian.Uint32(beef[:4]) == ATOMIC_BEEF {
		reader = bytes.NewReader(beef[36:])
	} else {
		reader = bytes.NewReader(beef)
	}
	version, err := readVersion(reader)
	if err != nil {
		return nil, err
	}

	if version == BEEF_V1 {
		BUMPs, err := readBUMPs(reader)
		if err != nil {
			return nil, err
		}

		txs, _, err := readAllTransactions(reader, BUMPs)
		if err != nil {
			return nil, err
		}

		// run through the txs map and convert to BeefTx
		beefTxs := make(map[chainhash.Hash]*BeefTx, len(txs))
		for _, tx := range txs {
			if tx.MerklePath != nil {
				// find which bump index this tx is in
				idx := -1
				for i, bump := range BUMPs {
					for _, leaf := range bump.Path[0] {
						if leaf.Hash != nil && tx.TxID().Equal(*leaf.Hash) {
							idx = i
						}
					}
				}
				beefTxs[*tx.TxID()] = &BeefTx{
					DataFormat:  RawTxAndBumpIndex,
					Transaction: tx,
					BumpIndex:   idx,
				}
			} else {
				beefTxs[*tx.TxID()] = &BeefTx{
					DataFormat:  RawTx,
					Transaction: tx,
				}
			}
		}

		return &Beef{
			Version:      version,
			BUMPs:        BUMPs,
			Transactions: beefTxs,
		}, nil
	}

	BUMPs, err := readBUMPs(reader)
	if err != nil {
		return nil, err
	}

	txs, err := readBeefTx(reader, BUMPs)
	if err != nil {
		return nil, err
	}

	return &Beef{
		Version:      version,
		BUMPs:        BUMPs,
		Transactions: *txs,
	}, nil
}

func NewBeefFromAtomicBytes(beef []byte) (*Beef, *chainhash.Hash, error) {
	if len(beef) < 36 {
		return nil, nil, fmt.Errorf("provided atomic BEEF length (%d) is too short", len(beef))
	} else if version := binary.LittleEndian.Uint32(beef[:4]); version != ATOMIC_BEEF {
		return nil, nil, fmt.Errorf("version %d is not atomic BEEF", version)
	} else if txid, err := chainhash.NewHash(beef[4:36]); err != nil {
		return nil, nil, fmt.Errorf("invalid txid: %w", err)
	} else if b, err := NewBeefFromBytes(beef[36:]); err != nil {
		return nil, nil, fmt.Errorf("invalid BEEF: %w", err)
	} else {
		return b, txid, nil
	}
}

func ParseBeef(beefBytes []byte) (*Beef, *Transaction, *chainhash.Hash, error) {
	if len(beefBytes) < 4 {
		return nil, nil, nil, fmt.Errorf("invalid-version")
	}
	version := binary.LittleEndian.Uint32(beefBytes[:4])
	switch version {
	case ATOMIC_BEEF:
		if len(beefBytes) < 36 {
			return nil, nil, nil, fmt.Errorf("invalid-atomic-beef")
		}
		if txid, err := chainhash.NewHash(beefBytes[4:36]); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid txid: %w", err)
		} else if b, err := NewBeefFromBytes(beefBytes[36:]); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid BEEF: %w", err)
		} else {
			return b, b.FindTransaction(txid.String()), txid, nil
		}
	case BEEF_V1:
		if tx, err := NewTransactionFromBEEF(beefBytes); err != nil {
			return nil, nil, nil, err
		} else if b, err := NewBeefFromTransaction(tx); err != nil {
			return nil, nil, nil, err
		} else {
			return b, tx, tx.TxID(), nil
		}
	case BEEF_V2:
		if beef, err := NewBeefFromBytes(beefBytes); err != nil {
			return nil, nil, nil, err
		} else {
			return beef, nil, nil, nil
		}
	default:
		return nil, nil, nil, fmt.Errorf("invalid-atomic-beef")
	}
}

func NewBeefFromTransaction(t *Transaction) (*Beef, error) {
	if t == nil {
		return nil, fmt.Errorf("transaction is nil")
	}
	beef := NewBeefV2()
	bumpMap := map[uint32]int{}
	txid := t.TxID()
	txns := map[chainhash.Hash]*Transaction{*txid: t}
	ancestors, err := t.collectAncestors(txid, txns, false)
	if err != nil {
		return nil, err
	}
	for _, txid := range ancestors {
		tx := txns[txid]
		if tx.MerklePath == nil {
			continue
		}
		if bumpIdx, ok := bumpMap[tx.MerklePath.BlockHeight]; !ok {
			bumpMap[tx.MerklePath.BlockHeight] = len(beef.BUMPs)
			beef.BUMPs = append(beef.BUMPs, tx.MerklePath)
		} else {
			err = beef.BUMPs[bumpIdx].Combine(tx.MerklePath)
			if err != nil {
				return nil, err
			}
		}
	}
	for _, txid := range ancestors {
		tx := txns[txid]
		beefTx := &BeefTx{
			Transaction: tx,
		}
		if tx.MerklePath != nil {
			beefTx.DataFormat = RawTxAndBumpIndex
			beefTx.BumpIndex = bumpMap[tx.MerklePath.BlockHeight]
		} else {
			beefTx.DataFormat = RawTx
		}
		beef.Transactions[txid] = beefTx
	}
	return beef, nil
}

func readVersion(reader *bytes.Reader) (uint32, error) {
	var version uint32
	err := binary.Read(reader, binary.LittleEndian, &version)
	if err != nil {
		return 0, err
	}
	if version != BEEF_V1 && version != BEEF_V2 {
		return 0, fmt.Errorf("invalid BEEF version. expected %d or %d, received %d", BEEF_V1, BEEF_V2, version)
	}
	return version, nil
}

func readBUMPs(reader *bytes.Reader) ([]*MerklePath, error) {
	var numberOfBUMPs util.VarInt
	_, err := numberOfBUMPs.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	BUMPs := make([]*MerklePath, numberOfBUMPs)
	for i := 0; i < int(numberOfBUMPs); i++ {
		BUMPs[i], err = NewMerklePathFromReader(reader)
		if err != nil {
			return nil, err
		}
	}
	return BUMPs, nil
}

func readTransactionsGetLast(reader *bytes.Reader, BUMPs []*MerklePath) (*Transaction, error) {
	_, tx, err := readAllTransactions(reader, BUMPs)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func readAllTransactions(reader *bytes.Reader, BUMPs []*MerklePath) (map[string]*Transaction, *Transaction, error) {
	var numberOfTransactions util.VarInt
	_, err := numberOfTransactions.ReadFrom(reader)
	if err != nil {
		return nil, nil, err
	}

	transactions := make(map[string]*Transaction, 0)
	var tx *Transaction
	for i := 0; i < int(numberOfTransactions); i++ {
		tx = &Transaction{}
		_, err = tx.ReadFrom(reader)
		if err != nil {
			return nil, nil, err
		}
		txid := tx.TxID()
		hasBump := make([]byte, 1)
		_, err = reader.Read(hasBump)
		if err != nil {
			return nil, nil, err
		}
		if hasBump[0] != 0 {
			var pathIndex util.VarInt
			_, err = pathIndex.ReadFrom(reader)
			if err != nil {
				return nil, nil, err
			}
			tx.MerklePath = BUMPs[int(pathIndex)]
		}
		for _, input := range tx.Inputs {
			sourceTxid := input.SourceTXID.String()
			if sourceObj, ok := transactions[sourceTxid]; ok {
				input.SourceTransaction = sourceObj
			}
		}
		transactions[txid.String()] = tx
	}

	return transactions, tx, nil
}

func NewTransactionFromBEEFHex(beefHex string) (*Transaction, error) {
	if beef, err := hex.DecodeString(beefHex); err != nil {
		return nil, err
	} else {
		return NewTransactionFromBEEF(beef)
	}
}

func (t *Transaction) BEEF() ([]byte, error) {
	b := new(bytes.Buffer)
	err := binary.Write(b, binary.LittleEndian, BEEF_V1)
	if err != nil {
		return nil, err
	}
	bumps := []*MerklePath{}
	bumpMap := map[uint32]int{}
	txns := map[chainhash.Hash]*Transaction{*t.TxID(): t}
	ancestors, err := t.collectAncestors(nil, txns, false)
	if err != nil {
		return nil, err
	}
	for _, txid := range ancestors {
		tx := txns[txid]
		if tx.MerklePath == nil {
			continue
		}
		if _, ok := bumpMap[tx.MerklePath.BlockHeight]; !ok {
			bumpMap[tx.MerklePath.BlockHeight] = len(bumps)
			bumps = append(bumps, tx.MerklePath)
		} else {
			err := bumps[bumpMap[tx.MerklePath.BlockHeight]].Combine(tx.MerklePath)
			if err != nil {
				return nil, err
			}
		}
	}

	b.Write(util.VarInt(len(bumps)).Bytes())
	for _, bump := range bumps {
		b.Write(bump.Bytes())
	}
	b.Write(util.VarInt(len(txns)).Bytes())
	for _, txid := range ancestors {
		tx := txns[txid]
		b.Write(tx.Bytes())
		if tx.MerklePath != nil {
			b.Write([]byte{1})
			b.Write(util.VarInt(bumpMap[tx.MerklePath.BlockHeight]).Bytes())
		} else {
			b.Write([]byte{0})
		}
	}
	return b.Bytes(), nil
}

func (t *Transaction) BEEFHex() (string, error) {
	if beef, err := t.BEEF(); err != nil {
		return "", err
	} else {
		return hex.EncodeToString(beef), nil
	}
}

func (t *Transaction) collectAncestors(txid *chainhash.Hash, txns map[chainhash.Hash]*Transaction, allowPartial bool) ([]chainhash.Hash, error) {
	if txid == nil {
		txid = t.TxID()
	}
	if t.MerklePath != nil {
		return []chainhash.Hash{*txid}, nil
	}
	ancestors := make([]chainhash.Hash, 0)
	for _, input := range t.Inputs {
		if input.SourceTransaction == nil {
			if allowPartial {
				continue
			} else {
				return nil, fmt.Errorf("missing previous transaction for %s", t.TxID())
			}
		}
		txns[*input.SourceTXID] = input.SourceTransaction
		if grands, err := input.SourceTransaction.collectAncestors(input.SourceTXID, txns, allowPartial); err != nil {
			return nil, err
		} else {
			ancestors = append(grands, ancestors...)
		}
	}
	ancestors = append(ancestors, *txid)

	found := make(map[chainhash.Hash]struct{})
	results := make([]chainhash.Hash, 0, len(ancestors))
	for _, ancestor := range ancestors {
		if _, ok := found[ancestor]; !ok {
			results = append(results, ancestor)
			found[ancestor] = struct{}{}
		}
	}

	return results, nil
}

func (b *Beef) FindBumpByHash(txid *chainhash.Hash) *MerklePath {
	if txid == nil {
		return nil
	}
	for _, bump := range b.BUMPs {
		for _, leaf := range bump.Path[0] {
			if leaf.Hash != nil && leaf.Hash.Equal(*txid) {
				return bump
			}
		}
	}
	return nil
}

func (b *Beef) FindBump(txid string) *MerklePath {
	idHash, err := chainhash.NewHashFromHex(txid)
	if err != nil {
		return nil
	}
	return b.FindBumpByHash(idHash)
}

func (b *Beef) FindTransactionByHash(txid *chainhash.Hash) *Transaction {
	if beefTx := b.findTxid(txid); beefTx != nil {
		return beefTx.Transaction
	}
	return nil
}

func (b *Beef) FindTransaction(txid string) *Transaction {
	idHash, err := chainhash.NewHashFromHex(txid)
	if err != nil {
		return nil
	}
	return b.FindTransactionByHash(idHash)
}

func (b *Beef) FindTransactionForSigningByHash(txid *chainhash.Hash) *Transaction {
	beefTx := b.findTxid(txid)
	if beefTx == nil {
		return nil
	}

	for _, input := range beefTx.Transaction.Inputs {
		if input.SourceTransaction == nil {
			itx := b.findTxid(input.SourceTXID)
			if itx != nil {
				input.SourceTransaction = itx.Transaction
			}
		}
	}

	return beefTx.Transaction
}

func (b *Beef) FindTransactionForSigning(txid string) *Transaction {
	idHash, err := chainhash.NewHashFromHex(txid)
	if err != nil {
		return nil
	}
	return b.FindTransactionForSigningByHash(idHash)
}

func (b *Beef) FindAtomicTransactionByHash(txid *chainhash.Hash) *Transaction {
	beefTx := b.findTxid(txid)
	if beefTx == nil {
		return nil
	}

	var addInputProof func(beef *Beef, tx *Transaction)
	addInputProof = func(beef *Beef, tx *Transaction) {
		mp := beef.FindBumpByHash(tx.TxID())
		if mp != nil {
			tx.MerklePath = mp
		} else {
			for _, input := range tx.Inputs {
				if input.SourceTransaction == nil {
					itx := beef.findTxid(input.SourceTXID)
					if itx != nil {
						input.SourceTransaction = itx.Transaction
					}
				}
				if input.SourceTransaction != nil {
					mp := beef.FindBumpByHash(input.SourceTransaction.TxID())
					if mp != nil {
						input.SourceTransaction.MerklePath = mp
					} else {
						addInputProof(beef, input.SourceTransaction)
					}
				}
			}
		}
	}

	addInputProof(b, beefTx.Transaction)

	return beefTx.Transaction
}

func (b *Beef) FindAtomicTransaction(txid string) *Transaction {
	idHash, err := chainhash.NewHashFromHex(txid)
	if err != nil {
		return nil
	}
	return b.FindAtomicTransactionByHash(idHash)
}

func (b *Beef) MergeBump(bump *MerklePath) int {
	var bumpIndex *int
	// If this proof is identical to another one previously added, we use that first.
	// Otherwise, we try to merge it with proofs from the same block.
	for i, existingBump := range b.BUMPs {
		if existingBump == bump { // Literally the same
			return i
		}
		if existingBump.BlockHeight == bump.BlockHeight {
			// Probably the same...
			rootA, err := existingBump.ComputeRoot(nil)
			if err != nil {
				return -1
			}
			rootB, err := bump.ComputeRoot(nil)
			if err != nil {
				return -1
			}
			if rootA == rootB {
				// Definitely the same... combine them to save space
				_ = existingBump.Combine(bump)
				bumpIndex = &i
				break
			}
		}
	}

	// if the proof is not yet added, add a new path.
	if bumpIndex == nil {
		newIndex := len(b.BUMPs)
		b.BUMPs = append(b.BUMPs, bump)
		bumpIndex = &newIndex
	}

	// review if any transactions are proven by this bump
	for _, tx := range b.Transactions {
		txid := tx.Transaction.TxID()
		if tx.Transaction.MerklePath == nil {
			for _, node := range b.BUMPs[*bumpIndex].Path[0] {
				if node.Hash != nil && node.Hash.Equal(*txid) {
					tx.Transaction.MerklePath = b.BUMPs[*bumpIndex]
					break
				}
			}
		}
	}

	return *bumpIndex
}

func (b *Beef) findTxid(txid *chainhash.Hash) *BeefTx {
	if txid == nil {
		return nil
	}
	if tx, ok := b.Transactions[*txid]; ok {
		return tx
	}
	return nil
}

func (b *Beef) MakeTxidOnly(txid *chainhash.Hash) *BeefTx {
	if txid == nil {
		return nil
	}
	tx, ok := b.Transactions[*txid]
	if !ok {
		return nil
	}
	if tx.DataFormat == TxIDOnly {
		return tx
	}
	tx = &BeefTx{
		DataFormat: TxIDOnly,
		KnownTxID:  txid,
	}
	b.Transactions[*txid] = tx
	return tx
}

func (b *Beef) MergeRawTx(rawTx []byte, bumpIndex *int) (*BeefTx, error) {
	tx := &Transaction{}
	reader := bytes.NewReader(rawTx)
	_, err := tx.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	txid := tx.TxID()
	b.RemoveExistingTxid(txid)

	beefTx := &BeefTx{
		DataFormat:  RawTx,
		Transaction: tx,
	}

	if bumpIndex != nil {
		if *bumpIndex < 0 || *bumpIndex >= len(b.BUMPs) {
			return nil, fmt.Errorf("invalid bump index")
		}
		beefTx.Transaction.MerklePath = b.BUMPs[*bumpIndex]
		beefTx.DataFormat = RawTxAndBumpIndex
	}

	b.Transactions[*txid] = beefTx
	b.tryToValidateBumpIndex(beefTx)

	return beefTx, nil
}

// RemoveExistingTxid removes an existing transaction from the BEEF, given its TXID
func (b *Beef) RemoveExistingTxid(txid *chainhash.Hash) {
	if txid != nil {
		delete(b.Transactions, *txid)
	}
}

func (b *Beef) tryToValidateBumpIndex(tx *BeefTx) {
	if tx.DataFormat == TxIDOnly || tx.Transaction == nil || tx.Transaction.MerklePath == nil {
		return
	}
	txid := tx.Transaction.TxID()
	for _, node := range tx.Transaction.MerklePath.Path[0] {
		if node.Hash != nil && node.Hash.Equal(*txid) {
			return
		}
	}
	tx.Transaction.MerklePath = nil
}

func (b *Beef) MergeTransaction(tx *Transaction) (*BeefTx, error) {
	txid := tx.TxID()
	b.RemoveExistingTxid(txid)

	var bumpIndex *int
	if tx.MerklePath != nil {
		index := b.MergeBump(tx.MerklePath)
		bumpIndex = &index
	}

	newTx := &BeefTx{
		DataFormat:  RawTx,
		Transaction: tx,
	}
	if bumpIndex != nil {
		newTx.DataFormat = RawTxAndBumpIndex
		newTx.BumpIndex = *bumpIndex
	}

	b.Transactions[*txid] = newTx
	b.tryToValidateBumpIndex(newTx)

	if bumpIndex == nil {
		for _, input := range tx.Inputs {
			if input.SourceTransaction != nil {
				if _, err := b.MergeTransaction(input.SourceTransaction); err != nil {
					return nil, err
				}
			}
		}
	}

	return newTx, nil
}

func (b *Beef) MergeTxidOnly(txid *chainhash.Hash) *BeefTx {
	if txid == nil {
		return nil
	}
	tx := b.findTxid(txid)
	if tx == nil {
		tx = &BeefTx{
			DataFormat: TxIDOnly,
			KnownTxID:  txid,
		}
		b.Transactions[*txid] = tx
	}
	return tx
}

func (b *Beef) MergeBeefTx(btx *BeefTx) (*BeefTx, error) {
	if btx == nil || btx.Transaction == nil {
		return nil, fmt.Errorf("nil transaction")
	}
	beefTx := b.findTxid(btx.Transaction.TxID())
	if btx.DataFormat == TxIDOnly && beefTx == nil {
		beefTx = b.MergeTxidOnly(btx.KnownTxID)
	} else if btx.Transaction != nil && (beefTx == nil || beefTx.DataFormat == TxIDOnly) {
		var err error
		beefTx, err = b.MergeTransaction(btx.Transaction)
		if err != nil {
			return nil, err
		}
	}
	return beefTx, nil
}

func (b *Beef) MergeBeefBytes(beef []byte) error {
	otherBeef, err := NewBeefFromBytes(beef)
	if err != nil {
		return err
	}
	return b.MergeBeef(otherBeef)
}

func (b *Beef) MergeBeef(otherBeef *Beef) error {
	for _, bump := range otherBeef.BUMPs {
		b.MergeBump(bump)
	}

	for _, tx := range otherBeef.Transactions {
		if _, err := b.MergeBeefTx(tx); err != nil {
			return err
		}
	}

	return nil
}

type verifyResult struct {
	valid bool
	roots map[uint32]string
}

func (b *Beef) IsValid(allowTxidOnly bool) bool {
	r := b.verifyValid(allowTxidOnly)
	return r.valid
}

func (b *Beef) Verify(ctx context.Context, chainTracker chaintracker.ChainTracker, allowTxidOnly bool) (bool, error) {
	r := b.verifyValid(allowTxidOnly)
	if !r.valid {
		return false, nil
	}
	for height, root := range r.roots {
		h, err := chainhash.NewHashFromHex(root)
		if err != nil {
			return false, err
		}
		ok, err := chainTracker.IsValidRootForHeight(ctx, h, height)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// ValidationResult contains the results of transaction validation
type ValidationResult struct {
	Valid             []string // Transactions that are fully validated
	NotValid          []string // Transactions that cannot be validated
	TxidOnly          []string // Transactions represented only by txid
	WithMissingInputs []string // Transactions with inputs not in BEEF
	MissingInputs     []string // Input txids that are missing
}

// ValidateTransactions validates the transactions in this BEEF and sorts them by dependency order.
// It returns a ValidationResult containing the validation status of each transaction.
//
// Validation rules:
// - Transactions with merkle paths are automatically valid
// - Transactions without merkle paths must have all inputs traceable to transactions with merkle paths
// - For DataFormat == RawTx or TxIDOnly, checks if the txid appears in BUMPs (has proof)
// - For DataFormat == RawTxAndBumpIndex, verifies the bump index is accurate
func (b *Beef) ValidateTransactions() *ValidationResult {
	// Build a map of txids that appear in BUMPs (have proof)
	txidsInBumps := make(map[chainhash.Hash]bool)
	for _, bump := range b.BUMPs {
		if len(bump.Path) > 0 {
			// Check level 0 (leaf level) for transaction hashes
			for _, elem := range bump.Path[0] {
				if elem.Hash != nil && elem.Txid != nil && *elem.Txid {
					txidsInBumps[*elem.Hash] = true
				}
			}
		}
	}

	result := &ValidationResult{
		MissingInputs:     []string{},
		NotValid:          []string{},
		Valid:             []string{},
		WithMissingInputs: []string{},
		TxidOnly:          []string{},
	}

	// Maps for tracking
	validTxids := make(map[chainhash.Hash]bool)
	missingInputs := make(map[chainhash.Hash]bool)

	// Lists for processing
	var hasProof []*BeefTx
	var txidOnly []*BeefTx
	var needsValidation []*BeefTx
	var withMissingInputs []*BeefTx

	// First pass: categorize transactions
	for txid, beefTx := range b.Transactions {
		switch beefTx.DataFormat {
		case TxIDOnly:
			// TxIDOnly transactions are valid if they appear in BUMPs
			if beefTx.KnownTxID != nil && txidsInBumps[*beefTx.KnownTxID] {
				validTxids[*beefTx.KnownTxID] = true
				txidOnly = append(txidOnly, beefTx)
			} else {
				// TxIDOnly without proof - add to txidOnly list but not valid
				txidOnly = append(txidOnly, beefTx)
			}
		case RawTxAndBumpIndex:
			// Verify the bump index is accurate
			if beefTx.BumpIndex >= 0 && beefTx.BumpIndex < len(b.BUMPs) {
				bump := b.BUMPs[beefTx.BumpIndex]
				// Check if this transaction appears in the specified bump
				foundInBump := false
				for _, elem := range bump.Path[0] {
					if elem.Hash != nil && elem.Hash.Equal(txid) {
						foundInBump = true
						break
					}
				}
				if foundInBump {
					validTxids[txid] = true
					hasProof = append(hasProof, beefTx)
				} else {
					// Invalid bump index - treat as needing validation
					needsValidation = append(needsValidation, beefTx)
				}
			} else {
				// Invalid bump index - treat as needing validation
				needsValidation = append(needsValidation, beefTx)
			}
		case RawTx:
			// RawTx is valid if it appears in a BUMP
			if txidsInBumps[txid] {
				validTxids[txid] = true
				hasProof = append(hasProof, beefTx)
			} else if beefTx.Transaction != nil {
				// Check if all inputs are available
				hasMissing := false
				for _, input := range beefTx.Transaction.Inputs {
					if _, exists := b.Transactions[*input.SourceTXID]; !exists {
						missingInputs[*input.SourceTXID] = true
						hasMissing = true
					}
				}
				if hasMissing {
					withMissingInputs = append(withMissingInputs, beefTx)
				} else {
					needsValidation = append(needsValidation, beefTx)
				}
			}
		}
	}

	// Iteratively validate transactions that depend on other transactions
	for len(needsValidation) > 0 {
		progress := false
		var stillNeedsValidation []*BeefTx

		for _, beefTx := range needsValidation {
			// Check if all inputs are valid
			allInputsValid := true
			if beefTx.Transaction != nil {
				for _, input := range beefTx.Transaction.Inputs {
					if !validTxids[*input.SourceTXID] {
						allInputsValid = false
						break
					}
				}
			}

			if allInputsValid {
				validTxids[*beefTx.Transaction.TxID()] = true
				hasProof = append(hasProof, beefTx)
				progress = true
			} else {
				stillNeedsValidation = append(stillNeedsValidation, beefTx)
			}
		}

		needsValidation = stillNeedsValidation
		if !progress {
			// No progress made - remaining transactions are not valid
			for _, beefTx := range needsValidation {
				if beefTx.Transaction != nil {
					result.NotValid = append(result.NotValid, beefTx.Transaction.TxID().String())
				}
			}
			break
		}
	}

	// Populate result lists
	// Add transactions with missing inputs
	for _, beefTx := range withMissingInputs {
		if beefTx.Transaction != nil {
			txid := beefTx.Transaction.TxID().String()
			result.WithMissingInputs = append(result.WithMissingInputs, txid)
		}
	}

	// Add txid-only transactions
	result.TxidOnly = make([]string, 0, len(txidOnly))
	for _, beefTx := range txidOnly {
		var txidHash *chainhash.Hash
		if beefTx.KnownTxID != nil {
			txidHash = beefTx.KnownTxID
		} else if beefTx.Transaction != nil {
			txidHash = beefTx.Transaction.TxID()
		} else {
			continue
		}
		result.TxidOnly = append(result.TxidOnly, txidHash.String())
		if validTxids[*txidHash] {
			result.Valid = append(result.Valid, txidHash.String())
		}
	}

	// Add valid transactions with proofs (in dependency order)
	for _, beefTx := range hasProof {
		if beefTx.Transaction != nil {
			result.Valid = append(result.Valid, beefTx.Transaction.TxID().String())
		}
	}

	// Populate missing inputs list
	result.MissingInputs = make([]string, 0, len(missingInputs))
	for txid := range missingInputs {
		result.MissingInputs = append(result.MissingInputs, txid.String())
	}

	return result
}

func (b *Beef) verifyValid(allowTxidOnly bool) verifyResult {
	r := verifyResult{valid: false, roots: map[uint32]string{}}

	// Validate and sort transactions
	vr := b.ValidateTransactions()

	// Check if validation passed
	if len(vr.MissingInputs) > 0 ||
		len(vr.NotValid) > 0 ||
		(len(vr.TxidOnly) > 0 && !allowTxidOnly) ||
		len(vr.WithMissingInputs) > 0 {
		return r
	}

	// Build valid txids set
	txids := make(map[string]bool)
	for _, txid := range vr.Valid {
		txids[txid] = true
	}

	confirmComputedRoot := func(mp *MerklePath, txid string) bool {
		h, err := chainhash.NewHashFromHex(txid)
		if err != nil {
			return false
		}
		root, err := mp.ComputeRoot(h)
		if err != nil {
			return false
		}
		if existing, ok := r.roots[mp.BlockHeight]; ok && existing != root.String() {
			return false
		}
		r.roots[mp.BlockHeight] = root.String()
		return true
	}

	// Verify all BUMPs have consistent roots
	for _, mp := range b.BUMPs {
		for _, n := range mp.Path[0] {
			if n.Txid != nil && *n.Txid && n.Hash != nil {
				if !confirmComputedRoot(mp, n.Hash.String()) {
					return r
				}
			}
		}
	}

	// Verify all transactions with BumpIndex have matching txid in the BUMP
	for txid, beefTx := range b.Transactions {
		if beefTx.DataFormat == RawTxAndBumpIndex {
			if beefTx.BumpIndex < 0 || beefTx.BumpIndex >= len(b.BUMPs) {
				return r
			}
			bump := b.BUMPs[beefTx.BumpIndex]
			found := false
			for _, leaf := range bump.Path[0] {
				if leaf.Hash != nil && *leaf.Hash == txid {
					found = true
					break
				}
			}
			if !found {
				return r
			}
		}
	}

	r.valid = true
	return r
}

// ToLogString returns a summary of `Beef` contents as multi-line string for debugging purposes.
func (b *Beef) ToLogString() string {
	var log string
	log += fmt.Sprintf(
		"BEEF with %d BUMPs and %d Transactions, isValid %t\n", len(b.BUMPs),
		len(b.Transactions),
		b.IsValid(true),
	)
	for i, bump := range b.BUMPs {
		log += fmt.Sprintf("  BUMP %d\n    block: %d\n    txids: [\n", i, bump.BlockHeight)
		for _, node := range bump.Path[0] {
			if node.Txid != nil {
				log += fmt.Sprintf("      '%s',\n", node.Hash.String())
			}
		}
		log += "    ]\n"
	}

txLoop:
	for i, tx := range b.Transactions {
		switch tx.DataFormat {
		case RawTx:
			log += fmt.Sprintf("  TX %d\n    txid: %s\n", i, tx.Transaction.TxID().String())
			log += fmt.Sprintf("    rawTx length=%d\n", len(tx.Transaction.Bytes()))
		case RawTxAndBumpIndex:
			log += fmt.Sprintf("  TX %d\n    txid: %s\n", i, tx.Transaction.TxID().String())
			log += fmt.Sprintf("    bumpIndex: %d\n", tx.Transaction.MerklePath.BlockHeight)
			log += fmt.Sprintf("    rawTx length=%d\n", len(tx.Transaction.Bytes()))
		case TxIDOnly:
			log += fmt.Sprintf("  TX %d\n    txid: %s\n", i, tx.KnownTxID.String())
			log += "    txidOnly\n"
			continue txLoop
		}

		if len(tx.Transaction.Inputs) > 0 {
			log += "    inputs: [\n"
			for _, input := range tx.Transaction.Inputs {
				log += fmt.Sprintf("      '%s',\n", input.SourceTXID.String())
			}
			log += fmt.Sprintf("    rawTx length=%d\n", len(tx.Transaction.Bytes()))
			if len(tx.Transaction.Inputs) > 0 {
				log += "    inputs: [\n"
				for _, input := range tx.Transaction.Inputs {
					log += fmt.Sprintf("      '%s',\n", input.SourceTXID.String())
				}
				log += "    ]\n"
			}
		}
	}
	return log
}

func (b *Beef) Clone() *Beef {
	c := &Beef{
		Version:      b.Version,
		BUMPs:        append([]*MerklePath(nil), b.BUMPs...),
		Transactions: make(map[chainhash.Hash]*BeefTx, len(b.Transactions)),
	}
	for k, v := range b.Transactions {
		c.Transactions[k] = v
	}
	return c
}

func (b *Beef) TrimknownTxIDs(knownTxIDs []string) {
	knownTxIDSet := make(map[string]struct{}, len(knownTxIDs))
	for _, txid := range knownTxIDs {
		knownTxIDSet[txid] = struct{}{}
	}

	for txid, tx := range b.Transactions {
		if tx.DataFormat == TxIDOnly {
			if _, ok := knownTxIDSet[txid.String()]; ok {
				delete(b.Transactions, txid)
			}
		}
	}

	// Trim unreferenced BUMP proofs
	b.trimUnreferencedBumps()
}

// trimUnreferencedBumps removes BUMP proofs that are no longer referenced by any remaining transactions
func (b *Beef) trimUnreferencedBumps() {
	if len(b.BUMPs) == 0 {
		return
	}

	// Track which BUMP indices are still referenced by remaining transactions
	usedBumpIndices := make(map[int]bool)

	// Build a set of transaction IDs that need BUMPs
	txidsNeedingBumps := make(map[chainhash.Hash]bool)

	for txid, tx := range b.Transactions {
		switch tx.DataFormat {
		case RawTxAndBumpIndex:
			// Direct BUMP reference
			usedBumpIndices[tx.BumpIndex] = true
		case RawTx:
			// Raw transaction without explicit BUMP - we need to check if any BUMP references this txid
			txidsNeedingBumps[txid] = true
		case TxIDOnly:
			// Known transaction ID - we need to check if any BUMP references this txid
			if tx.KnownTxID != nil {
				txidsNeedingBumps[*tx.KnownTxID] = true
			}
		}
	}

	// Check each BUMP to see if it's needed for any of the txids
	for bumpIndex, bump := range b.BUMPs {
		if bump != nil && len(bump.Path) > 0 && len(bump.Path[0]) > 0 {
			// Get the transaction ID from the first path element (leaf level)
			for _, leaf := range bump.Path[0] {
				if leaf.Hash != nil {
					if txidsNeedingBumps[*leaf.Hash] {
						usedBumpIndices[bumpIndex] = true
						break
					}
				}
			}
		}
	}

	// If all BUMPs are still in use, no trimming needed
	if len(usedBumpIndices) == len(b.BUMPs) {
		return
	}

	// Build new BUMP slice with only referenced BUMPs
	newBumps := make([]*MerklePath, 0, len(usedBumpIndices))
	bumpIndexMapping := make(map[int]int) // old index -> new index

	for oldIndex := 0; oldIndex < len(b.BUMPs); oldIndex++ {
		if usedBumpIndices[oldIndex] {
			newIndex := len(newBumps)
			newBumps = append(newBumps, b.BUMPs[oldIndex])
			bumpIndexMapping[oldIndex] = newIndex
		}
	}

	// Update BUMP indices in remaining transactions
	for _, tx := range b.Transactions {
		if tx.DataFormat == RawTxAndBumpIndex {
			if newIndex, exists := bumpIndexMapping[tx.BumpIndex]; exists {
				tx.BumpIndex = newIndex
			}
		}
	}

	// Replace the BUMP slice
	b.BUMPs = newBumps
}

func (b *Beef) GetValidTxids() []string {
	r := b.ValidateTransactions()
	return r.Valid
}

// AddComputedLeaves adds leaves that can be computed from row zero to the BUMP MerklePaths.
func (b *Beef) AddComputedLeaves() {
	for _, bump := range b.BUMPs {
		for row := 1; row < len(bump.Path); row++ {
			for _, leafL := range bump.Path[row-1] {
				if leafL.Hash != nil && (leafL.Offset&1) == 0 {
					leafR := findLeafByOffset(bump.Path[row-1], leafL.Offset+1)
					offsetOnRow := leafL.Offset >> 1
					if leafR != nil && leafR.Hash != nil && findLeafByOffset(bump.Path[row], offsetOnRow) == nil {
						bump.Path[row] = append(bump.Path[row], &PathElement{
							Offset: offsetOnRow,
							Hash:   MerkleTreeParent(leafL.Hash, leafR.Hash),
						})
					}
				}
			}
		}
	}
}

func findLeafByOffset(leaves []*PathElement, offset uint64) *PathElement {
	for _, leaf := range leaves {
		if leaf.Offset == offset {
			return leaf
		}
	}
	return nil
}

// Bytes returns the BEEF BRC-96 as a byte slice.
func (b *Beef) Bytes() ([]byte, error) {
	// version
	beef := make([]byte, 0)
	beef = append(beef, util.LittleEndianBytes(b.Version, 4)...)

	// bumps
	beef = append(beef, util.VarInt(len(b.BUMPs)).Bytes()...)
	for _, bump := range b.BUMPs {
		beef = append(beef, bump.Bytes()...)
	}

	// transactions / txids
	beef = append(beef, util.VarInt(len(b.Transactions)).Bytes()...)
	txs := make(map[chainhash.Hash]struct{}, len(b.Transactions))
	var appendTx func(tx *BeefTx) error
	appendTx = func(tx *BeefTx) error {
		var txid chainhash.Hash
		if tx.DataFormat == TxIDOnly {
			if tx.KnownTxID == nil {
				return fmt.Errorf("txid is nil")
			}
			txid = *tx.KnownTxID
		} else if tx.Transaction == nil {
			return fmt.Errorf("transaction is nil")
		} else {
			txid = *tx.Transaction.TxID()
		}
		if _, ok := txs[txid]; ok {
			return nil
		}
		if tx.DataFormat == TxIDOnly {
			beef = append(beef, byte(tx.DataFormat))
			beef = append(beef, tx.KnownTxID[:]...)
		} else {
			for _, txin := range tx.Transaction.Inputs {
				if parentTx := b.findTxid(txin.SourceTXID); parentTx != nil {
					if err := appendTx(parentTx); err != nil {
						return err
					}
				}
			}
			beef = append(beef, byte(tx.DataFormat))
			if tx.DataFormat == RawTxAndBumpIndex {
				beef = append(beef, util.VarInt(tx.BumpIndex).Bytes()...)
			}
			beef = append(beef, tx.Transaction.Bytes()...)
		}
		txs[txid] = struct{}{}
		return nil
	}
	for _, tx := range b.Transactions {
		if err := appendTx(tx); err != nil {
			return nil, err
		}
	}

	return beef, nil
}

func (b *Beef) AtomicBytes(txid *chainhash.Hash) ([]byte, error) {
	beef, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, 4+chainhash.HashSize+len(beef))
	result = append(result, util.LittleEndianBytes(ATOMIC_BEEF, 4)...)
	result = append(result, txid[:]...)
	result = append(result, beef...)

	return result, nil
}

func (b *Beef) TxidOnly() (*Beef, error) {
	c := &Beef{
		Version:      b.Version,
		BUMPs:        append([]*MerklePath(nil), b.BUMPs...),
		Transactions: make(map[chainhash.Hash]*BeefTx, len(b.Transactions)),
	}
	for txid, tx := range b.Transactions {
		idOnly := &BeefTx{
			DataFormat: TxIDOnly,
		}
		if tx.DataFormat == TxIDOnly {
			idOnly.KnownTxID = tx.KnownTxID
		} else {
			idOnly.KnownTxID = tx.Transaction.TxID()
		}
		c.Transactions[txid] = idOnly
	}
	return c, nil
}

package transaction

import (
	"bytes"
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
	Transactions map[string]*BeefTx
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
		Transactions: make(map[string]*BeefTx),
	}
}

func readBeefTx(reader *bytes.Reader, BUMPs []*MerklePath) (*map[string]*BeefTx, error) {
	var numberOfTransactions util.VarInt
	_, err := numberOfTransactions.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	txs := make(map[string]*BeefTx, 0)
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
			txs[txid.String()] = &beefTx
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
				sourceTxid := input.SourceTXID.String()
				if sourceObj, ok := txs[sourceTxid]; ok {
					input.SourceTransaction = sourceObj.Transaction
				} else if beefTx.Transaction.MerklePath == nil && beefTx.KnownTxID == nil {
					// TODO: Need to update logic to match ts-sdk
					// return nil, fmt.Errorf("reference to unknown txid in bump: %s", sourceTxid)
				}
			}

			txs[beefTx.Transaction.TxID().String()] = &beefTx
		}

	}

	return &txs, nil
}

func NewBeefFromBytes(beef []byte) (*Beef, error) {
	reader := bytes.NewReader(beef)

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
		beefTxs := make(map[string]*BeefTx, len(txs))
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
				beefTxs[tx.TxID().String()] = &BeefTx{
					DataFormat:  RawTxAndBumpIndex,
					Transaction: tx,
					BumpIndex:   idx,
				}
			} else {
				beefTxs[tx.TxID().String()] = &BeefTx{
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
	txns := map[string]*Transaction{t.TxID().String(): t}
	ancestors, err := t.collectAncestors(txns, false)
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
			} else if tx.MerklePath == nil {
				panic(fmt.Sprintf(
					"There is no Merkle Path or Source Transaction for outpoint: %s, %d",
					sourceTxid,
					input.SourceTxOutIndex,
				))
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
	txns := map[string]*Transaction{t.TxID().String(): t}
	ancestors, err := t.collectAncestors(txns, false)
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

func (t *Transaction) collectAncestors(txns map[string]*Transaction, allowPartial bool) ([]string, error) {
	txid := t.TxID().String()
	if t.MerklePath != nil {
		return []string{txid}, nil
	}
	ancestors := make([]string, 0)
	for _, input := range t.Inputs {
		if input.SourceTransaction == nil {
			if allowPartial {
				continue
			} else {
				return nil, fmt.Errorf("missing previous transaction for %s", t.TxID())
			}
		}
		sourceTxid := input.SourceTXID.String()
		txns[sourceTxid] = input.SourceTransaction
		if grands, err := input.SourceTransaction.collectAncestors(txns, allowPartial); err != nil {
			return nil, err
		} else {
			ancestors = append(grands, ancestors...)
		}
	}
	ancestors = append(ancestors, txid)

	found := make(map[string]struct{})
	results := make([]string, 0, len(ancestors))
	for _, ancestor := range ancestors {
		if _, ok := found[ancestor]; !ok {
			results = append(results, ancestor)
			found[ancestor] = struct{}{}
		}
	}

	return results, nil
}

func (b *Beef) FindBump(txid string) *MerklePath {
	idHash, _ := chainhash.NewHashFromHex(txid)
	if idHash == nil {
		return nil
	}
	for _, bump := range b.BUMPs {
		for _, leaf := range bump.Path[0] {
			if leaf.Hash != nil && leaf.Hash.Equal(*idHash) {
				return bump
			}
		}
	}
	return nil
}

func (b *Beef) FindTransaction(txid string) *Transaction {
	if beefTx := b.findTxid(txid); beefTx != nil {
		return beefTx.Transaction
	}
	return nil
}

func (b *Beef) FindTransactionForSigning(txid string) *Transaction {
	beefTx := b.findTxid(txid)
	if beefTx == nil {
		return nil
	}

	for _, input := range beefTx.Transaction.Inputs {
		if input.SourceTransaction == nil {
			itx := b.findTxid(input.SourceTXID.String())
			if itx != nil {
				input.SourceTransaction = itx.Transaction
			}
		}
	}

	return beefTx.Transaction
}

func (b *Beef) FindAtomicTransaction(txid string) *Transaction {
	beefTx := b.findTxid(txid)
	if beefTx == nil {
		return nil
	}

	var addInputProof func(beef *Beef, tx *Transaction)
	addInputProof = func(beef *Beef, tx *Transaction) {
		mp := beef.FindBump(tx.TxID().String())
		if mp != nil {
			tx.MerklePath = mp
		} else {
			for _, input := range tx.Inputs {
				if input.SourceTransaction == nil {
					itx := beef.findTxid(input.SourceTXID.String())
					if itx != nil {
						input.SourceTransaction = itx.Transaction
					}
				}
				if input.SourceTransaction != nil {
					mp := beef.FindBump(input.SourceTransaction.TxID().String())
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

func (b *Beef) findTxid(txid string) *BeefTx {
	if tx, ok := b.Transactions[txid]; ok {
		return tx
	}
	return nil
}

func (b *Beef) MakeTxidOnly(txid string) *BeefTx {
	tx, ok := b.Transactions[txid]
	if !ok {
		return nil
	}
	if tx.DataFormat == TxIDOnly {
		return tx
	}
	if knownTxID, err := chainhash.NewHashFromHex(txid); err != nil {
		return nil
	} else {
		tx = &BeefTx{
			DataFormat: TxIDOnly,
			KnownTxID:  knownTxID,
		}
		b.Transactions[txid] = tx
		return tx
	}
}

func (b *Beef) MergeRawTx(rawTx []byte, bumpIndex *int) (*BeefTx, error) {
	tx := &Transaction{}
	reader := bytes.NewReader(rawTx)
	_, err := tx.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	txid := tx.TxID().String()
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

	b.Transactions[txid] = beefTx
	b.tryToValidateBumpIndex(beefTx)

	return beefTx, nil
}

// RemoveExistingTxid removes an existing transaction from the BEEF, given its TXID
func (b *Beef) RemoveExistingTxid(txid string) {
	delete(b.Transactions, txid)
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
	txid := tx.TxID().String()
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

	b.Transactions[txid] = newTx
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

func (b *Beef) MergeTxidOnly(txid string) *BeefTx {
	tx := b.findTxid(txid)
	if tx == nil {
		knownTxID, err := chainhash.NewHashFromHex(txid)
		if err != nil {
			return nil
		}
		tx = &BeefTx{
			DataFormat: TxIDOnly,
			KnownTxID:  knownTxID,
		}
		b.Transactions[txid] = tx
		b.tryToValidateBumpIndex(tx)
	}
	return tx
}

func (b *Beef) MergeBeefTx(btx *BeefTx) (*BeefTx, error) {
	if btx == nil || btx.Transaction == nil {
		return nil, fmt.Errorf("nil transaction")
	}
	beefTx := b.findTxid(btx.Transaction.TxID().String())
	if btx.DataFormat == TxIDOnly && beefTx == nil {
		beefTx = b.MergeTxidOnly(btx.KnownTxID.String())
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

func (b *Beef) Verify(chainTracker chaintracker.ChainTracker, allowTxidOnly bool) (bool, error) {
	r := b.verifyValid(allowTxidOnly)
	if !r.valid {
		return false, nil
	}
	for height, root := range r.roots {
		h, err := chainhash.NewHashFromHex(root)
		if err != nil {
			return false, err
		}
		ok, err := chainTracker.IsValidRootForHeight(h, height)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// SortTxs sorts the transactions in the BEEF by dependency order.
func (b *Beef) SortTxs() struct {
	MissingInputs     []string
	NotValid          []string
	Valid             []string
	WithMissingInputs []string
	TxidOnly          []string
} {
	type sortResult struct {
		MissingInputs     []string
		NotValid          []string
		Valid             []string
		WithMissingInputs []string
		TxidOnly          []string
	}

	res := sortResult{}

	// Collect all transactions into a slice for sorting and keep track of which txid is valid
	allTxs := make([]*BeefTx, 0, len(b.Transactions))
	validTxids := map[string]bool{}
	missing := map[string]bool{}

	for txid, beefTx := range b.Transactions {
		allTxs = append(allTxs, beefTx)
		// Mark transactions with proof or no inputs as valid
		if beefTx.Transaction != nil && beefTx.Transaction.MerklePath != nil {
			validTxids[txid] = true
		} else if beefTx.DataFormat == TxIDOnly && beefTx.KnownTxID != nil {
			res.TxidOnly = append(res.TxidOnly, txid)
			validTxids[txid] = true
		}
	}

	// Separate transactions that have at least one missing input
	queue := make([]*BeefTx, 0)
	for _, beefTx := range allTxs {
		if beefTx.Transaction != nil {
			hasMissing := false
			for _, in := range beefTx.Transaction.Inputs {
				if !validTxids[in.SourceTXID.String()] && b.findTxid(in.SourceTXID.String()) == nil {
					missing[in.SourceTXID.String()] = true
					hasMissing = true
				}
			}
			if hasMissing {
				res.WithMissingInputs = append(res.WithMissingInputs, beefTx.Transaction.TxID().String())
			} else {
				queue = append(queue, beefTx)
			}
		}
	}

	// Try to validate any transactions whose inputs are now known
	oldLen := -1
	for oldLen != len(queue) {
		oldLen = len(queue)
		newQueue := make([]*BeefTx, 0, len(queue))
		for _, beefTx := range queue {
			if beefTx.Transaction != nil {
				allInputsValid := true
				for _, in := range beefTx.Transaction.Inputs {
					if !validTxids[in.SourceTXID.String()] {
						allInputsValid = false
						break
					}
				}
				if allInputsValid {
					validTxids[beefTx.Transaction.TxID().String()] = true
					res.Valid = append(res.Valid, beefTx.Transaction.TxID().String())
				} else {
					newQueue = append(newQueue, beefTx)
				}
			}
		}
		queue = newQueue
	}

	// Now, whatever is left in queue is not valid
	for _, beefTx := range queue {
		if beefTx.Transaction != nil {
			res.NotValid = append(res.NotValid, beefTx.Transaction.TxID().String())
		}
	}

	for k := range missing {
		res.MissingInputs = append(res.MissingInputs, k)
	}
	return struct {
		MissingInputs     []string
		NotValid          []string
		Valid             []string
		WithMissingInputs []string
		TxidOnly          []string
	}(res)
}

func (b *Beef) verifyValid(allowTxidOnly bool) verifyResult {
	r := verifyResult{valid: false, roots: map[uint32]string{}}
	b.SortTxs() // Assume this sorts transactions in dependency order

	txids := make(map[string]bool)
	for _, tx := range b.Transactions {
		if tx.DataFormat == TxIDOnly {
			if !allowTxidOnly {
				return r
			}
			txids[tx.KnownTxID.String()] = true
		}
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

	for _, mp := range b.BUMPs {
		for _, n := range mp.Path[0] {
			if n.Txid != nil && n.Hash != nil {
				if !confirmComputedRoot(mp, n.Hash.String()) {
					return r
				}
				txids[n.Hash.String()] = true
			}
		}
	}

	for txid, beefTx := range b.Transactions {
		if beefTx.DataFormat != TxIDOnly {
			for _, in := range beefTx.Transaction.Inputs {
				if !txids[in.SourceTXID.String()] {
					return r
				}
			}
		}
		txids[txid] = true
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
			log += fmt.Sprintf("  TX %s\n    txid: %s\n", i, tx.Transaction.TxID().String())
			log += fmt.Sprintf("    rawTx length=%d\n", len(tx.Transaction.Bytes()))
		case RawTxAndBumpIndex:
			log += fmt.Sprintf("  TX %s\n    txid: %s\n", i, tx.Transaction.TxID().String())
			log += fmt.Sprintf("    bumpIndex: %d\n", tx.Transaction.MerklePath.BlockHeight)
			log += fmt.Sprintf("    rawTx length=%d\n", len(tx.Transaction.Bytes()))
		case TxIDOnly:
			log += fmt.Sprintf("  TX %s\n    txid: %s\n", i, tx.KnownTxID.String())
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
		Transactions: make(map[string]*BeefTx, len(b.Transactions)),
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
			if _, ok := knownTxIDSet[txid]; ok {
				delete(b.Transactions, txid)
			}
		}
	}
	// TODO: bumps could be trimmed to eliminate unreferenced proofs.
}

func (b *Beef) GetValidTxids() []string {
	r := b.SortTxs()
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
	txs := make(map[string]struct{}, len(b.Transactions))
	var appendTx func(tx *BeefTx) error
	appendTx = func(tx *BeefTx) error {
		var txid string
		if tx.DataFormat == TxIDOnly {
			if tx.KnownTxID == nil {
				return fmt.Errorf("txid is nil")
			}
			txid = tx.KnownTxID.String()
		} else if tx.Transaction == nil {
			return fmt.Errorf("transaction is nil")
		} else {
			txid = tx.Transaction.TxID().String()
		}
		if _, ok := txs[txid]; ok {
			return nil
		}
		if tx.DataFormat == TxIDOnly {
			beef = append(beef, byte(tx.DataFormat))
			beef = append(beef, tx.KnownTxID[:]...)
		} else {
			for _, txin := range tx.Transaction.Inputs {
				if parentTx := b.findTxid(txin.SourceTXID.String()); parentTx != nil {
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
		Transactions: make(map[string]*BeefTx, len(b.Transactions)),
	}
	for i, tx := range b.Transactions {
		idOnly := &BeefTx{
			DataFormat: TxIDOnly,
		}
		if tx.DataFormat == TxIDOnly {
			idOnly.KnownTxID = tx.KnownTxID
		} else {
			idOnly.KnownTxID = tx.Transaction.TxID()
		}
		c.Transactions[i] = idOnly
	}
	return c, nil
}

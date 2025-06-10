package transaction_test

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/v2/script"
	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	feemodel "github.com/bsv-blockchain/go-sdk/v2/transaction/fee_model"
	"github.com/bsv-blockchain/go-sdk/v2/transaction/template/p2pkh"
	"github.com/stretchr/testify/require"
)

const BRC62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

func TestNewTransaction(t *testing.T) {
	t.Parallel()
	t.Run("create tx", func(t *testing.T) {
		// examlpe wif and associated address
		priv, _ := ec.PrivateKeyFromWif("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")
		address, _ := script.NewAddressFromPublicKey(priv.PubKey(), true)

		// Source transaction data
		sourceRawtx := "010000000138c7c61c14ffb063c3bb2664041a3e29ea6ea0412a0c18ff725ba4e9e12afae2030000006a47304402203e9ab8e4c14addf3b4741540b556cfb0e0efb67dc1a7b5ce84c3ac56b3fd447802203c9f49f7bd893ebd7060176dfc36bcaff9d2c443d9a0dd6cd2d59b372c024d20412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffff02dc050000000000002076a914eb0bd5edba389198e73f8efabddfc61666969ff788ac6a0568656c6c6faa0d0000000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
		sourceMerklePathHex := "fed7c509000a02fddd010069464172a5d0cd3d641516166091ab84d230e8848ac9ccdc93f185d7b1b07902fddc01029d81a1815050f3a7bf8392e077481151af50a011a10708d4fc480a8ead76b41101ef00a93658c713530e49e2d6cad2529ecf06eb20620b9e1d3bdf75dbef8f509a5cc101760040808d97bfcb804293013e2108c4df25996ea9ba517671ff721c7be73dbfc3c5013a000435fef874132a7ebda11760ad63eccf37ba82f41793d6453f744b0873829c77011c000a0d32242d744e2007e8c3ccbfd761380d7c4340a90d8255cd608ad307752cd8010f007718f8c034a5ff0adf9c3c337660c4592bd6a6ff10de2d8f01afbb8c65f9143e0106006214d394450c84eabdcf04e7ecc6b893e1649ecc48bb3a6f38d48afcb0f2bc6a0102006a5fe10c65d3ce6950b4cbbd2bd584bcec0263c5178c3226bde14d7e307d4557010000a14df02e34b74d15dbcd0c7896b3dfb8ffb136cc3ba61ec118b37ddc70974cd5010100a5f147afb93db1ffe573b69b7c84abc3582c6cd7f3eaf82b4142d7557c28f0ae"

		sourceTransaction, _ := transaction.NewTransactionFromHex(sourceRawtx)
		merklePath, _ := transaction.NewMerklePathFromHex(sourceMerklePathHex)
		sourceTransaction.MerklePath = merklePath

		// Create a new transaction
		tx := transaction.NewTransaction()

		// Create a new P2PKH unlocker from the private key
		unlocker, err := p2pkh.Unlock(priv, nil)
		require.NoError(t, err)

		// Add an input
		tx.AddInputFromTx(sourceTransaction, 0, unlocker)

		// Create a new P2PKH locking script from the address
		lock, err := p2pkh.Lock(address)
		require.NoError(t, err)

		// Add the outputs
		tx.AddOutput(&transaction.TransactionOutput{
			LockingScript: lock,
			Satoshis:      1,
		})
		require.NoError(t, err)

		// Sign the transaction
		if err := tx.Sign(); err != nil {
			require.NoError(t, err)
		}

		_, err = tx.BEEF()
		require.NoError(t, err)
	})
}

func TestIsCoinbase(t *testing.T) {
	tx, err := transaction.NewTransactionFromHex("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff17033f250d2f43555656452f2c903fb60859897700d02700ffffffff01d864a012000000001976a914d648686cf603c11850f39600e37312738accca8f88ac00000000")
	require.NoError(t, err)
	require.True(t, tx.IsCoinbase())
}

func TestIsValidTxID(t *testing.T) {
	valid, _ := hex.DecodeString("fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b295")
	require.True(t, transaction.IsValidTxID(valid))
	invalid, _ := hex.DecodeString("fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b2")
	require.False(t, transaction.IsValidTxID(invalid))
}

func TestBEEF(t *testing.T) {
	t.Parallel()
	t.Run("deserialize and serialize", func(t *testing.T) {
		tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
		require.NoError(t, err)
		require.Equal(t, uint32(814435), tx.Inputs[0].SourceTransaction.MerklePath.BlockHeight)
		beef, err := tx.BEEFHex()
		require.NoError(t, err)
		require.Equal(t, BRC62Hex, beef)
	})
}

func TestEF(t *testing.T) {
	t.Run("Serialization and deserialization", func(t *testing.T) {
		tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
		require.NoError(t, err)
		ef, err := tx.EFHex()
		require.NoError(t, err)
		require.Equal(t, "010000000000000000ef01ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff3e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000", ef)
	})
}

func TestShallowClone(t *testing.T) {
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)

	clone := tx.ShallowClone()
	require.Equal(t, tx.Bytes(), clone.Bytes())
}

func TestClone(t *testing.T) {
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)

	clone := tx.Clone()
	require.Equal(t, tx.Bytes(), clone.Bytes())
}

func BenchmarkClone(b *testing.B) {
	tx, _ := transaction.NewTransactionFromHex("0200000003a9bc457fdc6a54d99300fb137b23714d860c350a9d19ff0f571e694a419ff3a0010000006b48304502210086c83beb2b2663e4709a583d261d75be538aedcafa7766bd983e5c8db2f8b2fc02201a88b178624ab0ad1748b37c875f885930166237c88f5af78ee4e61d337f935f412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff0092bb9a47e27bf64fc98f557c530c04d9ac25e2f2a8b600e92a0b1ae7c89c20010000006b483045022100f06b3db1c0a11af348401f9cebe10ae2659d6e766a9dcd9e3a04690ba10a160f02203f7fbd7dfcfc70863aface1a306fcc91bbadf6bc884c21a55ef0d32bd6b088c8412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff9d0d4554fa692420a0830ca614b6c60f1bf8eaaa21afca4aa8c99fb052d9f398000000006b483045022100d920f2290548e92a6235f8b2513b7f693a64a0d3fa699f81a034f4b4608ff82f0220767d7d98025aff3c7bd5f2a66aab6a824f5990392e6489aae1e1ae3472d8dffb412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff02807c814a000000001976a9143a6bf34ebfcf30e8541bbb33a7882845e5a29cb488ac76b0e60e000000001976a914bd492b67f90cb85918494767ebb23102c4f06b7088ac67000000")

	b.Run("clone", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			clone := tx.ShallowClone()
			_ = clone
		}
	})
}

func TestUncomputedFee(t *testing.T) {
	tx, _ := transaction.NewTransactionFromBEEFHex(BRC62Hex)

	tx.AddOutput(&transaction.TransactionOutput{
		Change:        true,
		LockingScript: tx.Outputs[0].LockingScript,
	})

	err := tx.Sign()
	require.Error(t, err)

	err = tx.SignUnsigned()
	require.Error(t, err)
}

func TestSignUnsigned(t *testing.T) {
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)

	cloneTx := tx.ShallowClone()
	pk, _ := ec.NewPrivateKey()

	// Adding a script template with random key so sigs will be different
	for i := range tx.Inputs {
		cloneTx.Inputs[i].UnlockingScriptTemplate, err = p2pkh.Unlock(pk, nil)
		require.NoError(t, err)
	}

	// This should do nothing because the inputs from hex are already signed
	err = cloneTx.SignUnsigned()
	require.NoError(t, err)
	for i := range cloneTx.Inputs {
		require.Equal(t, tx.Inputs[i].UnlockingScript, cloneTx.Inputs[i].UnlockingScript)
	}

	// This should sign the inputs with the incorrect key which should change the sigs
	err = cloneTx.Sign()
	require.NoError(t, err)
	for i := range tx.Inputs {
		require.NotEqual(t, tx.Inputs[i].UnlockingScript, cloneTx.Inputs[i].UnlockingScript)
	}
}

func TestSignUnsignedNew(t *testing.T) {
	pk, _ := ec.PrivateKeyFromWif("L1y6DgX4TuonxXzRPuk9reK2TD2THjwQReNUwVrvWN3aRkjcbauB")
	address, _ := script.NewAddressFromPublicKey(pk.PubKey(), true)
	tx := transaction.NewTransaction()
	lockingScript, err := p2pkh.Lock(address)
	require.NoError(t, err)
	sourceTxID, _ := chainhash.NewHashFromHex("fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b295")
	unlockingScript, _ := p2pkh.Unlock(pk, nil)
	tx.AddInput(&transaction.TransactionInput{
		SourceTransaction: &transaction.Transaction{
			Outputs: []*transaction.TransactionOutput{
				{
					Satoshis:      1,
					LockingScript: lockingScript,
				},
			},
		},
		SourceTXID:              sourceTxID,
		UnlockingScriptTemplate: unlockingScript,
	})

	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1,
		LockingScript: lockingScript,
	})

	err = tx.SignUnsigned()
	require.NoError(t, err)

	for _, input := range tx.Inputs {
		require.NotEmpty(t, input.UnlockingScript.Bytes())
	}
}

func TestTransactionGetFee(t *testing.T) {
	// Use the BRC62Hex transaction
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)

	// Get the fee
	fee, err := tx.GetFee()
	require.NoError(t, err)

	// Calculate expected fee
	totalInputSatoshis, err := tx.TotalInputSatoshis()
	require.NoError(t, err)
	totalOutputSatoshis := tx.TotalOutputSatoshis()
	expectedFee := totalInputSatoshis - totalOutputSatoshis

	// Verify the fee matches the expected fee
	require.Equal(t, expectedFee, fee)
}

func TestTransactionFee(t *testing.T) {
	// Example WIF and associated address
	privKeyWIF := "KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS"
	privKey, err := ec.PrivateKeyFromWif(privKeyWIF)
	require.NoError(t, err)

	address, err := script.NewAddressFromPublicKey(privKey.PubKey(), true)
	require.NoError(t, err)

	// Source transaction data (a real transaction)
	sourceRawTx := "0100000001b1e5bf6e0649f299bb2b20964090b5b0a02e96db182eecedb0a9e4e7af03e06e000000006b483045022100ca75f7f664fa3086a3430b0f5d4a531d26e8d2ef3a72f086e890c5618d858fed022006e9a3c9f08e1743b033a55c27fb9d6c6cf1a1f6e0c40090e229d4ff8e5ecb31412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffff01b0f9d804000000001976a9144bd8c375bdac70fb6eb7261d6e6c70450787e6af88ac00000000"

	sourceTx, err := transaction.NewTransactionFromHex(sourceRawTx)
	require.NoError(t, err)

	// Create a new transaction
	tx := transaction.NewTransaction()

	// Create a P2PKH unlocker
	unlocker, err := p2pkh.Unlock(privKey, nil)
	require.NoError(t, err)

	// Add an input from the source transaction
	tx.AddInputFromTx(sourceTx, 0, unlocker)

	// Create a P2PKH locking script
	lockScript, err := p2pkh.Lock(address)
	require.NoError(t, err)

	// Add an output (sending 1,000,000 satoshis)
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: lockScript,
		Satoshis:      1000000, // 0.01 BSV
	})

	// Add a change output
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: lockScript,
		Change:        true,
	})

	// Create a fee model with 500 satoshis per kilobyte
	feeModel := &feemodel.SatoshisPerKilobyte{
		Satoshis: 500, // Fee rate
	}

	// Compute the fee
	err = tx.Fee(feeModel, transaction.ChangeDistributionEqual)
	require.NoError(t, err)

	// Sign the transaction
	err = tx.Sign()
	require.NoError(t, err)

	// Get the actual fee from the transaction
	fee, err := tx.GetFee()
	require.NoError(t, err)

	// Compute the expected fee using the fee model
	expectedFee, err := feeModel.ComputeFee(tx)
	require.NoError(t, err)

	// Verify that the actual fee matches the expected fee
	require.Equal(t, expectedFee, fee)

	// Verify that total inputs >= total outputs + fee
	totalInputs, err := tx.TotalInputSatoshis()
	require.NoError(t, err)
	totalOutputs := tx.TotalOutputSatoshis()
	require.GreaterOrEqual(t, totalInputs, totalOutputs+fee)

	// Print the fee for informational purposes
	t.Logf("Computed fee: %d satoshis", fee)
}

func TestAtomicBEEF(t *testing.T) {
	// First decode the BEEF data to get a transaction
	beefBytes, err := hex.DecodeString(BRC62Hex)
	require.NoError(t, err)

	// Parse the V1 BEEF data to get a transaction
	tx, err := transaction.NewTransactionFromBEEF(beefBytes)
	require.NoError(t, err)
	require.NotNil(t, tx)

	// Test AtomicBEEF with allowPartial=false first
	atomicBeef, err := tx.AtomicBEEF(false)
	require.NoError(t, err)
	require.NotNil(t, atomicBeef)

	// Verify the format:
	// 1. First 4 bytes should be ATOMIC_BEEF (0x01010101)
	require.Equal(t, uint32(0x01010101), binary.LittleEndian.Uint32(atomicBeef[:4]))

	// 2. Next 32 bytes should be the subject transaction's TXID
	txid := tx.TxID()
	require.Equal(t, txid[:], atomicBeef[4:36])

	// 3. Verify that the remaining bytes contain BEEF_V2 data
	require.Equal(t, transaction.BEEF_V2, binary.LittleEndian.Uint32(atomicBeef[36:40]))

	// Test with allowPartial=true
	atomicBeefPartial, err := tx.AtomicBEEF(true)
	require.NoError(t, err)
	require.NotNil(t, atomicBeefPartial)
}

// beef_test.go

package transaction

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

const BRC62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
const BEEF = "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"
const BEEFSet = "0200beef03fef1550d001102fd20c2009591fd79f7fb1fbd24c2fdc4911da930e1d7386f0216b6446b85eea29f978f1bfd21c202ac2a05abdae46fc2555c36a76035dedbf9fac4fc349eabffbd9d62ba440ffcb101fd116100cabeb714ea9a3f15a5e4f6138f6dd6b75bab32d8b40d178a0514e6e1e1b372f701fd8930007e04df7216a1d29bb8caabd1f78014b1b4f336eb6aee76bcf1797456ddc86b7501fd451800796afe5b113d8933f5eef2d180e72dc4b644fd76fb1243dfb791d9863702573701fd230c007a6edc003e02c429391cbf426816885731cb8054410599884eed508917a2f57c01fd100600eaa540de74506ed6abcb48e38cc544c53d373269271a7e6cf2143b7cc85d7ea401fd0903001e31aa04628b99d6cfa3e21fb4a7e773487ebc86a504e511eaff3f2176267b9401fd85010031e0d053497f85228b02879f69c4c7b43fb5abc3e0e47ea49a63853b117c9b5001c30083339d5a5b97ad77b74d3538678bb20ea7e61f8b02c24a625933eb496bebd3480160008ee445baec1613d591344a9915d77652f508e6442cd394626a3ff308bcb151f1013100f3f68f2a72e47bb41377e9e429daa496cd220bdcf702a36a209f9feba58d5552011900a01c52f4099bc7bdfea772ab03739bf009d72f24f68b5c4f8cc71a8c4da80804010d00c2ce2d5bfb9cbab9983ae1c871974f23a32c585d9b8440acc4ef5203c1d6c05401070072c7fc59a1717e90633f10d322e0f63272ae97c017d1efae04e4090abeeafac3010200a7aa5fa5576d1de6dd0e32d769592bc247be7bbd0b3e36e2d579fa1ec7d6ebce010000090cba670bea2e0d5c36e979e4cf9f79ad0874d734fb782fec2496d4c554e321010100d963646680643df73c34d7fa16f173595cf32a9ed6f64d2c8ee88a8af6b7bf52fedf590d001202fe66130200023275c6dde10d32d61af52b412b1e3956b5cd085605cd521778f11d53849fdb0cfe6713020000cd5e2298cf4d809c698c8adeeab66718e6b75b3d528bce74e6e01b984c736df901feb209010000736013454e087c89d813c99a043c9029cf2d427815c6a98ba3641c384ae52c4701fdd884007f742824bddca1582e4ded866d9609d9473397f8b86625376be74684f7fb947f01fd6d4200eb7f54ce4f920a3e4c7f96ef6b2d199c519df1b1286415581187ca608f3e47b801fd372100fa6c1c8cba3d3d5d030cd98eb91498cdffe70f0dad1000e123157d5dac22e22a01fd9a1000104c0294e478fbcac4e2325403afd86370c86043f295978b809004b2687a6c9a01fd4c08009ef5a5eaf16cab45a239c43852296ab323ca21faf256ab9768dd0a2f39970ec201fd2704006161cbd1755b66815eb69613b574920e9e836c8c3772aa2260ad3639848d520b01fd1202005e04b5afc0ea8d29dc22b611536832a2a2e7c860bbf4227ce0bdcc8a0e66284601fd0801009719f5f90e3937f3921045d202522fe315da1331acc3cce472c4b084d0debe65018500d79a1c3d45a3c41bf6526a9adbac2676159d2f3c753d7d3b6dba1dc3cbdd3c520143006b88b582d985bffc511556e471a6a20cfda2d41837245329f714214e009a3e48012000c1840dbdfc3014f1e912882b971c030fd21c0b023c01fe6fd7470d6d9bb2ab86011100f9c3de08d38588e225a5ee5334a3c03771a0b51318ca388dd1b5826951604d750109006e2b2e926c86214620d306a59522eee438a79157e9360cb76ee14a868fccc482010500d5c43ea372c432861db73ba0a6897fa29855e542a6ed910626dfb8954d94fa47010300d7863bafb5ca841ca0b13736fced1d492f0f741cb0a2beab1cafa517c878ae2c010000174ccda0879c20b85fa26d423deb0b34c5f2787127e244ccacfae39b5ba8fea7feeb590d001602fe46b3060002fa6ae8371111956f74412e3b1effcbd4fcb278124b6365b34c8cc20a5287bafffe47b306000011883eed76bdc7e7fb79efe23e3c50aa825ade46d79895de1a246e3d69a5b8cf01fea2590300009c92d7f67ac06e4bce0de4f18f438056f25138ee1a0cf61ed3a6d7f32261339b01fed0ac01000006178026214d61dc19c91cb5c08481f2f3daf03392c359de424cbd5d7135c5cf01fd69d6000174f6863438909d648fea32cdd65cbf457ab717f9be327d5d4352dbf157671e01fd356b0059536ea55010906b7071e36f78b20faaaede46a7f27ba4916dc1655836c73de701fd9b3500dee845c02c827dbcd862de359f5e6ad0ecca59213d9eb01896374d9efb7af9fd01fdcc1a00b22861b84b4537dfdaa8eb51957a51007af7836677ad14074601de6cd6c2871c01fd670d00591e76e7b07b26a6d7e940ec4f84497d9f3c7be111b15c336b24d83227db0c1001fdb20600f142d0ff9b2ddb7c21d8913f02adc7abc51fcdd5253154339450b87b59859aa601fd580300ce0307ff2027d405b8afa8a5c8834e9cc8bd073c4f463c3657562bbdb7843fe601fdad010027a3ce3a9829a3df0d9074099a6a3d76c81600a6a9c50f6cf857fb823c1a783901d700cca7689680c528f0a93fd9c980577016b37ce67ce75b1d728c4fa23008b1652b016a00b74bd3ab6c94f1216a803849afc254f37eea378c89167ff0686223db82767e3a013400434d5f48f733bb69fc5f0bd8238ffaec8d002951e6a1b52484fcc05819078372011b0053fef8153f4aed8aa8bdebeae0a6c1aa7712b84887fb565bcd9232fdd60fb0c0010c00009d9f21a9bc9e9d8c99aac9a1df47ffe02334fcb8bc8f3797d64c2564b3bf44010700838a284a4ee33c455b303e1eb23428b35d264b35c4f4b42bd6c68f1a7279f38801020042820e1ab5dbb77b0a6f266167b453f672d007d0c6eddc6229ce57c941f46c670100002c0da37e0453e7d01c810d2280a84792086b1fe1bc232e76ef6783f76c57757601010048746ad4d10a562bb53d2ed29438c9dfd0a6cacb78429277072e789d4d8dd8c101010091a52bf4a100e96dba15cbff933df60fcb26d95d6dd9b55fd5e450d5895e4526010100c202dcbdece72a45a1657ff7dbd979b031b1c8b839bc9a3b958683226644b736030100020000000140f6726035b03b90c1f770f0280444eeb041c45d026a8f4baaf00530bdc473a5020000006b483045022100ccdf467aa46d9570c4778f4e68491cc51dff4b815803d2406b6e8772d800f5ad02200ff8f11a59d207c734e9c68154dcef4023d75c37e661ab866b1d3e3ea77e6bda4121021cf99b6763736f48e6e063f99a43bfa82f15111ba0e0f9776280e6bd75d23af9ffffffff0377082800000000001976a91491b21f8856b862ff291ca0ac2ec924ba2419113788ac75330100000000001976a9144b5b285395052a61328b58c6594dd66aa6003d4988acf229f503000000001976a9148efcb6c55f5c299d48d0c74762dd811345c9093b88ac0000000001010200000001bcfe1adc5e99edb82c6a48f44cbae19bc0e5d31f9c8e4b3a92d6befb1cb2e510020000006a4730440220211655b505edd6fe9196aba77477dac5c9f638fe204243c09f1188a19164ac7f022035fb8640750515ca85df8197dec87a76db5c578f05b8ae645e30d8f70d429a324121028bf1be8161c50f98289df3ecd3185ed2273e9d448840232cf2f077f05e789c29ffffffff03d8000400000000001976a9144f427ee5f3099f0ac571f6b723a628e7b08fb64c88ac75330100000000001976a914f7cad87036406e5d3aef5d4a4d65887c76f9466788ac27db1004000000001976a9143219d1b6bd74f932dcb39a5f3b48cfde2b61cc0088ac0000000001020100000002e646efa607ff14299bc0b0cfaa65e035feb493cc440cb8abb8eb6225f8d4c1c4000000006b483045022100b410c4f82655f56fc8de4a622d3e4a8c662198de5ca8963989d70b85734986f502204fe884d99aa6ffd44bb01396b9f63bebcb7222b76e6e26c2bd60837ff555f1f8412103fda4ece7b0c9150872f8ef5241164b36a230fd9657bc43ca083d9e78bc0bcba6ffffffff3275c6dde10d32d61af52b412b1e3956b5cd085605cd521778f11d53849fdb0c000000006a473044022057f9d55ace1945866be0f83431867c58eda32d73ae3fdabed2d3424ebbe493530220553e286ae67bcaf49b0ea1d3163f41b1b3c91702a054e100c1e71ca4927f6dd8412103fda4ece7b0c9150872f8ef5241164b36a230fd9657bc43ca083d9e78bc0bcba6ffffffff04400d0300000000001976a9140e8338fa60e5391d54e99c734640e72461922d9988aca0860100000000001976a9140602787cc457f68c43581224fda6b9555aaab58e88ac10270000000000001976a91402cfbfc3931c7c1cf712574e80e75b1c2df14b2088acd5120000000000001976a914bd3dbab46060873e17ca754b0db0da4552c9a09388ac00000000"

func TestFromBEEF(t *testing.T) {
	// Decode the BEEF data from base64
	beefBytes, err := base64.StdEncoding.DecodeString(BEEF)
	require.NoError(t, err, "Failed to decode BEEF data")

	// Create a new Transaction object
	tx := &Transaction{}

	// Use the FromBEEF method to populate the transaction
	err = tx.FromBEEF(beefBytes)
	require.NoError(t, err, "FromBEEF method failed")

	expectedTxID := "ce70df889d5ba66a989b8e47294c751d19f948f004075cf265c4cbb2a7c97838"
	txid := tx.TxID()
	require.Equal(t, expectedTxID, txid.String(), "Transaction ID does not match")

	_, err = tx.collectAncestors(txid, map[string]*Transaction{}, true)
	require.NoError(t, err, "collectAncestors method failed")

	atomic, err := tx.AtomicBEEF(false)
	require.NoError(t, err, "AtomicBEEF method failed")

	tx2, err := NewTransactionFromBEEF(atomic)
	require.NoError(t, err, "NewTransactionFromBEEF method failed")
	require.Equal(t, tx.TxID().String(), tx2.TxID().String(), "Transaction ID does not match")

	_, txid, err = NewBeefFromAtomicBytes(atomic)
	require.NoError(t, err, "NewBeefFromAtomicBytes method failed")
	require.Equal(t, txid.String(), expectedTxID, "Transaction ID does not match")

	_, txFromBeef, _, err := ParseBeef(beefBytes)
	require.NoError(t, err, "ParseBeef method failed")
	require.Equal(t, txFromBeef.TxID().String(), expectedTxID, "Transaction ID does not match")

	_, err = NewBeefFromTransaction(tx)
	require.NoError(t, err, "NewBeefFromTransaction method failed")
}

func TestFromBeefErrorCase(t *testing.T) {
	tx := &Transaction{}
	err := tx.FromBEEF([]byte("invalid data"))
	require.Error(t, err, "FromBEEF method should fail with invalid data")
}

func TestNewEmptyBEEF(t *testing.T) {
	t.Run("New Beef V1", func(t *testing.T) {
		v1 := NewBeefV1()
		beefBytes, err := v1.Bytes()

		require.NoError(t, err)
		require.Equal(t, "0100beef0000", hex.EncodeToString(beefBytes))
	})
	t.Run("New Beef V2", func(t *testing.T) {
		v2 := NewBeefV2()
		beefBytes, err := v2.Bytes()

		require.NoError(t, err)
		require.Equal(t, "0200beef0000", hex.EncodeToString(beefBytes))
	})
}

func TestNewBEEFFromBytes(t *testing.T) {
	// Decode the BEEF data from base64
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err, "Failed to decode BEEF data from hex string")

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err, "NewBeefFromBytes method failed")

	// Check the Beef object's properties
	require.Equal(t, uint32(4022206466), beef.Version, "Version does not match")
	require.Len(t, beef.BUMPs, 3, "BUMPs length does not match")
	require.Len(t, beef.Transactions, 3, "Transactions length does not match")

	tx := beef.FindTransaction("b1fc0f44ba629dbdffab9e34fcc4faf9dbde3560a7365c55c26fe4daab052aac")
	require.NotNil(t, tx, "Transaction not found in BEEF data")

	atomic, err := tx.AtomicBEEF(false)
	require.NoError(t, err, "AtomicBEEF method failed")

	_, err = NewTransactionFromBEEF(atomic)
	require.NoError(t, err, "NewTransactionFromBEEF method failed")

	binary.LittleEndian.PutUint32(beefBytes[0:4], 0xdeadbeef)
	_, err = NewTransactionFromBEEF(beefBytes)
	require.Error(t, err, "use NewBeefFromBytes to parse anything which isn't V1 BEEF or AtomicBEEF")

}

func TestBeefTransactionFinding(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Test RemoveExistingTxid and findTxid
	for txid := range beef.Transactions {
		// Verify we can find it
		tx := beef.findTxid(txid)
		require.NotNil(t, tx)

		// Remove it
		beef.RemoveExistingTxid(txid)

		// Verify it's gone
		tx = beef.findTxid(txid)
		require.Nil(t, tx)
		break // just test one
	}
}

func TestBeefMakeTxidOnly(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Get first transaction and verify it exists
	var txid string
	var originalTx *BeefTx
	for id, tx := range beef.Transactions {
		if tx.Transaction != nil {
			txid = id
			originalTx = tx
			break
		}
	}
	require.NotEmpty(t, txid)
	require.NotNil(t, originalTx)

	// Convert the hash to ensure it's valid
	hash, err := chainhash.NewHashFromHex(txid)
	require.NoError(t, err)

	// Test MakeTxidOnly
	txidOnly := beef.MakeTxidOnly(txid)
	require.NotNil(t, txidOnly)
	require.Equal(t, TxIDOnly, txidOnly.DataFormat)
	require.NotNil(t, txidOnly.KnownTxID)
	require.Equal(t, hash.String(), txidOnly.KnownTxID.String())

	t.Log(beef.ToLogString())
}

func TestBeefSortTxs(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// First, let's check what transactions we have
	for txid, tx := range beef.Transactions {
		t.Logf("Transaction %s:", txid)
		t.Logf("  DataFormat: %v", tx.DataFormat)
		t.Logf("  Has Transaction: %v", tx.Transaction != nil)
		if tx.Transaction != nil {
			t.Logf("  Has MerklePath: %v", tx.Transaction.MerklePath != nil)
			t.Logf("  Number of Inputs: %d", len(tx.Transaction.Inputs))
		}
		t.Logf("  Has KnownTxID: %v", tx.KnownTxID != nil)
	}

	// Test SortTxs
	result := beef.SortTxs()
	require.NotNil(t, result)

	// Log the results
	t.Logf("Valid transactions: %v", result.Valid)
	t.Logf("TxIDOnly transactions: %v", result.TxidOnly)
	t.Logf("Transactions with missing inputs: %v", result.WithMissingInputs)
	t.Logf("Missing inputs: %v", result.MissingInputs)
	t.Logf("Not valid transactions: %v", result.NotValid)

	// Verify that valid transactions don't have missing inputs
	for _, txid := range result.Valid {
		require.NotContains(t, result.MissingInputs, txid, "Valid transaction should not have missing inputs")
		require.NotContains(t, result.NotValid, txid, "Valid transaction should not be in NotValid list")
		require.NotContains(t, result.WithMissingInputs, txid, "Valid transaction should not be in WithMissingInputs list")
	}

	// Verify that transactions with missing inputs are properly categorized
	for _, txid := range result.WithMissingInputs {
		require.NotContains(t, result.Valid, txid, "Transaction with missing inputs should not be in Valid list")
	}

	// Verify that invalid transactions are properly categorized
	for _, txid := range result.NotValid {
		require.NotContains(t, result.Valid, txid, "Invalid transaction should not be in Valid list")
	}
}

func TestBeefToLogString(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Get the log string
	logStr := beef.ToLogString()

	// Verify the log string contains expected information
	require.Contains(t, logStr, "BEEF with", "Log should contain BEEF summary")
	require.Contains(t, logStr, "BUMPs", "Log should mention BUMPs")
	require.Contains(t, logStr, "Transactions", "Log should mention Transactions")
	require.Contains(t, logStr, "isValid", "Log should mention validity")

	// Verify BUMP information is logged
	require.Contains(t, logStr, "BUMP", "Log should contain BUMP details")
	require.Contains(t, logStr, "block:", "Log should contain block height")
	require.Contains(t, logStr, "txids:", "Log should contain txids")

	// Verify Transaction information is logged
	require.Contains(t, logStr, "TX", "Log should contain transaction details")
	require.Contains(t, logStr, "txid:", "Log should contain transaction IDs")

	// Verify each BUMP and transaction is mentioned
	bumpCount := beef.BUMPs
	for i := 0; i < len(bumpCount); i++ {
		require.Contains(t, logStr, fmt.Sprintf("BUMP %d", i), "Log should contain each BUMP")
	}
	for _, tx := range beef.Transactions {
		if tx.Transaction != nil {
			require.Contains(t, logStr, tx.Transaction.TxID().String(), "Log should contain each transaction ID")
		}
	}
}

func TestBeefClone(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	original, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Clone the object
	clone := original.Clone()

	// Verify basic properties match
	require.Equal(t, original.Version, clone.Version, "Version should match")
	require.Equal(t, len(original.BUMPs), len(clone.BUMPs), "Number of BUMPs should match")
	require.Equal(t, len(original.Transactions), len(clone.Transactions), "Number of transactions should match")

	// Verify BUMPs are copied (not just referenced)
	for i, bump := range original.BUMPs {
		require.Equal(t, bump.BlockHeight, clone.BUMPs[i].BlockHeight, "BUMP BlockHeight should match")
		require.Equal(t, len(bump.Path), len(clone.BUMPs[i].Path), "BUMP Path length should match")

		// Verify each level of the path
		for j := range bump.Path {
			require.Equal(t, len(bump.Path[j]), len(clone.BUMPs[i].Path[j]), "Path level length should match")

			// Verify each PathElement
			for k := range bump.Path[j] {
				// Compare PathElement fields
				require.Equal(t, bump.Path[j][k].Offset, clone.BUMPs[i].Path[j][k].Offset, "PathElement Offset should match")
				if bump.Path[j][k].Hash != nil {
					require.Equal(t, bump.Path[j][k].Hash.String(), clone.BUMPs[i].Path[j][k].Hash.String(), "PathElement Hash should match")
				}
				if bump.Path[j][k].Txid != nil {
					require.Equal(t, *bump.Path[j][k].Txid, *clone.BUMPs[i].Path[j][k].Txid, "PathElement Txid should match")
				}
				if bump.Path[j][k].Duplicate != nil {
					require.Equal(t, *bump.Path[j][k].Duplicate, *clone.BUMPs[i].Path[j][k].Duplicate, "PathElement Duplicate should match")
				}
			}
		}
	}

	// Verify transactions are copied (not just referenced)
	for txid, tx := range original.Transactions {
		clonedTx, exists := clone.Transactions[txid]
		require.True(t, exists, "Transaction should exist in clone")
		require.Equal(t, tx.DataFormat, clonedTx.DataFormat, "Transaction DataFormat should match")
		if tx.Transaction != nil {
			require.Equal(t, tx.Transaction.TxID().String(), clonedTx.Transaction.TxID().String(), "Transaction ID should match")
		}
		if tx.KnownTxID != nil {
			require.Equal(t, tx.KnownTxID.String(), clonedTx.KnownTxID.String(), "KnownTxID should match")
		}
	}

	// Modify clone and verify original is unchanged
	clone.Version = 999
	require.NotEqual(t, original.Version, clone.Version, "Modifying clone should not affect original")

	// Remove a transaction from clone and verify original is unchanged
	for txid := range clone.Transactions {
		delete(clone.Transactions, txid)
		_, exists := original.Transactions[txid]
		require.True(t, exists, "Removing transaction from clone should not affect original")
		break // just test one
	}
}

func TestBeefTrimknownTxIDs(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Convert some transactions to TxIDOnly format
	var txidsToTrim []string
	for txid, tx := range beef.Transactions {
		if tx.Transaction != nil {
			// Convert to TxIDOnly and add to our list to trim
			beef.MakeTxidOnly(txid)
			txidsToTrim = append(txidsToTrim, txid)
			if len(txidsToTrim) >= 2 { // Convert 2 transactions to test with
				break
			}
		}
	}
	require.GreaterOrEqual(t, len(txidsToTrim), 1, "Should have at least one transaction to trim")

	// Verify the transactions are now in TxIDOnly format
	for _, txid := range txidsToTrim {
		tx := beef.findTxid(txid)
		require.NotNil(t, tx)
		require.Equal(t, TxIDOnly, tx.DataFormat)
	}

	// Trim the known TxIDs
	beef.TrimknownTxIDs(txidsToTrim)

	// Verify the transactions were removed
	for _, txid := range txidsToTrim {
		tx := beef.findTxid(txid)
		require.Nil(t, tx, "Transaction should have been removed")
	}

	// Verify other transactions still exist
	for txid, tx := range beef.Transactions {
		require.NotContains(t, txidsToTrim, txid, "Remaining transaction should not have been in trim list")
		if tx.DataFormat == TxIDOnly {
			require.NotContains(t, txidsToTrim, txid, "TxIDOnly transaction that wasn't in trim list should still exist")
		}
	}
}

func TestBeefGetValidTxids(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// First, let's check what transactions we have
	t.Log("Checking transactions in BEEF:")
	for txid, tx := range beef.Transactions {
		t.Logf("Transaction %s:", txid)
		t.Logf("  DataFormat: %v", tx.DataFormat)
		t.Logf("  Has Transaction: %v", tx.Transaction != nil)
		if tx.Transaction != nil {
			t.Logf("  Has MerklePath: %v", tx.Transaction.MerklePath != nil)
			t.Logf("  Number of Inputs: %d", len(tx.Transaction.Inputs))
			for i, input := range tx.Transaction.Inputs {
				t.Logf("    Input %d SourceTXID: %s", i, input.SourceTXID.String())
			}
		}
		t.Logf("  Has KnownTxID: %v", tx.KnownTxID != nil)
	}

	// Get sorted transactions to see what's valid
	sorted := beef.SortTxs()
	t.Log("\nSorted transaction results:")
	t.Logf("  Valid: %v", sorted.Valid)
	t.Logf("  TxidOnly: %v", sorted.TxidOnly)
	t.Logf("  WithMissingInputs: %v", sorted.WithMissingInputs)
	t.Logf("  MissingInputs: %v", sorted.MissingInputs)
	t.Logf("  NotValid: %v", sorted.NotValid)

	// Get valid txids
	validTxids := beef.GetValidTxids()
	t.Logf("\nGetValidTxids result: %v", validTxids)

	// Verify results match
	require.Equal(t, sorted.Valid, validTxids, "GetValidTxids should return same txids as SortTxs.Valid")

	// If we have any valid transactions, verify they exist and have valid inputs
	if len(validTxids) > 0 {
		for _, txid := range validTxids {
			tx := beef.findTxid(txid)
			require.NotNil(t, tx, "Valid txid should exist in transactions map")

			// If it has a transaction, verify it has no missing inputs
			if tx.Transaction != nil {
				for _, input := range tx.Transaction.Inputs {
					sourceTx := beef.findTxid(input.SourceTXID.String())
					require.NotNil(t, sourceTx, "Input transaction should exist for valid transaction")
				}
			}
		}
	} else {
		t.Log("No valid transactions found - this is expected if all transactions have missing inputs or are not valid")
	}
}

func TestBeefFindTransactionForSigning(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// First, let's check what transactions we have
	t.Log("Checking transactions in BEEF:")
	for txid, tx := range beef.Transactions {
		t.Logf("Transaction %s:", txid)
		t.Logf("  DataFormat: %v", tx.DataFormat)
		t.Logf("  Has Transaction: %v", tx.Transaction != nil)
		if tx.Transaction != nil {
			t.Logf("  Has MerklePath: %v", tx.Transaction.MerklePath != nil)
			t.Logf("  Number of Inputs: %d", len(tx.Transaction.Inputs))
			for i, input := range tx.Transaction.Inputs {
				t.Logf("    Input %d SourceTXID: %s", i, input.SourceTXID.String())
			}
		}
		t.Logf("  Has KnownTxID: %v", tx.KnownTxID != nil)
	}

	// Get sorted transactions to see what's valid
	sorted := beef.SortTxs()
	t.Log("\nSorted transaction results:")
	t.Logf("  Valid: %v", sorted.Valid)
	t.Logf("  TxidOnly: %v", sorted.TxidOnly)
	t.Logf("  WithMissingInputs: %v", sorted.WithMissingInputs)
	t.Logf("  MissingInputs: %v", sorted.MissingInputs)
	t.Logf("  NotValid: %v", sorted.NotValid)

	// Get valid txids
	validTxids := beef.GetValidTxids()
	t.Logf("\nGetValidTxids result: %v", validTxids)

	// For this test, we'll use any transaction that has full data
	var testTxid string
	for txid, tx := range beef.Transactions {
		if tx.Transaction != nil {
			testTxid = txid
			break
		}

	}
	require.NotEmpty(t, testTxid, "Should have at least one transaction with full data")

	// Test FindTransactionForSigning
	tx := beef.FindTransactionForSigning(testTxid)
	require.NotNil(t, tx, "Should find a transaction for signing")
	require.Equal(t, testTxid, tx.TxID().String(), "Transaction ID should match")
}

func TestBeefFindAtomicTransaction(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Get a transaction ID to test with
	var testTxid string
	for txid, tx := range beef.Transactions {
		if tx.Transaction != nil {
			testTxid = txid
			break
		}
	}
	require.NotEmpty(t, testTxid, "Should have at least one transaction with full data")

	// Test FindAtomicTransaction
	tx := beef.FindAtomicTransaction(testTxid)
	require.NotNil(t, tx, "Should find an atomic transaction")
	require.Equal(t, testTxid, tx.TxID().String(), "Transaction ID should match")
}

func TestTransactionsReadFrom(t *testing.T) {
	t.Run("normal transaction", func(t *testing.T) {
		// Get a transaction from BEEFSet
		beefBytes, err := hex.DecodeString(BEEFSet)
		require.NoError(t, err)
		beef, err := NewBeefFromBytes(beefBytes)
		require.NoError(t, err)

		// Find a transaction with full data
		var txBytes []byte
		for _, tx := range beef.Transactions {
			if tx.Transaction != nil {
				// Create a buffer with transaction count (1) followed by the transaction data
				buf := bytes.NewBuffer(nil)
				buf.WriteByte(1) // Write count of 1 transaction
				buf.Write(tx.Transaction.Bytes())
				txBytes = buf.Bytes()
				break
			}
		}
		require.NotEmpty(t, txBytes, "Should have found a transaction with full data")

		// Test ReadFrom
		reader := bytes.NewReader(txBytes)
		txs := &Transactions{}
		n, err := txs.ReadFrom(reader)
		require.NoError(t, err)
		require.Equal(t, int64(len(txBytes)), n)
		require.NotEmpty(t, *txs)
	})

	t.Run("incomplete transaction with zero inputs", func(t *testing.T) {
		// Create a buffer with transaction count (0)
		buf := bytes.NewBuffer(nil)
		buf.WriteByte(0) // Write count of 0 transactions

		// Test ReadFrom
		reader := bytes.NewReader(buf.Bytes())
		txs := &Transactions{}
		n, err := txs.ReadFrom(reader)
		require.NoError(t, err)
		require.Equal(t, int64(1), n) // Should only read the count byte
		require.Empty(t, *txs)
	})
}

func TestBeefMergeBump(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create two Beef objects
	beef1, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)
	beef2, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Get a BUMP to merge
	require.NotEmpty(t, beef2.BUMPs, "Should have BUMPs to test with")
	bumpToMerge := beef2.BUMPs[0]

	// Record initial state
	initialBumpCount := len(beef1.BUMPs)

	// Test MergeBump
	beef1.MergeBump(bumpToMerge)

	// Verify the BUMP was merged
	require.Len(t, beef1.BUMPs, initialBumpCount+1, "Should have one more BUMP after merge")
	require.Equal(t, bumpToMerge.BlockHeight, beef1.BUMPs[len(beef1.BUMPs)-1].BlockHeight, "Merged BUMP should have same block height")

	// Verify the paths are equal but not the same instance
	require.Equal(t, len(bumpToMerge.Path), len(beef1.BUMPs[len(beef1.BUMPs)-1].Path), "Path lengths should match")
	for i := range bumpToMerge.Path {
		require.Equal(t, len(bumpToMerge.Path[i]), len(beef1.BUMPs[len(beef1.BUMPs)-1].Path[i]), "Path element lengths should match")
		for j := range bumpToMerge.Path[i] {
			require.Equal(t, bumpToMerge.Path[i][j].Offset, beef1.BUMPs[len(beef1.BUMPs)-1].Path[i][j].Offset, "Path element offset should match")
			if bumpToMerge.Path[i][j].Hash != nil {
				require.Equal(t, bumpToMerge.Path[i][j].Hash.String(), beef1.BUMPs[len(beef1.BUMPs)-1].Path[i][j].Hash.String(), "Path element hash should match")
			}
		}
	}
}

func TestBeefMergeTransactions(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create two Beef objects
	beef1, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)
	beef2, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Get a transaction to merge and modify it to make it unique
	var txToMerge *BeefTx
	var txid string
	for id, tx := range beef2.Transactions {
		if tx.Transaction != nil {
			// Delete this transaction from beef1 to ensure we can merge it
			delete(beef1.Transactions, id)
			txToMerge = tx
			txid = id
			break
		}
	}
	require.NotNil(t, txToMerge, "Should have a transaction to test with")
	require.NotEmpty(t, txid, "Should have a transaction ID")

	// Test MergeRawTx
	initialTxCount := len(beef1.Transactions)
	rawTx := txToMerge.Transaction.Bytes()
	beefTx, err := beef1.MergeRawTx(rawTx, nil)
	require.NoError(t, err)
	require.NotNil(t, beefTx)
	require.Len(t, beef1.Transactions, initialTxCount+1, "Should have one more transaction after merge")

	// Test MergeTransaction
	beef3, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)
	delete(beef3.Transactions, txid)
	initialTxCount = len(beef3.Transactions)
	beefTx, err = beef3.MergeTransaction(txToMerge.Transaction)
	require.NoError(t, err)
	require.NotNil(t, beefTx)
	require.Len(t, beef3.Transactions, initialTxCount+1, "Should have one more transaction after merge")
}

func TestBeefErrorHandling(t *testing.T) {
	t.Run("invalid_transaction_format", func(t *testing.T) {
		// Create a transaction with corrupted format byte
		beefBytes, err := hex.DecodeString(BEEFSet)
		require.NoError(t, err)

		// Find the first transaction format byte
		// The format byte comes after the version (4 bytes), number of BUMPs (VarInt),
		// BUMP data, and number of transactions (VarInt)
		reader := bytes.NewReader(beefBytes)

		// Skip version
		_, err = reader.Seek(4, io.SeekStart)
		require.NoError(t, err)

		// Skip number of BUMPs and BUMP data
		var numberOfBUMPs util.VarInt
		_, err = numberOfBUMPs.ReadFrom(reader)
		require.NoError(t, err)

		// Skip BUMP data
		for i := 0; i < int(numberOfBUMPs); i++ {
			bump, err := NewMerklePathFromReader(reader)
			require.NoError(t, err)
			_ = bump
		}

		// Skip number of transactions
		var numberOfTransactions util.VarInt
		_, err = numberOfTransactions.ReadFrom(reader)
		require.NoError(t, err)

		// Now we're at the first transaction format byte
		pos, err := reader.Seek(0, io.SeekCurrent)
		require.NoError(t, err)

		// Create a copy of the bytes and corrupt the format byte
		corruptedBytes := make([]byte, len(beefBytes))
		copy(corruptedBytes, beefBytes)
		corruptedBytes[pos] = 0xFF // Invalid format byte

		// Attempt to create a new Beef object with corrupted data
		_, err = NewBeefFromBytes(corruptedBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid data format", "Error should mention invalid format")
	})
}

func TestBeefEdgeCases(t *testing.T) {
	t.Run("BEEF_with_only_TxIDOnly_transactions", func(t *testing.T) {
		// Create a minimal BEEF V2 data structure
		buf := new(bytes.Buffer)

		// Write version (BEEF_V2)
		err := binary.Write(buf, binary.LittleEndian, BEEF_V2)
		require.NoError(t, err)

		// Write number of BUMPs (0)
		buf.Write(util.VarInt(0).Bytes())

		// Write number of transactions (1)
		buf.Write(util.VarInt(1).Bytes())

		// Write one TxIDOnly transaction
		buf.WriteByte(byte(TxIDOnly)) // DataFormat

		// Create a valid txid hash
		txidBytes, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
		require.NoError(t, err)
		buf.Write(txidBytes)

		// Create a new Beef object from the bytes
		beef, err := NewBeefFromBytes(buf.Bytes())
		require.NoError(t, err)
		t.Logf("Created BEEF object with %d transactions", len(beef.Transactions))

		// Verify the transaction is TxIDOnly and has valid KnownTxID
		for txid, tx := range beef.Transactions {
			t.Logf("Verifying transaction %s", txid)
			t.Logf("  DataFormat: %v", tx.DataFormat)
			t.Logf("  Has Transaction: %v", tx.Transaction != nil)
			t.Logf("  Has KnownTxID: %v", tx.KnownTxID != nil)

			// Test the behavior of TxIDOnly transactions
			require.Equal(t, TxIDOnly, tx.DataFormat, "Transaction should be TxIDOnly format")
			require.NotNil(t, tx.KnownTxID, "TxIDOnly transaction should have KnownTxID")

			// Test that TxIDOnly transactions are properly categorized
			sorted := beef.SortTxs()
			require.NotContains(t, sorted.Valid, txid, "TxIDOnly transaction should not be considered valid")
			require.Contains(t, sorted.TxidOnly, txid, "TxIDOnly transaction should be in TxidOnly list")

			// Test that the transaction is not returned by GetValidTxids
			validTxids := beef.GetValidTxids()
			require.NotContains(t, validTxids, txid, "TxIDOnly transaction should not be in GetValidTxids result")
		}
	})
}

func TestBeefMergeBeefBytes(t *testing.T) {
	// Create first BEEF object
	beefBytes1, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)
	beef1, err := NewBeefFromBytes(beefBytes1)
	require.NoError(t, err)

	// Create a minimal second BEEF object with a single transaction
	buf := new(bytes.Buffer)

	// Write version (BEEF_V2)
	err = binary.Write(buf, binary.LittleEndian, BEEF_V2)
	require.NoError(t, err)

	// Write number of BUMPs (0)
	buf.Write(util.VarInt(0).Bytes())

	// Write number of transactions (1)
	buf.Write(util.VarInt(1).Bytes())

	// Write one RawTx transaction
	buf.WriteByte(byte(RawTx))

	// Create a simple transaction
	tx := &Transaction{
		Version:  1,
		Inputs:   []*TransactionInput{},
		Outputs:  []*TransactionOutput{},
		LockTime: 0,
	}

	// Write the transaction
	txBytes := tx.Bytes()
	buf.Write(txBytes)

	// Record initial state
	initialTxCount := len(beef1.Transactions)

	// Test MergeBeefBytes
	err = beef1.MergeBeefBytes(buf.Bytes())
	require.NoError(t, err)

	// Verify transactions were merged
	require.Len(t, beef1.Transactions, initialTxCount+1, "Should have merged one transaction")

	// Test merging invalid BEEF bytes
	invalidBytes := []byte("invalid beef data")
	err = beef1.MergeBeefBytes(invalidBytes)
	require.Error(t, err, "Should error on invalid BEEF bytes")
}

func TestBeefMergeBeefTx(t *testing.T) {
	t.Run("merge valid transaction", func(t *testing.T) {
		// Create a valid transaction
		tx := &Transaction{
			Version:  1,
			Inputs:   make([]*TransactionInput, 0),
			Outputs:  make([]*TransactionOutput, 0),
			LockTime: 0,
		}

		beef := &Beef{
			Version:      BEEF_V2,
			BUMPs:        make([]*MerklePath, 0),
			Transactions: make(map[string]*BeefTx),
		}

		btx := &BeefTx{
			DataFormat:  RawTx,
			Transaction: tx,
		}

		result, err := beef.MergeBeefTx(btx)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, beef.Transactions, 1)
	})

	t.Run("handle nil transaction", func(t *testing.T) {
		beef := &Beef{
			Version:      BEEF_V2,
			BUMPs:        make([]*MerklePath, 0),
			Transactions: make(map[string]*BeefTx),
		}

		// Test with nil BeefTx
		result, err := beef.MergeBeefTx(nil)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "nil transaction")
		require.Empty(t, beef.Transactions)
	})

	t.Run("handle BeefTx with nil Transaction", func(t *testing.T) {
		beef := &Beef{
			Version:      BEEF_V2,
			BUMPs:        make([]*MerklePath, 0),
			Transactions: make(map[string]*BeefTx),
		}

		// Test with BeefTx that has nil Transaction
		btx := &BeefTx{
			DataFormat:  RawTx,
			Transaction: nil,
		}

		result, err := beef.MergeBeefTx(btx)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "nil transaction")
		require.Empty(t, beef.Transactions)
	})
}

func TestBeefFindAtomicTransactionWithSourceTransactions(t *testing.T) {
	// Create a BEEF object with transactions that have source transactions
	beef := &Beef{
		Version:      BEEF_V2,
		BUMPs:        make([]*MerklePath, 0),
		Transactions: make(map[string]*BeefTx),
	}

	// Create source transaction
	sourceTx := &Transaction{
		Version:  1,
		Inputs:   make([]*TransactionInput, 0),
		Outputs:  make([]*TransactionOutput, 0),
		LockTime: 0,
	}
	sourceBeefTx := &BeefTx{
		DataFormat:  RawTx,
		Transaction: sourceTx,
	}
	sourceTxid := sourceTx.TxID().String()
	beef.Transactions[sourceTxid] = sourceBeefTx

	// Create main transaction that references the source
	mainTx := &Transaction{
		Version: 1,
		Inputs: []*TransactionInput{
			{
				SourceTXID:        sourceTx.TxID(),
				SourceTransaction: sourceTx,
				SourceTxOutIndex:  0,
				SequenceNumber:    0xFFFFFFFF,
				UnlockingScript:   script.NewFromBytes([]byte{}),
			},
		},
		Outputs:  make([]*TransactionOutput, 0),
		LockTime: 0,
	}
	mainBeefTx := &BeefTx{
		DataFormat:  RawTx,
		Transaction: mainTx,
	}
	mainTxid := mainTx.TxID().String()
	beef.Transactions[mainTxid] = mainBeefTx

	// Create a BUMP for the source transaction
	bump := &MerklePath{
		BlockHeight: 1234,
		Path: [][]*PathElement{
			{
				&PathElement{
					Hash:   sourceTx.TxID(),
					Offset: 0,
				},
			},
		},
	}
	beef.BUMPs = append(beef.BUMPs, bump)

	// Test FindAtomicTransaction
	result := beef.FindAtomicTransaction(mainTxid)
	require.NotNil(t, result)
	require.Equal(t, mainTxid, result.TxID().String())

	// Verify source transaction has merkle path
	require.NotNil(t, mainTx.Inputs[0].SourceTransaction)
	require.NotNil(t, mainTx.Inputs[0].SourceTransaction.MerklePath)
}

func TestBeefMergeTxidOnly(t *testing.T) {
	// Create a BEEF object
	beef := &Beef{
		Version:      BEEF_V2,
		BUMPs:        make([]*MerklePath, 0),
		Transactions: make(map[string]*BeefTx),
	}

	// Create a transaction ID
	txidBytes, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	txid, err := chainhash.NewHash(txidBytes)
	require.NoError(t, err)

	// Test MergeTxidOnly
	result := beef.MergeTxidOnly(txid.String())
	require.NotNil(t, result)
	require.Equal(t, TxIDOnly, result.DataFormat)
	require.NotNil(t, result.KnownTxID)
	require.Equal(t, txid.String(), result.KnownTxID.String())
	require.Nil(t, result.Transaction)

	// Verify the transaction was added to the BEEF object
	require.Len(t, beef.Transactions, 1)
	require.Contains(t, beef.Transactions, txid.String())

	// Test merging the same txid again
	result2 := beef.MergeTxidOnly(txid.String())
	require.NotNil(t, result2)
	require.Equal(t, result, result2)
	require.Len(t, beef.Transactions, 1)
}

func TestBeefFindBumpWithNilBumpIndex(t *testing.T) {
	// Create a BEEF object
	beef := &Beef{
		Version:      BEEF_V2,
		BUMPs:        make([]*MerklePath, 0),
		Transactions: make(map[string]*BeefTx),
	}

	// Create a transaction with a source transaction
	sourceTx := &Transaction{
		Version:  1,
		Inputs:   make([]*TransactionInput, 0),
		Outputs:  make([]*TransactionOutput, 0),
		LockTime: 0,
	}

	mainTx := &Transaction{
		Version: 1,
		Inputs: []*TransactionInput{
			{
				SourceTXID:        sourceTx.TxID(),
				SourceTransaction: sourceTx,
				SourceTxOutIndex:  0,
				SequenceNumber:    0xFFFFFFFF,
				UnlockingScript:   script.NewFromBytes([]byte{}),
			},
		},
		Outputs:  make([]*TransactionOutput, 0),
		LockTime: 0,
	}

	// Add transactions to BEEF
	beef.Transactions[sourceTx.TxID().String()] = &BeefTx{
		DataFormat:  RawTx,
		Transaction: sourceTx,
	}
	beef.Transactions[mainTx.TxID().String()] = &BeefTx{
		DataFormat:  RawTx,
		Transaction: mainTx,
	}

	// Test FindBump with no BUMPs (nil bumpIndex)
	result := beef.FindBump(mainTx.TxID().String())
	require.Nil(t, result)

	// Verify the code path for checking source transactions was executed
	// This is mainly to cover the uncovered lines, as the functionality
	// is already tested in other test cases
}

func TestBeefBytes(t *testing.T) {
	t.Run("serialize and deserialize", func(t *testing.T) {
		// Create a BEEF object with different types of transactions
		beef := &Beef{
			Version:      BEEF_V2,
			BUMPs:        make([]*MerklePath, 0),
			Transactions: make(map[string]*BeefTx),
		}

		// Add a TxIDOnly transaction
		txidBytes, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
		require.NoError(t, err)
		txid, err := chainhash.NewHash(txidBytes)
		require.NoError(t, err)
		beef.MergeTxidOnly(txid.String())

		// Add a RawTx transaction
		tx := &Transaction{
			Version:  1,
			Inputs:   make([]*TransactionInput, 0),
			Outputs:  make([]*TransactionOutput, 0),
			LockTime: 0,
		}
		beefTx, err := beef.MergeRawTx(tx.Bytes(), nil)
		require.NoError(t, err)
		require.Equal(t, RawTx, beefTx.DataFormat)

		// Add a RawTxAndBumpIndex transaction
		bump := &MerklePath{
			BlockHeight: 1234,
			Path: [][]*PathElement{
				{
					&PathElement{
						Hash:   txid,
						Offset: 0,
					},
				},
			},
		}
		beef.BUMPs = append(beef.BUMPs, bump)
		bumpIndex := 0
		tx2 := &Transaction{
			Version:  1,
			Inputs:   make([]*TransactionInput, 0),
			Outputs:  make([]*TransactionOutput, 0),
			LockTime: 0,
		}
		beefTx2, err := beef.MergeRawTx(tx2.Bytes(), &bumpIndex)
		require.NoError(t, err)
		require.Equal(t, RawTxAndBumpIndex, beefTx2.DataFormat)

		// Serialize to bytes
		bytes, err := beef.Bytes()
		require.NoError(t, err)

		// Deserialize and verify
		beef2, err := NewBeefFromBytes(bytes)
		require.NoError(t, err)
		require.Equal(t, beef.Version, beef2.Version)
		require.Equal(t, len(beef.BUMPs), len(beef2.BUMPs))
		require.Equal(t, len(beef.Transactions), len(beef2.Transactions))

		// Verify transactions maintained their format
		for txid, tx := range beef.Transactions {
			tx2, ok := beef2.Transactions[txid]
			require.True(t, ok)
			require.Equal(t, tx.DataFormat, tx2.DataFormat)
			if tx.DataFormat == TxIDOnly {
				require.Equal(t, tx.KnownTxID.String(), tx2.KnownTxID.String())
			}
		}
	})
}

func TestBeefAddComputedLeaves(t *testing.T) {
	// Create a BEEF object with a BUMP that has incomplete leaves
	beef := &Beef{
		Version:      BEEF_V2,
		BUMPs:        make([]*MerklePath, 0),
		Transactions: make(map[string]*BeefTx),
	}

	// Create leaf hashes
	leaf1, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000001")
	leaf2, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000002")

	// Create a BUMP with two leaves in row 0 and no computed parent in row 1
	bump := &MerklePath{
		BlockHeight: 1234,
		Path: [][]*PathElement{
			{
				&PathElement{Hash: leaf1, Offset: 0}, // Left leaf
				&PathElement{Hash: leaf2, Offset: 1}, // Right leaf
			},
			{}, // Empty row for parent
		},
	}
	beef.BUMPs = append(beef.BUMPs, bump)

	// Call AddComputedLeaves
	beef.AddComputedLeaves()

	// Verify the parent hash was computed and added
	require.Len(t, beef.BUMPs[0].Path[1], 1, "Should have one computed parent hash")
	require.Equal(t, uint64(0), beef.BUMPs[0].Path[1][0].Offset, "Parent offset should be 0")
	expectedParent := MerkleTreeParent(leaf1, leaf2)
	require.Equal(t, expectedParent.String(), beef.BUMPs[0].Path[1][0].Hash.String(), "Parent hash should match")

	// Test findLeafByOffset
	foundLeaf := findLeafByOffset(beef.BUMPs[0].Path[0], 0)
	require.NotNil(t, foundLeaf, "Should find leaf at offset 0")
	require.Equal(t, leaf1.String(), foundLeaf.Hash.String(), "Found leaf should match")

	foundLeaf = findLeafByOffset(beef.BUMPs[0].Path[0], 1)
	require.NotNil(t, foundLeaf, "Should find leaf at offset 1")
	require.Equal(t, leaf2.String(), foundLeaf.Hash.String(), "Found leaf should match")

	foundLeaf = findLeafByOffset(beef.BUMPs[0].Path[0], 2)
	require.Nil(t, foundLeaf, "Should not find leaf at offset 2")

	// Test case where right leaf is missing
	bump2 := &MerklePath{
		BlockHeight: 1235,
		Path: [][]*PathElement{
			{
				&PathElement{Hash: leaf1, Offset: 0}, // Left leaf only
			},
			{}, // Empty row for parent
		},
	}
	beef.BUMPs = append(beef.BUMPs, bump2)

	// Call AddComputedLeaves again
	beef.AddComputedLeaves()

	// Verify no parent was computed for bump2 since right leaf is missing
	require.Empty(t, beef.BUMPs[1].Path[1], "Should not compute parent when right leaf is missing")
}

func TestBeefFromV1(t *testing.T) {
	beefData, err := hex.DecodeString(BRC62Hex)
	require.NoError(t, err)
	beef, err := NewBeefFromBytes(beefData)
	require.NoError(t, err)
	require.NotNil(t, beef)
	require.True(t, beef.IsValid(false), "BEEF should be valid")
}

func TestBEEFGeneratedFromComplexTransactionTree2(t *testing.T) {
	// given:
	sources := make(map[string]*SourceTx)
	var id string
	var src *SourceTx

	id, src = TxSrcFromBEEF(t, "0100beef01fe0f810d000a021e02f0514e101c685bb48cbc2d79670bc0857eeee02b743cf0828a1adc30a86e7c9e1f0009c19aaa48c7cd5d22c122880de58aac101907bb055faa7128205f4295af3b94010e002adf38f2ad5aa56c0212d082a7ac2cbe752fe0532cc2003ed173c16c795d846e010600af5005c049426f10642fbdf6af435d31dea0a77c32954f58eec6a60f1e38e8dc01020039e473d0c3ccedee39b06b9391d5b8aa8a561da05269ffe3c4d53250a233df390100000bfb38834b449f137e5a898dec46e242dcceff4192e78e58a824417c7e37958d0101008b7f3f693a1f94e798df88c90c2173892326c013d13cdffb2c55b359626165f101010086bb023baeae6e66ee9b1d5f3582125ea3157d99b7265a0d6b9a874cd19b83250101005db280781ee936daf96a79b06af85790949c8cf14b53b34e066d7ef90e885c5001010055b2765acd3ee55fa5f6f749ab44d28dc20e5d42946e5ca643152ac656430e1e01010069d43d5002daa90dfcf30266aaaa3bca4d12ac12e05494cc81134eb46d209c8a010100000001e65b9ef3d391becf8cb0e4a5e2776510d10a783a4ec63f2c801bd2b931d21920010000006a47304402204c0d70b3ad01a24db1d47faa76572d4e0e0f5961de28da95e9ec606ddc4d6d3e02202fc9df216a7d54c1aade6e7e6dc2e45b8e77a5147d7bab8b7d6ad38a3de22dea41210258663c23d1ffbbc31d32202f4c9a20172f53caa392fc0c7e17aa7ad205ad8ad4ffffffff020b000000000000001976a9148d0ef30e7977226af25db1d5cefd5f063dffdbbf88ac4e000000000000001976a9147bf428515ed60ac36c7df98fd6065e6660e2057088ac000000000100")
	sources[id] = src

	id, src = TxSrcFromBEEF(t, "0100beef01fe8c820d0008029000f3bcd3bdd7b463bd9e059884043d5f1b7efa5806019ae26ec5409a7b2443f75291023a8db70c78fb351eb81218117aaa3cf97d504d43a27906d55de1b8ff26d0877c0149007471492588010811c176fc3279ee9fe9ff186bed8afb84824c7ca8ae1c6c85700125005aeecc9cf38154eeb77d3052a7b6095f54334532a7248db3935691c7e05c41de011300e7f39a587fc25eeefd67296f754b9cad2e5550ade2cc0da700484998646f902b01080033294c88c26581f660a38ee11cfb483a88418c02288e3b741efae3d8d9e2e9f3010500b8976d76be19369cca6fd2caee7721aeee6a24fc90c4db9c4a1dc9e395e371b9010300b13689864cb4f043bd377229dde575b419d40a9c28fcd9c158e1f83db6c60973010000e3ae43275988bf8d18cdad807db5548a0cbc8c2f33dbb36829b79feb5e1c61010101000000015137849f7901ee43c7a82edec1feeeb80f82156f7ab5c14a86b02ce81eca8196010000006b4830450221009c7b5c5ca5e172fa11688c8ce699498a4bddb410102eda49d6858489b7d39f9a02200a99d9ee4aa92fc7c0f6bdbe72c30f00375273d3947e76ca3bd16b513693af364121021dd8cf0b64cbbcf25cdfc92d24c8101feb5631725758acc1dd5815e7fae72483ffffffff020b000000000000001976a914aeda7f9e6377a2a747e99e26dfc30cffb658ada988ac4e000000000000001976a9145f0d0c7967a487646cb4cf9dfeb2de5f6904eced88ac000000000100")
	sources[id] = src

	id, src = TxSrcFromBEEF(t, "0100beef01fe97820d000802c400c301d72d906e3e0316f3a0ecd52aed8511020dc4ce6cc10262dbd603c9d0b41ec502c76dc34e4617ec07c9ea3510ee5d9bda2ac1c43fe930f787f934115d16ce5bfb01630089d026105541b0465f1cfe4a57a6f1568de20d966144f5338fb7cff71605ac0001300030e82dedc0233bc7f88634dfcceb996a159b4262cd7033d99e3e3830bc127384011900a27db4bc8d35d88e516497dd3ed4d1a5034fbc5a72fc87afcdc8c68b075e8358010d002922bd782a72383114526d6115bafbc022256950482512ceb5160a27cef206a1010700b465873d19ecc75b4efd6edd3544dab62708198466898feec38899ec00636b5a010200b634935f8344bdd49d1c2c5c44042b87906e4a63539cf522f8b80e94814c3454010000e87df8f3484892e60cf21ed471bcbf262f5878946bdc5f3e4ece466f283af8e60101000000019d2c128af4f8d2c6bae49aed16040af8c3410156ccc7a5ddde7edb4a6643e1ed010000006b4830450221009b5cb0d017741fe541a1375779301d81c085ee47c387fd69dd2fdadb8d2c7aa202202bf687cbf5a707a2c436c5ed6f975e2f4aa79d5ddf2745e75e94f5116f88136a4121021ebcca6e3be95a904fd76c50315c9b896a6f9692d45ed7c03dd33a081f966541ffffffff020b000000000000001976a914f87afd6cf2f4c69df61a36dd5acbc21b4d85bf8588ac100d0300000000001976a9149a3cf43b016f0d564942944fd1d190648e5ec3c388ac000000000100")
	sources[id] = src

	id, src = TxSrcFromBEEF(t, "0100beef02fe97820d000804b8002084cdfeab486fe3b20e1cd162b6a2ee3a2aa5eadfe417eb0d6790b81d3e5494b90264ac0de5489f8d45561beb6ed395acdf3a7b2d85ee6a51128bf3429377041fe7c20007eaa967ea31aaf6ccbd82946f5e3bc3816f35152488c2fb20ad3247a555a801c3024c9762c3ca1d1a60f2bc9225eeaa6f90c25009334675f483aa874985da5ede14025d000aed61a6011474c581cc51d46c1a0a1dbe254b1bd5db571ea7adda5ee4fe14fd60001684868a3bb030fe2cba0d93a299ab5e417aeff5614bc1813ab06cb131f47b0b022f000f39e0d53c105a77c69d370bab5de08ec12dd911dc746524a5fb75a4f6114059310032cf5520a213a028423a7d010268ff1095c87868edc939c9655394eb8b908c72021600250edad903fe55892d062031cc6d7f28b31362a0d7f0cf0032d947cbb6cc609e1900a27db4bc8d35d88e516497dd3ed4d1a5034fbc5a72fc87afcdc8c68b075e8358020a0076f57c22f1a6974817d64159d308ab4de6c87575a0849b37094fe2257090eb610d002922bd782a72383114526d6115bafbc022256950482512ceb5160a27cef206a1020400ae529a976118bb9d21266677bfe24c40169b22b7a88a8931e6e15598c2b6f6d80700b465873d19ecc75b4efd6edd3544dab62708198466898feec38899ec00636b5a020200b634935f8344bdd49d1c2c5c44042b87906e4a63539cf522f8b80e94814c34540300366945d0cb65c7619a8d20f61532d9badf0f0e248b3cfaedc06cc0ee8fb73dd2010000e87df8f3484892e60cf21ed471bcbf262f5878946bdc5f3e4ece466f283af8e6fe42830d000b02fdba05003f8ebd318392d16df651c58ec61d153dea5c4c91d2b7c8f0e5e058b1dc65c462fdbb05022d476e68e2de750cd818542f7e67e5759b41342a7099cdef2af2529dc792a58401fddc02000ec96ba9d747237868f1d2c86e47268c26ef36f6c94a1912b3733314d633bdf201fd6f010072a3b0ab6b21cc40b3d19ac7939ab6f78cb3a0183a7b4bfb6a7d59f2f016451701b600d7a7c1fed5491b1a56caa519da77897df5cf40d4bf68338f5982f29231532801015a0004ac4da4093d73e32c6fa18d1e54e7b105c8ff4e2f576546f4ae6719111ab884012c009d9659c893f191fcae323cb131248ad0cf62b5d453a7c6ebcc03fe37bf14a3d4011700a0c1489667907f2af5c1e296bcc9f306bea2bcb4380bcb037c2339d568700eb0010a0081c97c06ab9720c1160e893fbda97a84d00616ed5a709403df1251dd9f1c5f310104008bd6f0d52d27d6c7bf8445797e1955e6915001a2d3d112fe92f085445c1877730103004616b36c0aef0a3a7007687709683109063502a8d774d1e15a5f74bd1d8a5883010000a9c52f139127db83df7dd23e73656fc883622d83197296f1a298d22baa151d9a0c0100000001876717879bb784106ca0684ecc97dfbe03e94db4d9de8889c7bb4efc0784bd84010000006a473044022012ac460542c42f45c7bf57411ea993f58dead3c55b9a5145af1e7848173bf7760220268b179f198d32f3b7215d86e3c627c609ac25e346a2a6aa2e4fdb76f762293041210301931e21a4aade35c54507b93ca0a827878ba048bc505de6fd0609ef1e5bedd1ffffffff020b000000000000001976a9149af8d563369946c602bd58527c615dc38fc0c27888ac1e000000000000001976a9148b0733136657e6fd58047d31542c6794d41a7fdb88ac000000000100010000000171f98beef012b4a8dad0acff55dfe1ce09dc680f55eb8f3b93621d369f0b94e3010000006b483045022100b9a1fccba25c7f079a594ede2596f399d660d47e0b7765d51a75ec44f8d20e53022022872b14b7270ad3a96844c15036776c1e03e77dedc3b1e76ded95ec8d8eafae4121038ef4bbd95c86e7c84451509a9a21c353ec98a948610a7a467d1b0206e4f7d9f0ffffffff020b000000000000001976a9143ffda33164eae9530ff261777b419c49ec36f9b688ac440c0300000000001976a914f05ea9383d3d59df1eef949f5f446ba9d2bbf7ac88ac00000000010101000000012d476e68e2de750cd818542f7e67e5759b41342a7099cdef2af2529dc792a584010000006a47304402207097290a8d6e08198929abb49794f46b479186174d77fe35132ff894551acb9802207afaee1405fab2346d92017054c83346f5d112cab521f07407500be4706c8f544121028cf7d7a2acc018baff58cbbd3f89395218c50a5b30c7e9b5f0a95f5f8988c012ffffffff020c2b0000000000001976a9146ff6dd8608b17c1ee7bb92defdc4ec6e3ca1a56088ac37e10200000000001976a914189a648dc4549073fd2cedff94688807e754a7d288ac000000000001000000013b95c65f45913abd2b948489a111079ae85e55b395a975c96fa477ea5c0f74e3010000006a473044022021cd63b4f7cff0760405174a2e74b1a81ab957f6546b0c2d84a6df3ce82a6ac6022059ba2373b6b1bbefd99ca4b0e5c4b6be6fc8a828eb6a0a456255cf84b02743e24121022de6e3f77c0e53625fcca43df3dd2a634a3909f7fcd4c4d947876760e2544abfffffffff0264000000000000001976a9141539936ebf76f0f0f78b223545238152ca0f6cf488acd2e00200000000001976a9140253efeedd43b4bb2f713f0b73f358143d71acdb88ac000000000001000000014a011070c3f14e63a4a188c0f87837b01abe8290d49e17e1b3b51644954dadbd010000006b483045022100f458180c028f17bac03a95f14141f9c5fc77964d570fab4cebee2b16dcabc3d002201c91e2778f8e0bce523da5ee4e682cd85dff7698a9feb3461879eb424386cb01412103b71b611936c48df959bbfc01abac9c9cdc7a4fa564d13777e7772b0581ddc5a2ffffffff020b000000000000001976a9148b1e270b2787a9a159b353cfa3337f909239fd3c88acc6e00200000000001976a914db17bd8a8711b30d1e0048107d9565517ced1f2e88ac00000000000100000001b654ad6fc865c7f1ac147342bfa528a44505a8cd0f4fe85d23c3ef75fae21941010000006a473044022027153a12a930608fa6380a6126ab70c4380bec1e4609b1b5e9fd6701fe5392a702205d20c6da5f36b34ad4f6775f28843ceb1c5865154e67adc66f226b70bdc83319412102ff9b41495e940cc1de05b599d1d0d6f53e14f15178b67e8de00b785ecdf9d4eaffffffff0264000000000000001976a914790b92b33e746411e27fb1dfb280abbbace3229c88ac61e00200000000001976a914224987cce1af70e7d23395c6977f9a4488cc329e88ac00000000000100000001f0514e101c685bb48cbc2d79670bc0857eeee02b743cf0828a1adc30a86e7c9e010000006b483045022100d7575dc72530884cff94599e54f6aa522236abe35ceb8e7829105a7d10ba9f2402205f18feda4f27518e39f496393356475f7bf36233998542a9566caf1e5ff6a3be412102f3f58ff0fdf942b938a69d9ce006c7e084881a2dd80d9ae2d9d504a1129ac0f4ffffffff020b000000000000001976a9145d4a8b60aaed268f0da2f22d10a624aeb4b396bf88ac42000000000000001976a91419bef7044f06df9d78c194e40628dd41e74251bc88ac000000000100010000000164ac0de5489f8d45561beb6ed395acdf3a7b2d85ee6a51128bf3429377041fe7000000006b483045022100c558e43be4f247103e85b91df60e168ea8c2d8ba32562c8d6616a9e2e2fa346d022056890b08e7804fc5e92f08dc9b3a30aeedf68d4ddf04b2e46c6e70f454a63eca412102e034156bc78abd91fca9d17f0f9743d535bdc8bcab830c4c8fc4236da0a82ca6ffffffff0200000000000000001d006a0474657374012013323032352d30322d32375431353a34323a35370a000000000000001976a91411db5f363d6f894bbddeb4425c9f58c816bbd45f88ac000000000001000000018d00ed22dd1ea3c38c35a04205a0b97d8cfb1c3bb5ab6de02916892f20292139010000006a47304402201258e7ae73db1d1dc05cb6251b0c5523a5779044a4687617b8c8e7ff35d3641f0220114661cbdb8bdce2657db2434ea0364e4ec3c16bd1f3acd5a7e8ec0014943d77412103ff9a106b2916c1e55dd6b010896532654f6f882ba62d1bcdb40d4e9c0de8ee09ffffffff0201000000000000001976a914a602ad12a493bd01e6606a94a98a24c3408cca2388ac08000000000000001976a914ff160272e879cc563841bd2cf6ba913bd3ba592288ac00000000000100000001960bb575d5e87ff68c58100eec25a7c7afd54d0ff38e6069b1c6071a25ee2afb010000006a47304402201728f503cde071696c07c8efb8b41cf2294f37ecdd8d647532fa7586195ef66402207941d4ee103e88414b3ed53697026ff03650f0d4b70b4d93fdb37f3a7a41f8f44121036afb62a41fb3309e1bc7ad9310573452f9d0ced15b12b3fe968e7e3e0e347f7cffffffff0201000000000000001976a914d9f85171d099cb8cb5d86051a6fed273489972e088ac06000000000000001976a9149ad96cbf880d570aa7af12de1de3af2bb26f9cb388ac0000000000010000000288d195e41aba852138219700bf75c74afe6154071b80a6524e16b8bdb344b68f010000006b483045022100d62db15d6c373bb724db70821d02a335d19a64c4455f8f1b0832654e49b3881d022033bcddc774322c5a2a7c24ea5165ee076fee63d13c466e6cd1dd25d93fda2d074121033ccc472975ad22f7d6a040655f78bb5ce848862f79abb557eff907cd590bcb6fffffffff8cd3664f6d35aab4fd3c056c4e9b3c0ead5f3965eb425ce729b25d9305dea59e000000006b483045022100ac37067c325612a7b7eea0402086c6de04bb974f851fbe9361961aa83ba94dcd02203d7b48c01e7704e4757d97ad93fd23e285ade1f74a6e7387f7129ef541ffc8384121038f40345e830f5eef93ea2a1c39c5f7f67a652baf8b0aa16af6b06ce4cc3d955fffffffff020b000000000000001976a914a934f6a9e1ddea8dedbf23eb6858bb6e3b24202688ac5e000000000000001976a9140d31ff65a608a552636f86c5ccc0f6e7f5bd800b88ac000000000001000000025b82fe078b567f65e840bb48c244250e37e7421be21bbb57bfaef0010bbc8f5b010000006b483045022100c739454243cfdf354e0d06bd0170ae78e9f257337ac1e7ffd6c09b3f1673552702203137cf3615a488aec4bbda527d0da7c8d1259fd5ed3fb75fc9e4c88fca04a84b412103548f121e285e6e9d3cf3aa22ad1c491af5d0c7c0d27fe519bea69bf8061c1abeffffffff4c9762c3ca1d1a60f2bc9225eeaa6f90c25009334675f483aa874985da5ede14000000006a473044022067027594ebd867794b1c98a308d926fe6765a575635644dd86e922052a8111c002200df6d5a4e6b12eaa582873ad1534a8dd5cf5eda116c7e7c7efec3efd107b7b9d41210366ab1803a73bbf674b301af200b9ef2027bc12372054d6e2159d0226fcff591dffffffff0264000000000000001976a9149f9878814d4ac95dcb01a45cf4f47e4243dcfc3388ac04000000000000001976a91499621f2f7e67cc363a8855f2ad805d5bf72c0fec88ac0000000000")
	sources[id] = src

	id, src = TxSrcFromBEEF(t, "0100beef01fe42830d000b02fdba05003f8ebd318392d16df651c58ec61d153dea5c4c91d2b7c8f0e5e058b1dc65c462fdbb05022d476e68e2de750cd818542f7e67e5759b41342a7099cdef2af2529dc792a58401fddc02000ec96ba9d747237868f1d2c86e47268c26ef36f6c94a1912b3733314d633bdf201fd6f010072a3b0ab6b21cc40b3d19ac7939ab6f78cb3a0183a7b4bfb6a7d59f2f016451701b600d7a7c1fed5491b1a56caa519da77897df5cf40d4bf68338f5982f29231532801015a0004ac4da4093d73e32c6fa18d1e54e7b105c8ff4e2f576546f4ae6719111ab884012c009d9659c893f191fcae323cb131248ad0cf62b5d453a7c6ebcc03fe37bf14a3d4011700a0c1489667907f2af5c1e296bcc9f306bea2bcb4380bcb037c2339d568700eb0010a0081c97c06ab9720c1160e893fbda97a84d00616ed5a709403df1251dd9f1c5f310104008bd6f0d52d27d6c7bf8445797e1955e6915001a2d3d112fe92f085445c1877730103004616b36c0aef0a3a7007687709683109063502a8d774d1e15a5f74bd1d8a5883010000a9c52f139127db83df7dd23e73656fc883622d83197296f1a298d22baa151d9a06010000000171f98beef012b4a8dad0acff55dfe1ce09dc680f55eb8f3b93621d369f0b94e3010000006b483045022100b9a1fccba25c7f079a594ede2596f399d660d47e0b7765d51a75ec44f8d20e53022022872b14b7270ad3a96844c15036776c1e03e77dedc3b1e76ded95ec8d8eafae4121038ef4bbd95c86e7c84451509a9a21c353ec98a948610a7a467d1b0206e4f7d9f0ffffffff020b000000000000001976a9143ffda33164eae9530ff261777b419c49ec36f9b688ac440c0300000000001976a914f05ea9383d3d59df1eef949f5f446ba9d2bbf7ac88ac00000000010001000000012d476e68e2de750cd818542f7e67e5759b41342a7099cdef2af2529dc792a584010000006a47304402207097290a8d6e08198929abb49794f46b479186174d77fe35132ff894551acb9802207afaee1405fab2346d92017054c83346f5d112cab521f07407500be4706c8f544121028cf7d7a2acc018baff58cbbd3f89395218c50a5b30c7e9b5f0a95f5f8988c012ffffffff020c2b0000000000001976a9146ff6dd8608b17c1ee7bb92defdc4ec6e3ca1a56088ac37e10200000000001976a914189a648dc4549073fd2cedff94688807e754a7d288ac000000000001000000013b95c65f45913abd2b948489a111079ae85e55b395a975c96fa477ea5c0f74e3010000006a473044022021cd63b4f7cff0760405174a2e74b1a81ab957f6546b0c2d84a6df3ce82a6ac6022059ba2373b6b1bbefd99ca4b0e5c4b6be6fc8a828eb6a0a456255cf84b02743e24121022de6e3f77c0e53625fcca43df3dd2a634a3909f7fcd4c4d947876760e2544abfffffffff0264000000000000001976a9141539936ebf76f0f0f78b223545238152ca0f6cf488acd2e00200000000001976a9140253efeedd43b4bb2f713f0b73f358143d71acdb88ac000000000001000000014a011070c3f14e63a4a188c0f87837b01abe8290d49e17e1b3b51644954dadbd010000006b483045022100f458180c028f17bac03a95f14141f9c5fc77964d570fab4cebee2b16dcabc3d002201c91e2778f8e0bce523da5ee4e682cd85dff7698a9feb3461879eb424386cb01412103b71b611936c48df959bbfc01abac9c9cdc7a4fa564d13777e7772b0581ddc5a2ffffffff020b000000000000001976a9148b1e270b2787a9a159b353cfa3337f909239fd3c88acc6e00200000000001976a914db17bd8a8711b30d1e0048107d9565517ced1f2e88ac00000000000100000001b654ad6fc865c7f1ac147342bfa528a44505a8cd0f4fe85d23c3ef75fae21941010000006a473044022027153a12a930608fa6380a6126ab70c4380bec1e4609b1b5e9fd6701fe5392a702205d20c6da5f36b34ad4f6775f28843ceb1c5865154e67adc66f226b70bdc83319412102ff9b41495e940cc1de05b599d1d0d6f53e14f15178b67e8de00b785ecdf9d4eaffffffff0264000000000000001976a914790b92b33e746411e27fb1dfb280abbbace3229c88ac61e00200000000001976a914224987cce1af70e7d23395c6977f9a4488cc329e88ac000000000001000000018cd3664f6d35aab4fd3c056c4e9b3c0ead5f3965eb425ce729b25d9305dea59e010000006b483045022100a011eec1088b833fe4fb9e7dae616654250bdd431411d480a148703d4b39be3802206c71cd8769c0b7b523496b754a568c19440f3c57a0bf97d833936a8ae88275a44121022ac3f8f8666da5c7449764f72400787ec80cf385da6d7a2660ee0695ac9aa4aeffffffff0264000000000000001976a914bee1ac8bbba0840cd965b5289cfd4d8b9514474588acfcdf0200000000001976a914ef6631ea873d78c77fdc05112ac7cf367418374288ac0000000000")
	sources[id] = src

	// and:
	theTx := TxFromRaw(t, "0100000005f0514e101c685bb48cbc2d79670bc0857eeee02b743cf0828a1adc30a86e7c9e0000000000ffffffff3a8db70c78fb351eb81218117aaa3cf97d504d43a27906d55de1b8ff26d0877c0000000000ffffffffc76dc34e4617ec07c9ea3510ee5d9bda2ac1c43fe930f787f934115d16ce5bfb0000000000ffffffffaef16b9f2d9363e4cac281fda82f15b8a434280e08204b782727808e9d1437260100000000ffffffff5ed00276113ddaf7c1db4894fafb79a78812a47bce614d00827da8662f961a270000000000ffffffff0265000000000000001976a9142fc9b0396256e15c8eedc36233eced559935ddad88ac23000000000000001976a91488d411324bfac5de6bd5a427ba465dd82f50b08288ac00000000")

	hydrateInputs(t, sources, theTx.Inputs)

	// when:
	log.Println("theTx", theTx.TxID().String())
	beef, err := theTx.BEEFHex()
	if err != nil {
		t.Fatalf("failed to generate BEEF hex, %v", err)
	}

	// then:
	_, err = NewTransactionFromBEEFHex(beef)
	if err != nil {
		t.Fatalf("failed to parse restored transaction, %v", err)
	}
}

type SourceTx struct {
	Tx      *Transaction // Parsed transaction.
	HadBeef bool         // Indicates if the transaction originated from a BEEF format.
}

func TxSrcFromBEEF(t testing.TB, beef string) (id string, sourceTx *SourceTx) {
	tx, err := NewTransactionFromBEEFHex(beef)
	if err != nil {
		t.Fatalf("failed to parse BEEF transaction, %v \n BEEF: %s", err, beef)
	}

	return tx.TxID().String(), &SourceTx{Tx: tx, HadBeef: true}
}

func TxFromRaw(t testing.TB, raw string) *Transaction {
	tx, err := NewTransactionFromHex(raw)
	if err != nil {
		t.Fatalf("failed to parse raw transaction, %v \n raw tx: %s", err, raw)
	}

	return tx
}

func hydrateInputs(t testing.TB, sourceTxs map[string]*SourceTx, inputs []*TransactionInput) {
	for _, input := range inputs {
		sourceTxID := input.SourceTXID.String()
		val := sourceTxs[sourceTxID]
		if val == nil {
			t.Fatalf("input %s not found in sourceTxs", sourceTxID)
		} else if val.Tx == nil {
			t.Fatalf("sourceTx %s is nil", sourceTxID)
		} else {
			input.SourceTransaction = val.Tx
			if val.HadBeef {
				continue
			}
		}

		hydrateInputs(t, sourceTxs, input.SourceTransaction.Inputs)
	}
}

func TestMakeTxidOnlyAndBytes(t *testing.T) {
	// Decode the BEEF data from hex string
	beefBytes, err := hex.DecodeString(BEEFSet)
	require.NoError(t, err)

	// Create a new Beef object
	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	knownTxID := "b1fc0f44ba629dbdffab9e34fcc4faf9dbde3560a7365c55c26fe4daab052aac"

	beef.MakeTxidOnly(knownTxID)

	_, err = beef.Bytes() // <--------- it panics here
	require.NoError(t, err)
	_ = beef.ToLogString()
}

func TestBeefVerify(t *testing.T) {
	const iterations = 1000

	tests := map[string]struct {
		hex string
	}{
		// the following [not mined] beefs contain transactions that don't have BUMPS
		// e.g.: (not mined tx) -> (not mined tx) -> (mined tx)
		"beef v2 from testvectors one-in-one-out [not mined]": {
			hex: "0200beef01fde80301010000f6282a580ebf0cebd3edbb4ac129d2d7f8a1b337ab642f70377f3d9040eca1d102010001000000012e3f4683e173b40a20527fe5719633ba070df649983614886e90e45aecf2ac56000000006b483045022100c7ddc5159fc630d28f4beeeafa73bc8d32f25b01909732d8d44b9cdbbc85888502206a0a6269bc47c633441a7b5aff120fd0760024badd660f24f713889c0ee70ecb4121034d2d6d23fbcb6eefe3e80c47044e36797dcb80d0ac5e96e732ef03c3c550a116ffffffff01a2860100000000001976a91494677c56fa2968644c90a517214338b4139899ce88ac00000000000100000001f6282a580ebf0cebd3edbb4ac129d2d7f8a1b337ab642f70377f3d9040eca1d1000000006a4730440220291e6769c2383c82fd3c06de833589d9401dbb55838bdc02a76d8d7a98d3cac302207ad2de40877eab59981f2d46dba1cdefd40846db840ae24094eb07688b3e4ee64121034d2d6d23fbcb6eefe3e80c47044e36797dcb80d0ac5e96e732ef03c3c550a116ffffffff01a0860100000000001976a9143cf53c49c322d9d811728182939aee2dca087f9888ac00000000",
		},
		"beef v1 from mainnet tx [not mined]": {
			hex: "0100beef02fe22d10d000a04fd4c02021f0ade7298c9ee505c4ce728eff01b8ee5afebfd6bf78fc055de007adc1b9045fd4d020090bc5a08cf51172b344a5ffbe3ff7be0257a7ac1ffe635d2a2e4b3c609580594fd5602024d985cfd5e069fabc0af08d61d29dc7bb73e4ce2d7fe5f67078e224330b7eb04fd570200c73c2513231ea9f077fc213f38b69ce6ddc6a547ee7f5a8fef05433036add1ac02fd27010029634f4fdbad28cbb98b69df1526b0a6fb8003d301eee886ce7b50721af06185fd2a0100524ca2123d76c175e7775c63558f8c9559e75c12be22192ba3f01ad69251d39102920001752ececf0498cd217680ffa35036213ec65192e547a82fd87dda64745bc57c9400ed1c963033420dd37b50a52b0106fce7f3b17797328ad06197ba14b3c02406510248000773709f08fb89f4dd3f6c1ecdc533e57956d684d123f55d0a1c2fa81d497e5c4b00e6fa5029ff33b5039dcf1ad29d48ec31a3f1280e05228a09a45fff89773117c30224008d830b0871e68181c11fa55bcfc7b4ba4cfe7c141c83e5572c241e16b5501c4925002de377765a914b52423169c000e6f01e022a6d82c624eec484d7de37bf98cea8011300032584497fb4c4d774f0e5b9f60cfe71020dfa4d62be03004c43c27b93c4b1e5010800b738e56ae3afbd6b9ea3a5f2ee28105197a5b047ea90c09af8388a743faef7e50105006c9ab3fde287ab528744668c0d472bb20b8408af403cc17155d8d5770b1a758e0103009bfb3e063448a27874885f3914a52f4793c38cfc754856008b47a5ba944de7d0010000b2ed8e6765ee98e38dd452855c7e36b2be0a077e476d717cd7166b15acc87f5efecab20d000a02fd2b02022412eba9148402370dcd9bdebc2335684fa843452f9c903a1926056c2ded9e9dfd2a0200912b4cfa67a29ad0566906d45438f7595e891675a05f196510a70bd7a78978b501fd1401002444c9b082f3b799b43deb4759df3222edb0d318ee658059183bb0ebf7f94a76018b004bcccd23218a409e11f721b2fed87c2da39291b56187e19ab8c588433a4f7364014400c183687dac2384ab0c1578fb458b9c00329614c8bd75a330045375cab2b014a10123009ea881f36d2698031183fc7ddba5577060fac586d9938166b7a2a7886e2521fa011000e35f0f6da83643cdd837d6f4aed1975a1dd0f8f79a4879c56c189645f7dd003a010900ae7f1a9ef7f64782d6a0f09beefc74f03627730992491f2529cc3e03adea221b01050054a684e36d6da791b60ef667425b94656e61c97db48fe6319686e59fb17e3ff40103008e5cfeadb07f2471590fea982cf7b8c6e113cc4cda99e330e517be3bde55db8d010000a022a5a0fbd1be17f9690056818d7308002b62d2b60d1ecd99014ddda5af6bdf050100000002a3513ec0e99df0307459aeabb3ec2447f680543375be279f981d9ab74ff0564e000000006b48304502210093d7862f1b8adefa47cd53c383721beebcd0691c889069d70435a7eef3f5f8e002205d5cd9323670b2e97b5d6b9d7506c7e8e518b35401c432cc00727ba0ece27eca4121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff6cf9e14113fe68992d84a2beba57307dc6db17cd5f6c6776ac3d28abdb60054f010000006a47304402205c58c456d527074320ad7d1ee383e3fc2f8423c39e5125161bb9e7ee8b330b7d02206e161f172b8d6ddfde08a9f0607cc224adc1919d510d52daf42868ccc3e808b04121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff020c000000000000001976a9147072e2ef390050bc43726d487c117f96da9c534b88ac7a6f0100000000001976a9147072e2ef390050bc43726d487c117f96da9c534b88ac0000000001000100000002ecdbe1d3168f8ac58c0c9a723700de27671132dd532bda051b2b67f53815fa4d000000006b483045022100d9a8278ed88a26b73b2e7a32267572c2c3a5f1692fa3aa2874b4b420f3c6aadf02205ec100c4870a0c8920898554b3f17727b7a60c68ec5bfdc3b17f29a2e449b6854121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffffa3513ec0e99df0307459aeabb3ec2447f680543375be279f981d9ab74ff0564e010000006b483045022100c4833dc2da31901e50394d493d6f4c2863eb81c2e671c3e17cfa815fc3255199022043029192ed27a3527d8bb60c9c927ac88c8bfa9f8d2f1cd8d789e554ec8e36bf4121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff020d000000000000001976a9147072e2ef390050bc43726d487c117f96da9c534b88ac27690100000000001976a9147072e2ef390050bc43726d487c117f96da9c534b88ac00000000010001000000021f0ade7298c9ee505c4ce728eff01b8ee5afebfd6bf78fc055de007adc1b9045000000006b483045022100a44a9236494e95be20a9e7bc96e14bb7bef03e2ce33f338f0081ca99484d929a0220787494efdf7ebd7790599f06ffbb21fb906c6b47c89f180ec8ca62f145e71f484121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff4d985cfd5e069fabc0af08d61d29dc7bb73e4ce2d7fe5f67078e224330b7eb04010000006a47304402203efba1a8cf538998a0975949898e42d2c69df36561969c5a29b38cf33511e9580220614f98ddaa9d5bb05fad38010764332964ec1b41f967861679e390236a4efe814121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff020d000000000000001976a9147072e2ef390050bc43726d487c117f96da9c534b88ac706f0100000000001976a9147072e2ef390050bc43726d487c117f96da9c534b88ac00000000000100000007720e0554f291086056263b0e0b43d482bd28cb62a63d61d9729d15795cccebd600000000b24730440220197cd052433a71be1b6c31d9ae7807b65e7e90118b789ec30226f0c703e4327d02201ca938d1c3c3831552ed2b0df55deb1eac0bbeb0ef856c2cd5d52a7058ec69854147304402206abca1efc5513bc7e7bea68f033378db2d7399fc2bee0caac97104ba2cad4f950220339053f1aca658ceb45ca43abb941041013af13fc89051aae47a4e59c61bd20dc12102bd45e58523dfc46c2ef3ee325802d324e30a193cd83271e4e2142989626ccefaffffffff8a35b1e15447fcaa5cce7c85431705f009c726b9e7ca90c0a054b8c884cb1b3c00000000b2473044022036590d5105abfcf19e7f19f78e40a844bf3cb8c68588450a4af80ab18502663602202a8e2193a44a37ff66853b8fa499e55098f3c08e36d0cd68e3ab4224c5d778f14147304402204edc61ce6ebbe3426f36fb02e3c6ca9f34ab355a26751d5180b10140b49d925b02206b438187b6d1a539699c66259f74815c2535b646e659960d28fc1f498b10a022c12102bd45e58523dfc46c2ef3ee325802d324e30a193cd83271e4e2142989626ccefaffffffff319787bdc7b90a3a607f86f44c452944e778abbe8ee6761a82b3ae4024e6795702000000b4483045022100e3598caa01b47ea6ca5e8b186f3fc647eeda32ea97ff77719be76cda9504143a02200c996409d852460dd6c371f53603327e8a4ccb39bcf9c34da41ac02116d4e84c41483045022100e7c6e466b5eb1f79eae6d896de2b0ddbda189387e35ccbc9969f43cee416e6730220071dc62f847857973dea94eaaa4226ba39b07e09422cb9f2ce81e3d21572f0f7c12102bd45e58523dfc46c2ef3ee325802d324e30a193cd83271e4e2142989626ccefaffffffff3def520b9880fc97a032e84ce3381da111588e97d6f536a72a6b9aeb3375297302000000b2473044022017700a6811f0db93143a8d9cd92ec320affa762a29d75270a6fcffd1b29183de0220595092b981da29b66e823899010dfe07a4eb53e8eb4ec1b8ee4139ece56b7e6441473044022015b6355e7640d54fb72d3ad93a0d76691fe96cbd589ff6a9196e327d9c41aa4702204ef00e1ad3d133e73ee53d2dc2208f931eabcee519c30419ffdd603f8a56d289c12102bd45e58523dfc46c2ef3ee325802d324e30a193cd83271e4e2142989626ccefaffffffff4df52d1c36b5794a82cd01046fad0ba9e34456b50267bb0e4372c753e8cf08ea00000000b3473044022055cc1b09e7dcdb76344cf2120c60792578f3518e62ecef5fe9ea8fb117338781022058d0ec4741cb9a5380b0478df068333ed45e4f3cb25bc16d9162b683020eb04041483045022100bf49323c19f8d2283a31f8047b07cac04237096d15df014f85661460dbf4c01802205863c8f6935b202e2647a1e6ec45f367cd298bd61ce4c7c3c1c6be738eb6b038c12102bd45e58523dfc46c2ef3ee325802d324e30a193cd83271e4e2142989626ccefaffffffff801c15e3596aeb2859953b4b412a2737944d7d3177ed3d34e2546dac4d50201302000000b2473044022006210e58b3e206f14f2a4dd9536d837b00271b695210f1a1e8a2047d71b4b85402202a6ad9f4ee00dcc99c421e257e46500a19110e319601566403241798e507954b4147304402204e5e10917378c0b4225ba7f5a317bc670359d40afdb1e7e8dd8247928770524202207b77f8e3eb534cba7413c465f9e7d83922478b44e8bf9e62ea726ac807b08647c12102bd45e58523dfc46c2ef3ee325802d324e30a193cd83271e4e2142989626ccefaffffffff912b4cfa67a29ad0566906d45438f7595e891675a05f196510a70bd7a78978b5000000006b483045022100f950eef70d59afd91e988dbb2fa9e620c508a2a71ecc4044ea73981e27dc055302200b30bb9705be23f8bc2fba08c201caf77609abc0e9bb4e42e0826e1809de05504121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff030100000000000000d20063036f726451126170706c69636174696f6e2f6273762d3230004c787b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a22616535396633623839386563363161636264623663633761323435666162656465643063303934626630343666333532303661336165633630656638383132375f30222c22616d74223a2232383730383133227d6876a914b5ff6c546a60342e88e5ebe7dad51a24143383f588ad21020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fac0100000000000000cf0063036f726451126170706c69636174696f6e2f6273762d3230004c757b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a22616535396633623839386563363161636264623663633761323435666162656465643063303934626630343666333532303661336165633630656638383132375f30222c22616d74223a2231303030227d6876a9145d34be178f0bc32c3d85671427f1e70694ca8a3b88ad21020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fac0100000000000000d30063036f726451126170706c69636174696f6e2f6273762d3230004c797b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a22616535396633623839386563363161636264623663633761323435666162656465643063303934626630343666333532303661336165633630656638383132375f30222c22616d74223a223137373431363233227d6876a914a5854b1a82f5c71b664a19b64c358f54d6acb18c88ad21020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fac00000000010101000000022412eba9148402370dcd9bdebc2335684fa843452f9c903a1926056c2ded9e9d00000000b3473044022017c67b7d2ec56df57643b97855cbde504772b45b5aa3d3f2f70543d0c7f640e10220102b8fce1bc9e0fa7b633119baae429522ffc08de063770c78a007cb7ab1d2d241483045022100a85692c4ba3828b0f12b6d5c36ff5fffb3e6a0f8a0684ebc59d925c75a64d91c0220776ad270f133ce0f5fc28b8d7ac8dcc6236304346d909ccbb8db3dddb910571bc121036823f82f6c9c279b17c6e5edb0de192a9757778ef978112a62c9a1d17efa4ebaffffffffb05957c4cf6e745f2e147610575f4ba632a84032c86862dec0c656db0ba37911000000006a47304402203bb4c3d0fcae2c72fa6d88f4045447fd8fa2e33afb5867d4092923fa872af67802204faece6a38513d97440c31169a6fc6d69fb4766b4ad9e905218996179c7441f44121020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fffffffff030100000000000000d20063036f726451126170706c69636174696f6e2f6273762d3230004c787b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a22616535396633623839386563363161636264623663633761323435666162656465643063303934626630343666333532303661336165633630656638383132375f30222c22616d74223a2231303030303030227d6876a914a5854b1a82f5c71b664a19b64c358f54d6acb18c88ad21020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fac0100000000000000ce0063036f726451126170706c69636174696f6e2f6273762d3230004c747b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a22616535396633623839386563363161636264623663633761323435666162656465643063303934626630343666333532303661336165633630656638383132375f30222c22616d74223a22313030227d6876a9145d34be178f0bc32c3d85671427f1e70694ca8a3b88ad21020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fac0100000000000000d20063036f726451126170706c69636174696f6e2f6273762d3230004c787b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a22616535396633623839386563363161636264623663633761323435666162656465643063303934626630343666333532303661336165633630656638383132375f30222c22616d74223a2231383730373133227d6876a914b5ff6c546a60342e88e5ebe7dad51a24143383f588ad21020a177d6a5e6f3a8689acd2e313bd1cf0dcf5a243d1cc67b7218602aee9e04b2fac0000000000",
		},

		// the following [mined] beefs contain transactions that all have BUMPS
		"beef v1 from actual testnet tx [mined]": {
			hex: "0100beef01fe849e19000c02fdcf0a02c8c06c5fac63510b2b02ccab974a6ef0b0a4910dd8e881c06964f2b52d7ff415fdce0a00ac05565e579d8c4257313d90ce7bea754aa41add817a0616a9199c84a89d273301fd66050072958bee9c51d1a7511759ef6c73aa03a0533749e887c06514504c466a185fc201fdb202004d106b759b760b423b05be8e53b7ccd44db1cf8c39fd609ee70c316b0a2964df01fd5801003521b209685ae64f5a7f41fcfc5d487fe1b0162ee5a311620c252f6f48714ad101ad000af15dea439d12d3330dc65b5fac8a8e786d80c9f4e8c10dec91807c2fa085380157000e5a9d088abcc6bfb57f6aeb7f12a4fbe63fa07477bef78fa87f967466c374d4012a0083c8207772fb8586071053e855af973a2cce232d45d6a90e3ad403015a003ad1011400074cd69e726d1f7b9f7f1f301f701eef3dd36cbec654ddf7ee897d2567fbc2d4010b00620e7f9bd848d9123aad73e7b28b05e830eaf7d7188f3322d79b2256934026f9010400bbb0cac6a484ac94f774b0c795fa9f116f8251e7cdfe7b374938b8806563f383010300a7074e5aa1e7ffc5754fb762c7853adc20a80c25fad6ad60ddbf80b6d8ad02e40100009c956d581a811c8d45a81b716fbb9c4349c4be011f24c44d236a493b24ca5f4201010000000122ffae11e662c209b8cc5ecce312af425b06f44668d667bb8b09fc04f1e25653010000006b483045022100bac3cea0816c2c8863b6a5207bef9c2236716c58140448d980241f851705872f02201a912284e254e76f33fab9b82eb577921950e9091edf4e79d9a6d00453a23a4e41210231c72ef229534d40d08af5b9a586b619d0b2ee2ace2874339c9cbcc4a79281c0ffffffff0201000000000000001976a914d430654b50459aa04e308c07daf4871185efdc3088ac0d000000000000001976a914cd5ea7065a42329a574b1eb7af9fbbca8a94e44b88ac000000000100",
		},
		"beef v1 from actual mainnet tx [mined]": {
			hex: "0100beef01feb2d20d000402070275108dbcbc9b210d852d90e79f17feebb5ac99640b23055a33daf6aa1860fa670600aaccf30ae2fc73c7ed85601ce3aff36361b8a197e1a4860da4288b452d903a4a010200d1e94851f84a3aa5c2d893c386607471b67f2eec27f8f116c1e05197e84d0c6b010000d87dca62e921e12ed2bc69fc988a922065fa38ae6ad62b07417bfd3e9f74697101010051bb5ce45a8c5e4101246e1f48ae969ef6fc337000fd9dfa4db39e2e114c85af010100000001dc3a61bb7feca472a600ac66b1cbea3e119500853b6aa4f6839cae84e0c3c862010000006b48304502210085bd20643d927b9c505b2bd27c84f447c7407bcdca8d727510d9181a39d71a6f02204210132e103a4460c4fea60d5a915b73861d00876a8f1fa50936100ae8f72ad4412102ae912ff4cf65d91f8174fc8620ea4c627fb9ae282a915ff2fa3dd31044971177ffffffff0200000000000000004c006a4953454e534f52415f50524f4f4601012a0104f81c1b83c30000000000000001000000006878cec70001727e4a61a0971fdebe760d73e8a9de80e507062482806701eced6c7ee3df20bd87020000000000001976a9146c6ec50d57d4ac54ff23ff6482fb6695070c2d7a88ac000000000100",
		},
		"beef v2 from the above BeefSet [mined]": {
			hex: BEEFSet,
		},
		"beef v1 from the above BRC62Hex [mined]": {
			hex: BRC62Hex,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Decode BEEF hex
			beefData, err := hex.DecodeString(test.hex)
			require.NoError(t, err)

			// Parse BEEF
			beef, err := NewBeefFromBytes(beefData)
			require.NoError(t, err)

			// Count success/failure
			successCount := 0
			failureCount := 0

			// Run validation multiple times
			for i := 0; i < iterations; i++ {
				if beef.IsValid(true) {
					successCount++
				} else {
					failureCount++
				}
			}

			// Debug: Check what's in the BEEF
			if failureCount > 0 || successCount == 0 {
				t.Logf("BEEF has %d transactions and %d BUMPs", len(beef.Transactions), len(beef.BUMPs))
				for txid, tx := range beef.Transactions {
					if tx.Transaction != nil {
						t.Logf("Transaction %s has %d inputs, MerklePath: %v", txid, len(tx.Transaction.Inputs), tx.Transaction.MerklePath != nil)
						for i, input := range tx.Transaction.Inputs {
							t.Logf("  Input %d: %s", i, input.SourceTXID.String())
						}
					}
				}
			}

			// Log results
			t.Logf("Success count: %d", successCount)
			t.Logf("Failure count: %d", failureCount)

			// Check for consistency - all iterations should have the same result
			if successCount > 0 && failureCount > 0 {
				t.Errorf("Inconsistent validation results: %d successes, %d failures", successCount, failureCount)
			}
		})
	}
}

package transaction

import (
	"context"
	"encoding/json"
	"log"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction/testdata"
	"github.com/stretchr/testify/require"
)

var BRC74Hex = "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4"

var BRC74Root = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
var BRC74TXID1 = "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"
var BRC74TXID2 = "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00"
var BRC74TXID3 = "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e"

func hexToChainhash(hexStr string) *chainhash.Hash {
	if hash, err := chainhash.NewHashFromHex(hexStr); err != nil {
		log.Panicln("Error decoding hex string:", err)
		return nil
	} else {
		return hash
	}
}

var TRUE = true
var BRC74JSON = MerklePath{
	BlockHeight: 813706,
	Path: [][]*PathElement{
		{
			{Offset: 3048, Hash: hexToChainhash("304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711")},
			{Offset: 3049, Txid: &TRUE, Hash: hexToChainhash("d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00")},
			{Offset: 3050, Txid: &TRUE, Hash: hexToChainhash("98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e")},
			{Offset: 3051, Duplicate: &TRUE},
		},
		{
			{Offset: 1524, Hash: hexToChainhash("811ae75c80fecd27efff5ef272c2adf7edb6e535447f27a4087d23724f397106")},
			{Offset: 1525, Hash: hexToChainhash("82520a4501a06061dd2386fb92fa5e9ceaed14747acc00edf34a6cecabcc2b26")},
		},
		{{Offset: 763, Duplicate: &TRUE}},
		{{Offset: 380, Hash: hexToChainhash("858e41febe934b4cbc1cb80a1dc8e254cb1e69acff8e4f91ecdd779bcaefb393")}},
		{{Offset: 191, Duplicate: &TRUE}},
		{{Offset: 94, Hash: hexToChainhash("f80263e813c644cd71bcc88126d0463df070e28f11023a00543c97b66e828158")}},
		{{Offset: 46, Hash: hexToChainhash("f36f792fa2b42acfadfa043a946d4d7b6e5e1e2e0266f2cface575bbb82b7ae0")}},
		{{Offset: 22, Hash: hexToChainhash("7d5051f0d4ceb7d2e27a49e448aedca2b3865283ceffe0b00b9c3017faca2081")}},
		{{Offset: 10, Hash: hexToChainhash("43aeeb9b6a9e94a5a787fbf04380645e6fd955f8bf0630c24365f492ac592e50")}},
		{{Offset: 4, Hash: hexToChainhash("45be5d16ac41430e3589a579ad780e5e42cf515381cc309b48d0f4648f9fcd1c")}},
		{{Offset: 3, Duplicate: &TRUE}},
		{{Offset: 0, Hash: hexToChainhash("d40cb31af3ef53dd910f5ce15e9a1c20875c009a22d25eab32c11c7ece6487af")}},
	},
}

var BRC74JSONTrimmed = `{"blockHeight":813706,"path":[[{"offset":3048,"hash":"304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"},{"offset":3049,"hash":"d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00","txid":true},{"offset":3050,"hash":"98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e","txid":true},{"offset":3051,"duplicate":true}],[],[{"offset":763,"duplicate":true}],[{"offset":380,"hash":"858e41febe934b4cbc1cb80a1dc8e254cb1e69acff8e4f91ecdd779bcaefb393"}],[{"offset":191,"duplicate":true}],[{"offset":94,"hash":"f80263e813c644cd71bcc88126d0463df070e28f11023a00543c97b66e828158"}],[{"offset":46,"hash":"f36f792fa2b42acfadfa043a946d4d7b6e5e1e2e0266f2cface575bbb82b7ae0"}],[{"offset":22,"hash":"7d5051f0d4ceb7d2e27a49e448aedca2b3865283ceffe0b00b9c3017faca2081"}],[{"offset":10,"hash":"43aeeb9b6a9e94a5a787fbf04380645e6fd955f8bf0630c24365f492ac592e50"}],[{"offset":4,"hash":"45be5d16ac41430e3589a579ad780e5e42cf515381cc309b48d0f4648f9fcd1c"}],[{"offset":3,"duplicate":true}],[{"offset":0,"hash":"d40cb31af3ef53dd910f5ce15e9a1c20875c009a22d25eab32c11c7ece6487af"}]]}`

func TestMerklePathParseHex(t *testing.T) {
	t.Parallel()

	t.Run("parses from hex", func(t *testing.T) {
		mp, err := NewMerklePathFromHex(BRC74Hex)
		require.NoError(t, err)
		require.Equal(t, BRC74Hex, mp.Hex())
	})
}

func TestMerklePathToHex(t *testing.T) {
	t.Parallel()

	t.Run("serializes to hex", func(t *testing.T) {
		// Create a local copy to avoid race conditions
		path := MerklePath{
			BlockHeight: BRC74JSON.BlockHeight,
			Path:        make([][]*PathElement, len(BRC74JSON.Path)),
		}
		// Deep copy the path elements
		for i, level := range BRC74JSON.Path {
			path.Path[i] = make([]*PathElement, len(level))
			for j, elem := range level {
				// Create a new PathElement with copied values
				newElem := &PathElement{
					Offset: elem.Offset,
				}
				if elem.Hash != nil {
					hash := *elem.Hash
					newElem.Hash = &hash
				}
				if elem.Txid != nil {
					txid := *elem.Txid
					newElem.Txid = &txid
				}
				if elem.Duplicate != nil {
					dup := *elem.Duplicate
					newElem.Duplicate = &dup
				}
				path.Path[i][j] = newElem
			}
		}

		hex := path.Hex()
		require.Equal(t, BRC74Hex, hex)
	})
}

func TestMerklePathComputeRootHex(t *testing.T) {
	t.Parallel()

	t.Run("computes a root", func(t *testing.T) {
		// Create a local copy to avoid race conditions
		path := MerklePath{
			BlockHeight: BRC74JSON.BlockHeight,
			Path:        make([][]*PathElement, len(BRC74JSON.Path)),
		}
		// Deep copy the path elements
		for i, level := range BRC74JSON.Path {
			path.Path[i] = make([]*PathElement, len(level))
			for j, elem := range level {
				// Create a new PathElement with copied values
				newElem := &PathElement{
					Offset: elem.Offset,
				}
				if elem.Hash != nil {
					hash := *elem.Hash
					newElem.Hash = &hash
				}
				if elem.Txid != nil {
					txid := *elem.Txid
					newElem.Txid = &txid
				}
				if elem.Duplicate != nil {
					dup := *elem.Duplicate
					newElem.Duplicate = &dup
				}
				path.Path[i][j] = newElem
			}
		}

		txid := BRC74TXID1
		root, err := path.ComputeRootHex(&txid)
		require.NoError(t, err)
		require.Equal(t, BRC74Root, root)
	})
}

// Define a struct that implements the ChainTracker interface.
type MyChainTracker struct{}

// Implement the IsValidRootForHeight method on MyChainTracker.
func (mct MyChainTracker) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	// Convert BRC74Root hex string to a byte slice for comparison
	// expectedRoot, _ := hex.DecodeString(BRC74Root)

	// Assuming BRC74JSON.BlockHeight is of type uint64, and needs to be cast to uint64
	return root.String() == BRC74Root && height == BRC74JSON.BlockHeight, nil
}

func (mct MyChainTracker) CurrentHeight(ctx context.Context) (uint32, error) {
	return 800000, nil // Return a dummy height for testing
}

func TestMerklePath_Verify(t *testing.T) {
	t.Parallel()

	t.Run("verifies using a ChainTracker", func(t *testing.T) {
		// Create a local copy to avoid race conditions
		path := MerklePath{
			BlockHeight: BRC74JSON.BlockHeight,
			Path:        make([][]*PathElement, len(BRC74JSON.Path)),
		}
		// Deep copy the path elements
		for i, level := range BRC74JSON.Path {
			path.Path[i] = make([]*PathElement, len(level))
			for j, elem := range level {
				// Create a new PathElement with copied values
				newElem := &PathElement{
					Offset: elem.Offset,
				}
				if elem.Hash != nil {
					hash := *elem.Hash
					newElem.Hash = &hash
				}
				if elem.Txid != nil {
					txid := *elem.Txid
					newElem.Txid = &txid
				}
				if elem.Duplicate != nil {
					dup := *elem.Duplicate
					newElem.Duplicate = &dup
				}
				path.Path[i][j] = newElem
			}
		}

		tracker := MyChainTracker{}
		ctx := t.Context()
		txid := BRC74TXID1
		result, err := path.VerifyHex(ctx, txid, tracker)
		require.NoError(t, err)
		require.True(t, result)
	})

}

func TestMerklePathCombine(t *testing.T) {
	t.Parallel()

	t.Run("combines two paths", func(t *testing.T) {
		path0A := append(BRC74JSON.Path[0][:2], BRC74JSON.Path[0][4:]...)
		path0B := BRC74JSON.Path[0][2:]
		path1A := BRC74JSON.Path[1][1:]
		path1B := BRC74JSON.Path[1][:len(BRC74JSON.Path[1])-1]
		pathRest := BRC74JSON.Path[2:]

		pathA := MerklePath{
			BlockHeight: BRC74JSON.BlockHeight,
			Path:        append([][]*PathElement{path0A, path1A}, pathRest...),
		}

		pathB := MerklePath{
			BlockHeight: BRC74JSON.BlockHeight,
			Path:        append([][]*PathElement{path0B, path1B}, pathRest...),
		}
		pathARoot, err := pathA.ComputeRootHex(&BRC74TXID2)
		require.NoError(t, err)
		require.Equal(t, pathARoot, BRC74Root)

		_, err = pathA.ComputeRootHex(&BRC74TXID3)
		require.Error(t, err)
		_, err = pathB.ComputeRootHex(&BRC74TXID2)
		require.Error(t, err)
		pathBRoot, err := pathB.ComputeRootHex(&BRC74TXID3)
		require.NoError(t, err)
		require.Equal(t, pathBRoot, BRC74Root)

		err = pathA.Combine(&pathB)
		require.NoError(t, err)
		pathARoot, err = pathA.ComputeRootHex(&BRC74TXID2)
		require.NoError(t, err)
		require.Equal(t, pathARoot, BRC74Root)

		pathARoot, err = pathA.ComputeRootHex(&BRC74TXID3)
		require.NoError(t, err)
		require.Equal(t, pathARoot, BRC74Root)

		// Create a deep copy of BRC74JSON to avoid modifying the global variable
		jsonCopy := MerklePath{
			BlockHeight: BRC74JSON.BlockHeight,
			Path:        make([][]*PathElement, len(BRC74JSON.Path)),
		}
		for i, level := range BRC74JSON.Path {
			jsonCopy.Path[i] = make([]*PathElement, len(level))
			for j, elem := range level {
				newElem := &PathElement{
					Offset: elem.Offset,
				}
				if elem.Hash != nil {
					hash := *elem.Hash
					newElem.Hash = &hash
				}
				if elem.Txid != nil {
					txid := *elem.Txid
					newElem.Txid = &txid
				}
				if elem.Duplicate != nil {
					dup := *elem.Duplicate
					newElem.Duplicate = &dup
				}
				jsonCopy.Path[i][j] = newElem
			}
		}

		err = jsonCopy.Combine(&jsonCopy)
		require.NoError(t, err)
		out, err := json.Marshal(jsonCopy)
		require.NoError(t, err)
		require.JSONEq(t, BRC74JSONTrimmed, string(out))
		root, err := jsonCopy.ComputeRootHex(nil)
		require.NoError(t, err)
		require.Equal(t, root, BRC74Root)

	})

	t.Run("rejects invalid bumps", func(t *testing.T) {
		for _, invalid := range testdata.InvalidBumps {
			_, err := NewMerklePathFromHex(invalid.Bump)
			require.Error(t, err)
		}
	})

	t.Run("verifies valid bumps", func(t *testing.T) {
		for _, valid := range testdata.ValidBumps {
			_, err := NewMerklePathFromHex(valid.Bump)
			require.NoError(t, err)
		}
	})
}

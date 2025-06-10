package primitives

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	keyshares "github.com/bsv-blockchain/go-sdk/primitives/keyshares"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

func TestPrivKeys(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{
			name: "check curve",
			key: []byte{
				0xea, 0xf0, 0x2c, 0xa3, 0x48, 0xc5, 0x24, 0xe6,
				0x39, 0x26, 0x55, 0xba, 0x4d, 0x29, 0x60, 0x3c,
				0xd1, 0xa7, 0x34, 0x7d, 0x9d, 0x65, 0xcf, 0xe9,
				0x3c, 0xe1, 0xeb, 0xff, 0xdc, 0xa2, 0x26, 0x94,
			},
		},
	}

	for _, test := range tests {
		priv, pub := PrivateKeyFromBytes(test.key)

		_, err := ParsePubKey(pub.Uncompressed())
		if err != nil {
			t.Errorf("%s privkey: %v", test.name, err)
			continue
		}

		hash := []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9}
		sig, err := priv.Sign(hash)
		if err != nil {
			t.Errorf("%s could not sign: %v", test.name, err)
			continue
		}

		if !sig.Verify(hash, pub) {
			t.Errorf("%s could not verify: %v", test.name, err)
			continue
		}

		serializedKey := priv.Serialize()
		if !bytes.Equal(serializedKey, test.key) {
			t.Errorf("%s unexpected serialized bytes - got: %x, "+
				"want: %x", test.name, serializedKey, test.key)
		}
	}
}

// Test vector struct
type privateTestVector struct {
	SenderPublicKey     string `json:"senderPublicKey"`
	RecipientPrivateKey string `json:"recipientPrivateKey"`
	InvoiceNumber       string `json:"invoiceNumber"`
	ExpectedPrivateKey  string `json:"privateKey"`
}

const createPolyFail = "Failed to create polynomial: %v"

func TestBRC42PrivateVectors(t *testing.T) {
	// Determine the directory of the current test file
	_, currentFile, _, ok := runtime.Caller(0)
	testdataPath := filepath.Join(filepath.Dir(currentFile), "testdata", "BRC42.private.vectors.json")

	require.True(t, ok, "Could not determine the directory of the current test file")

	// Read in the file
	vectors, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatalf("Could not read test vectors: %v", err) // use Fatalf to stop test if file cannot be read
	}
	// unmarshal the json
	var testVectors []privateTestVector
	err = json.Unmarshal(vectors, &testVectors)
	if err != nil {
		t.Errorf("Could not unmarshal test vectors: %v", err)
	}
	for i, v := range testVectors {
		t.Run("BRC42 private vector #"+strconv.Itoa(i+1), func(t *testing.T) {
			publicKey, err := PublicKeyFromString(v.SenderPublicKey)
			if err != nil {
				t.Errorf("Could not parse public key: %v", err)
			}
			privateKey, err := PrivateKeyFromHex(v.RecipientPrivateKey)
			if err != nil {
				t.Errorf("Could not parse private key: %v", err)
			}
			derived, err := privateKey.DeriveChild(publicKey, v.InvoiceNumber)
			if err != nil {
				t.Errorf("Could not derive child key: %v", err)
			}

			// Convert derived private key to hex and compare
			derivedHex := hex.EncodeToString(derived.Serialize())
			if derivedHex != v.ExpectedPrivateKey {
				t.Errorf("Derived private key does not match expected: got %v, want %v", derivedHex, v.ExpectedPrivateKey)
			}
		})
	}
}

func TestPrivateKeyFromInvalidHex(t *testing.T) {
	hex := ""
	_, err := PrivateKeyFromHex(hex)
	require.Error(t, err)

	wif := "L4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWq"
	_, err = PrivateKeyFromHex(wif)
	require.Error(t, err)
}

func TestPrivateKeyFromInvalidWif(t *testing.T) {
	wif := "L401GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWq"
	_, err := PrivateKeyFromWif(wif)
	require.Error(t, err)

	wif = "L4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkW"
	_, err = PrivateKeyFromWif(wif)
	require.Error(t, err)

	wif = "L4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWqL4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWq"
	_, err = PrivateKeyFromWif(wif)
	require.Error(t, err)
}

// TestPolynomialFromPrivateKey checks if a polynomial is correctly created from a private key
func TestPolynomialFromPrivateKey(t *testing.T) {

	pk, _ := NewPrivateKey()
	threshold := 3

	poly, err := pk.ToPolynomial(threshold)
	if err != nil {
		t.Fatalf(createPolyFail, err)
	}

	if len(poly.Points) != threshold {
		t.Errorf("Incorrect number of points. Expected %d, got %d", threshold, len(poly.Points))
	}

	if poly.Points[0].X.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("First point x-coordinate should be 0, got %v", poly.Points[0].X)
	}

	if poly.Points[0].Y.Cmp(pk.D) != 0 {
		t.Errorf("First point y-coordinate should be the key, got %v", poly.Points[0].Y)
	}

	// Check for uniqueness of x-coordinates
	xCoords := make(map[string]bool)
	for _, point := range poly.Points {
		if xCoords[point.X.String()] {
			t.Errorf("Duplicate x-coordinate found: %v", point.X)
		}
		xCoords[point.X.String()] = true
	}
}

func TestPolynomialFullProcess(t *testing.T) {
	// Create a private key
	privateKey, err := PrivateKeyFromWif("L1vTr2wRMZoXWBM3u1Mvbzk9bfoJE5PT34t52HYGt9jzZMyavWrk")
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	threshold := 3
	totalShares := 5

	// Generate the polynomial
	poly, err := privateKey.ToPolynomial(threshold)
	if err != nil {
		t.Fatalf(createPolyFail, err)
	}

	t.Logf("Generated polynomial:")

	// Log the generated polynomial points
	t.Logf("Generated polynomial points:")
	for i, point := range poly.Points {
		t.Logf("Point %d: (%s, %s)", i, point.X, point.Y)
	}

	// Generate shares
	points := make([]*keyshares.PointInFiniteField, 0)
	t.Logf("Generated shares:")
	for i := 0; i < totalShares; i++ {
		x := big.NewInt(int64(i + 1))
		y := poly.ValueAt(x)
		points = append(points, keyshares.NewPointInFiniteField(x, y))
		t.Logf("Share %d: (%s, %s)", i+1, points[i].X, points[i].Y)
	}

	// Reconstruct the secret using threshold number of shares
	reconstructPoly := keyshares.NewPolynomial(points[:threshold], threshold)
	reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))

	t.Logf("Original secret: %v", privateKey.D)
	t.Logf("Reconstructed secret: %v", reconstructedSecret)

	if reconstructedSecret.Cmp(privateKey.D) != 0 {
		t.Errorf("Secret reconstruction failed. Expected %v, got %v", privateKey.D, reconstructedSecret)
	}
}

func TestStaticKeyShares(t *testing.T) {
	pk, err := PrivateKeyFromWif("L1vTr2wRMZoXWBM3u1Mvbzk9bfoJE5PT34t52HYGt9jzZMyavWrk")
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	threshold := 3

	bigInt1, _ := new(big.Int).SetString("96062736363790697194862546171394473697392259359830162418218835520086413272341", 10)
	bigInt2, _ := new(big.Int).SetString("30722461044811690128856937028727798465838823013972760604497780310461152961290", 10)
	bigInt3, _ := new(big.Int).SetString("99029341976844930668697872705368631679110273751030257450922903721724195163244", 10)
	bigInt4, _ := new(big.Int).SetString("69399200685258027967243383183941157630666642239721524878579037738057870534877", 10)
	bigInt5, _ := new(big.Int).SetString("57624126407367177448064453473133284173777913145687126926923766367371013747852", 10)

	points := []*keyshares.PointInFiniteField{{
		X: big.NewInt(1), Y: bigInt1},
		{X: big.NewInt(2), Y: bigInt2},
		{X: big.NewInt(3), Y: bigInt3},
		{X: big.NewInt(4), Y: bigInt4},
		{X: big.NewInt(5), Y: bigInt5},
	}

	reconstructedPoly := keyshares.NewPolynomial(points[1:threshold+1], threshold)
	reconstructedSecret := reconstructedPoly.ValueAt(big.NewInt(0))

	t.Logf("Original secret: %v", pk.D)
	t.Logf("Reconstructed secret: %v", reconstructedSecret)
	require.Equal(t, pk.D, reconstructedSecret)
}

func TestUmod(t *testing.T) {
	big, _ := new(big.Int).SetString("96062736363790697194862546171394473697392259359830162418218835520086413272341", 10)

	umodded := util.Umod(big, keyshares.NewCurve().P)

	require.Equal(t, umodded, big)
}

func TestPolynomialDifferentThresholdsAndShares(t *testing.T) {
	testCases := []struct {
		threshold   int
		totalShares int
	}{
		{2, 3},
		{3, 5},
		{5, 10},
		{10, 20},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Threshold_%d_TotalShares_%d", tc.threshold, tc.totalShares), func(t *testing.T) {
			privateKey, _ := NewPrivateKey()
			poly, err := privateKey.ToPolynomial(tc.threshold)
			if err != nil {
				t.Fatalf(createPolyFail, err)
			}

			shares := make([]*keyshares.PointInFiniteField, tc.totalShares)
			for i := 0; i < tc.totalShares; i++ {
				x := big.NewInt(int64(i + 1))
				y := poly.ValueAt(x)
				shares[i] = keyshares.NewPointInFiniteField(x, y)
			}

			reconstructPoly := keyshares.NewPolynomial(shares[:tc.threshold], tc.threshold)
			reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))

			if reconstructedSecret.Cmp(privateKey.D) != 0 {
				t.Errorf("Secret reconstruction failed. Expected %v, got %v", privateKey.D, reconstructedSecret)
			}
		})
	}
}

func TestPolynomialEdgeCases(t *testing.T) {
	privateKey, _ := NewPrivateKey()

	// Minimum threshold (2)
	t.Run("MinimumThreshold", func(t *testing.T) {
		threshold := 2
		totalShares := 3
		poly, _ := privateKey.ToPolynomial(threshold)
		shares := make([]*keyshares.PointInFiniteField, totalShares)
		for i := 0; i < totalShares; i++ {
			x := big.NewInt(int64(i + 1))
			y := poly.ValueAt(x)
			shares[i] = keyshares.NewPointInFiniteField(x, y)
		}
		reconstructPoly := keyshares.NewPolynomial(shares[:threshold], threshold)
		reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))
		if reconstructedSecret.Cmp(privateKey.D) != 0 {
			t.Errorf("Secret reconstruction failed for minimum threshold")
		}
	})

	// Maximum threshold (total shares)
	t.Run("MaximumThreshold", func(t *testing.T) {
		threshold := 10
		totalShares := 10
		poly, _ := privateKey.ToPolynomial(threshold)
		shares := make([]*keyshares.PointInFiniteField, totalShares)
		for i := 0; i < totalShares; i++ {
			x := big.NewInt(int64(i + 1))
			y := poly.ValueAt(x)
			shares[i] = keyshares.NewPointInFiniteField(x, y)
		}
		reconstructPoly := keyshares.NewPolynomial(shares, threshold)
		reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))
		if reconstructedSecret.Cmp(privateKey.D) != 0 {
			t.Errorf("Secret reconstruction failed for maximum threshold")
		}
	})
}

func TestPolynomialReconstructionWithDifferentSubsets(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	threshold := 3
	totalShares := 5

	poly, _ := privateKey.ToPolynomial(threshold)
	shares := make([]*keyshares.PointInFiniteField, totalShares)
	for i := 0; i < totalShares; i++ {
		x := big.NewInt(int64(i + 1))
		y := poly.ValueAt(x)
		shares[i] = keyshares.NewPointInFiniteField(x, y)
	}

	subsets := [][]int{
		{0, 1, 2},
		{1, 2, 3},
		{2, 3, 4},
		{0, 2, 4},
	}

	for i, subset := range subsets {
		t.Run(fmt.Sprintf("Subset_%d", i), func(t *testing.T) {
			subsetShares := make([]*keyshares.PointInFiniteField, threshold)
			for j, idx := range subset {
				subsetShares[j] = shares[idx]
			}
			reconstructPoly := keyshares.NewPolynomial(subsetShares, threshold)
			reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))
			if reconstructedSecret.Cmp(privateKey.D) != 0 {
				t.Errorf("Secret reconstruction failed for subset %v", subset)
			}
		})
	}
}

func TestPolynomialErrorHandling(t *testing.T) {
	privateKey, _ := NewPrivateKey()

	// Test with invalid threshold (too low)
	_, err := privateKey.ToPolynomial(1)
	if err == nil {
		t.Errorf("Expected error for threshold too low, got nil")
	}

	// Test reconstruction with insufficient shares
	threshold := 3
	poly, _ := privateKey.ToPolynomial(threshold)
	shares := make([]*keyshares.PointInFiniteField, 2)
	for i := 0; i < 2; i++ {
		x := big.NewInt(int64(i + 1))
		y := poly.ValueAt(x)
		shares[i] = keyshares.NewPointInFiniteField(x, y)
	}
	reconstructPoly := keyshares.NewPolynomial(shares, 2)
	reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))
	if reconstructedSecret.Cmp(privateKey.D) == 0 {
		t.Errorf("Expected incorrect reconstruction with insufficient shares")
	}
}

func TestPolynomialConsistency(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	threshold := 3
	totalShares := 5

	for i := 0; i < 10; i++ {
		poly, _ := privateKey.ToPolynomial(threshold)
		shares := make([]*keyshares.PointInFiniteField, totalShares)
		for j := 0; j < totalShares; j++ {
			x := big.NewInt(int64(j + 1))
			y := poly.ValueAt(x)
			shares[j] = keyshares.NewPointInFiniteField(x, y)
		}
		reconstructPoly := keyshares.NewPolynomial(shares[:threshold], threshold)
		reconstructedSecret := reconstructPoly.ValueAt(big.NewInt(0))
		if reconstructedSecret.Cmp(privateKey.D) != 0 {
			t.Errorf("Inconsistent secret reconstruction in run %d", i)
		}
	}
}

func TestPrivateKeyToKeyShares(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	threshold := 2
	totalShares := 5

	// it should split the private key into shares correctly
	shares, err := privateKey.ToKeyShares(threshold, totalShares)
	if err != nil {
		t.Fatalf("Failed to create initial key shares: %v", err)
	}

	backup, err := shares.ToBackupFormat()
	if err != nil {
		t.Fatalf("Failed to create backup format: %v", err)
	}

	if len(backup) != totalShares {
		t.Errorf("Incorrect number of shares. Expected %d, got %d", totalShares, len(backup))
	}

	if shares.Threshold != threshold {
		t.Errorf("Incorrect threshold. Expected %d, got %d", threshold, shares.Threshold)
	}

	// it should recombine the shares into a private key correctly
	for i := 0; i < 3; i++ {
		key, _ := NewPrivateKey()
		allShares, err := key.ToKeyShares(3, 5)
		if err != nil {
			t.Fatalf("Failed to create key shares: %v", err)
		}
		backup, _ := allShares.ToBackupFormat()
		log.Printf("backup: %v", backup)
		someShares, err := keyshares.NewKeySharesFromBackupFormat(backup[:3])
		if err != nil {
			t.Fatalf("Failed to create key shares from backup format: %v", err)
		}
		rebuiltKey, err := PrivateKeyFromKeyShares(someShares)
		if err != nil {
			t.Fatalf("Failed to create private key from key shares: %v", err)
		}
		if !strings.EqualFold(rebuiltKey.Wif(), key.Wif()) {
			t.Errorf("Reconstructed key does not match original key")
		}
	}
}

// threshold should be less than or equal to totalShares
func TestThresholdLargerThanTotalShares(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	_, err := privateKey.ToKeyShares(50, 5)
	if err == nil {
		t.Errorf("Expected error for threshold must be less than total shares")
	}
}

func TestTotalSharesLessThanTwo(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	_, err := privateKey.ToKeyShares(2, 1)
	if err == nil {
		t.Errorf("Expected error for totalShares must be at least 2")
	}
}

func TestFewerPointsThanThreshold(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	shares, err := privateKey.ToKeyShares(3, 5)
	if err != nil {
		t.Fatalf("Failed to create key shares: %v", err)
	}

	shares.Points = shares.Points[:2]
	_, err = PrivateKeyFromKeyShares(shares)
	if err == nil {
		t.Errorf("Expected error for fewer points than threshold")
	}
}

// should throw an error for invalid threshold
func TestInvalidThreshold(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	_, err := privateKey.ToKeyShares(1, 2)
	if err == nil {
		t.Errorf("Expected error for threshold must be at least 2")
	}
}

// should throw an error for invalid totalShares
func TestInvalidTotalShares(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	_, err := privateKey.ToKeyShares(2, -4)
	if err == nil {
		t.Errorf("Expected error for totalShares must be at least 2")
	}
}

// should throw an error for totalShares being less than threshold
func TestTotalSharesLessThanThreshold(t *testing.T) {
	privateKey, _ := NewPrivateKey()
	_, err := privateKey.ToKeyShares(3, 2)
	if err == nil {
		t.Errorf("Expected error for threshold should be less than or equal to totalShares")
	}
}

// should throw an error if the same share is included twice during recovery
func TestSameShareTwiceDuringRecovery(t *testing.T) {
	backup := []string{
		"45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M.A7nZrGux15nEsQGNZ1mbfnMKugNnS6SYYEQwfhfbDZG8.3.2f804d43",
		"7aPzkiGZgvU4Jira5PN9Qf9o7FEg6uwy1zcxd17NBhh3.CCt7NH1sPFgceb6phTRkfviim2WvmUycJCQd2BxauxP9.3.2f804d43",
		"9GaS2Tw5sXqqbuigdjwGPwPsQuEFqzqUXo5MAQhdK3es.8MLh2wyE3huyq6hiBXjSkJRucgyKh4jVY6ESq5jNtXRE.3.2f804d43",
		"GBmoNRbsMVsLmEK5A6G28fktUNonZkn9mDrJJ58FXgsf.HDBRkzVUCtZ38ApEu36fvZtDoDSQTv3TWmbnxwwR7kto.3.2f804d43",
		"2gHebXBgPd7daZbsj6w9TPDta3vQzqvbkLtJG596rdN1.E7ZaHyyHNDCwR6qxZvKkPPWWXzFCiKQFentJtvSSH5Bi.3.2f804d43",
	}
	recovery, err := keyshares.NewKeySharesFromBackupFormat([]string{backup[0], backup[1], backup[1]})
	if err != nil {
		t.Fatalf("Failed to create key shares from backup format: %v", err)
	}
	_, err = PrivateKeyFromKeyShares(recovery)
	if err == nil {
		t.Errorf("Expected error for duplicate share detected, each must be unique")
	}
}

// should be able to create a backup array from a private key, and recover the same key back from the backup
func TestBackupAndRecovery(t *testing.T) {
	key, _ := NewPrivateKey()
	backup, err := key.ToBackupShares(3, 5)
	if err != nil {
		t.Fatalf("Failed to create backup shares: %v", err)
	}
	recoveredKey, err := PrivateKeyFromBackupShares(backup[:3])
	if err != nil {
		t.Logf("Backup shares: %v", backup)
		t.Fatalf("Failed to recover key from backup shares: %v", err)
	}
	if !bytes.Equal(recoveredKey.Serialize(), key.Serialize()) {
		t.Errorf("Recovered key does not match original key")
	}
}

func TestExampleBackupAndRecovery(t *testing.T) {
	share1 := "3znuzt7DZp8HzZTfTh5MF9YQKNX3oSxTbSYmSRGrH2ev.2Nm17qoocmoAhBTCs8TEBxNXCskV9N41rB2PckcgYeqV.2.35449bb9"
	share2 := "Cm5fuUc39X5xgdedao8Pr1kvCSm8Gk7Cfenc7xUKcfLX.2juyK9BxCWn2DiY5JUAgj9NsQ77cc9bWksFyW45haXZm.2.35449bb9"

	shares, err := keyshares.NewKeySharesFromBackupFormat([]string{share1, share2})
	require.NoError(t, err)
	recoveredKey, err := PrivateKeyFromKeyShares(shares)
	if err != nil {
		t.Fatalf("Failed to recover key from backup shares: %v", err)
	}
	if recoveredKey == nil {
		t.Errorf("Failed to recover key from backup shares")
	}
}

func TestExampleFromTypescript(t *testing.T) {

	recoveryShares := []string{
		"HYkALskEizXkRLHr5Q5fzj9w7ThpdgwqBwjHih9sifVW.6zRqQ7LMKFu7eFSf9eABfuugnvzG9tSiv4uj8zXrX6r7.6.35449bb9",
		"CnAGiYWrGzKZn5GcAu4FZSnZkNi6pToVRkPfUaCtiDm6.4e3M6FN2R3iUssJwJ8PazCX7fCvx3mgu1M82GREXrptn.6.35449bb9",
		"5A9BTHruTVx68LyxeWKNaHDmvsXJckp7gcYQQsxfPRxy.88nKAkDTpEAGR4humi9wFsLwWKoVxqnyFA1i4FfyjGZD.6.35449bb9",
		"HF1DnP2BotERLxZmHVDZKgEgzCAiUCkFuDxHRFdhVXSe.3EzbKevL6ha2hXi6Evs7sZzdp9S16HUTBs7JRwWkYC1B.6.35449bb9",
		"BCYHiXpcJqif5D96BV35fKm3waMwnP5RVoUVBE9FYSqi.7H2myBNnQwmeEvgLTDUD2ArBZUpfN8Uqm61KRopzpBww.6.35449bb9",
		"DoJmFZi3XhKmFVRGYVrPjYA5BppAKpZ2kGHVJZeKSUYq.52chnjed4L5nABtRwERZnhtzx1HLWnjkS51shFZYd1CQ.6.35449bb9",
	}

	wif := "L1aFAHMKJrkGLQ3V6fM3a9PBewA26H2AydsnpArh9sLscSgNn5gy"
	pk, err := PrivateKeyFromWif(wif)
	require.NoError(t, err)
	backup, err := pk.ToBackupShares(6, 30)
	require.NoError(t, err)
	require.NotNil(t, backup)

	recovery := recoveryShares[:6]
	recoveredKey, err := PrivateKeyFromBackupShares(recovery)
	require.NoError(t, err)
	require.NotNil(t, recoveredKey)
	require.Equal(t, wif, recoveredKey.Wif())
}

func TestKnownPolynomialValueAt(t *testing.T) {
	wif := "L1vTr2wRMZoXWBM3u1Mvbzk9bfoJE5PT34t52HYGt9jzZMyavWrk"
	pk, err := PrivateKeyFromWif(wif)
	require.NoError(t, err)
	expectedPkD := "8c507a209d082d9db947bea9ffb248bbb977e59953405dacf5ea8c4be3a11a2f"
	require.Equal(t, expectedPkD, hex.EncodeToString(pk.D.Bytes()))
	poly, err := pk.ToPolynomial(3)
	require.NoError(t, err)
	result := poly.ValueAt(big.NewInt(0))
	expected := "8c507a209d082d9db947bea9ffb248bbb977e59953405dacf5ea8c4be3a11a2f"
	require.Equal(t, expected, hex.EncodeToString(result.Bytes()))
}

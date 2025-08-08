package primitives

import (
	"encoding/hex"
	"math/big"
	"testing"

	keyshares "github.com/bsv-blockchain/go-sdk/primitives/keyshares"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

// Selected Shamir-related tests moved from privatekey_test.go for cohesion
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

func TestPolynomialFullProcess_Shamir(t *testing.T) {
	pk, err := PrivateKeyFromWif("L1vTr2wRMZoXWBM3u1Mvbzk9bfoJE5PT34t52HYGt9jzZMyavWrk")
	require.NoError(t, err)

	threshold := 3
	totalShares := 5

	poly, err := pk.ToPolynomial(threshold)
	require.NoError(t, err)

	points := make([]*keyshares.PointInFiniteField, 0)
	for i := 0; i < totalShares; i++ {
		x := big.NewInt(int64(i + 1))
		y := poly.ValueAt(x)
		points = append(points, keyshares.NewPointInFiniteField(x, y))
	}

	reconstructPoly := keyshares.NewPolynomial(points[:threshold], threshold)
	reconstructed := reconstructPoly.ValueAt(big.NewInt(0))
	require.Equal(t, pk.D, reconstructed)
}

func TestStaticKeyShares_Shamir(t *testing.T) {
	pk, err := PrivateKeyFromWif("L1vTr2wRMZoXWBM3u1Mvbzk9bfoJE5PT34t52HYGt9jzZMyavWrk")
	require.NoError(t, err)
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
	reconstructed := reconstructedPoly.ValueAt(big.NewInt(0))
	require.Equal(t, pk.D, reconstructed)
}

func TestUmod_Shamir(t *testing.T) {
	bigNum, _ := new(big.Int).SetString("96062736363790697194862546171394473697392259359830162418218835520086413272341", 10)
	umodded := util.Umod(bigNum, keyshares.NewCurve().P)
	require.Equal(t, umodded, bigNum)
}

func TestKnownPolynomialValueAt_Shamir(t *testing.T) {
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

func TestToKeyShares_FailFirst_ZeroAndDuplicateX(t *testing.T) {
	// Zero x failure
	orig := testDeriveShareX
	defer func() { testDeriveShareX = orig }()
	testDeriveShareX = func(shareIndex, attempt int, seed []byte) *big.Int {
		if shareIndex == 0 {
			return big.NewInt(0)
		}
		return big.NewInt(int64(shareIndex + 1))
	}

	key, _ := NewPrivateKey()
	shares, err := key.ToKeyShares(2, 3)
	if err == nil || shares != nil {
		t.Fatalf("expected error when zero x-coordinate is produced, got shares=%v err=%v", shares, err)
	}

	// Duplicate x failure
	testDeriveShareX = func(shareIndex, attempt int, seed []byte) *big.Int {
		if shareIndex < 2 {
			return big.NewInt(42)
		}
		return big.NewInt(int64(100 + shareIndex))
	}
	key2, _ := NewPrivateKey()
	shares, err = key2.ToKeyShares(2, 3)
	if err == nil || shares != nil {
		t.Fatalf("expected error when duplicate x-coordinate is produced, got shares=%v err=%v", shares, err)
	}
}

// Fail-first tests for TOB-BSV-2: ensure zero or duplicate x-coordinates are rejected
func TestToKeyShares_ZeroXCoordinate_FailsFirst(t *testing.T) {
	// Arrange: force x = 0 for first share
	orig := testDeriveShareX
	defer func() { testDeriveShareX = orig }()
	testDeriveShareX = func(shareIndex, attempt int, seed []byte) *big.Int {
		if shareIndex == 0 {
			return big.NewInt(0)
		}
		return big.NewInt(int64(shareIndex + 1))
	}

	key, _ := NewPrivateKey()
	// Act
	shares, err := key.ToKeyShares(2, 3)
	// Assert: current implementation should fail after fix; fail-first expects error now
	if err == nil || shares != nil {
		t.Fatalf("expected error when zero x-coordinate is produced, got shares=%v err=%v", shares, err)
	}
}

func TestToKeyShares_DuplicateXCoordinate_FailsFirst(t *testing.T) {
	// Arrange: force duplicate x for first two shares
	orig := testDeriveShareX
	defer func() { testDeriveShareX = orig }()
	testDeriveShareX = func(shareIndex, attempt int, seed []byte) *big.Int {
		if shareIndex < 2 {
			return big.NewInt(42) // duplicate
		}
		return big.NewInt(int64(100 + shareIndex))
	}

	key, _ := NewPrivateKey()
	shares, err := key.ToKeyShares(2, 3)
	if err == nil || shares != nil {
		t.Fatalf("expected error when duplicate x-coordinate is produced, got shares=%v err=%v", shares, err)
	}
}

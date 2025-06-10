package primitives

import (
	"log"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

// TestPointInFiniteField verifies the creation and string conversion of points
func TestPointInFiniteField(t *testing.T) {
	x := big.NewInt(10)
	y := big.NewInt(20)

	point := NewPointInFiniteField(x, y)

	if point.X.Cmp(x) != 0 || point.Y.Cmp(y) != 0 {
		t.Errorf("Point creation failed. Expected (%v, %v), got (%v, %v)", x, y, point.X, point.Y)
	}

	str := point.String()
	log.Printf("Point string: %s", str)
	reconstructedPoint, err := PointFromString(str)
	if err != nil {
		t.Errorf("Failed to reconstruct point from string: %v", err)
	}

	if reconstructedPoint.X.Cmp(point.X) != 0 || reconstructedPoint.Y.Cmp(point.Y) != 0 {
		t.Errorf("Point reconstruction failed. Expected (%v, %v), got (%v, %v)",
			point.X, point.Y, reconstructedPoint.X, reconstructedPoint.Y)
	}
}

// TestPolynomialValueAt verifies the polynomial evaluation at specific points
func TestPolynomialValueAt(t *testing.T) {
	points := []*PointInFiniteField{
		NewPointInFiniteField(big.NewInt(0), big.NewInt(1)),
		NewPointInFiniteField(big.NewInt(1), big.NewInt(2)),
		NewPointInFiniteField(big.NewInt(2), big.NewInt(3)),
	}
	poly := NewPolynomial(points, 3)

	testCases := []struct {
		x int64
	}{
		{0},
		{1},
		{2},
		{3},
	}

	for _, tc := range testCases {
		x := big.NewInt(tc.x)
		result := poly.ValueAt(x)
		// We're not checking against specific values here, just ensuring it doesn't panic
		t.Logf("Value at x=%d: %v", tc.x, result)
	}
}

// Test util.Umod with Curve.P
func TestUmod(t *testing.T) {
	require.Equal(t, int64(100), util.Umod(big.NewInt(100), NewCurve().P).Int64())
	require.Equal(t, int64(63), util.Umod(NewCurve().P, big.NewInt(100)).Int64())
	require.Equal(t, int64(63), util.Umod(NewCurve().P, big.NewInt(-100)).Int64())
}

func TestValueAtStaticPoly(t *testing.T) {
	threshold := 3
	totalShares := 5
	bigInt0x := big.NewInt(0)
	bigInt0y, _ := new(big.Int).SetString("63465989459149561019572730115992841667230613457321334813170901334782306753071", 10)
	bigInt1x, _ := new(big.Int).SetString("60098049464719082536908106929717058139237866646407792639097261741118523954739", 10)
	bigInt1y, _ := new(big.Int).SetString("5445227977440784036220256291344012565233687922480676424981735065099509271083", 10)
	bigInt2x, _ := new(big.Int).SetString("1052059428069456700843310926531798840191498924785835970686579452590270423430", 10)
	bigInt2y, _ := new(big.Int).SetString("98174180884762975979793822263175877424237569238167613939083869503184221497454", 10)

	startingPoints := []*PointInFiniteField{
		{X: bigInt0x, Y: bigInt0y},
		{X: bigInt1x, Y: bigInt1y},
		{X: bigInt2x, Y: bigInt2y},
	}

	share1, _ := new(big.Int).SetString("98209580936265727237729889604490309223950058914015254484773717993541175692579", 10)
	share2, _ := new(big.Int).SetString("28381905659213213900229646735188926996459360747522498927113843756675333610380", 10)
	share3, _ := new(big.Int).SetString("85567142102624411854213971525464510691298488289124196219106446640002449849800", 10)
	share4, _ := new(big.Int).SetString("38181111791866930252540893957941244601927472207539218281836358627704855067513", 10)
	share5, _ := new(big.Int).SetString("2015903964256964518781399041307036581616297168408129154761163727691383935182", 10)

	expectedShares := []*PointInFiniteField{
		{X: big.NewInt(1), Y: share1},
		{X: big.NewInt(2), Y: share2},
		{X: big.NewInt(3), Y: share3},
		{X: big.NewInt(4), Y: share4},
		{X: big.NewInt(5), Y: share5},
	}

	actualShares := make([]*PointInFiniteField, 0)
	poly := NewPolynomial(startingPoints, threshold)
	for i := 0; i < totalShares; i++ {
		x := big.NewInt(int64(i + 1))
		y := new(big.Int).Set(poly.ValueAt(x))
		actualShares = append(actualShares, NewPointInFiniteField(x, y))
	}

	for i, share := range actualShares {
		log.Printf("Share %d: %s", i, share.String())
		require.Equal(t, expectedShares[i].X, share.X, "X %d Expected: %s, Got: %s", i, expectedShares[i].X, share.X)
		require.Equal(t, expectedShares[i].Y, share.Y, "Y %d Expected: %s, Got: %s", i, expectedShares[i].Y, share.Y)
	}
}

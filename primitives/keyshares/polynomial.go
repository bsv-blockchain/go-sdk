package primitives

import (
	"fmt"
	"math/big"
	"strings"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	"github.com/bsv-blockchain/go-sdk/util"
)

type Polynomial struct {
	Points    []*PointInFiniteField
	Threshold int
}

type Curve struct {
	P *big.Int
}

func NewCurve() *Curve {
	hexString := "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f"

	// Remove spaces
	compactHexString := strings.ReplaceAll(hexString, " ", "")

	// Convert the compact hex string to a big.Int
	p, _ := new(big.Int).SetString(compactHexString, 16)
	return &Curve{P: p}
}

// PointInFiniteField represents a point in a finite field
type PointInFiniteField struct {
	X, Y *big.Int
}

func NewPointInFiniteField(x, y *big.Int) *PointInFiniteField {
	curve := NewCurve()

	return &PointInFiniteField{
		X: util.Umod(x, curve.P),
		Y: util.Umod(y, curve.P),
	}
}

func (p *PointInFiniteField) String() string {
	return base58.Encode(p.X.Bytes()) + "." + base58.Encode(p.Y.Bytes())
}

func PointFromString(s string) (*PointInFiniteField, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid point string")
	}

	// decode from base58
	x, err := base58.Decode(parts[0])
	if err != nil {
		return nil, err
	}
	y, err := base58.Decode(parts[1])
	if err != nil {
		return nil, err
	}
	return NewPointInFiniteField(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)), nil
}

func NewPolynomial(points []*PointInFiniteField, threshold int) *Polynomial {
	if threshold == 0 {
		threshold = len(points)
	}
	return &Polynomial{
		Points:    points,
		Threshold: threshold,
	}
}

func (p *Polynomial) ValueAt(x *big.Int) *big.Int {
	P := NewCurve().P
	y := big.NewInt(0)

	for i := 0; i < p.Threshold; i++ {
		term := p.Points[i].Y
		for j := 0; j < p.Threshold; j++ {
			if i != j {
				numerator := new(big.Int).Sub(x, p.Points[j].X)
				numerator = util.Umod(numerator, P)

				denominator := new(big.Int).Sub(p.Points[i].X, p.Points[j].X)
				denominator = util.Umod(denominator, P)

				denominatorInv := new(big.Int).ModInverse(denominator, P)
				if denominatorInv == nil {
					denominatorInv = new(big.Int).SetInt64(0)
				}

				fraction := new(big.Int).Mul(numerator, denominatorInv)
				fraction = util.Umod(fraction, P)

				term = new(big.Int).Mul(term, fraction)
				term = util.Umod(term, P)
			}
		}
		y = y.Add(y, term)
		y = util.Umod(y, P)
	}
	return y
}

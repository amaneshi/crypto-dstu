package ec

import (
	"crypto-dstu/gf2m"
	"fmt"
	"math/big"
)

// Point represents a point on an elliptic curve over GF(2^m).
type Point struct {
	X     gf2m.Element
	Y     gf2m.Element
	Curve *Curve
	Inf   bool // true if point at infinity
}

// NewPoint creates a new point on the curve.
func NewPoint(curve *Curve, x, y gf2m.Element) *Point {
	return &Point{
		X:     x,
		Y:     y,
		Curve: curve,
		Inf:   false,
	}
}

// Infinity returns the point at infinity for the curve.
func Infinity(curve *Curve) *Point {
	return &Point{
		X:     curve.NewElement(),
		Y:     curve.NewElement(),
		Curve: curve,
		Inf:   true,
	}
}

// IsInfinity returns true if the point is the point at infinity.
func (p *Point) IsInfinity() bool {
	return p.Inf
}

// Equal returns true if two points are equal.
func (p *Point) Equal(q *Point) bool {
	if p.Inf && q.Inf {
		return true
	}
	if p.Inf || q.Inf {
		return false
	}
	return p.X.Equal(q.X) && p.Y.Equal(q.Y)
}

// Add returns p + q using affine coordinates.
// For curve y² + xy = x³ + ax² + b.
func (p *Point) Add(q *Point) *Point {
	if p.Curve != q.Curve {
		panic("points must be on the same curve")
	}

	// Handle point at infinity
	if p.Inf {
		return q.Clone()
	}
	if q.Inf {
		return p.Clone()
	}

	// Check if points are equal
	if p.X.Equal(q.X) {
		if p.Y.Equal(q.Y) {
			// Point doubling
			return p.Double()
		}
		// p + (-p) = O
		return Infinity(p.Curve)
	}

	// Point addition: P + Q where P ≠ Q
	// λ = (y_P + y_Q) / (x_P + x_Q)
	numerator := gf2m.Add(p.Y, q.Y)
	denominator := gf2m.Add(p.X, q.X)
	denominatorInv := gf2m.Inv(denominator, p.Curve.ModBits)
	lambda := gf2m.ModMul(numerator, denominatorInv, p.Curve.ModBits)

	// x_R = λ² + λ + x_P + x_Q + a
	lambdaSqr := gf2m.ModSqr(lambda, p.Curve.ModBits)
	xR := gf2m.Add(lambdaSqr, lambda)
	xR = gf2m.Add(xR, p.X)
	xR = gf2m.Add(xR, q.X)
	xR = gf2m.Add(xR, p.Curve.A)

	// y_R = λ(x_P + x_R) + x_R + y_P
	xDiff := gf2m.Add(p.X, xR)
	yR := gf2m.ModMul(lambda, xDiff, p.Curve.ModBits)
	yR = gf2m.Add(yR, xR)
	yR = gf2m.Add(yR, p.Y)

	return &Point{
		X:     xR,
		Y:     yR,
		Curve: p.Curve,
		Inf:   false,
	}
}

// Double returns 2*p using affine coordinates.
func (p *Point) Double() *Point {
	if p.Inf {
		return p.Clone()
	}

	// Check if x = 0 (point of order 2)
	if p.X.IsZero() {
		return Infinity(p.Curve)
	}

	// Point doubling: 2P
	// λ = x_P + y_P / x_P
	xInv := gf2m.Inv(p.X, p.Curve.ModBits)
	yOverX := gf2m.ModMul(p.Y, xInv, p.Curve.ModBits)
	lambda := gf2m.Add(p.X, yOverX)

	// x_R = λ² + λ + a
	lambdaSqr := gf2m.ModSqr(lambda, p.Curve.ModBits)
	xR := gf2m.Add(lambdaSqr, lambda)
	xR = gf2m.Add(xR, p.Curve.A)

	// y_R = x_P² + (λ + 1) · x_R
	xSqr := gf2m.ModSqr(p.X, p.Curve.ModBits)
	one, _ := gf2m.FromHex("1", p.Curve.Words)
	lambdaPlusOne := gf2m.Add(lambda, one)
	yR := gf2m.ModMul(lambdaPlusOne, xR, p.Curve.ModBits)
	yR = gf2m.Add(xSqr, yR)

	return &Point{
		X:     xR,
		Y:     yR,
		Curve: p.Curve,
		Inf:   false,
	}
}

// Neg returns -p (the negation of p).
// For binary curves: -P = (x, x + y).
func (p *Point) Neg() *Point {
	if p.Inf {
		return p.Clone()
	}

	negY := gf2m.Add(p.X, p.Y)
	return &Point{
		X:     p.X.Clone(),
		Y:     negY,
		Curve: p.Curve,
		Inf:   false,
	}
}

// ScalarMul returns k*p using simple double-and-add algorithm (LSB to MSB).
func (p *Point) ScalarMul(k *big.Int) *Point {
	if k.Sign() == 0 || p.Inf {
		return Infinity(p.Curve)
	}

	// Handle negative scalars
	if k.Sign() < 0 {
		k = new(big.Int).Neg(k)
		p = p.Neg()
	}

	result := Infinity(p.Curve)
	addend := p.Clone()

	// Simple double-and-add from LSB to MSB
	for i := range k.BitLen() {
		if k.Bit(i) == 1 {
			result = result.Add(addend)
		}
		addend = addend.Double()
	}

	return result
}

// ScalarBaseMul returns k*G where G is the base point.
func (c *Curve) ScalarBaseMul(k *big.Int) *Point {
	g := c.BasePoint()
	return g.ScalarMul(k)
}

// Clone creates a deep copy of the point.
func (p *Point) Clone() *Point {
	return &Point{
		X:     p.X.Clone(),
		Y:     p.Y.Clone(),
		Curve: p.Curve,
		Inf:   p.Inf,
	}
}

// String returns a string representation of the point.
func (p *Point) String() string {
	if p.Inf {
		return "Point(∞)"
	}
	return fmt.Sprintf("Point(x=%s, y=%s)", p.X.String(), p.Y.String())
}

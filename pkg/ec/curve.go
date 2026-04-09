package ec

import (
	"crypto-dstu/pkg/gf2m"
	"fmt"
)

// Curve represents an elliptic curve over GF(2^m) with equation y² + xy = x³ + ax² + b.
type Curve struct {
	M        int          // field extension degree
	ModBits  gf2m.ModBits // irreducible polynomial sparse form
	A        gf2m.Element // curve parameter a (0 or 1 for DSTU curves)
	B        gf2m.Element // curve parameter b
	N        []byte       // order of base point (big-endian integer)
	Cofactor int          // cofactor (2 or 4)
	Gx       gf2m.Element // base point x-coordinate
	Gy       gf2m.Element // base point y-coordinate
	Words    int          // ceil(M/32) — word count for field elements
}

// NewCurve creates a new elliptic curve with the given parameters.
func NewCurve(m int, modBits gf2m.ModBits, a, b, gx, gy gf2m.Element, n []byte, cofactor int) *Curve {
	return &Curve{
		M:        m,
		ModBits:  modBits,
		A:        a,
		B:        b,
		N:        n,
		Cofactor: cofactor,
		Gx:       gx,
		Gy:       gy,
		Words:    modBits.WordCount(),
	}
}

// BasePoint returns the base point (generator) of the curve.
func (c *Curve) BasePoint() *Point {
	return &Point{
		X:     c.Gx,
		Y:     c.Gy,
		Curve: c,
		Inf:   false,
	}
}

// Contains checks if a point lies on the curve.
// Verifies: y² + xy = x³ + ax² + b.
func (c *Curve) Contains(p *Point) bool {
	if p.Inf {
		return true
	}

	// LHS = y² + xy
	ySqr := gf2m.ModSqr(p.Y, c.ModBits)
	xy := gf2m.ModMul(p.X, p.Y, c.ModBits)
	lhs := gf2m.Add(ySqr, xy)

	// RHS = x³ + ax² + b
	xSqr := gf2m.ModSqr(p.X, c.ModBits)
	xCube := gf2m.ModMul(xSqr, p.X, c.ModBits)
	axSqr := gf2m.ModMul(c.A, xSqr, c.ModBits)
	rhs := gf2m.Add(xCube, axSqr)
	rhs = gf2m.Add(rhs, c.B)

	return lhs.Equal(rhs)
}

// NewElement creates a zero field element for this curve.
func (c *Curve) NewElement() gf2m.Element {
	return gf2m.NewElement(c.Words)
}

// String returns a string representation of the curve.
func (c *Curve) String() string {
	return fmt.Sprintf("Curve(m=%d, a=%s, b=%s)", c.M, c.A.String(), c.B.String())
}

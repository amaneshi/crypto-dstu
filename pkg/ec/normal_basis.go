package ec

import (
	"errors"

	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
)

// normalBasis holds mutually inverse binary linear maps. Curve arithmetic stays
// in polynomial basis; DSTU ONB field values cross these maps at wire boundaries.
// Column m-1-j is root^(2^j), matching the DSTU bit ordering in Cryptonite.
type normalBasis struct {
	toPolynomial []gf2m.Element
	toNormal     []gf2m.Element
}

func newNormalBasis(mod gf2m.ModBits, root gf2m.Element) *normalBasis {
	m, words := mod.M(), mod.WordCount()
	columns := make([]gf2m.Element, m)
	value := root.Clone()
	for j := range m {
		columns[m-1-j] = value
		value = gf2m.ModSqr(value, mod)
	}
	// Invert the public basis matrix once with binary Gaussian elimination.
	// This avoids a second ONB multiplication implementation and large tables.
	left, right := make([]gf2m.Element, m), make([]gf2m.Element, m)
	for row := range m {
		left[row], right[row] = gf2m.NewElement(words), gf2m.NewElement(words)
		right[row].SetBit(row)
		for col := range m {
			if columns[col].TestBit(row) {
				left[row].SetBit(col)
			}
		}
	}
	for col := range m {
		pivot := col
		for pivot < m && !left[pivot].TestBit(col) {
			pivot++
		}
		if pivot == m {
			panic("ec: singular built-in ONB basis")
		}
		left[col], left[pivot] = left[pivot], left[col]
		right[col], right[pivot] = right[pivot], right[col]
		for row := range m {
			if row != col && left[row].TestBit(col) {
				left[row] = gf2m.Add(left[row], left[col])
				right[row] = gf2m.Add(right[row], right[col])
			}
		}
	}
	inverse := make([]gf2m.Element, m)
	for col := range m {
		inverse[col] = gf2m.NewElement(words)
		for row := range m {
			if right[row].TestBit(col) {
				inverse[col].SetBit(row)
			}
		}
	}
	return &normalBasis{toPolynomial: columns, toNormal: inverse}
}

func applyBasis(columns []gf2m.Element, e gf2m.Element, words int) gf2m.Element {
	out := gf2m.NewElement(words)
	for i, column := range columns {
		if e.TestBit(i) {
			out = gf2m.Add(out, column)
		}
	}
	return out
}

// IsONB reports whether field values use the DSTU optimal-normal-basis encoding.
// Point coordinates stored in Curve/Point always use polynomial basis.
func (c *Curve) IsONB() bool { return c.basis != nil }

// DecodeField converts an m-bit encoded field value into the polynomial basis
// used by arithmetic. It is the identity for PB curves; scalars are not fields
// and must never be passed through this conversion.
func (c *Curve) DecodeField(e gf2m.Element) (gf2m.Element, error) {
	if e.BitLen() > c.M {
		return gf2m.Element{}, errors.New("ec: encoded value is outside the field")
	}
	return c.decodeField(e), nil
}

// EncodeField converts a polynomial-basis arithmetic value to the curve's
// external field representation. It is the identity for PB curves.
func (c *Curve) EncodeField(e gf2m.Element) (gf2m.Element, error) {
	if e.BitLen() > c.M {
		return gf2m.Element{}, errors.New("ec: arithmetic value is outside the field")
	}
	return c.encodeField(e), nil
}

func (c *Curve) decodeField(e gf2m.Element) gf2m.Element {
	if c.basis == nil {
		return gf2m.FromBytes(e.Bytes(), c.Words)
	}
	return applyBasis(c.basis.toPolynomial, e, c.Words)
}

func (c *Curve) encodeField(e gf2m.Element) gf2m.Element {
	if c.basis == nil {
		return gf2m.FromBytes(e.Bytes(), c.Words)
	}
	return applyBasis(c.basis.toNormal, e, c.Words)
}

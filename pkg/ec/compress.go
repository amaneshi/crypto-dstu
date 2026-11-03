package ec

import (
	"errors"
	"fmt"

	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
)

// Compress returns the compressed representation of the point.
// The low bit encodes Tr(y/x); the other bits encode x. Bytes are big-endian.
func (p *Point) Compress() []byte {
	if p.Inf {
		// Return zero bytes for point at infinity
		return make([]byte, (p.Curve.M+7)/8)
	}

	out := make([]byte, (p.Curve.M+7)/8)
	x := p.Curve.encodeField(p.X).Bytes()
	copy(out[len(out)-len(x):], x)
	if !p.X.IsZero() {
		z := gf2m.ModMul(p.Y, gf2m.Inv(p.X, p.Curve.ModBits), p.Curve.ModBits)
		out[len(out)-1] = out[len(out)-1]&0xfe | byte(fieldTrace(z, p.Curve.ModBits))
	}
	return out
}

// Expand decompresses a point from its compressed representation.
// Expand recovers both coordinates, including the encoded choice of y.
func (c *Curve) Expand(compressed []byte) (*Point, error) {
	if len(compressed) == 0 || len(compressed) > (c.M+7)/8 {
		return nil, errors.New("invalid compressed point length")
	}

	encodedX := gf2m.FromBytes(compressed, c.Words)
	if encodedX.BitLen() > c.M {
		return nil, errors.New("compressed point is outside the field")
	}

	// The all-zero encoding represents the finite point x=0, y=sqrt(b).
	if encodedX.IsZero() {
		// Special case: x = 0, compute y from curve equation
		y := computeYForZeroX(c)
		return &Point{X: encodedX, Y: y, Curve: c, Inf: false}, nil
	}
	selector := encodedX.TestBit(0)
	x := c.decodeField(encodedX)
	if fieldTrace(x, c.ModBits) != int(c.A.Words()[0]&1) {
		if encodedX.TestBit(0) {
			encodedX.ClearBit(0)
		} else {
			encodedX.SetBit(0)
		}
		x = c.decodeField(encodedX)
	}
	// A nonzero wire encoding must not become x=0 after restoring the
	// selector bit. Zero has its own canonical encoding handled above.
	if x.IsZero() {
		return nil, errors.New("noncanonical zero compressed coordinate")
	}

	// Compute y from x using the curve equation
	// y² + xy = x³ + ax² + b
	// Divide by x²: (y/x)² + (y/x) = x + a + b/x²
	// Let z = y/x, then: z² + z = x + a + b/x²

	xSqr := gf2m.ModSqr(x, c.ModBits)
	xSqrInv := gf2m.Inv(xSqr, c.ModBits)
	bOverXSqr := gf2m.ModMul(c.B, xSqrInv, c.ModBits)

	w := gf2m.Add(x, c.A)
	w = gf2m.Add(w, bOverXSqr)

	// Solve z² + z = w using fsquad (half-trace)
	z, err := fsquad(w, c.ModBits)
	if err != nil {
		return nil, fmt.Errorf("point expansion failed: %w", err)
	}
	if (fieldTrace(z, c.ModBits) != 0) != selector {
		if z.TestBit(0) {
			z.ClearBit(0)
		} else {
			z.SetBit(0)
		}
	}

	// y = z * x
	y := gf2m.ModMul(z, x, c.ModBits)

	point := &Point{X: x, Y: y, Curve: c, Inf: false}

	// Verify the point is on the curve
	if !c.Contains(point) {
		return nil, errors.New("expanded point is not on curve")
	}

	return point, nil
}

func fieldTrace(x gf2m.Element, modBits gf2m.ModBits) int {
	sum := x.Clone()
	power := x.Clone()
	for i := 1; i < modBits.M(); i++ {
		power = gf2m.ModSqr(power, modBits)
		sum = gf2m.Add(sum, power)
	}
	if sum.TestBit(0) {
		return 1
	}
	return 0
}

// fsquad solves z² + z = w in GF(2^m) using the half-trace algorithm.
// Only works for odd m.
func fsquad(w gf2m.Element, modBits gf2m.ModBits) (gf2m.Element, error) {
	m := modBits.M()

	if m%2 == 0 {
		return gf2m.Element{}, errors.New("fsquad only works for odd m")
	}

	// For odd m, use half-trace algorithm:
	// z = w^(2^0) + w^(2^2) + w^(2^4) + ... + w^(2^(m-1))
	z := w.Clone()
	temp := w.Clone()

	for i := 1; i <= (m-1)/2; i++ {
		// temp = temp^4 (square twice)
		temp = gf2m.ModSqr(temp, modBits)
		temp = gf2m.ModSqr(temp, modBits)

		// z = z + temp
		z = gf2m.Add(z, temp)
	}

	// Verify: z² + z should equal w
	zSqr := gf2m.ModSqr(z, modBits)
	check := gf2m.Add(zSqr, z)

	if !check.Equal(w) {
		return gf2m.Element{}, errors.New("no solution exists for z² + z = w")
	}

	return z, nil
}

// computeYForZeroX computes y when x = 0.
// For x = 0: y² = b, so y = b^(2^(m-1)).
func computeYForZeroX(c *Curve) gf2m.Element {
	m := c.M
	y := c.B.Clone()

	// Compute b^(2^(m-1)) by repeated squaring
	for range m - 1 {
		y = gf2m.ModSqr(y, c.ModBits)
	}

	return y
}

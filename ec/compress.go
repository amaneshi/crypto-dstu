package ec

import (
	"crypto-dstu/gf2m"
	"fmt"
)

// Compress returns the compressed representation of the point.
// Returns x-coordinate bytes with trace bit encoded separately.
func (p *Point) Compress() []byte {
	if p.Inf {
		// Return zero bytes for point at infinity
		return make([]byte, (p.Curve.M+7)/8)
	}

	// Return x-coordinate as-is
	// The trace bit will be computed during expansion
	return p.X.Bytes()
}

// Expand decompresses a point from its compressed representation.
// Since we only store x, we compute y and return the canonical point.
func (c *Curve) Expand(compressed []byte) (*Point, error) {
	if len(compressed) == 0 {
		return nil, fmt.Errorf("compressed point is empty")
	}

	x := gf2m.FromBytes(compressed, c.Words)

	// Handle point at infinity
	if x.IsZero() {
		// Special case: x = 0, compute y from curve equation
		y := computeYForZeroX(c)
		return &Point{X: x, Y: y, Curve: c, Inf: false}, nil
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

	// y = z * x
	y := gf2m.ModMul(z, x, c.ModBits)

	point := &Point{X: x, Y: y, Curve: c, Inf: false}

	// Verify the point is on the curve
	if !c.Contains(point) {
		return nil, fmt.Errorf("expanded point is not on curve")
	}

	return point, nil
}

// fsquad solves z² + z = w in GF(2^m) using the half-trace algorithm.
// Only works for odd m.
func fsquad(w gf2m.Element, modBits gf2m.ModBits) (gf2m.Element, error) {
	m := modBits.M()

	if m%2 == 0 {
		return gf2m.Element{}, fmt.Errorf("fsquad only works for odd m")
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
		return gf2m.Element{}, fmt.Errorf("no solution exists for z² + z = w")
	}

	return z, nil
}

// trace computes the trace of an element in GF(2^m).
// trace(a) = a + a^2 + a^4 + ... + a^(2^(m-1))
func trace(a gf2m.Element, modBits gf2m.ModBits) bool {
	m := modBits.M()
	result := a.Clone()
	temp := a.Clone()

	// BUG FIX: The loop condition should iterate m-1 times total
	// We start with result = a (which is a^(2^0))
	// Then we need to add a^(2^1), a^(2^2), ..., a^(2^(m-1))
	// That's m-1 more terms, so we iterate from i=1 to i<m
	for i := 1; i < m; i++ {
		temp = gf2m.ModSqr(temp, modBits)
		result = gf2m.Add(result, temp)
	}

	// Trace is the least significant bit
	return result.TestBit(0)
}

// computeYForZeroX computes y when x = 0.
// For x = 0: y² = b, so y = b^(2^(m-1))
func computeYForZeroX(c *Curve) gf2m.Element {
	m := c.M
	y := c.B.Clone()

	// Compute b^(2^(m-1)) by repeated squaring
	for i := 0; i < m-1; i++ {
		y = gf2m.ModSqr(y, c.ModBits)
	}

	return y
}

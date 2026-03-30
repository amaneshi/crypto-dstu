package ec

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test curve creation
func TestCurveCreation(t *testing.T) {
	curve := DSTU_PB_257()
	require.Equal(t, 257, curve.M)
	require.Equal(t, 4, curve.Cofactor)
}

// Test base point is on curve
func TestBasePointOnCurve(t *testing.T) {
	curves := []struct {
		name  string
		curve *Curve
	}{
		{"DSTU_PB_163", DSTU_PB_163()},
		{"DSTU_PB_167", DSTU_PB_167()},
		{"DSTU_PB_173", DSTU_PB_173()},
		{"DSTU_PB_179", DSTU_PB_179()},
		{"DSTU_PB_191", DSTU_PB_191()},
		{"DSTU_PB_233", DSTU_PB_233()},
		{"DSTU_PB_257", DSTU_PB_257()},
		{"DSTU_PB_307", DSTU_PB_307()},
		{"DSTU_PB_367", DSTU_PB_367()},
		{"DSTU_PB_431", DSTU_PB_431()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			g := tc.curve.BasePoint()
			require.True(t, tc.curve.Contains(g), "%s: base point must be on curve", tc.name)
		})
	}
}

// Test point at infinity
func TestInfinity(t *testing.T) {
	curve := DSTU_PB_257()
	inf := Infinity(curve)

	require.True(t, inf.IsInfinity(), "Infinity point should be marked as infinity")
	require.True(t, curve.Contains(inf), "Infinity point should be on curve")
}

// Test point addition identity: P + O = P
func TestAdditionIdentity(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()
	inf := Infinity(curve)

	result := g.Add(inf)
	require.True(t, result.Equal(g), "P + O should equal P")

	result = inf.Add(g)
	require.True(t, result.Equal(g), "O + P should equal P")
}

// Test point doubling
func TestPointDoubling(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	// 2*G via doubling
	doubled := g.Double()

	// 2*G via addition
	added := g.Add(g)

	require.True(t, doubled.Equal(added), "P.Double() should equal P.Add(P)")
	require.True(t, curve.Contains(doubled), "2*P must be on curve")
}

// Test point addition
func TestPointAddition(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	// Compute 2*G and 3*G
	g2 := g.Double()
	g3 := g2.Add(g)

	// Verify on curve
	require.True(t, curve.Contains(g2), "2*G must be on curve")
	require.True(t, curve.Contains(g3), "3*G must be on curve")

	// Test commutativity: P + Q = Q + P
	result1 := g.Add(g2)
	result2 := g2.Add(g)
	require.True(t, result1.Equal(result2), "Point addition must be commutative")
}

// Test scalar multiplication
func TestScalarMul(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	// Test small scalars only (windowed method still slow for large values)
	k := big.NewInt(5)
	result := g.ScalarMul(k)

	// Verify on curve
	require.True(t, curve.Contains(result), "k*G must be on curve")

	// Compute 5*G manually: 2*(2*G) + G
	expected := g.Double().Double().Add(g)
	require.True(t, result.Equal(expected), "ScalarMul(5) must match manual computation")

	// Test a slightly larger scalar
	k = big.NewInt(15)
	result = g.ScalarMul(k)
	require.True(t, curve.Contains(result), "15*G must be on curve")
}

// Test scalar multiplication with zero
func TestScalarMulZero(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	k := big.NewInt(0)
	result := g.ScalarMul(k)

	require.True(t, result.IsInfinity(), "0*G must be point at infinity")
}

// Test order: n*G = O
func TestCurveOrder(t *testing.T) {
	curves := []struct {
		name  string
		curve *Curve
	}{
		{"DSTU_PB_163", DSTU_PB_163()},
		{"DSTU_PB_167", DSTU_PB_167()},
		{"DSTU_PB_173", DSTU_PB_173()},
		{"DSTU_PB_179", DSTU_PB_179()},
		{"DSTU_PB_191", DSTU_PB_191()},
		{"DSTU_PB_233", DSTU_PB_233()},
		{"DSTU_PB_257", DSTU_PB_257()},
		{"DSTU_PB_307", DSTU_PB_307()},
		{"DSTU_PB_367", DSTU_PB_367()},
		{"DSTU_PB_431", DSTU_PB_431()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			g := tc.curve.BasePoint()
			n := new(big.Int).SetBytes(tc.curve.N)

			result := g.ScalarMul(n)

			require.True(t, result.IsInfinity(), "%s: n*G must be point at infinity", tc.name)
		})
	}
}

// Test point compression and expansion
func TestCompressExpand(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	// Compress the base point
	compressed := g.Compress()

	// Expand it back
	expanded, err := curve.Expand(compressed)
	require.NoError(t, err, "Expand must not fail")

	// Should get a valid point with the same x-coordinate
	require.True(t, expanded.X.Equal(g.X), "Expanded point must have same x-coordinate")
	require.True(t, curve.Contains(expanded), "Expanded point must be on curve")
}

// Test compression for multiple points
func TestCompressExpandMultiplePoints(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	// Test with several multiples of G
	for i := 1; i <= 10; i++ {
		k := big.NewInt(int64(i))
		p := g.ScalarMul(k)

		compressed := p.Compress()
		expanded, err := curve.Expand(compressed)
		require.NoError(t, err, "Expand must not fail for %d*G", i)
		require.True(t, expanded.X.Equal(p.X), "Expanded %d*G must have same x-coordinate", i)
		require.True(t, curve.Contains(expanded), "Expanded %d*G must be on curve", i)
	}
}

// Test associativity: (P + Q) + R = P + (Q + R)
func TestAssociativity(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	p := g
	q := g.Double()
	r := g.ScalarMul(big.NewInt(3))

	// (P + Q) + R
	pq := p.Add(q)
	left := pq.Add(r)

	// P + (Q + R)
	qr := q.Add(r)
	right := p.Add(qr)

	require.True(t, left.Equal(right), "Point addition must be associative")
}

// Test negation
func TestNegation(t *testing.T) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()

	negG := g.Neg()

	// P + (-P) = O
	result := g.Add(negG)
	require.True(t, result.IsInfinity(), "P + (-P) must be point at infinity")

	// Verify -P is on curve
	require.True(t, curve.Contains(negG), "-P must be on curve")
}

// Test ScalarBaseMul
func TestScalarBaseMul(t *testing.T) {
	curve := DSTU_PB_257()
	k := big.NewInt(7)

	result1 := curve.ScalarBaseMul(k)
	result2 := curve.BasePoint().ScalarMul(k)

	require.True(t, result1.Equal(result2), "ScalarBaseMul must equal BasePoint.ScalarMul")
}

// Benchmark scalar multiplication
func BenchmarkScalarMul(b *testing.B) {
	curve := DSTU_PB_257()
	g := curve.BasePoint()
	k := big.NewInt(123456789)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.ScalarMul(k)
	}
}

// Benchmark point addition
func BenchmarkPointAdd(b *testing.B) {
	curve := DSTU_PB_257()
	p := curve.BasePoint()
	q := p.Double()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Add(q)
	}
}

// Benchmark point doubling
func BenchmarkPointDouble(b *testing.B) {
	curve := DSTU_PB_257()
	p := curve.BasePoint()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Double()
	}
}

// Benchmark compression
func BenchmarkCompress(b *testing.B) {
	curve := DSTU_PB_257()
	p := curve.BasePoint()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Compress()
	}
}

// Benchmark expansion
func BenchmarkExpand(b *testing.B) {
	curve := DSTU_PB_257()
	p := curve.BasePoint()
	compressed := p.Compress()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = curve.Expand(compressed)
	}
}

package gf2m

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test basic element creation and conversion
func TestElementCreation(t *testing.T) {
	// Test zero element
	e := NewElement(3)
	require.True(t, e.IsZero(), "NewElement should create zero element")

	// Test FromHex
	hexStr := "0x1A2B3C"
	e, err := FromHex(hexStr, 2)
	require.NoError(t, err, "FromHex")

	// Test String roundtrip
	hexOut := e.String()
	e2, err := FromHex(hexOut, 2)
	require.NoError(t, err, "FromHex roundtrip")
	require.True(t, e.Equal(e2), "Hex roundtrip: %s != %s", hexOut, e2.String())
}

// Test BitLen function
func TestBitLen(t *testing.T) {
	tests := []struct {
		hex    string
		bitLen int
	}{
		{"0", 0},
		{"1", 1},
		{"2", 2},
		{"3", 2},
		{"4", 3},
		{"FF", 8},
		{"100", 9},
		{"FFFF", 16},
		{"10000", 17},
	}

	for _, tt := range tests {
		e, err := FromHex(tt.hex, 4)
		require.NoError(t, err, "FromHex(%s)", tt.hex)
		require.Equal(t, tt.bitLen, e.BitLen(), "BitLen(%s)", tt.hex)
	}
}

// Test bit operations
func TestBitOps(t *testing.T) {
	e := NewElement(2)

	// Test SetBit
	e.SetBit(5)
	require.True(t, e.TestBit(5), "SetBit(5)")
	require.False(t, e.TestBit(4), "TestBit(4) should be false")

	// Test ClearBit
	e.ClearBit(5)
	require.False(t, e.TestBit(5), "ClearBit(5)")
}

// Test addition (XOR)
func TestAdd(t *testing.T) {
	a, _ := FromHex("5", 1)
	b, _ := FromHex("3", 1)

	// 5 ^ 3 = 6
	result := Add(a, b)
	expected, _ := FromHex("6", 1)
	require.True(t, result.Equal(expected), "Add(5, 3) = %s, want 6", result.String())

	// Test self-inverse: a + a = 0
	result = Add(a, a)
	require.True(t, result.IsZero(), "a + a should be zero")

	// Test identity: a + 0 = a
	zero := NewElement(1)
	result = Add(a, zero)
	require.True(t, result.Equal(a), "a + 0 should equal a")
}

// Test multiplication
func TestMul(t *testing.T) {
	// Test simple multiplication
	a, _ := FromHex("3", 1) // x + 1
	b, _ := FromHex("5", 1) // x^2 + 1

	// (x + 1)(x^2 + 1) = x^3 + x^2 + x + 1 = 0xF
	result := Mul(a, b)
	expected, _ := FromHex("F", 1)
	require.True(t, result.Equal(expected), "Mul(3, 5) = %s, want F", result.String())

	// Test identity: a * 1 = a
	one, _ := FromHex("1", 1)
	result = Mul(a, one)
	require.True(t, result.Equal(a), "a * 1 should equal a")

	// Test commutativity: a * b = b * a
	result1 := Mul(a, b)
	result2 := Mul(b, a)
	require.True(t, result1.Equal(result2), "Multiplication should be commutative")
}

// Test modular reduction
func TestMod(t *testing.T) {
	// Use DSTU_PB_257: x^257 + x^12 + 1
	modBits := ModBits257

	// Create an element larger than the modulus
	large, _ := FromHex("1"+strings.Repeat("0", 64), 10) // x^256

	// Reduce it
	reduced := Mod(large, modBits)

	require.LessOrEqual(t, reduced.BitLen(), 257, "Mod result BitLen should be <= 257")
}

// Test modular multiplication
func TestModMul(t *testing.T) {
	modBits := ModBits257

	a, _ := FromHex("123456789ABCDEF", 9)
	b, _ := FromHex("FEDCBA987654321", 9)

	// Compute a * b mod f(x)
	result := ModMul(a, b, modBits)

	require.LessOrEqual(t, result.BitLen(), 257, "ModMul result BitLen should be <= 257")

	// Test commutativity
	result2 := ModMul(b, a, modBits)
	require.True(t, result.Equal(result2), "ModMul should be commutative")
}

// Test modular inversion
func TestInv(t *testing.T) {
	modBits := ModBits257

	// Test with a simple non-zero element
	a, _ := FromHex("5", 9)

	// Compute inverse
	aInv := Inv(a, modBits)

	// Verify: a * a^(-1) = 1 mod f(x)
	product := ModMul(a, aInv, modBits)
	one, _ := FromHex("1", 9)
	require.True(t, product.Equal(one), "a * Inv(a) = %s, want 1", product.String())
}

// Test field axioms with random elements
func TestFieldAxioms(t *testing.T) {
	modBits := ModBits257
	wordCount := modBits.WordCount()

	// Create some test elements
	a, _ := FromHex("123456789", wordCount)
	b, _ := FromHex("ABCDEF012", wordCount)
	c, _ := FromHex("987654321", wordCount)

	// Test associativity: (a * b) * c = a * (b * c)
	ab := ModMul(a, b, modBits)
	abc1 := ModMul(ab, c, modBits)

	bc := ModMul(b, c, modBits)
	abc2 := ModMul(a, bc, modBits)

	require.True(t, abc1.Equal(abc2), "Multiplication is not associative")

	// Test distributivity: a * (b + c) = a*b + a*c
	bc_sum := Add(b, c)
	left := ModMul(a, bc_sum, modBits)

	ab = ModMul(a, b, modBits)
	ac := ModMul(a, c, modBits)
	right := Add(ab, ac)

	require.True(t, left.Equal(right), "Distributivity does not hold")
}

// Test inversion for multiple field sizes
func TestInvMultipleFields(t *testing.T) {
	fields := []ModBits{
		ModBits163,
		ModBits257,
		ModBits431,
	}

	for _, modBits := range fields {
		t.Run(fmt.Sprintf("m=%d", modBits.M()), func(t *testing.T) {
			wordCount := modBits.WordCount()

			// Test with a few different elements
			testValues := []string{"3", "7", "AB", "12345"}

			for _, hexVal := range testValues {
				a, err := FromHex(hexVal, wordCount)
				require.NoError(t, err, "FromHex")

				if a.IsZero() {
					continue
				}

				aInv := Inv(a, modBits)
				product := ModMul(a, aInv, modBits)

				one, _ := FromHex("1", wordCount)
				require.True(t, product.Equal(one), "Inv(%s) failed: a * a^(-1) != 1", hexVal)
			}
		})
	}
}

// Benchmark multiplication
func BenchmarkMul(b *testing.B) {
	a, _ := FromHex("123456789ABCDEF0123456789ABCDEF", 9)
	x, _ := FromHex("FEDCBA9876543210FEDCBA987654321", 9)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Mul(a, x)
	}
}

// Benchmark modular multiplication
func BenchmarkModMul(b *testing.B) {
	modBits := ModBits257
	a, _ := FromHex("123456789ABCDEF0123456789ABCDEF", 9)
	x, _ := FromHex("FEDCBA9876543210FEDCBA987654321", 9)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ModMul(a, x, modBits)
	}
}

// Benchmark inversion
func BenchmarkInv(b *testing.B) {
	modBits := ModBits257
	a, _ := FromHex("123456789ABCDEF", 9)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Inv(a, modBits)
	}
}

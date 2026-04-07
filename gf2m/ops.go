package gf2m

// Add returns a + b in GF(2^m). In binary fields, addition is XOR.
func Add(a, b Element) Element {
	maxLen := max(len(b.words), len(a.words))

	result := NewElement(maxLen)

	for i := range len(a.words) {
		result.words[i] ^= a.words[i]
	}
	for i := range len(b.words) {
		result.words[i] ^= b.words[i]
	}

	return result
}

// AddAssign adds other to e in place (e = e + other).
func (e *Element) AddAssign(other Element) {
	for i := 0; i < len(other.words) && i < len(e.words); i++ {
		e.words[i] ^= other.words[i]
	}
}

// mul1x1 multiplies two 32-bit polynomials and returns the 64-bit result as (hi, lo).
// This is carry-less multiplication using a lookup table approach.
func mul1x1(a, b uint32) (uint32, uint32) {
	// Extract top 2 bits of a
	top2b := a >> 30

	// Work with lower 30 bits
	a1 := a & 0x3fffffff
	a2 := a1 << 1
	a4 := a2 << 1

	// Build lookup table for multiples of a
	tab := [8]uint32{
		0,
		a1,
		a2,
		a1 ^ a2,
		a4,
		a1 ^ a4,
		a2 ^ a4,
		a1 ^ a2 ^ a4,
	}

	var s, l, h uint32

	// Process b in 3-bit chunks
	s = tab[b&0x7]
	l = s

	s = tab[(b>>3)&0x7]
	l ^= s << 3
	h = s >> 29

	s = tab[(b>>6)&0x7]
	l ^= s << 6
	h ^= s >> 26

	s = tab[(b>>9)&0x7]
	l ^= s << 9
	h ^= s >> 23

	s = tab[(b>>12)&0x7]
	l ^= s << 12
	h ^= s >> 20

	s = tab[(b>>15)&0x7]
	l ^= s << 15
	h ^= s >> 17

	s = tab[(b>>18)&0x7]
	l ^= s << 18
	h ^= s >> 14

	s = tab[(b>>21)&0x7]
	l ^= s << 21
	h ^= s >> 11

	s = tab[(b>>24)&0x7]
	l ^= s << 24
	h ^= s >> 8

	s = tab[(b>>27)&0x7]
	l ^= s << 27
	h ^= s >> 5

	s = tab[b>>30]
	l ^= s << 30
	h ^= s >> 2

	// Handle top 2 bits of a
	if top2b&1 != 0 {
		l ^= b << 30
		h ^= b >> 2
	}
	if top2b&2 != 0 {
		l ^= b << 31
		h ^= b >> 1
	}

	return h, l
}

// mul2x2 multiplies two 64-bit polynomials (a1:a0 and b1:b0) using Karatsuba.
// Returns result as [r3, r2, r1, r0] where the product is r3:r2:r1:r0.
func mul2x2(a1, a0, b1, b0 uint32) [4]uint32 {
	var ret [6]uint32

	// ret[3:2] = a1 * b1
	ret[3], ret[2] = mul1x1(a1, b1)

	// ret[1:0] = a0 * b0
	ret[1], ret[0] = mul1x1(a0, b0)

	// ret[5:4] = (a0 ^ a1) * (b0 ^ b1)
	ret[5], ret[4] = mul1x1(a0^a1, b0^b1)

	// Combine using Karatsuba formula
	// Middle term = (a0^a1)*(b0^b1) ^ a1*b1 ^ a0*b0
	ret[2] ^= ret[5] ^ ret[1] ^ ret[3]
	ret[1] = ret[3] ^ ret[2] ^ ret[0] ^ ret[4] ^ ret[5]

	return [4]uint32{ret[0], ret[1], ret[2], ret[3]}
}

// Mul returns a * b (polynomial multiplication without reduction).
// The result may have up to len(a) + len(b) words.
func Mul(a, b Element) Element {
	aLen := len(a.words)
	bLen := len(b.words)

	if aLen == 0 || bLen == 0 {
		return NewElement(1)
	}

	// Result needs up to aLen + bLen words
	result := NewElement(aLen + bLen)

	// Multiply using mul2x2 for pairs of words
	for j := 0; j < bLen; j += 2 {
		y0 := b.words[j]
		y1 := uint32(0)
		if j+1 < bLen {
			y1 = b.words[j+1]
		}

		for i := 0; i < aLen; i += 2 {
			x0 := a.words[i]
			x1 := uint32(0)
			if i+1 < aLen {
				x1 = a.words[i+1]
			}

			prod := mul2x2(x1, x0, y1, y0)

			// Add product to result at position i+j
			if i+j < len(result.words) {
				result.words[i+j] ^= prod[0]
			}
			if i+j+1 < len(result.words) {
				result.words[i+j+1] ^= prod[1]
			}
			if i+j+2 < len(result.words) {
				result.words[i+j+2] ^= prod[2]
			}
			if i+j+3 < len(result.words) {
				result.words[i+j+3] ^= prod[3]
			}
		}
	}

	return result
}

// Sqr returns a^2 (squaring in GF(2^m)).
// For now, implemented as Mul(a, a). Can be optimized later with bit interleaving.
func Sqr(a Element) Element {
	return Mul(a, a)
}

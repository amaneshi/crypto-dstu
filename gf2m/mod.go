package gf2m

// Mod reduces a modulo the irreducible polynomial specified by modBits.
// This implements polynomial reduction in GF(2^m).
func Mod(a Element, modBits ModBits) Element { //nolint:funlen
	if len(modBits) == 0 || modBits[0] == 0 {
		return a.Clone()
	}

	m := modBits.M()
	wordCount := modBits.WordCount()

	// Make a copy to work with
	ret := a.Clone()
	if len(ret.words) < wordCount {
		// Extend if needed
		newWords := make([]uint32, wordCount)
		copy(newWords, ret.words)
		ret.words = newWords
	}

	// Start reduction from the highest word down to dN
	dN := m / 32

	for j := len(ret.words) - 1; j > dN; {
		zz := ret.words[j]
		if zz == 0 {
			j--
			continue
		}
		ret.words[j] = 0

		// For each term in the polynomial (except the leading x^m term)
		for k := 1; k < len(modBits) && modBits[k] != 0; k++ {
			// Reducing component x^modBits[k]
			n := m - modBits[k]
			d0 := n % 32
			d1 := 32 - d0
			wordOffset := n / 32

			ret.words[j-wordOffset] ^= zz >> d0
			if d0 != 0 && j-wordOffset-1 >= 0 {
				ret.words[j-wordOffset-1] ^= zz << d1
			}
		}

		// Reducing component x^0 (constant term)
		d0 := m % 32
		d1 := 32 - d0

		ret.words[j-dN] ^= zz >> d0
		if d0 != 0 && j-dN-1 >= 0 {
			ret.words[j-dN-1] ^= zz << d1
		}
	}

	// Final round of reduction at the boundary word
	for {
		d0 := m % 32
		if dN >= len(ret.words) {
			break
		}
		zz := ret.words[dN] >> d0
		if zz == 0 {
			break
		}
		d1 := 32 - d0

		// Clear up the top d1 bits
		if d0 != 0 {
			ret.words[dN] = (ret.words[dN] << d1) >> d1
		} else {
			ret.words[dN] = 0
		}

		// Reduction x^0 component
		ret.words[0] ^= zz

		// For each term in the polynomial
		for k := 1; k < len(modBits) && modBits[k] != 0; k++ {
			n := modBits[k] / 32
			dk0 := modBits[k] % 32
			dk1 := 32 - dk0

			ret.words[n] ^= zz << dk0
			tmpUlong := zz >> dk1
			if dk0 != 0 && tmpUlong != 0 && n+1 < len(ret.words) {
				ret.words[n+1] ^= tmpUlong
			}
		}
	}

	// Truncate result to proper size (wordCount words)
	// This is critical - without this, the element size doubles on each ModSqr
	if len(ret.words) > wordCount {
		truncated := NewElement(wordCount)
		copy(truncated.words, ret.words[:wordCount])
		return truncated
	}

	return ret
}

// ModMul returns (a * b) mod f(x) where f(x) is specified by modBits.
func ModMul(a, b Element, modBits ModBits) Element {
	prod := Mul(a, b)
	return Mod(prod, modBits)
}

// ModSqr returns (a^2) mod f(x) where f(x) is specified by modBits.
func ModSqr(a Element, modBits ModBits) Element {
	sq := Sqr(a)
	return Mod(sq, modBits)
}

package gf2m

// Inv computes the modular inverse of a modulo the irreducible polynomial.
// Returns a^(-1) mod f(x) using the extended binary GCD algorithm.
func Inv(a Element, modBits ModBits) Element {
	if a.IsZero() {
		panic("cannot invert zero element")
	}

	wordCount := modBits.WordCount()

	// Create polynomial representation for the algorithm
	p := computeModulus(modBits)

	// Initialize variables for extended GCD
	// Ensure all elements have the same word count
	b := NewElement(wordCount)
	b.words[0] = 1             // b = 1
	c := NewElement(wordCount) // c = 0

	// Clone and ensure proper size
	v := NewElement(wordCount)
	copy(v.words, p.words)
	u := NewElement(wordCount)
	copy(u.words, a.words)

	ubits := u.BitLen()
	vbits := v.BitLen()

	for {
		if ubits < 0 {
			panic("internal error in Inv")
		}

		// While u is even
		for ubits > 0 && (u.words[0]&1) == 0 {
			u0 := u.words[0]
			b0 := b.words[0]

			// Determine mask based on whether b is odd
			mask := uint32(0)
			if b0&1 != 0 {
				mask = 0xffffffff
			}

			// If b is odd, b ^= p
			b0 ^= p.words[0] & mask

			// Shift u and b right by 1
			for idx := 0; idx < len(u.words)-1; idx++ {
				u1 := u.words[idx+1]
				u.words[idx] = (u0 >> 1) | (u1 << 31)
				u0 = u1

				b1 := b.words[idx+1]
				if idx+1 < len(p.words) {
					b1 ^= p.words[idx+1] & mask
				}
				b.words[idx] = (b0 >> 1) | (b1 << 31)
				b0 = b1
			}

			u.words[len(u.words)-1] = u0 >> 1
			b.words[len(b.words)-1] = b0 >> 1

			ubits--
		}

		// Check if u == 1
		if ubits <= 32 && u.words[0] == 1 {
			allZero := true
			for i := 1; i < len(u.words); i++ {
				if u.words[i] != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				break
			}
		}

		// If deg(u) < deg(v), swap (u,v) and (b,c)
		if ubits < vbits {
			ubits, vbits = vbits, ubits
			u, v = v, u
			b, c = c, b
		}

		// u ^= v, b ^= c
		maxLen := len(v.words)
		if len(u.words) < maxLen {
			maxLen = len(u.words)
		}
		for idx := 0; idx < maxLen; idx++ {
			u.words[idx] ^= v.words[idx]
			b.words[idx] ^= c.words[idx]
		}

		// Recompute ubits if needed
		if ubits == vbits {
			ubits = u.BitLen()
		}
	}

	return b
}

// computeModulus constructs the full modulus polynomial from ModBits.
// For x^m + x^k1 + ... + 1, this returns the element with bits set at positions m, k1, ..., 0.
func computeModulus(modBits ModBits) Element {
	m := modBits.M()
	wordCount := modBits.WordCount()

	result := NewElement(wordCount)

	// Set bit m (the leading term)
	result.SetBit(m)

	// Set bits for intermediate terms
	for i := 1; i < len(modBits) && modBits[i] != 0; i++ {
		result.SetBit(modBits[i])
	}

	// Set bit 0 (constant term)
	result.SetBit(0)

	return result
}

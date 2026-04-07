package gf2m

// ModBits represents an irreducible polynomial in sparse form.
// For trinomial: [m, k, 0] represents x^m + x^k + 1
// For pentanomial: [m, k1, k2, k3, 0] represents x^m + x^k1 + x^k2 + x^k3 + 1
// The array is terminated by 0.
type ModBits []int

// Standard irreducible polynomials for DSTU 4145-2002 curves.
var (
	// ModBits163 and related are pentanomials and trinomials for DSTU 4145-2002.
	ModBits163 = ModBits{163, 7, 6, 3, 0}  // x^163 + x^7 + x^6 + x^3 + 1
	ModBits167 = ModBits{167, 6, 0}        // x^167 + x^6 + 1
	ModBits173 = ModBits{173, 10, 2, 1, 0} // x^173 + x^10 + x^2 + x + 1 (pentanomial)
	ModBits179 = ModBits{179, 4, 2, 1, 0}  // x^179 + x^4 + x^2 + x + 1 (pentanomial)
	ModBits191 = ModBits{191, 9, 0}        // x^191 + x^9 + 1
	ModBits233 = ModBits{233, 9, 4, 1, 0}  // x^233 + x^9 + x^4 + x + 1 (pentanomial)
	ModBits257 = ModBits{257, 12, 0}       // x^257 + x^12 + 1
	ModBits307 = ModBits{307, 8, 4, 2, 0}  // x^307 + x^8 + x^4 + x^2 + 1
	ModBits367 = ModBits{367, 21, 0}       // x^367 + x^21 + 1
	ModBits431 = ModBits{431, 5, 3, 1, 0}  // x^431 + x^5 + x^3 + x^1 + 1
)

// M returns the degree of the polynomial (the highest exponent).
func (mb ModBits) M() int {
	if len(mb) > 0 {
		return mb[0]
	}
	return 0
}

// WordCount returns the number of uint32 words needed to store an element in this field.
func (mb ModBits) WordCount() int {
	m := mb.M()
	return (m + 31) / 32
}

// IsTrinomial returns true if this is a trinomial (x^m + x^k + 1).
func (mb ModBits) IsTrinomial() bool {
	return len(mb) >= 3 && mb[2] == 0
}

// IsPentanomial returns true if this is a pentanomial.
func (mb ModBits) IsPentanomial() bool {
	return len(mb) >= 5 && mb[4] == 0 && mb[3] != 0
}

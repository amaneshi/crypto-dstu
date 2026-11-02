# Phase 1 — Binary Field Arithmetic `gf2m`

## Goal
Implement GF(2^m) finite field arithmetic — the mathematical foundation for DSTU 4145-2002 elliptic curve operations. All elements are polynomials over GF(2), stored as little-endian `[]uint32` word arrays.

## Prerequisites
None — this is the foundational layer.

## Package
`github.com/amaneshi/crypto-dstu/gf2m`

## JS Reference
- `jkurwa/lib/gf2m.js` — core arithmetic (`mul_1x1`, `mul_2x2`, `fmul`, `fmod`, `finv`, `blength`, `shiftRight`)
- `jkurwa/lib/field.js` — `Field` class wrapping `Uint32Array` with `mod_mul`, `addM`, `invert`, `trace`, bit ops

## Files to Create

| File | Purpose |
|------|---------|
| `gf2m/element.go` | `Element` type (`[]uint32`), constructors, conversion (hex, bytes, uint32 slice) |
| `gf2m/ops.go` | `Add`, `Mul` (`mul1x1`, `mul2x2`, `mulFull`), `Sqr` |
| `gf2m/mod.go` | `Mod` — polynomial reduction using sparse irreducible poly representation |
| `gf2m/inv.go` | `Inv` — modular inversion via extended binary GCD |
| `gf2m/poly.go` | `Poly` type for irreducible polynomials, `ModBits` representation `[m, k1, k2?, k3?, 0]` |
| `gf2m/gf2m_test.go` | Test suite |

## Step-by-Step Instructions

### 1. Define `Element` type
```go
type Element struct {
    words []uint32 // little-endian: words[0] is least significant
}
```
- Constructor `NewElement(words int) Element` — allocate zero element with given word count
- `FromHex(s string, words int) Element` — parse hex string to element (big-endian hex → LE words)
- `FromBytes(b []byte, words int) Element` — parse big-endian byte slice
- `Bytes() []byte` — export as big-endian byte slice
- `BitLen() int` — find highest set bit (port `blength` from jkurwa)
- `TestBit(n int) bool`, `SetBit(n int)`, `ClearBit(n int)`
- `IsZero() bool`, `Equal(other) bool`
- `Clone() Element`
- `String() string` — hex representation

### 2. Define `Poly` (irreducible polynomial)
```go
// ModBits stores sparse representation: [m, k1, k2, k3, 0] for pentanomial
// or [m, k, 0] for trinomial. Terminated by 0.
type ModBits []int
```
- Used by `Mod` to efficiently reduce without storing full polynomial
- Standard polynomials for each curve field size (from DSTU 4145-2002)

### 3. Implement `Add`
GF(2) addition = XOR. Simply XOR corresponding words:
```go
func Add(a, b Element) Element // result[i] = a.words[i] ^ b.words[i]
func (e *Element) AddAssign(other Element) // in-place XOR
```

### 4. Implement `Mul`
Port the carry-less multiplication chain from jkurwa:
1. **`mul1x1(a, b uint32) (hi, lo uint32)`** — multiply two 32-bit polynomials using lookup table of 8 multiples
   - Build table: `tab = [0, a1, a2, a1^a2, a4, a1^a4, a2^a4, a1^a2^a4]`
   - Process `b` in 3-bit chunks, accumulate shifts
   - Handle top 2 bits of `a` separately
2. **`mul2x2(a1, a0, b1, b0 uint32) [4]uint32`** — Karatsuba-style: `mul1x1(a1,b1)`, `mul1x1(a0,b0)`, `mul1x1(a0^a1, b0^b1)`, combine
3. **`Mul(a, b Element, scratch Element) Element`** — full polynomial multiplication
   - Double-nested loop over word pairs, calling `mul2x2`
   - Result has `len(a) + len(b)` words

### 5. Implement `Sqr`
Optimized squaring: interleave zero bits between each bit of input, then reduce.
- Can use a 256-entry lookup table for byte-level interleaving
- Or simply call `Mul(a, a)` as initial implementation

### 6. Implement `Mod`
Port `fmod` from jkurwa. Reduce polynomial modulo sparse irreducible:
```
Input: a (2n words), modBits [m, k1, ...]
Output: a mod f(x) where f(x) = x^m + x^k1 + ... + 1
```
- Process from highest word down to `dN = m/32`
- For each non-zero high word, XOR shifted copies at positions defined by modBits
- Final round handles the word at `dN` boundary
- Result fits in `ceil(m/32)` words

### 7. Implement `Inv`
Port `finv` from jkurwa — extended binary GCD:
```
Input: a, modulus polynomial p
Output: a^(-1) mod f(x)
```
Algorithm:
1. Set `u=a`, `v=poly`, `b=1`, `c=0`
2. While `u ≠ 1`:
   - While `u` is even: shift right, if `b` odd then `b ^= poly`, shift `b` right
   - If `deg(u) < deg(v)`: swap `(u,v)` and `(b,c)`
   - `u ^= v`, `b ^= c`
3. Return `b`

### 8. Write Tests
- **Identity**: `a + 0 = a`, `a * 1 = a`
- **Self-inverse addition**: `a + a = 0`
- **Inverse**: `a * Inv(a) = 1` for random elements
- **Associativity**: `(a*b)*c = a*(b*c)`
- **Commutativity**: `a*b = b*a`
- **Reduction**: `Mod` result has `BitLen <= m`
- Use field parameters from DSTU_PB_257 (m=257, k=12) for testing

## Acceptance Criteria
- [ ] All field axioms pass for random elements on at least 3 different field sizes
- [ ] `Inv` correctly computes inverses verified by `a * Inv(a) mod f = 1`
- [ ] `Mod` reduces to correct bit length
- [ ] Hex roundtrip: `FromHex(e.Hex()) == e`
- [ ] Benchmarks show reasonable performance (not a hard requirement but good to have)

## Notes
- jkurwa uses 32-bit words (`Uint32Array`) — we match this for easy cross-referencing
- Little-endian word order: `words[0]` contains bits 0-31
- The `Mul` function is the performance bottleneck — optimize later with CLMUL intrinsics if needed

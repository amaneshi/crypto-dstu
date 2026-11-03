# Phase 2 — Elliptic Curves over GF(2^m) `ec`

## Goal
Implement elliptic curve arithmetic over binary fields for the curve form `y² + xy = x³ + ax² + b` as defined in DSTU 4145-2002. Include all 10 standard named curves and point compression/expansion.

## Prerequisites
- **Phase 1** (`gf2m`) — field arithmetic must be complete and tested

## Package
`github.com/amaneshi/crypto-dstu/ec`

## JS Reference
- `jkurwa/lib/curve.js` — `Curve` class: constructor, `expand()`, `contains()`, `keygen()`, `truncate()`, `curve_id()`
- `jkurwa/lib/point.js` — `Point` class: `add()`, `twice()`, `mul()`, `compress()`
- `jkurwa/lib/standard.js` — named curve parameters (DSTU_PB_257, DSTU_PB_431)
- `jkurwa/lib/wnaf/` — windowed NAF scalar multiplication with precomputation

## Files to Create

| File | Purpose |
|------|---------|
| `ec/curve.go` | `Curve` struct, field parameters, `Contains()`, `NewCurve()` |
| `ec/point.go` | `Point` struct, `Add()`, `Double()`, `ScalarMul()`, `ScalarBaseMul()`, infinity point |
| `ec/compress.go` | `Compress()` → `[]byte`, `Expand([]byte)` → `Point`, `fsquad()` solver |
| `ec/params.go` | All 10 standard DSTU 4145-2002 named curves with parameters |
| `ec/ec_test.go` | Comprehensive tests |

## Step-by-Step Instructions

### 1. Define `Curve` struct
```go
type Curve struct {
    M        int           // field extension degree
    ModBits  gf2m.ModBits  // irreducible polynomial sparse form
    A        gf2m.Element  // curve parameter a (0 or 1)
    B        gf2m.Element  // curve parameter b
    N        gf2m.Element  // order of base point (big-endian integer)
    Cofactor int           // cofactor (2 or 4)
    Gx       gf2m.Element  // base point x-coordinate
    Gy       gf2m.Element  // base point y-coordinate
    Words    int           // ceil(M/32) — word count for field elements
}
```

### 2. Define `Point` struct
```go
type Point struct {
    X, Y  gf2m.Element
    Curve *Curve
    Inf   bool  // true if point at infinity
}
```

### 3. Implement point operations (affine coordinates)
Start with affine for correctness, optimize to projective later if needed.

**Point Addition** (`P + Q` where `P ≠ Q`):
For curve `y² + xy = x³ + ax² + b`:
```
λ = (y_P + y_Q) / (x_P + x_Q)
x_R = λ² + λ + x_P + x_Q + a
y_R = λ(x_P + x_R) + x_R + y_P
```
Division = multiply by inverse in GF(2^m).

**Point Doubling** (`2P`):
```
λ = x_P + y_P / x_P
x_R = λ² + λ + a
y_R = x_P² + (λ + 1) · x_R
```

**Identity**: Point at infinity is the identity element.

### 4. Implement scalar multiplication
**Basic double-and-add** (initial implementation):
```go
func (p *Point) ScalarMul(k gf2m.Element) *Point
```
Process bits of k from MSB to LSB: double, conditionally add.

**wNAF** (optimized, port from `jkurwa/lib/wnaf/`):
- Precompute odd multiples: `[1]P, [3]P, [5]P, ...`
- Convert scalar to wNAF representation
- Scan wNAF digits: double, conditionally add/subtract precomputed point
- Window size selection based on field size `m` (jkurwa: `getWindowSize(m)`)

### 5. Implement point compression / expansion
The bit-0 outline below describes PB. Current ONB uses bit `m-1` for the
selector; see [ONB encoding and native evidence](../onb.md).

**Compress** (from jkurwa `point.compress()`):
- Store x-coordinate + 1 bit (trace of `y/x`)
- If `x = 0`, y = b^(2^(m-1)) (special case)
- Otherwise: set bit 0 of x based on trace of `y/x`

**Expand** (from jkurwa `curve.expand()`):
- Extract trace bit k from bit 0, clear bit 0 of x
- Handle trace of x: if `trace(x) ≠ 0` and `a = 0`, or `trace(x) = 0` and `a = 1`, set bit 0
- Compute `y` by solving `z² + z = x + a + b/x²` using `fsquad()`
- Adjust sign bit based on k and trace of result

**`fsquad` (half-trace / quadratic solver)**:
For odd m, solve `z² + z = w`:
```
z = w
for i in 1..((m-1)/2):
    z = z² · z² + w    (square twice, add w)
```
Verify: `z² + z == w`

### 6. Implement `Contains`
Verify point (x,y) satisfies `y² + xy = x³ + ax² + b`:
```go
func (c *Curve) Contains(p *Point) bool {
    // LHS = y² + xy
    // RHS = x³ + ax² + b
    // return LHS == RHS
}
```

### 7. Define all 10 named curves in `params.go`

| Curve Name | m | Irreducible Poly | a | Cofactor |
|------------|---|------------------|---|----------|
| DSTU_PB_163 | 163 | x^163 + x^7 + 1 | 1 | 2 |
| DSTU_PB_167 | 167 | x^167 + x^6 + 1 | 1 | 2 |
| DSTU_PB_173 | 173 | x^173 + x^10 + 1 | 0 | 2 |
| DSTU_PB_179 | 179 | x^179 + x^4 + 1 | 1 | 2 |
| DSTU_PB_191 | 191 | x^191 + x^9 + 1 | 1 | 2 |
| DSTU_PB_233 | 233 | x^233 + x^74 + 1 | 1 | 2 |
| DSTU_PB_257 | 257 | x^257 + x^12 + 1 | 0 | 4 |
| DSTU_PB_307 | 307 | x^307 + x^8 + x^4 + x^2 + 1 | 1 | 2 |
| DSTU_PB_367 | 367 | x^367 + x^21 + 1 | 1 | 2 |
| DSTU_PB_431 | 431 | x^431 + x^5 + x^3 + x + 1 | 1 | 2 |

For each curve, provide: b (hex), base point (compressed or x,y), order n (hex).

Source the exact parameter values from:
- jkurwa `lib/standard.js` (has DSTU_PB_257 and DSTU_PB_431)
- DSTU 4145-2002 standard document (all 10 curves)
- cryptonite C library `src/cryptolib/c/dstu4145ec2m.c`

### 8. Write Tests
- **Base point on curve**: `curve.Contains(G)` for every named curve
- **Order**: `n * G = O` (point at infinity) — at least for DSTU_PB_257, DSTU_PB_431
- **Compress/Expand roundtrip**: `Expand(Compress(P)) == P`
- **Addition identity**: `P + O = P`
- **Doubling consistency**: `P + P = 2P`
- **Associativity**: `(P + Q) + R = P + (Q + R)` for random points
- **Scalar mul consistency**: `k*G` via double-and-add matches wNAF

## Acceptance Criteria
- [ ] All 10 named curves defined with correct parameters
- [ ] Base point validated on-curve for all 10 curves
- [ ] `n * G = O` verified for at least 2 curves (DSTU_PB_257, DSTU_PB_431)
- [ ] Point compression/expansion roundtrip works
- [ ] Scalar multiplication produces correct results
- [ ] `Contains` correctly validates and rejects points

## Notes
- jkurwa stores parameters as hex strings, parses to `Uint32Array` — we do similar with `gf2m.FromHex`
- The `order` field is a large integer (not a field element) — used for modular arithmetic in signature
- López-Dahab projective coordinates can be added later for performance
- `Truncate` function (clip hash to curve order bit length) is needed in Phase 5 but can be added here

# Phase 3 — Hash Functions `kupyna`, `gost34311`

## Goal
Implement two hash functions required by the Ukrainian cryptographic stack:
1. **Kupyna** (DSTU 7564:2014) — the modern Ukrainian national hash standard
2. **GOST 34.311-95** — legacy hash function used with GOST 28147 cipher

Both must implement Go's `hash.Hash` interface.

## Prerequisites
None — hash functions are independent of field/curve arithmetic.
However, GOST 34.311 internally uses the GOST 28147 cipher, so either:
- Implement a minimal internal GOST 28147 ECB encrypt for the hash, or
- Implement Phase 4 (GOST 28147) first, then use it here

**Recommended**: implement Kupyna first (fully independent), then GOST 34.311 after Phase 4.

## Packages
- `crypto-dstu/kupyna`
- `crypto-dstu/gost34311`

## JS Reference
- Kupyna: no JS impl in dstucrypt (they use GOST hash). Use the **C reference** from `privat-it/cryptonite` and the **spec paper** https://eprint.iacr.org/2015/885.pdf
- GOST 34.311: `dstucrypt/gost89` `lib/hash.js` — full JS implementation

## Reference Implementations for Kupyna
- `privat-it/cryptonite` → `src/cryptolib/c/kupyna.c`
- `sjinks/kupyna-c` → https://github.com/sjinks/kupyna-c (clean C implementation)
- Specification: DSTU 7564:2014, eprint 2015/885

## Files to Create

### Kupyna
| File | Purpose |
|------|---------|
| `kupyna/kupyna.go` | `New256()`, `New384()`, `New512()` returning `hash.Hash`; internal `digest` struct |
| `kupyna/compress.go` | `T_xor` and `T_plus` permutations, Davies-Meyer compression |
| `kupyna/sbox.go` | Four S-box lookup tables (256 entries each) |
| `kupyna/consts.go` | Round constants, MDS matrix coefficients, number of rounds per variant |
| `kupyna/kupyna_test.go` | Test vectors |

### GOST 34.311
| File | Purpose |
|------|---------|
| `gost34311/hash.go` | `New()` returning `hash.Hash`; uses GOST 28147 cipher internally |
| `gost34311/hash_test.go` | Test vectors from gost89 JS lib |

## Step-by-Step: Kupyna

### 1. Define constants (`consts.go`)
- **State sizes**: Kupyna-256/384 use 512-bit state (8×8 byte matrix), Kupyna-512 uses 1024-bit state (8×16)
- **Rounds**: 10 rounds for 512-bit state, 14 rounds for 1024-bit state
- **MDS matrix**: 8×8 matrix over GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
  - Reduction polynomial coefficients: `[0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04]`
- **Round constants**: generated from column index and round number

### 2. Define S-boxes (`sbox.go`)
Four S-boxes, each 256 bytes. These are identical to Kalyna's S-boxes:
```
sbox0[256], sbox1[256], sbox2[256], sbox3[256]
```
The S-boxes are applied cyclically: column `j` uses `sbox[j % 4]`.
Source exact values from `kupyna-c` or `cryptonite` C source.

### 3. Implement permutations (`compress.go`)
The compression function uses two permutations T⊕ and T+, each consisting of 4 sub-operations:

**SubBytes**: Apply S-box to each byte of state
```
state[i][j] = sbox[j % 4][state[i][j]]
```

**ShiftBytes**: Cyclically shift rows of the state matrix
- For 512-bit state (l=8): shifts = [0, 1, 2, 3, 4, 5, 6, 7]
- For 1024-bit state (l=16): shifts = [0, 1, 2, 3, 4, 5, 6, 11]

**MixColumns**: Matrix multiplication in GF(2^8)
- Multiply each column by the MDS matrix
- Use `gf_mul(a, b byte) byte` helper with reduction poly 0x11D

**AddConstant**:
- T⊕ (XOR variant): `state[0][j] ^= (j << 4) ^ round_number`
- T+ (ADD variant): add round constant to first row with carry

### 4. Implement compression function
Davies-Meyer construction:
```
h_{i+1} = T⊕(h_i ⊕ m_i) ⊕ T+(m_i) ⊕ h_i
```
Where `m_i` is the message block and `h_i` is the chaining value.

### 5. Implement hash.Hash interface (`kupyna.go`)
```go
type digest struct {
    state    []byte    // internal state (64 or 128 bytes)
    buf      []byte    // partial block buffer
    length   uint64    // total message length in bits
    hashSize int       // output size: 32, 48, or 64 bytes
    blockSize int      // 64 for Kupyna-256/384, 128 for Kupyna-512
}

func New256() hash.Hash
func New384() hash.Hash
func New512() hash.Hash
```

**Padding**: append `1` bit, then zeros, then 96-bit message length (in bits) as LE.

**Finalization**: one more compression with the message length counter, then truncate state to output size.
- For Kupyna-256: return last 32 bytes of 64-byte state
- For Kupyna-384: return last 48 bytes of 64-byte state
- For Kupyna-512: return last 64 bytes of 128-byte state

### 6. Test vectors (`kupyna_test.go`)
From Wikipedia and the standard:
```
Kupyna-256("") = cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6
Kupyna-512("") = 656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538
Kupyna-256("The quick brown fox jumps over the lazy dog") = 996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6
Kupyna-256("The quick brown fox jumps over the lazy dog.") = 88ea8ce988fe67eb83968cdc0f6f3ca693baa502612086c0dcec761a98e2fb1f
```

Also source additional test vectors from the DSTU 7564:2014 standard appendix.

## Step-by-Step: GOST 34.311-95

### 1. Implement hash (`hash.go`)
The GOST hash processes 256-bit blocks using the GOST 28147 cipher:
- Internal state: `h` (256 bits), `Σ` (256 bits running sum), `N` (256 bits message length)
- For each 256-bit block M:
  1. Generate four 256-bit keys from h and M
  2. Encrypt h with each key using GOST 28147 in ECB mode
  3. Apply a permutation/shuffle to produce new h
  4. Update: `Σ += M`, `N += 256`
- Finalization: process remaining bytes with padding, then compress `N`, then compress `Σ`

Reference: `gost89/lib/hash.js` — `Hash.init()`, `Hash.update()`, `Hash.finish()`

### 2. Test vectors
From gost89 JS reference:
```
gosthash("") = expected_hex_value (get from gost89 test suite)
gosthash("LA LA LA SHTIRLITZ KURWA VODKA MATRIOSKA") = 0a327f3bcee1f3de0f40612ec3ced0a32951b8b2168e9a010f5b1546c0a91d93
```

## Acceptance Criteria
- [ ] `kupyna.New256()`, `kupyna.New384()`, `kupyna.New512()` implement `hash.Hash`
- [ ] All known Kupyna test vectors pass
- [ ] Empty string hashes match Wikipedia values exactly
- [ ] `gost34311.New()` implements `hash.Hash` (after Phase 4 cipher is available)
- [ ] GOST hash test vectors pass
- [ ] `hash.Hash` contract: `Reset()` works, multiple `Write()` calls produce same result as single `Write()`

## Notes
- Kupyna's S-boxes are the same as Kalyna's — consider sharing `sbox.go` or duplicating for package independence
- The MDS multiplication in GF(2^8) is small and self-contained — no dependency on the `gf2m` package
- For GOST 34.311, you need GOST 28147 ECB encrypt — either import `gost28147` package or embed minimal cipher
- Kupyna is the priority — it's needed for DSTU 4145 signatures with modern algorithms

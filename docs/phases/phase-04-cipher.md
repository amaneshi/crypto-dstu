# Phase 4 — Block Ciphers `kalyna`, `gost28147`

## Goal
Implement two symmetric block ciphers:
1. **Kalyna** (DSTU 7624:2014) — modern Ukrainian national block cipher
2. **GOST 28147-89** (DSTU variant) — legacy cipher with Ukrainian S-boxes, CFB mode, and key wrapping

Both must implement Go's `cipher.Block` interface.

## Prerequisites
None — block ciphers are independent of EC/field arithmetic.
(GOST 34.311 hash from Phase 3 depends on this cipher, so this should ideally be done before or alongside Phase 3.)

## Packages
- `crypto-dstu/kalyna`
- `crypto-dstu/gost28147`

## JS Reference
- Kalyna: **no JS impl** in dstucrypt — use C reference from `Roman-Oliynykov/Kalyna-reference` (`main.c`, `kalyna.c`, `tables.c`) and `privat-it/cryptonite`
- GOST 28147: `dstucrypt/gost89` — `lib/cipher.js`, `lib/wrap.js`

## Files to Create

### Kalyna
| File | Purpose |
|------|---------|
| `kalyna/kalyna.go` | `NewCipher(key []byte) (cipher.Block, error)` — supports all key/block combinations |
| `kalyna/keysched.go` | Key schedule: pre-round key, sigma function, round key generation |
| `kalyna/sbox.go` | Four S-box tables (256 entries each, shared with Kupyna) |
| `kalyna/consts.go` | MDS matrix, round counts, block/key size constants |
| `kalyna/kalyna_test.go` | Test vectors from reference C implementation |

### GOST 28147
| File | Purpose |
|------|---------|
| `gost28147/cipher.go` | `NewCipher(key []byte) cipher.Block` — ECB mode, 64-bit block |
| `gost28147/cfb.go` | CFB stream mode encrypt/decrypt |
| `gost28147/sbox.go` | Ukrainian DSTU S-box tables (8 × 16 entries) |
| `gost28147/wrap.go` | Key wrapping per DSTSZI specification |
| `gost28147/gost28147_test.go` | Test vectors |

## Step-by-Step: Kalyna (DSTU 7624:2014)

### 1. Understand variants
| Variant | Block (bits) | Key (bits) | Rounds | State columns |
|---------|-------------|-----------|--------|---------------|
| Kalyna-128/128 | 128 | 128 | 10 | 2 (of uint64) |
| Kalyna-128/256 | 128 | 256 | 14 | 2 |
| Kalyna-256/256 | 256 | 256 | 14 | 4 |
| Kalyna-256/512 | 256 | 512 | 18 | 4 |
| Kalyna-512/512 | 512 | 512 | 18 | 8 |

State is treated as a matrix of bytes, organized column-wise into `uint64` words.

### 2. S-boxes (`sbox.go`)
Four S-boxes, 256 bytes each. Same as Kupyna:
```go
var sbox0, sbox1, sbox2, sbox3 [256]byte
var inv_sbox0, inv_sbox1, inv_sbox2, inv_sbox3 [256]byte // for decryption
```
Source from `Kalyna-reference/tables.c` or `cryptonite`.

### 3. Round function
Each round consists of:
1. **SubBytes**: apply S-boxes cyclically to state bytes: `state[i] = sbox[i % 4][state[i]]`
2. **ShiftRows**: cyclically shift rows of the state matrix
   - 128-bit: shifts = [0, -1, -2, -3, -4, -5, -6, -7] (mod 2 columns)
   - 256-bit: shifts = [0, -1, -2, -3, -4, -5, -6, -7] (mod 4 columns)
   - 512-bit: shifts = [0, -1, -2, -3, -4, -5, -6, -7] (mod 8 columns)
3. **MixColumns**: multiply each column by MDS matrix in GF(2^8) with poly 0x11D
   - Matrix coefficients: `[1, 1, 5, 1, 8, 6, 7, 4]` (circulant)
4. **AddRoundKey** (XOR) or **AddRoundKeyExpand** (modular addition for first/last rounds)

Encryption structure:
```
AddRoundKey(state, rk[0])        // pre-whitening (modular add)
for r = 1 to Nr-1:
    SubBytes → ShiftRows → MixColumns → XorRoundKey(state, rk[r])
SubBytes → ShiftRows → MixColumns → AddRoundKey(state, rk[Nr])  // post-whitening (modular add)
```

### 4. Key schedule (`keysched.go`)
This is the most complex part. Algorithm:
1. Compute **pre-round key** `kt` using the sigma function (a reduced version of the cipher itself)
2. Generate even-indexed round keys: `rk[2i] = EncryptRound(kt, constant_i)`
3. Generate odd-indexed round keys: `rk[2i+1] = RotateLeft(rk[2i])` (shift left by 1 uint64 in state)

The sigma function for `kt`:
```
kt = key
Apply 2 rounds of the cipher using key halves as round keys
```

Port the exact logic from `Kalyna-reference/kalyna.c` functions:
- `KeyExpand()`, `KalynaCiphering()`, `SubShiftMixRound()`

### 5. Implement `cipher.Block` (`kalyna.go`)
```go
type kalynaBlock struct {
    roundKeys [][]uint64  // Nr+1 round keys
    blockSize int         // 16, 32, or 64 bytes
    rounds    int         // 10, 14, or 18
}

func NewCipher(key []byte) (cipher.Block, error)
func (k *kalynaBlock) BlockSize() int
func (k *kalynaBlock) Encrypt(dst, src []byte)
func (k *kalynaBlock) Decrypt(dst, src []byte)
```
Auto-detect variant from key length:
- 16-byte key → Kalyna-128/128
- 32-byte key → ambiguous (Kalyna-128/256 or Kalyna-256/256) — need block size param
- 64-byte key → Kalyna-256/512 or Kalyna-512/512

Provide explicit constructors: `NewCipher128_128`, `NewCipher128_256`, etc.

### 6. Test vectors
From `Kalyna-reference/main.c` — it contains test vectors for all 5 variants with known plaintext/key/ciphertext.

## Step-by-Step: GOST 28147-89

### 1. S-boxes (`sbox.go`)
GOST uses 8 substitution boxes, each mapping 4 bits → 4 bits (16 entries per S-box).
The **Ukrainian DSTU variant** uses different S-boxes than the original Russian GOST.

From `gost89/lib/cipher.js`:
```javascript
// DSTU S-boxes (default in gost89)
const sboxes = [
    [0xa, 0x9, 0xd, 0x6, ...], // S1
    ...
];
```
Port these exact tables.

### 2. Core cipher (`cipher.go`)
GOST 28147-89 is a Feistel cipher:
- 64-bit block, 256-bit key
- 32 rounds
- Key schedule: 8 subkeys of 32 bits each, used in specific order:
  - Rounds 1-24: subkeys `k0,k1,...,k7` repeated 3 times
  - Rounds 25-32: subkeys `k7,k6,...,k0` (reverse order)

Round function `f(R, K)`:
1. `temp = (R + K) mod 2^32`
2. Apply 8 S-boxes: each processes 4 bits of temp
3. Rotate result left by 11 bits

```go
type gostCipher struct {
    key [8]uint32
    sbox [8][16]byte
}

func NewCipher(key []byte) cipher.Block
func (g *gostCipher) BlockSize() int { return 8 }
func (g *gostCipher) Encrypt(dst, src []byte)
func (g *gostCipher) Decrypt(dst, src []byte)
```

### 3. CFB mode (`cfb.go`)
GOST CFB (cipher feedback) mode:
```go
func NewCFBEncrypter(block cipher.Block, iv []byte) cipher.Stream
func NewCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream
```
Standard CFB with 64-bit feedback register matching the 64-bit block size.

### 4. Key wrapping (`wrap.go`)
Port from `gost89/lib/wrap.js`:
```go
func WrapKey(kek, cek, iv []byte) []byte    // wrap content encryption key
func UnwrapKey(kek, wrapped []byte) []byte   // unwrap
```
Uses GOST cipher in ECB mode with specific padding and MAC.

### 5. Test vectors
From `gost89` test suite and GOST standard:
```
// Known plaintext/key/ciphertext pairs
// CFB mode test vectors
// Key wrap test vectors
```

## Acceptance Criteria
- [ ] `kalyna.NewCipher*()` returns `cipher.Block` for all 5 variants
- [ ] Kalyna encrypt/decrypt roundtrip: `Decrypt(Encrypt(pt)) == pt`
- [ ] All Kalyna reference test vectors pass
- [ ] `gost28147.NewCipher()` returns `cipher.Block`
- [ ] GOST encrypt/decrypt roundtrip works
- [ ] GOST CFB mode produces correct stream cipher
- [ ] GOST key wrap/unwrap roundtrip works
- [ ] All test vectors from reference implementations pass

## Notes
- Kalyna and Kupyna share the same 4 S-boxes — consider a shared `internal/sbox` package or just duplicate
- Kalyna's MDS matrix multiplication is identical to Kupyna's — another candidate for sharing
- GOST 28147 has a tiny block size (64 bits) — it's legacy but required for transport containers
- The `gost89` JS lib uses the DSTU S-box variant by default — make sure to use the same tables
- Performance: GOST is simple and fast; Kalyna benefits from precomputed T-tables (combined SubBytes+MixColumns)

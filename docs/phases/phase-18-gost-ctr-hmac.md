# Phase 18 — GOST 28147 CTR Mode & HMAC (`pkg/gost28147`, new `pkg/hmac`)

## Goal
1. Add **CTR (counter / gamma) mode** to `pkg/gost28147`, mirroring
   `gost28147_init_ctr` from cryptonite.
2. Create a new **`pkg/hmac`** package implementing HMAC keyed on
   GOST 34.311-95 (`hmac_alloc_gost34_311`) and optionally Kupyna-256
   (`hmac_alloc_kupyna`), following cryptonite `hmac.h`.

## Prerequisites
- **Phase 4** (`gost28147`) — existing ECB / CFB / MAC implementation
- **Phase 3** (`gost34311`, `kupyna`) — hash functions used inside HMAC

## Packages
- `crypto-dstu/pkg/gost28147` — add CTR mode in-place
- `crypto-dstu/pkg/hmac` — new package

## Reference
- `_ref/cryptonite/src/cryptonite/c/gost28147.h` — `gost28147_init_ctr`
- `_ref/cryptonite/src/cryptonite/c/hmac.h` — `hmac_alloc_gost34_311`,
  `hmac_alloc_sha2` (structure to follow)
- `_ref/cryptonite/src/cryptoniteUtest/` — CTR and HMAC test vectors

## Files to Create / Modify

| File | Action |
|------|--------|
| `pkg/gost28147/ctr.go` | New — CTR stream mode |
| `pkg/gost28147/gost28147_test.go` | Extend — CTR test vectors |
| `pkg/hmac/hmac.go` | New — generic HMAC + GOST34311 / Kupyna constructors |
| `pkg/hmac/hmac_test.go` | New — test vectors |

## Step-by-Step Instructions

### 1. GOST 28147 CTR mode (`ctr.go`)

GOST 28147 CTR (gamma mode) per GOST 28147-89 §8:
- IV (sync) is 8 bytes (64-bit)
- Counter advances as: `ctr = (ctr + C1) mod 2^32 || (ctr_hi + C2) mod (2^32 - 1)`
  where C1 = 0x01010101, C2 = 0x01010104 (GOST standard constants)
- Each counter block is ECB-encrypted → keystream XOR'd with plaintext

```go
// NewCTR returns a GOST 28147 CTR stream cipher.
// iv must be exactly 8 bytes (BlockSize).
func NewCTR(block cipher.Block, iv []byte) cipher.Stream
```

Cryptonite reference: `gost28147_init_ctr` in `gost28147.c`.
Counter increment constants must match cryptonite exactly for
inter-operability — verify against test vectors.

### 2. HMAC package (`hmac/hmac.go`)

Generic HMAC construction (RFC 2104) wrapping any `hash.Hash`:

```go
// New returns an HMAC over the given hash function.
// This is equivalent to crypto/hmac.New but accepts any hash.Hash factory.
func New(h func() hash.Hash, key []byte) hash.Hash
```

Specific constructors matching cryptonite naming:

```go
// NewGOST34311 returns HMAC keyed with GOST 34.311-95 (Ukrainian S-box).
// sync is the 8-byte IV for the GOST 34.311 hash (may be nil → zero IV).
func NewGOST34311(key []byte, sync []byte) hash.Hash

// NewKupyna256 returns HMAC-Kupyna-256.
func NewKupyna256(key []byte) hash.Hash

// NewKupyna512 returns HMAC-Kupyna-512.
func NewKupyna512(key []byte) hash.Hash
```

Implementation notes:
- HMAC-GOST34311: the inner hash uses GOST 34.311 with the given `sync`
  parameter passed at construction; ipad/opad are applied to `key` as
  per RFC 2104 (block size = 32 bytes for GOST 34.311)
- For Kupyna: block size is 64 bytes (Kupyna-256) or 128 bytes (Kupyna-512)
- Use `crypto/hmac` internally where the hash factory maps cleanly;
  for GOST34311 with sync, wrap manually since the sync must be fixed
  at construction time

### 3. Test vectors

GOST 28147 CTR:
- Extract from `_ref/cryptonite/src/cryptoniteUtest/` — `gost28147_*ctr*`
- Encrypt known plaintext with known key+IV → compare to expected ciphertext
- Verify CTR is self-inverse (decrypt = encrypt)

HMAC-GOST34311:
- Extract from `_ref/cryptonite/src/cryptoniteUtest/` — `hmac_*gost*`
- Known key + message → expected MAC (32 bytes)

HMAC-Kupyna-256:
- Known key + message → expected MAC

## Acceptance Criteria
- [ ] GOST 28147 CTR output matches cryptonite reference vectors
- [ ] CTR mode is self-inverse (stream cipher property)
- [ ] HMAC-GOST34311 tag matches cryptonite reference for all test vectors
- [ ] HMAC-Kupyna256 / HMAC-Kupyna512 tags match expected values
- [ ] All existing `gost28147` tests still pass
- [ ] `hmac.New` works with any `hash.Hash` factory (including standard `sha256.New`)

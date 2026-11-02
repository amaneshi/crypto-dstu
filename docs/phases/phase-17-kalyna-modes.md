# Phase 17 — Kalyna Additional Modes (`pkg/kalyna`)

## Goal
Extend the `kalyna` package beyond the raw `cipher.Block` (ECB) to implement
all operating modes that cryptonite exposes for DSTU 7624, with priority on
those needed for CMS/PKI: **CTR, CBC, CFB, OFB, GCM (GMAC), CMAC, XTS, KW**.

CCM is deferred (complex; not required by current UA PKI profiles).

## Prerequisites
- **Phase 4** (`kalyna`) — existing `cipher.Block` implementation

## Package
`github.com/amaneshi/crypto-dstu/pkg/kalyna` — extend in-place

## Reference
- `_ref/cryptonite/src/cryptonite/c/dstu7624.h`
- `_ref/cryptonite/src/cryptoniteUtest/` — mode test vectors
- DSTU 7624:2014 — Annex A (mode specifications)

## Files to Create / Modify

| File | Action |
|------|--------|
| `pkg/kalyna/modes.go` | New — CTR, CBC, CFB, OFB wrappers |
| `pkg/kalyna/gcm.go` | New — GCM encrypt+MAC and GMAC |
| `pkg/kalyna/cmac.go` | New — CMAC message authentication |
| `pkg/kalyna/xts.go` | New — XTS disk-sector encryption |
| `pkg/kalyna/kw.go` | New — Key wrap / unwrap (KW mode) |
| `pkg/kalyna/kalyna_test.go` | Extend — mode test vectors |

## Step-by-Step Instructions

### 1. Standard stream modes (`modes.go`)

Wrap Go standard `crypto/cipher` — these are trivially correct because
`kalyna` already implements `cipher.Block`:

```go
// NewCTR returns a CTR stream cipher over a Kalyna block.
func NewCTR(block cipher.Block, iv []byte) cipher.Stream

// NewCBC returns a CBC block mode.
func NewCBC(block cipher.Block, iv []byte) cipher.BlockMode   // encrypt
func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode

// NewCFB returns a CFB stream cipher (full-block feedback).
func NewCFB(block cipher.Block, iv []byte) cipher.Stream      // encrypt
func NewCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream

// NewOFB returns an OFB stream cipher.
func NewOFB(block cipher.Block, iv []byte) cipher.Stream
```

These are one-liners delegating to `cipher.NewCTR`, `cipher.NewCBC*`,
`cipher.NewCFB*`, `cipher.NewOFB` from the standard library.

### 2. GCM / GMAC (`gcm.go`)

DSTU 7624 GCM is identical in structure to AES-GCM but uses the Kalyna
permutation. Use Go's `cipher.NewGCM` / `cipher.NewGCMWithNonceSize` since
`cipher.Block` is already implemented:

```go
// NewGCM returns a GCM AEAD wrapping the given Kalyna block.
// iv must equal block.BlockSize() bytes.
func NewGCM(block cipher.Block) (cipher.AEAD, error)

// NewGCMWithTagSize allows a shorter tag (q bytes, 1 ≤ q ≤ blockSize).
func NewGCMWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error)
```

For GMAC (authentication without encryption):
```go
// GMAC computes a q-byte authentication tag over aad using iv.
func GMAC(block cipher.Block, iv, aad []byte, q int) ([]byte, error)
```

### 3. CMAC (`cmac.go`)

CMAC per NIST SP 800-38B / DSTU 7624 §A.6:

```go
// NewCMAC returns a CMAC MAC keyed with the given Kalyna block.
// tagSize must satisfy 1 ≤ tagSize ≤ block.BlockSize().
func NewCMAC(block cipher.Block, tagSize int) (hash.Hash, error)
```

Implementation:
1. Generate subkeys K1, K2 from Encrypt(0…0) with CMAC doubling in GF(2^128/256/512)
2. Pad last block with ISO/IEC 7816-4 if incomplete
3. XOR K1 (complete) or K2 (incomplete last block)
4. Final ECB encryption → tag[:tagSize]

### 4. XTS (`xts.go`)

XTS per IEEE 1619 / DSTU 7624 §A.8:

```go
// NewXTS returns an XTS cipher for disk-sector encryption.
// key must be 2 × underlying key length (two independent Kalyna keys).
func NewXTS(newCipher func([]byte) (cipher.Block, error), key []byte) (*XTS, error)

type XTS struct { /* unexported */ }

// Encrypt encrypts a sector. sectorNum is the logical sector index.
func (x *XTS) Encrypt(dst, src []byte, sectorNum uint64) error
func (x *XTS) Decrypt(dst, src []byte, sectorNum uint64) error
```

### 5. Key Wrap (`kw.go`)

Key wrap per RFC 3394 / DSTU 7624 §A.9:

```go
// Wrap encrypts a key (keyToWrap) using the wrapping key material in block.
// Returns the wrapped key (len(keyToWrap) + blockSize bytes).
func Wrap(block cipher.Block, keyToWrap []byte) ([]byte, error)

// Unwrap decrypts a wrapped key.
func Unwrap(block cipher.Block, wrappedKey []byte) ([]byte, error)
```

### 6. Test vectors

For each mode, extract vectors from:
- `_ref/cryptonite/src/cryptoniteUtest/` — files matching `dstu7624_*`
- DSTU 7624:2014 Annex A

Minimum coverage:
- CTR, CBC, CFB, OFB: encrypt + decrypt roundtrip for all 5 Kalyna variants
- GCM: encrypt+tag, decrypt+verify, wrong tag rejected
- CMAC: known tag, `Reset` re-use
- XTS: known sector encryption
- KW: wrap + unwrap roundtrip, corrupted ciphertext rejected

## Acceptance Criteria
- [ ] CTR/CBC/CFB/OFB mode output matches cryptonite reference vectors
- [ ] GCM produces correct authentication tag; wrong tag returns error
- [ ] CMAC tag matches cryptonite vectors
- [ ] XTS encrypt/decrypt roundtrip for all block sizes
- [ ] KW wrap/unwrap roundtrip; corrupted bytes return error
- [ ] All existing kalyna `cipher.Block` tests still pass

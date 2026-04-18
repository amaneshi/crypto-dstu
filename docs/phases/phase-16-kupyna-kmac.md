# Phase 16 — Kupyna KMAC (`pkg/kupyna`)

## Goal
Add KMAC (Keyed MAC) mode to the existing `kupyna` package, mirroring
`dstu7564_init_kmac` / `dstu7564_update_kmac` / `dstu7564_final_kmac` from
cryptonite (`_ref/cryptonite/src/cryptonite/c/dstu7564.h`).

## Prerequisites
- **Phase 3** (`kupyna`) — existing hash implementation; KMAC builds on top of it

## Package
`crypto-dstu/pkg/kupyna` — extend in-place, no new package

## Reference
- `_ref/cryptonite/src/cryptonite/c/dstu7564.h` — `dstu7564_init_kmac`,
  `dstu7564_update_kmac`, `dstu7564_final_kmac`
- `_ref/cryptonite/src/cryptoniteUtest/` — KMAC test vectors

## Standard
- DSTU 7564:2014 §B.4 — KMAC construction

## Files to Create / Modify

| File | Action |
|------|--------|
| `pkg/kupyna/kmac.go` | New — KMAC implementation |
| `pkg/kupyna/kupyna_test.go` | Extend — add KMAC test cases |

## Step-by-Step Instructions

### 1. KMAC construction (`kmac.go`)

KMAC in Kupyna is a prefix-key construction:
1. Pad the key to a full Kupyna block (64 bytes for 256-bit output, 128 bytes
   for 384/512-bit output)
2. XOR the padded key into the initial hash state (same initial vector as the
   plain hash, but first block is key⊕IV)
3. Feed the message normally via `Write`
4. Call `Sum` to finalize

```go
// NewKMAC256 returns a Kupyna-256 KMAC with the given key.
// Key is padded/truncated to the internal block size (64 bytes).
func NewKMAC256(key []byte) hash.Hash

// NewKMAC384 returns a Kupyna-384 KMAC (128-byte block).
func NewKMAC384(key []byte) hash.Hash

// NewKMAC512 returns a Kupyna-512 KMAC (128-byte block).
func NewKMAC512(key []byte) hash.Hash
```

Implementation detail — compare with cryptonite `dstu7564.c`:
- KMAC state is initialized identically to plain hash (`state[0][0] = blockSize`)
- Key bytes are zero-padded to `blockSize`, then processed as the very first
  input block through the compression function directly (not via `Write`) so
  that the internal counter `totalBits` is NOT advanced by the key
- After that, normal `Write`/`Sum` usage applies

### 2. Test vectors

Extract KMAC test vectors from:
- `_ref/cryptonite/src/cryptoniteUtest/` — search for `kmac` or `dstu7564_kmac`
- DSTU 7564:2014 Annex B

Minimum test cases:
- KMAC-256: zero key + empty message
- KMAC-256: known key + known message → expected MAC
- KMAC-512: known vectors
- `Reset` + re-use produces same result
- Different keys → different MAC for same message

## Acceptance Criteria
- [ ] `NewKMAC256` / `NewKMAC384` / `NewKMAC512` implement `hash.Hash`
- [ ] Output matches cryptonite reference vectors for all tested cases
- [ ] `Reset()` correctly reinitialises keyed state (key is preserved)
- [ ] Zero-length key degenerates gracefully (no panic)
- [ ] All existing `kupyna` tests still pass

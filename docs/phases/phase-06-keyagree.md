# Phase 6 — Key Agreement `dstu15946`

## Goal
Implement EC Diffie-Hellman key agreement and key derivation as specified in DSTU ISO/IEC 15946-3:2006. This is used to establish shared symmetric keys for encryption between two parties.

## Prerequisites
- **Phase 1** (`gf2m`) — field arithmetic
- **Phase 2** (`ec`) — elliptic curve operations
- **Phase 3** (`kupyna` or `gost34311`) — hash function for KDF

## Package
`github.com/amaneshi/crypto-dstu/dstu15946`

## JS Reference
- `jkurwa/lib/models/Priv.js` — `sharedSecret()` method, `dh()` method
- `jkurwa/lib/app/ctx.js` — `derive()` function that produces symmetric key from ECDH
- `gost89/lib/wrap.js` — how the derived key is used for key wrapping

## Files to Create

| File | Purpose |
|------|---------|
| `dstu15946/dh.go` | `SharedSecret()` — ECDH shared secret computation |
| `dstu15946/kdf.go` | `DeriveKey()` — key derivation from shared secret |
| `dstu15946/kdf_test.go` | Tests |

## Step-by-Step Instructions

### 1. ECDH shared secret
```go
func SharedSecret(priv *dstu4145.PrivateKey, pub *dstu4145.PublicKey) (gf2m.Element, error)
```

Algorithm:
1. Validate that `pub.Q` is on the curve
2. Compute `S = priv.D · pub.Q` (scalar multiplication)
3. If `S` is point at infinity, return error
4. Return `x_S` (x-coordinate of shared point)

From jkurwa `Priv.sharedSecret()`:
```javascript
sharedSecret(pub, ukm, rng) {
    // compute e·Q_recipient
    // the shared point's x-coordinate is the raw shared secret
}
```

### 2. Key derivation function (KDF)
```go
func DeriveKey(sharedSecret []byte, ukm []byte, keyLen int, hash func() hash.Hash) ([]byte, error)
```

The KDF takes the raw shared secret and optional UKM (user keying material) and produces a symmetric key of desired length.

Algorithm (DSTU-specific KDF):
1. Concatenate: `seed = sharedSecret || ukm`
2. Counter-mode hashing:
   ```
   K = Hash(0x00000001 || seed) || Hash(0x00000002 || seed) || ...
   ```
3. Truncate to `keyLen` bytes

**Alternative**: Some implementations use a simpler approach — just hash the shared secret:
```
K = Hash(sharedSecret || ukm)
```

Verify the exact KDF used by checking jkurwa's `ctx.js` `derive()` function and how it feeds into `gost89.wrap_key()`.

### 3. Full key agreement workflow
The typical flow for encrypting a message to a recipient:
1. Sender generates ephemeral key pair `(e, eG)`
2. Sender computes shared secret: `S = e · Q_recipient`
3. Sender derives symmetric key: `K = KDF(S, ukm)`
4. Sender wraps content encryption key (CEK) with K using GOST key wrap
5. Sender encrypts message with CEK using GOST CFB
6. Sender sends: ephemeral public key `eG`, wrapped CEK, IV, ciphertext

```go
// High-level convenience function
func KeyAgreement(
    senderPriv *dstu4145.PrivateKey,
    recipientPub *dstu4145.PublicKey,
    ukm []byte,
    keyLen int,
) (sharedKey []byte, error)
```

### 4. Write tests
- **Roundtrip**: Alice and Bob compute same shared secret
  1. Alice: `S_a = a · B` (Alice's private × Bob's public)
  2. Bob: `S_b = b · A` (Bob's private × Alice's public)
  3. Verify: `S_a == S_b`
- **KDF determinism**: same inputs produce same key
- **Different keys produce different secrets**
- **Invalid point rejection**: public key not on curve → error

## Acceptance Criteria
- [ ] ECDH produces matching shared secrets for both parties
- [ ] KDF produces deterministic keys from shared secret + UKM
- [ ] Invalid public keys are rejected
- [ ] Works on at least DSTU_PB_257 and DSTU_PB_431 curves

## Notes
- The UKM (user keying material) is typically a random 64-bit value included in CMS EnvelopedData
- The exact KDF may vary between implementations — verify against jkurwa/agent behavior
- This phase is relatively small but critical for the encryption workflow in Phase 12
- The shared secret is a field element — its byte representation must match the convention (LE vs BE)

# Phase 5 — Digital Signature `dstu4145`

## Goal
Implement the DSTU 4145-2002 elliptic curve digital signature algorithm: key generation, signing, verification, and ASN.1 marshaling.

## Prerequisites
- **Phase 1** (`gf2m`) — field arithmetic
- **Phase 2** (`ec`) — elliptic curve operations and named curves
- **Phase 3** (`kupyna` or `gost34311`) — at least one hash function for message digests

## Package
`crypto-dstu/dstu4145`

## JS Reference
- `jkurwa/lib/models/Priv.js` — `sign()`, `pub()` (derive public key)
- `jkurwa/lib/models/Pub.js` — `verify()`
- `jkurwa/lib/curve.js` — `truncate()`, `rand()`, `keygen()`
- `jkurwa/lib/spec/dstszi.js` — ASN.1 schema for signatures

## Files to Create

| File | Purpose |
|------|---------|
| `dstu4145/dstu4145.go` | `Sign()`, `Verify()`, `GenerateKey()` |
| `dstu4145/params.go` | Domain parameters struct, OID ↔ curve mapping |
| `dstu4145/marshal.go` | ASN.1 DER encoding/decoding of signature (r, s) |
| `dstu4145/dstu4145_test.go` | Test vectors, roundtrip sign/verify |

## Step-by-Step Instructions

### 1. Define types
```go
type PrivateKey struct {
    D     *big.Int    // private scalar d ∈ [1, n-1]
    Curve *ec.Curve   // domain parameters
}

type PublicKey struct {
    Q     *ec.Point   // public point Q = d·G
    Curve *ec.Curve
}

type Signature struct {
    R gf2m.Element    // r value (field element)
    S *big.Int        // s value (integer mod n)
}
```

### 2. Key generation
```go
func GenerateKey(curve *ec.Curve) (*PrivateKey, error)
```
1. Generate random `d ∈ [1, n-1]` using `crypto/rand`
2. Compute `Q = d · G` (scalar multiplication of base point)
3. Verify `Q` is on the curve
4. Return `PrivateKey{D: d, Curve: curve}`

Public key derivation:
```go
func (priv *PrivateKey) Public() *PublicKey
```

### 3. Signature generation
Port from jkurwa `Priv.sign()`:

```go
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (*Signature, error)
```

Algorithm:
1. **Truncate hash** to curve order bit length:
   - `h = truncate(hash, bitLen(n))`
   - If `h == 0`, set `h = 1`
2. **Generate random** `e ∈ [1, n-1]`
3. **Compute** `R = e · G` (scalar multiply base point)
4. **Compute r**:
   - `Fe = x_R` (x-coordinate of R, as field element)
   - `r = (Fe * h) mod f(x)` — field multiplication, then reduce
   - `r_int = fieldElementToInteger(r)` — interpret reduced field element as integer
   - `r_int = r_int mod n`
   - If `r_int == 0`, go to step 2
5. **Compute s**:
   - `s = (e + d * r_int) mod n`
   - If `s == 0`, go to step 2
6. **Return** `Signature{R: r, S: s}`

**Key detail from jkurwa**: The `r` value in the signature is a **field element** (not just an integer). The field multiplication `Fe * h` happens in GF(2^m), not modular integer arithmetic.

### 4. Signature verification
Port from jkurwa `Pub.verify()`:

```go
func Verify(pub *PublicKey, hash []byte, sig *Signature) bool
```

Algorithm:
1. **Truncate hash**: `h = truncate(hash, bitLen(n))`
2. **Compute** `R' = s·G - r_int·Q`
   - `sG = s · G`
   - `rQ = r_int · Q`
   - `R' = sG + (-rQ)` (point subtraction = add negation)
3. **Compute r'**:
   - `Fe' = x_{R'}` (x-coordinate as field element)
   - `r' = (Fe' * h) mod f(x)` — field multiplication
4. **Verify**: `r' == sig.R` (compare field elements)

### 5. ASN.1 marshaling (`marshal.go`)
DSTU 4145 signatures are encoded as ASN.1:
```asn1
SEQUENCE {
    r  OCTET STRING,   -- field element bytes (little-endian per DSTU convention)
    s  INTEGER         -- integer value
}
```

```go
func MarshalSignature(sig *Signature) ([]byte, error)   // → DER bytes
func UnmarshalSignature(der []byte) (*Signature, error)  // ← DER bytes
```

**Important**: DSTU uses **little-endian** byte order for field elements in ASN.1 encoding (unlike typical big-endian). Verify this against jkurwa's `lib/spec/dstszi.js`.

### 6. OID mapping (`params.go`)
Ukrainian PKI OID tree for DSTU 4145:
```
1.2.804.2.1.1.1.1.3.1.1 — DSTU 4145 with GOST 34.311 hash
1.2.804.2.1.1.1.1.3.1.2 — DSTU 4145 with Kupyna-256
1.2.804.2.1.1.1.1.3.1.3 — DSTU 4145 with Kupyna-512
```

Curve parameter OIDs:
```
1.2.804.2.1.1.1.1.3.1.1.2.0 — DSTU_PB_163
1.2.804.2.1.1.1.1.3.1.1.2.1 — DSTU_PB_167
...
1.2.804.2.1.1.1.1.3.1.1.2.9 — DSTU_PB_431
```

```go
type DomainParams struct {
    Curve    *ec.Curve
    Hash     crypto.Hash    // which hash to use
    OID      asn1.ObjectIdentifier
    CurveOID asn1.ObjectIdentifier
}

func ParamsByOID(oid asn1.ObjectIdentifier) *DomainParams
func ParamsByCurve(name string) *DomainParams
```

### 7. Implement `crypto.Signer` interface
```go
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
func (priv *PrivateKey) Public() crypto.PublicKey
```
This makes `PrivateKey` usable with Go's standard crypto interfaces.

### 8. Write tests
- **Roundtrip**: `Sign → Verify` with random keys on each named curve
- **Known test vectors**: from DSTU 4145-2002 standard appendix
- **Invalid signature**: modify r or s, verify returns false
- **Wrong key**: sign with key A, verify with key B → false
- **Edge cases**: hash = 0, s = 0 retry, r = 0 retry
- **ASN.1 roundtrip**: `Unmarshal(Marshal(sig)) == sig`
- **Cross-validate**: generate signature, verify with known-good implementation if possible

## Acceptance Criteria
- [ ] `GenerateKey` produces valid key pairs for all 10 curves
- [ ] `Sign` + `Verify` roundtrip succeeds for all curves
- [ ] Modified signatures are correctly rejected
- [ ] ASN.1 marshaling/unmarshaling is correct
- [ ] `crypto.Signer` interface is implemented
- [ ] OID mapping covers all curves and hash combinations

## Notes
- The DSTU 4145 signature differs from ECDSA — `r` is a field element, not just an integer
- jkurwa uses `curve.truncate()` to clip hash bits to curve order length — critical for correctness
- Little-endian byte order for field elements in ASN.1 is a DSTU-specific convention
- The `r` computation involves field multiplication (GF(2^m)), not integer multiplication
- Performance: signing requires 1 scalar multiplication + 1 field mul; verification requires 2 scalar muls

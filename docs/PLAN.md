# crypto-dstu — Implementation Plan

Go library implementing Ukrainian national cryptographic standards (DSTU) for digital signature, encryption, and tax office document exchange.

## Reference Implementations

| Project | Language | Coverage | URL |
|---------|----------|----------|-----|
| **jkurwa** | JS | DSTU 4145 EC crypto, transport container, CMS/PKCS#7, X.509, key stores | https://github.com/dstucrypt/jkurwa |
| **gost89** | JS | GOST 28147 cipher (ECB/CFB), GOST 34.311 hash, key wrap, PBKDF | https://github.com/dstucrypt/gost89 |
| **agent** | JS | CLI for sign/encrypt/decrypt, TSP, OCSP, CAdES, tax office workflow | https://github.com/dstucrypt/agent |
| **cryptonite** | C | Full suite: DSTU 4145, Kupyna, Kalyna, GOST 28147, AES | https://github.com/privat-it/cryptonite |
| **Kalyna-reference** | C | Official reference Kalyna (DSTU 7624) with test vectors | https://github.com/Roman-Oliynykov/Kalyna-reference |
| **dstu4145 (C++)** | C++ | DSTU 4145-2002 in modern C++17 | https://github.com/shamray/dstu4145 |
| **jksreader** | JS | Java KeyStore parser (PrivatBank keys) | https://github.com/dstucrypt/jksreader |

## Standards & Specifications

| Standard | Subject | Notes |
|----------|---------|-------|
| DSTU 4145-2002 | Digital signature (EC over GF(2^m)) | Curves m ∈ {163,167,173,179,191,233,257,307,367,431} |
| DSTU 7564:2014 | Kupyna hash function | 256/384/512-bit digests, KMAC |
| DSTU 7624:2014 | Kalyna block cipher | 128/256/512-bit blocks, key = block or 2×block |
| GOST 28147-89 | Block cipher (DSTU S-box variant) | ECB/CFB/OFB modes, key wrap |
| GOST 34.311-95 | Hash function | 256-bit digest, used with GOST cipher |
| DSTU ISO/IEC 15946-3 | Key agreement | Diffie-Hellman over EC |
| Order #499 (12.07.2010) | Transport container format | Binary format for tax office exchange |
| ETSI CAdES/XAdES/PAdES | Signature formats | Used with Ukrainian algorithms |
| RFC 3161 | Timestamp Protocol (TSP) | Required for long-term signatures |

## Regulatory References

- Tax office API: https://cabinet.tax.gov.ua/help/api.html
- Transport container format: https://zakon.rada.gov.ua/rada/show/v0499225-10
- Test examples: https://czo.gov.ua/testexamples
- Technical specs: https://czo.gov.ua/formattechspecs
- Signature verification: https://czo.gov.ua/verify
- Certificate format: http://zakon4.rada.gov.ua/laws/show/z1398-12
- Key container format (PBES2-like): http://zakon3.rada.gov.ua/laws/show/z2227-13

---

## Project Structure

```
crypto-dstu/
├── go.mod
├── README.md
├── PLAN.md                      ← this file
│
├── docs/phases/                 # Per-phase implementation instructions
│   ├── phase-01-gf2m.md         #   → start prompt for each phase
│   ├── phase-02-ec.md
│   ├── phase-03-hash.md
│   ├── phase-04-cipher.md
│   ├── phase-05-dstu4145.md
│   ├── phase-06-keyagree.md
│   ├── phase-07-keystore.md
│   ├── phase-08-cert.md
│   ├── phase-09-transport.md
│   ├── phase-10-cms.md
│   ├── phase-11-tsp.md
│   ├── phase-12-ua.md
│   └── phase-13-czo.md
│
│  ══════════════════════════════════════════
│  LAYER 0 — Field Arithmetic
│  ══════════════════════════════════════════
│
├── gf2m/                        # Binary field GF(2^m) arithmetic
│   ├── element.go               #   Element type (Uint32 word array)
│   ├── ops.go                   #   add, mul (mul_1x1, mul_2x2, fmul), sqr
│   ├── mod.go                   #   Reduction modulo irreducible polynomial
│   ├── inv.go                   #   Modular inversion (extended Euclidean)
│   ├── poly.go                  #   Irreducible polynomial representation
│   └── gf2m_test.go             #   Tests: identity, associativity, inverses
│
│  ══════════════════════════════════════════
│  LAYER 1 — Cryptographic Primitives
│  ══════════════════════════════════════════
│
├── ec/                          # Elliptic curves over GF(2^m)
│   ├── curve.go                 #   Curve y²+xy = x³+ax²+b
│   ├── point.go                 #   Point add, double, scalar mul (wNAF)
│   ├── compress.go              #   Point compression / expansion
│   ├── params.go                #   Standard named curves (DSTU_PB_163..431)
│   └── ec_test.go
│
├── kupyna/                      # DSTU 7564:2014 — Kupyna hash
│   ├── kupyna.go                #   hash.Hash interface (New256, New384, New512)
│   ├── compress.go              #   T⊕ and T+ permutations
│   ├── sbox.go                  #   Four S-box tables
│   ├── consts.go                #   Round constants, MDS matrix
│   └── kupyna_test.go           #   Test vectors from standard
│
├── kalyna/                      # DSTU 7624:2014 — Kalyna block cipher
│   ├── kalyna.go                #   cipher.Block interface
│   ├── keysched.go              #   Key schedule algorithm
│   ├── sbox.go                  #   Four S-box tables
│   ├── consts.go                #   MDS matrix, round constants
│   └── kalyna_test.go           #   Test vectors from reference impl
│
├── gost28147/                   # GOST 28147-89 block cipher (DSTU variant)
│   ├── cipher.go                #   cipher.Block interface (ECB)
│   ├── cfb.go                   #   CFB stream mode
│   ├── sbox.go                  #   Ukrainian DSTU S-box tables
│   ├── wrap.go                  #   Key wrapping (DSTSZI spec)
│   └── gost28147_test.go
│
├── gost34311/                   # GOST 34.311-95 hash function
│   ├── hash.go                  #   hash.Hash interface
│   └── hash_test.go
│
│  ══════════════════════════════════════════
│  LAYER 2 — Signature & Key Agreement
│  ══════════════════════════════════════════
│
├── dstu4145/                    # DSTU 4145-2002 — Digital signature
│   ├── dstu4145.go              #   Sign, Verify, GenerateKey
│   ├── params.go                #   Domain parameters, OID mapping
│   ├── marshal.go               #   ASN.1 encoding of (r, s) signatures
│   └── dstu4145_test.go         #   Test vectors from standard
│
├── dstu15946/                   # DSTU ISO/IEC 15946-3 — Key agreement
│   ├── kdf.go                   #   Key derivation function
│   ├── dh.go                    #   EC Diffie-Hellman shared secret
│   └── kdf_test.go
│
│  ══════════════════════════════════════════
│  LAYER 3 — Key Storage & Certificates
│  ══════════════════════════════════════════
│
├── keystore/                    # Private key containers
│   ├── key6.go                  #   Key-6.dat format (PBES2-like, password)
│   ├── jks.go                   #   JKS format (PrivatBank, multiple keys)
│   ├── pkcs12.go                #   PKCS#12/PFX container
│   ├── pem.go                   #   PEM/DER detection, stripping, import/export
│   ├── raw.go                   #   Raw ASN.1 private key parsing (unencrypted)
│   ├── guess.go                 #   Auto-detection: try each parser in order
│   └── keystore_test.go
│
├── cert/                        # X.509 certificate handling
│   ├── parse.go                 #   Parse X.509v3 with Ukrainian OIDs
│   ├── info.go                  #   Extract EDRPOU, DRFO, name, dates
│   ├── verify.go                #   Certificate chain validation
│   ├── role.go                  #   Role detection (personal/fop/director/stamp)
│   └── cert_test.go
│
├── oid/                         # Ukrainian PKI OID definitions
│   └── oid.go                   #   OID tree 1.2.804.2.1.1.1.*
│
│  ══════════════════════════════════════════
│  LAYER 4 — Transport & Message Formats
│  ══════════════════════════════════════════
│
├── transport/                   # Transport container (Order #499)
│   ├── header.go                #   TRANSPORTABLE header build/parse
│   ├── section.go               #   Section encode/decode (label\0 + len + data)
│   ├── container.go             #   Full container compose/parse
│   ├── crc32.go                 #   CRC32 checksum for CRC32_SIGN/CRC32_FILE
│   └── transport_test.go
│
├── cms/                         # CMS/PKCS#7 signed & enveloped data
│   ├── signed.go                #   SignedData creation & parsing
│   ├── enveloped.go             #   EnvelopedData creation & parsing
│   ├── attrs.go                 #   Signed/unsigned attributes
│   └── cms_test.go
│
├── tsp/                         # RFC 3161 Timestamp Protocol
│   ├── request.go               #   TSP request building
│   ├── response.go              #   TSP response parsing & verification
│   └── tsp_test.go
│
│  ══════════════════════════════════════════
│  LAYER 5 — High-Level API
│  ══════════════════════════════════════════
│
├── ua/                          # High-level operations
│   ├── signer.go                #   SignDocument / UnsignDocument
│   ├── crypto.go                #   EncryptDocument / DecryptDocument
│   ├── verify.go                #   VerifyCert / VerifyCertPKMatch
│   ├── certinfo.go              #   GetCertInfo → CertInfo struct
│   ├── box.go                   #   Box — stateful context (keys, certs, CA list)
│   └── ua_test.go
│
└── testdata/                    # Test vectors & fixtures
    ├── kupyna/                  #   Hash test vectors from DSTU 7564
    ├── kalyna/                  #   Cipher test vectors from DSTU 7624
    ├── gost/                    #   GOST cipher & hash test vectors
    ├── dstu4145/                #   Signature test vectors from DSTU 4145
    ├── czo/                     #   CZO test examples (CAdES/XAdES/PAdES)
    └── keys/                    #   Test key pairs and certificates
```

---

## Implementation Phases

### Phase 1 — Foundational Field Arithmetic `[gf2m]` ✅ COMPLETE
> **Reference:** cryptonite gf2m arithmetic

- [x] `Element` type — `[]uint32` word array representation — `gf2m/element.go`
- [x] `Add` — XOR of word arrays (GF(2^m) addition = subtraction)
- [x] `Mul` — Carry-less multiplication + reduction
- [x] `Mod` — Polynomial reduction using sparse irreducible poly `[m, k1, k2?, k3?, 0]`
- [x] `Inv` — Extended binary GCD inversion
- [x] `Sqr` — Optimized squaring
- [x] Tests: field axioms (a+a=0, a·1=a, a·a⁻¹=1), random element tests

### Phase 2 — Elliptic Curves `[ec]` ✅ COMPLETE
> **Reference:** cryptonite ec arithmetic

- [x] Curve definition: `y² + xy = x³ + ax² + b` over GF(2^m) — `ec/curve.go`
- [x] Point representation (affine) — `ec/point.go`
- [x] Point addition and doubling
- [x] Scalar multiplication — wNAF — `ec/scalar.go`
- [x] Point compression (x-coordinate) and expansion (`fsquad`) — `ec/compress.go`
- [x] `Contains` — verify point lies on curve
- [x] Named curves: all 10 standard parameter sets (DSTU_PB_163 through DSTU_PB_431) — `ec/params.go`
- [x] Tests: base point on curve, n·G = O, roundtrip compress/expand

### Phase 3 — Hash Functions `[kupyna, gost34311]` ✅ COMPLETE
> **Reference:** cryptonite kupyna.c, gost34311.c

#### Kupyna (DSTU 7564:2014)
- [x] S-box tables, MDS matrix, round constants — `kupyna/tables.go`
- [x] T⊕ and T+ permutations (SubBytes, ShiftBytes, MixColumns, AddConstant)
- [x] Davies–Meyer compression function
- [x] Padding and finalization
- [x] `hash.Hash` interface: `New256()`, `New384()`, `New512()` — `kupyna/kupyna.go`
- [x] Test vectors: Kupyna-256/512 empty string + known vectors pass

#### GOST 34.311-95
- [x] Hash implementation using GOST 28147 cipher — `gost34311/hash.go`
- [x] `hash.Hash` interface
- [x] Test vectors from cryptonite reference pass

### Phase 4 — Block Ciphers `[kalyna, gost28147]` ✅ COMPLETE
> **Reference:** cryptonite kalyna.c, gost28147.c

#### Kalyna (DSTU 7624:2014)
- [x] S-box tables, key schedule, round function — `kalyna/kalyna.go`
- [x] `cipher.Block` interface for all 5 variants:
  - Kalyna-128/128, Kalyna-128/256, Kalyna-256/256, Kalyna-256/512, Kalyna-512/512
- [x] Test vectors from Roman Oliynykov reference C implementation pass

#### GOST 28147-89 (DSTU variant)
- [x] Ukrainian S-box tables — `gost28147/sbox.go`
- [x] `cipher.Block` interface (ECB, 64-bit block, 256-bit key) — `gost28147/gost28147.go`
- [x] CFB stream mode
- [x] MAC computation
- [x] Key wrapping (DSTSZI / keywrap)
- [x] Test vectors from cryptonite reference pass

### Phase 5 — Digital Signature `[dstu4145]` ✅ COMPLETE
> **Reference:** cryptonite dstu4145.c, DSTU 4145-2002 standard

- [x] Key generation: random `d ∈ [1, n-1]`, Q = d·G — `dstu4145/dstu4145.go`
- [x] Signature generation (r, s) using DSTU 4145 algorithm
- [x] Signature verification via R' = s·G - r·Q
- [x] ASN.1 marshaling (DER SEQUENCE { r INTEGER, s INTEGER }) — `dstu4145/asn1.go`
- [x] OID mapping for all 10 curves + sig-alg OIDs — `dstu4145/params.go`
- [x] `crypto.Signer` interface implementation
- [x] Tests: sign-verify roundtrip, all 10 curves, known test vectors pass

### Phase 6 — Key Agreement `[dstu15946]` ✅ COMPLETE
> **Reference:** cryptonite dstu4145_dh, DSTU ISO/IEC 15946-3

- [x] ECDH shared secret computation — `dstu15946/kdf.go`
- [x] KDF (key derivation function using GOST/Kupyna hash) — `dstu15946/kdf.go`
- [x] CMS-layer DeriveKey / KeyAgreement — `dstu15946/kdf.go`
- [x] Tests: SharedSecret vectors, DeriveKey, KeyAgreement roundtrip

### Phase 7 — Key Storage `[keystore]` ✅ COMPLETE
> **Reference:** cryptonite pkcs5.c, pkcs8.c, pkcs12.c

- [x] **Key-6.dat** parser/writer — PBES2+PBKDF2-GOST+GOST28147-CFB — `keystore/key6.go`
- [x] **JKS** format parser — Java KeyStore (PrivatBank) binary format — `keystore/jks.go`
- [x] **PKCS#12/PFX** parser — GOST-encrypted key+cert container — `keystore/pkcs12.go`
- [x] **Raw DER** parser/writer — unencrypted PKCS#8 ASN.1 — `keystore/raw.go`
- [x] **PEM** handling — detect, strip, encode PEM wrappers — `keystore/pem.go`
- [x] **Auto-detection** (`Parse`) — PEM → Key-6.dat → JKS → PFX → raw — `keystore/guess.go`
- [x] Tests: roundtrip encode/decode, wrong password, format auto-detection, scalar range check

### Phase 8 — Certificates `[cert, oid]` ✅ COMPLETE
> **Reference:** cryptonite pkix_utils.c, pkix_cert.c, cert format law z1398-12

- [x] Ukrainian PKI OID tree (1.2.804.2.1.1.1.*) — `oid/oid.go`
- [x] X.509v3 certificate parsing with UA-specific extensions — `cert/parse.go`
- [x] `CertInfo` struct: Serial, EDRPOU, DRFO, Name, Email, Title, dates — `cert/info.go`
- [x] Certificate chain verification — `cert/verify.go`
- [x] Role detection: personal / fop / director / stamp / other — `cert/role.go`
- [x] Certificate ↔ private key matching — `cert/verify.go`
- [x] Tests: OID lookup, role detection, parse/verify, chain, PKMatch — `cert/cert_test.go`

### Phase 9 — Transport Container `[transport]` ✅ COMPLETE
> **Reference:** Order #499 (12.07.2010), Ukrainian tax office binary container format

- [x] Section format: `label\0` + `uint32LE(length)` + `data` — `transport/section.go`
- [x] TRANSPORTABLE/ZPOSTTRANSPORTABLE header: `key=value\r\n` + null — `transport/header.go`
- [x] All 14 header fields: FILENAME, SND_NAME, SND_EMAIL, RCV_NAME, RCV_EMAIL, PRG_TYPE, PRG_VER, SND_DATE, CERTYPE, CRC32_SIGN, CRC32_FILE, SUBJECT, GET_STAMP, RESULT
- [x] Section types: UA_SIGN1, UA1_SIGN/CRYPT/STAMP, QLB_SIGN/CRYPT, USC_SIGN/CRYPT (label-only), PACKED_XML — `transport/container.go`
- [x] CRC32-IEEE checksum, CRC32Hex for header fields — `transport/crc32.go`
- [x] `Encode` / `Decode` with convenience methods: `FindSection`, `SignSections`, `CryptSection`, `StampSection`
- [x] Tests: 26 tests covering CRC32, section roundtrip, header roundtrip, container roundtrip, all section types, error cases

### Phase 10 — CMS/PKCS#7 `[cms]` ✅ Complete
> **Reference:** cryptonite CMS profile, RFC 5652

- [x] SignedData (CAdES-BES): content + signer info + certificates
- [x] EnvelopedData: recipient info + encrypted content (ECDH+GOST28147)
- [x] Signed attributes (content type, message digest, signing time)
- [x] Detached signatures (no encapsulated content)
- [x] Manual ASN.1 encode/decode for SignerInfo, SignedData, KeyAgreeRecipientInfo (fixes Go asn1 RawValue+big.Int bug)
- [x] Tests: 26 tests covering sign/verify roundtrip, detached, tampered content, custom content type, encrypt/decrypt roundtrip, wrong key, invalid DER, error cases

### Phase 11 — Timestamp Protocol `[tsp]` ✅ Complete
> **Reference:** RFC 3161, RFC 5816

- [x] TSP request building (hash algorithm OID + message imprint, random nonce, CertReq)
- [x] TSP response parsing (PKIStatusInfo, TimeStampToken extraction)
- [x] TSTInfo parsing from CMS SignedData eContent
- [x] Timestamp token verification (CMS sig + hash imprint + nonce)
- [x] HTTP client (POST application/timestamp-query, mock-testable)
- [x] Tests: 18 tests covering request build/marshal, response parse, TSTInfo extraction, verify valid/wrong-hash/nonce-mismatch/invalid-DER, HTTP client mock/error/bad-URL

### Phase 12 — High-Level API `[ua]` ✅ Complete
> **Reference:** agent CLI workflows, RFC 5652

- [x] `Box` — stateful context: keys, CA certs, TSP clients; `LoadKey`, `AddCert`, `AddTSP`, `KeyByRole`
- [x] `SignDocument` — raw CMS (NoTax) or transport container; detached support
- [x] `UnsignDocument` — transport container or raw CMS; cert injection fallback via `cms.ResolveCertificates`
- [x] `EncryptDocument` / `DecryptDocument` — ECDH+GOST28147 roundtrip
- [x] `SignAndEncrypt` — sign then encrypt, returns transport container or raw CMS
- [x] `GetCertInfo` / `certInfoFromCert` — wraps `cert.ExtractCertInfo`
- [x] `VerifyCert`, `VerifyCertPKMatch`, `VerifyCertPKMatchDirect`
- [x] `cms.ResolveCertificates` added to cms package for post-hoc SID matching
- [x] Tests: 21 tests covering Box lifecycle, sign/unsign roundtrip, encrypt/decrypt, SignAndEncrypt, certinfo, verify

### Phase 13 — CZO Test Examples `[testdata/czo]`
> **Reference:** https://czo.gov.ua/testexamples

- [ ] Download test example files for CAdES / XAdES / PAdES
- [ ] Verify signature parsing against all test examples
- [ ] Verify hash computation matches expected values
- [ ] Cross-verify with https://czo.gov.ua/verify

---

## Progress Tracking

| Phase | Package | Status | Notes |
|-------|---------|--------|-------|
| 1 | `gf2m` | ✅ Complete | All field axiom tests pass |
| 2 | `ec` | ✅ Complete | All 10 curves: base point on curve + n·G=O pass |
| 3 | `kupyna`, `gost34311` | ✅ Complete | Kupyna + GOST 34.311 all vectors pass (cryptonite-aligned) |
| 4 | `kalyna`, `gost28147` | ✅ Complete | All 5 Kalyna variants + GOST ECB/CFB/MAC/wrap pass |
| 5 | `dstu4145` | ✅ Complete | Sign/Verify/GenerateKey/ASN.1/crypto.Signer; all 10 curves pass |
| 6 | `dstu15946` | ✅ Complete | SharedSecret (cryptonite dstu4145_dh) + CMS-layer DeriveKey/KeyAgreement |
| 7 | `keystore` | ✅ Complete | PEM/DER, PKCS#8 raw, Key-6.dat (PBES2+PBKDF2-GOST+GOST28147-CFB), JKS, PKCS#12, auto-detect |
| 8 | `cert`, `oid` | ✅ Complete | OID registry; X.509v3 parse; CertInfo; chain verify; role detection; PKMatch |
| 9 | `transport` | ✅ Complete | Section encode/decode; TRANSPORTABLE header; CRC32; Container Encode/Decode; 26 tests |
| 10 | `cms` | ✅ Complete | Depends on Phase 5, 8 |
| 11 | `tsp` | ✅ Complete | Depends on Phase 3, 10 |
| 12 | `ua` | ✅ Complete | Depends on all above |
| 13 | `testdata/czo` | 🔲 Not started | Depends on Phase 10-12 |

### Dependency Graph

```
Phase 1 (gf2m) ──→ Phase 2 (ec) ──→ Phase 5 (dstu4145) ──→ Phase 8 (cert)
                                  ↗                       ↘
Phase 3 (kupyna/gost hash) ──────                          Phase 10 (cms) → Phase 11 (tsp)
                                                          ↗                          ↘
Phase 4 (kalyna/gost cipher) → Phase 7 (keystore)       Phase 9 (transport)     Phase 12 (ua)
                             → Phase 6 (key agreement) ──────────────────────────────↗
```

## Key Design Decisions

1. **Go standard interfaces** — Implement `hash.Hash`, `cipher.Block`, `crypto.Signer` where applicable
2. **No CGo** — Pure Go implementation for portability
3. **Constant-time where feasible** — Note: jkurwa explicitly warns about non-constant-time; we should aim better but document limitations
4. **Little-endian word arrays** — Match jkurwa's `Uint32Array` representation for easier cross-referencing
5. **ASN.1 via `encoding/asn1`** — Use Go's standard library for ASN.1 encoding
6. **Test-driven** — Every primitive must have test vectors before integration

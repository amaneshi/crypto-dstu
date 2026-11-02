# Phase 7 — Key Storage `keystore`

## Goal
Implement parsers and writers for all private key container formats used in Ukrainian PKI:
1. **Key-6.dat** — PBES2-like encrypted container (password-protected), used by most Ukrainian CAs
2. **JKS** — Java KeyStore format, used by PrivatBank (multiple keys per file, role-based selection)
3. **PKCS#12/PFX** — Standard encrypted key+cert container
4. **Raw DER/PEM** — Unencrypted private keys (import/export)
5. **Auto-detection** — `guess_parse()` pattern: try each parser in sequence

## Prerequisites
- **Phase 4** (`gost28147`) — GOST cipher for Key-6.dat decryption and key wrapping
- **Phase 3** (`gost34311`) — GOST hash for PBKDF in Key-6.dat
- **Phase 5** (`dstu4145`) — private key types

## Package
`github.com/amaneshi/crypto-dstu/keystore`

## Reference
- `privat-it/cryptonite/tree/master/src/storage` — cryptonite storage utilities (key unwrapping)
- `pavlo-v-chernykh/keystore-go` — Go implementation of JKS format

## Files to Create

| File | Purpose |
|------|---------|
| `keystore/key6.go` | Key-6.dat encrypted container: parse, decrypt with password |
| `keystore/jks.go` | JKS (Java KeyStore): parse, extract keys by alias/role |
| `keystore/pkcs12.go` | PKCS#12/PFX container: parse, decrypt |
| `keystore/pem.go` | PEM/DER detection, stripping, import/export |
| `keystore/raw.go` | Raw ASN.1 private key parsing (unencrypted DER) |
| `keystore/guess.go` | `Parse()` auto-detection — try each format in order |
| `keystore/keystore_test.go` | Tests with sample key files |

## Step-by-Step Instructions

### 1. PEM handling (`pem.go`)
```go
func IsPEM(data []byte) bool          // check for "-----BEGIN" marker
func DecodePEM(data []byte) ([]byte, string, error)  // strip PEM → raw DER + type label
func EncodePEM(der []byte, pemType string) []byte     // DER → PEM
func MaybePEM(data []byte) []byte     // if PEM, decode; otherwise return as-is
```

Port from jkurwa `lib/util/pem.js`:
- Detect `-----BEGIN` prefix
- Strip header/footer lines
- Base64 decode the body
- Return raw DER bytes + the type string (e.g., "PRIVATE KEY", "ENCRYPTED PRIVATE KEY")

### 2. Raw DER private key (`raw.go`)
Parse unencrypted ASN.1 private key:
```go
func ParseRawKey(der []byte) (*dstu4145.PrivateKey, error)
```

ASN.1 structure (from jkurwa `Priv.from_asn1()`):
```asn1
SEQUENCE {
    INTEGER (version = 0)
    SEQUENCE {
        OID (algorithm — DSTU 4145 OID)
        SEQUENCE (curve parameters or named curve OID)
    }
    OCTET STRING {
        -- contains the private key value d as big-endian or LE bytes
    }
}
```

Export:
```go
func MarshalRawKey(priv *dstu4145.PrivateKey) ([]byte, error)
```

### 3. Key-6.dat encrypted container (`key6.go`)
This is the most common Ukrainian key format. Structure (ASN.1):
```asn1
SEQUENCE {
    SEQUENCE {
        OID (PBES2)
        SEQUENCE {
            SEQUENCE {  -- KDF parameters
                OID (PBKDF2 or GOST-KDF)
                SEQUENCE {
                    OCTET STRING (salt)
                    INTEGER (iterations)
                }
            }
            SEQUENCE {  -- encryption algorithm
                OID (GOST 28147 CFB)
                OCTET STRING (IV)
            }
        }
    }
    OCTET STRING (encrypted data)
}
```

Decryption flow:
1. Parse ASN.1 structure to extract: salt, iterations, IV, encrypted data, algorithm OIDs
2. Derive key from password: `key = PBKDF(password, salt, iterations)` using GOST 34.311 hash
3. Decrypt with GOST 28147 in CFB mode: `plaintext = GOST_CFB_Decrypt(key, IV, encrypted_data)`
4. Parse decrypted data as raw ASN.1 private key

```go
func ParseKey6(data []byte, password string) (*dstu4145.PrivateKey, error)
```

Port from jkurwa `lib/spec/keystore.js` `enc_parse()` and `lib/spec/pbes.js` `pbes2_parse()`.

PBKDF implementation (from gost89):
```go
func pbkdf(password, salt []byte, iterations int) []byte {
    // N iterations of GOST 34.311 hash
    h := gosthash(password || salt)
    for i := 1; i < iterations; i++ {
        h = gosthash(h)
    }
    return h  // 32-byte key
}
```

### 4. JKS format (`jks.go`)
Java KeyStore format used by PrivatBank. Binary format:
```
Magic: 0xFEEDFEED
Version: 0x00000002
Entry count: N
For each entry:
    Tag (1=key, 2=cert)
    Alias (UTF-16BE string)
    Timestamp (int64 millis)
    Key data (length-prefixed)
    Certificate chain (count + certs)
```

```go
type JKSEntry struct {
    Alias       string
    PrivateKey  *dstu4145.PrivateKey
    CertChain   [][]byte   // DER-encoded certificates
}

func ParseJKS(data []byte, password string) ([]JKSEntry, error)
func (entries []JKSEntry) FindByRole(role string) *JKSEntry
```

Key decryption in JKS:
- Key is encrypted with a password-derived key
- JKS uses a specific password-based key derivation (SHA1-based for standard JKS)
- PrivatBank JKS may use GOST-based derivation — verify against `dstucrypt/jksreader`

Port from `dstucrypt/jksreader`:
- `parse.js` — binary format parsing
- `decode.js` — key decryption

**Role selection** (from agent `--role` option):
```go
type Role string
const (
    RolePersonal  Role = "personal"   // natural person, no corporate entity
    RoleFOP       Role = "fop"        // private entrepreneur (DRFO == EDRPOU)
    RoleDirector  Role = "director"   // can sign for corporate entity
    RoleStamp     Role = "stamp"      // corporate entity seal
    RoleOther     Role = "other"      // DRFO present but != EDRPOU
)
```

JKS files from PrivatBank contain multiple keys (typically stamp + personal). The `--role` option selects which key to use. Role detection requires parsing the associated certificate to check EDRPOU/DRFO fields.

### 5. PKCS#12/PFX (`pkcs12.go`)
Standard PKCS#12 container. Go has `golang.org/x/crypto/pkcs12` but it doesn't support GOST/DSTU algorithms. Need custom parsing.

```go
func ParsePKCS12(data []byte, password string) ([]*KeyCertPair, error)

type KeyCertPair struct {
    PrivateKey *dstu4145.PrivateKey
    Cert       []byte   // DER
}
```

Port from jkurwa `lib/spec/pfx.js` — handles PFX bags with GOST encryption.

### 6. Auto-detection (`guess.go`)
Try each parser in sequence, return first success:

```go
func Parse(data []byte, password string) (*ParseResult, error)

type ParseResult struct {
    Keys  []*dstu4145.PrivateKey
    Certs [][]byte  // DER-encoded certificates
    Format string   // "key6", "jks", "pkcs12", "raw", "pem"
}
```

Parser order (from jkurwa `keycoder.js`):
1. `MaybePEM()` — strip PEM if detected
2. Try `enc_parse` (Key-6.dat encrypted store)
3. Try `pbes2_parse` (PBES2 encrypted key)
4. Try `pfx_parse` (PKCS#12/PFX)
5. Try `privkey_parse` (raw ASN.1 private key)
6. Try `cert_parse` (X.509 certificate — not a key, but detected)
7. If all fail, return error "Unknown format"

### 7. Write tests
- **Key-6.dat**: load test key file, decrypt with known password, verify key value
- **JKS**: load PrivatBank-style JKS, extract keys by role
- **Raw DER**: parse unencrypted key, marshal back, compare
- **PEM**: roundtrip PEM encode/decode
- **Auto-detect**: feed each format to `Parse()`, verify correct detection
- **Wrong password**: Key-6.dat with wrong password → error
- **Corrupted data**: truncated/modified files → error

Test key files should be placed in `testdata/keys/`:
- `testdata/keys/test.key6` — sample Key-6.dat
- `testdata/keys/test.jks` — sample JKS
- `testdata/keys/test.raw.der` — raw private key
- `testdata/keys/test.raw.pem` — PEM-wrapped private key

## Acceptance Criteria
- [ ] Key-6.dat parsing and decryption works with correct password
- [ ] JKS parsing extracts all entries with aliases
- [ ] Role-based key selection works for JKS entries
- [ ] Raw DER/PEM import/export roundtrip
- [ ] PKCS#12 basic parsing works
- [ ] Auto-detection correctly identifies format
- [ ] Wrong password produces clear error (not garbage key)

## Notes
- Key-6.dat is the most important format — it's used by the majority of Ukrainian CAs
- JKS is PrivatBank-specific but very common in practice
- The PBKDF in Key-6.dat uses GOST hash — may be "dumb KDF" (N iterations of hash) rather than standard PBKDF2
- JKS password handling may differ from standard Java JKS — verify against jksreader
- PKCS#12 with GOST algorithms requires custom ASN.1 parsing — Go's standard pkcs12 won't work
- Role detection requires certificate parsing (Phase 8) — implement a basic version here, full version in Phase 8

# Phase 8 — Certificates & OIDs `cert`, `oid`

## Goal
Implement X.509v3 certificate parsing with Ukrainian PKI extensions, certificate chain validation, role detection, and a comprehensive OID registry for all DSTU/GOST algorithms.

## Prerequisites
- **Phase 5** (`dstu4145`) — signature algorithm for certificate verification
- **Phase 3** (`kupyna`/`gost34311`) — hash algorithms referenced in certificates

## Packages
- `github.com/amaneshi/crypto-dstu/cert`
- `github.com/amaneshi/crypto-dstu/oid`

## JS Reference
- `jkurwa/lib/models/Certificate.js` — certificate parsing, `from_asn1()`, extensions
- `jkurwa/lib/spec/dstszi.js` — ASN.1 schemas for Ukrainian certificates
- `jkurwa/lib/util/role.js` — role detection logic (personal/fop/director/stamp)
- Certificate format law: http://zakon4.rada.gov.ua/laws/show/z1398-12

## Files to Create

### `oid` package
| File | Purpose |
|------|---------|
| `oid/oid.go` | All Ukrainian PKI OID constants and lookup functions |

### `cert` package
| File | Purpose |
|------|---------|
| `cert/parse.go` | Parse X.509v3 certificates with UA extensions |
| `cert/info.go` | `CertInfo` struct, `GetCertInfo()` extraction |
| `cert/verify.go` | Certificate chain validation, signature check |
| `cert/role.go` | Role detection: personal/fop/director/stamp/other |
| `cert/cert_test.go` | Tests with real test certificates |

## Step-by-Step Instructions

### 1. Ukrainian OID registry (`oid/oid.go`)
Define all OIDs used in Ukrainian PKI. Root: `1.2.804.2.1.1.1`

```go
package oid

import "encoding/asn1"

// Algorithm OIDs
var (
    // DSTU 4145-2002 signature algorithm
    DSTU4145WithGOST34311  = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,3,1,1}
    DSTU4145WithKupyna256  = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,3,1,2}
    DSTU4145WithKupyna512  = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,3,1,3}

    // Named curve OIDs
    DSTU_PB_163 = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,3,1,1,2,0}
    DSTU_PB_167 = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,3,1,1,2,1}
    // ... through DSTU_PB_431 (index 9)

    // GOST 28147-89
    GOST28147       = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,1,1,3}
    GOST28147_CFB   = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,1,1,3,1}
    GOST28147_Wrap  = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,1,1,3,2}

    // GOST 34.311-95 hash
    GOST34311 = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,2,1}

    // Kupyna hash
    Kupyna256 = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,2,2,1}
    Kupyna384 = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,2,2,2}
    Kupyna512 = asn1.ObjectIdentifier{1,2,804,2,1,1,1,1,2,2,3}

    // Subject DN attribute OIDs (Ukrainian specific)
    EDRPOU     = asn1.ObjectIdentifier{1,2,804,2,1,1,1,11,1,4,1,1}   // corporate code
    DRFO       = asn1.ObjectIdentifier{1,2,804,2,1,1,1,11,1,4,1,2}   // personal code (tax ID)
    IPN        = asn1.ObjectIdentifier{1,2,804,2,1,1,1,11,1,4,2,1}   // tax number
)

// Lookup functions
func CurveOIDByName(name string) asn1.ObjectIdentifier
func CurveNameByOID(oid asn1.ObjectIdentifier) string
func AlgorithmName(oid asn1.ObjectIdentifier) string
```

Source exact OID values from jkurwa `lib/spec/dstszi.js` and the certificate format regulation.

### 2. Certificate parsing (`cert/parse.go`)
Use Go's `crypto/x509` as much as possible, but Ukrainian certificates have non-standard extensions. Strategy:

```go
type Certificate struct {
    Raw          []byte              // original DER bytes
    TBSRaw      []byte              // TBS (to-be-signed) portion
    Version      int
    SerialNumber *big.Int
    Issuer       pkix.RDNSequence
    Subject      pkix.RDNSequence
    NotBefore    time.Time
    NotAfter     time.Time
    PublicKey    *dstu4145.PublicKey  // parsed DSTU public key
    SigAlgOID    asn1.ObjectIdentifier
    Signature    []byte
    Extensions   []pkix.Extension

    // Ukrainian-specific parsed fields
    EDRPOU       string   // corporate identification code
    DRFO         string   // personal tax identification number
    IPN          string   // another tax number format
    Email        string
    Title        string   // job title
}

func ParseCertificate(der []byte) (*Certificate, error)
func ParseCertificates(der []byte) ([]*Certificate, error)  // parse PKCS#7 cert bag
```

Parsing steps:
1. Decode outer ASN.1 SEQUENCE (Certificate)
2. Extract TBS, signature algorithm, signature value
3. Parse TBS: version, serial, issuer, validity, subject, public key, extensions
4. Parse subject DN for Ukrainian OIDs (EDRPOU, DRFO)
5. Parse public key: algorithm OID → DSTU 4145, then curve params + point

### 3. Certificate info extraction (`cert/info.go`)
```go
type CertInfo struct {
    Serial       string
    Issuer       string    // formatted issuer name
    Subject      string    // formatted subject name
    EDRPOU       string    // corporate code (8 digits)
    DRFO         string    // personal code (10 digits)
    IPN          string
    Email        string
    CommonName   string
    Organization string
    Title        string    // job title / посада
    NotBefore    time.Time
    NotAfter     time.Time
    KeyUsage     []string
    IsCA         bool
    CurveOID     string
    HashOID      string
}

func GetCertInfo(der []byte) (*CertInfo, error)
```

### 4. Certificate verification (`cert/verify.go`)
```go
func VerifyCert(cert *Certificate, issuerCert *Certificate) error
func VerifyCertChain(cert *Certificate, roots []*Certificate) error
func VerifyCertPKMatch(cert *Certificate, priv *dstu4145.PrivateKey) error
```

Verification steps:
1. Check validity period (NotBefore ≤ now ≤ NotAfter)
2. Check issuer matches subject of issuer cert
3. Verify signature on cert using issuer's public key:
   - Hash the TBS portion with the algorithm specified in signature
   - Verify hash against signature using `dstu4145.Verify()`
4. Check basic constraints (isCA, pathLen)
5. Check key usage extensions

For `VerifyCertPKMatch`:
- Derive public key from private key: `pub = priv.D · G`
- Compare with certificate's public key

### 5. Role detection (`cert/role.go`)
Port from jkurwa `lib/util/role.js` and agent `--role` logic:

```go
func DetectRole(cert *Certificate) Role

type Role string
const (
    RolePersonal Role = "personal"  // no EDRPOU, only DRFO
    RoleFOP      Role = "fop"       // DRFO == EDRPOU (private entrepreneur)
    RoleDirector Role = "director"  // has DRFO + different EDRPOU
    RoleStamp    Role = "stamp"     // no DRFO, only EDRPOU (corporate seal)
    RoleOther    Role = "other"     // DRFO present, doesn't match EDRPOU
)
```

Detection logic:
- **personal**: DRFO present, no EDRPOU (or EDRPOU is empty/absent)
- **fop**: both DRFO and EDRPOU present and they match (or EDRPOU is in natural person range)
- **director**: DRFO present, EDRPOU present, EDRPOU != DRFO, EDRPOU is corporate (not natural person range)
- **stamp**: no DRFO, EDRPOU present → this is a corporate seal certificate
- **other**: fallback for ambiguous cases

Natural person EDRPOU codes: 8, 9, or 10 digits matching DRFO format.

### 6. Write tests
- **Parse real certificates**: use test certificates from CZO or generated ones
- **OID lookup**: verify all OID constants are correct
- **Role detection**: test each role case with crafted certificate info
- **Verification**: sign a TBS with known key, verify with certificate
- **Chain validation**: root → intermediate → leaf chain
- **CertPKMatch**: matching and non-matching key pairs

Place test certificates in `testdata/keys/`:
- `testdata/keys/test.cert.der` — test signing certificate
- `testdata/keys/test.ca.der` — CA certificate
- `testdata/keys/test.stamp.der` — corporate seal certificate

## Acceptance Criteria
- [ ] All Ukrainian OIDs defined and lookup functions work
- [ ] Certificate parsing extracts EDRPOU, DRFO, and all standard fields
- [ ] Certificate signature verification works with DSTU 4145
- [ ] Role detection correctly classifies certificates
- [ ] `VerifyCertPKMatch` correctly matches/rejects key pairs
- [ ] Chain verification works for root → leaf

## Notes
- Go's `crypto/x509` cannot parse DSTU certificates — need custom ASN.1 parsing
- EDRPOU and DRFO are stored in subject DN extensions, not standard attributes
- Certificate encoding may use either explicit curve parameters or named curve OID — handle both
- Public key in certificate may be compressed point — need `ec.Expand()` from Phase 2
- jkurwa uses big-endian or little-endian for key bytes depending on context — verify carefully

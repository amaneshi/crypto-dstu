# Phase 12 — High-Level API `ua`

## Goal
Implement the high-level operations that compose all lower-level primitives into a complete workflow for signing, encrypting, decrypting, and verifying documents in the Ukrainian tax office exchange protocol. Provide a `Box` context object that manages keys, certificates, and CA lists.

## Prerequisites
- **All previous phases** — this layer orchestrates everything:
  - Phase 5 (`dstu4145`) — signing
  - Phase 6 (`dstu15946`) — key agreement for encryption
  - Phase 7 (`keystore`) — loading keys from Key-6.dat, JKS, raw
  - Phase 8 (`cert`) — certificate handling
  - Phase 9 (`transport`) — transport container format
  - Phase 10 (`cms`) — CMS signed/enveloped data
  - Phase 11 (`tsp`) — timestamps

## Package
`crypto-dstu/ua`

## JS Reference
- `dstucrypt/agent/index.js` — full CLI workflow: sign, encrypt, decrypt, unwrap
- `jkurwa/lib/app/ctx.js` — context object managing keys and certificates
- Agent README — all command-line options and their behavior

## Files to Create

| File | Purpose |
|------|---------|
| `ua/box.go` | `Box` struct — stateful context (keys, certs, CA list, TSP config) |
| `ua/signer.go` | `SignDocument()`, `UnsignDocument()` |
| `ua/crypto.go` | `EncryptDocument()`, `DecryptDocument()` |
| `ua/verify.go` | `VerifyCert()`, `VerifyCertPKMatch()` |
| `ua/certinfo.go` | `GetCertInfo()` → `CertInfo` struct |
| `ua/ua_test.go` | Integration tests |

## Step-by-Step Instructions

### 1. Box context (`box.go`)

```go
type Box struct {
    // Loaded keys (may have multiple for different roles)
    Keys       []*KeyEntry

    // CA certificate list for chain verification
    CACerts    []*cert.Certificate

    // TSP configuration
    TSPClients []*tsp.Client

    // Options
    DefaultHash crypto.Hash  // Kupyna256 or GOST34311
}

type KeyEntry struct {
    PrivateKey *dstu4145.PrivateKey
    SignCert   *cert.Certificate   // signing certificate
    CryptCert  *cert.Certificate   // encryption certificate (may differ)
    Role       cert.Role
}

// Constructor
func NewBox() *Box

// Load keys from any supported format
func (b *Box) LoadKey(data []byte, password string) error

// Load key from file path
func (b *Box) LoadKeyFile(path string, password string) error

// Add certificates
func (b *Box) AddCert(der []byte) error
func (b *Box) AddCertFile(path string) error

// Load CA certificate bundle (PKCS#7 bag or directory)
func (b *Box) LoadCABundle(data []byte) error
func (b *Box) LoadCABundleFile(path string) error

// Configure TSP
func (b *Box) AddTSP(url string)

// Find key by role
func (b *Box) KeyByRole(role cert.Role) *KeyEntry
```

### 2. Sign document (`signer.go`)

```go
type SignOptions struct {
    // Signature type
    Detached    bool   // produce detached signature (no content embedded)
    NoTax       bool   // raw CMS output, no transport header or UA_SIGN1 prefix

    // Timestamp
    TSPLevel    string // "none", "signature", "content", "all"

    // CAdES level
    IncludeChain string // "none", "ref", "full" (cert refs or full cert values)
    IncludeOCSP  bool   // include OCSP response (CAdES-XL)

    // Transport header fields (when NoTax=false)
    Email       string
    Filename    string
}

// SignDocument creates a signed (and optionally encrypted) document
// ready for tax office submission
func (b *Box) SignDocument(content []byte, opts SignOptions) ([]byte, error)
```

Workflow (full tax office mode, `NoTax=false`):
1. Select signing key from Box (by role or first available)
2. Compute hash of content
3. Create CMS SignedData (`cms.Sign()`)
4. If `TSPLevel != "none"`: request timestamps, add to unsigned attributes
5. If `IncludeChain == "full"`: add CA cert values to unsigned attributes
6. If `IncludeOCSP`: request and add OCSP response
7. Prepend `UA_SIGN1\0` prefix + length to CMS DER
8. Build transport container:
   - TRANSPORTABLE header (filename, email, dates, CRC32s)
   - Sign section (UA1_SIGN with CMS data)
9. Return transport container bytes

Workflow (raw CMS mode, `NoTax=true`):
1-6 same as above
7. Return raw CMS DER bytes (optionally with `.p7s` extension)

```go
// UnsignDocument parses and verifies a signed document
func (b *Box) UnsignDocument(data []byte) (*UnsignResult, error)

type UnsignResult struct {
    Content     []byte              // original document
    Signers     []SignerResult       // verification results for each signer
    Timestamps  []TimestampResult    // timestamp verification results
    Header      *transport.Header    // transport header (if present)
}

type SignerResult struct {
    Certificate *cert.Certificate
    CertInfo    *CertInfo
    SigningTime time.Time
    Valid       bool
    Error       error
}

type TimestampResult struct {
    Time  time.Time
    Type  string  // "signature" or "content"
    Valid bool
    Error error
}
```

Unsign workflow:
1. Try to parse as transport container → extract sections
2. Find sign section (UA_SIGN1 / UA1_SIGN), strip prefix
3. Parse CMS SignedData
4. Verify each signer's signature
5. If CA certs loaded: verify signer certificate chains
6. If timestamps present: verify TSP tokens
7. If encrypted section present: needs `DecryptDocument` first
8. Return original content + verification results

### 3. Encrypt / Decrypt (`crypto.go`)

```go
// EncryptDocument encrypts content for a recipient
func (b *Box) EncryptDocument(content []byte, recipientCert *cert.Certificate) ([]byte, error)

// DecryptDocument decrypts an incoming encrypted document
func (b *Box) DecryptDocument(data []byte) ([]byte, error)
```

Encrypt workflow:
1. Select encryption key from Box
2. Create CMS EnvelopedData (`cms.Encrypt()`)
3. Return CMS DER bytes

Decrypt workflow:
1. Parse as transport container (if applicable)
2. Find crypt section, strip prefix
3. Parse CMS EnvelopedData
4. Find matching recipient info for our key
5. Decrypt using `cms.DecryptEnveloped()`
6. Return plaintext

### 4. Full sign+encrypt for tax office

```go
// SignAndEncrypt signs content and encrypts for tax office recipient
func (b *Box) SignAndEncrypt(content []byte, recipientCert *cert.Certificate, opts SignOptions) ([]byte, error)
```

Workflow (matching agent `--sign --crypt`):
1. Sign content → CMS SignedData
2. Encrypt the SignedData → CMS EnvelopedData
3. Build transport container with both sections
4. Compute CRC32 checksums for header
5. Return complete transport container

### 5. Certificate operations (`verify.go`, `certinfo.go`)

```go
// VerifyCert validates a certificate against loaded CA list
func (b *Box) VerifyCert(certDER []byte) error

// VerifyCertPKMatch checks if certificate matches a private key
func VerifyCertPKMatch(certDER []byte, keyData []byte, password string) error

// GetCertInfo extracts human-readable information from a certificate
func GetCertInfo(certDER []byte) (*CertInfo, error)

type CertInfo struct {
    Serial       string
    Issuer       string
    Subject      string
    CommonName   string
    Organization string
    Title        string       // job title
    EDRPOU       string       // corporate code
    DRFO         string       // personal tax ID
    Email        string
    NotBefore    time.Time
    NotAfter     time.Time
    Role         cert.Role
    KeyUsage     []string
    IsCA         bool
    Algorithm    string       // "DSTU4145-Kupyna256", etc.
    CurveName    string       // "DSTU_PB_257", etc.
}
```

### 6. Write tests
- **Full roundtrip**: `SignAndEncrypt` → `DecryptDocument` → `UnsignDocument` → original content
- **Sign-only**: `SignDocument` → `UnsignDocument` → verify
- **Detached signature**: sign detached, verify with separate content
- **Raw CMS mode**: `NoTax=true`, output is valid CMS parseable by other tools
- **GetCertInfo**: parse test certificate, verify all fields
- **VerifyCert**: valid cert → nil error, expired cert → error
- **Box loading**: load Key-6.dat + certs, verify Box state
- **Multiple keys**: load JKS with multiple keys, select by role

Test fixtures: use keys and certs from `testdata/keys/`.

## Acceptance Criteria
- [ ] `Box` correctly loads keys from all supported formats
- [ ] `SignDocument` produces valid signed output (verifiable by `czo.gov.ua/verify`)
- [ ] `UnsignDocument` correctly extracts content and verifies signatures
- [ ] `EncryptDocument` / `DecryptDocument` roundtrip works
- [ ] `SignAndEncrypt` produces valid tax office transport container
- [ ] `GetCertInfo` extracts all Ukrainian-specific fields
- [ ] TSP timestamps are correctly requested and embedded
- [ ] Role-based key selection works

## Notes
- The `Box` pattern follows jkurwa's `ctx.js` approach — single object managing all crypto state
- Tax office expects specific filename format in transport header (see agent README)
- CRC32 values in header must be computed over the correct data blocks
- The signing order for multiple signatures (accountant → director → seal) is handled by calling `SignDocument` multiple times with different keys
- For incoming tax office responses: parse transport container → decrypt → unsign → get XML response
- `czo.gov.ua/verify` can be used to cross-validate output

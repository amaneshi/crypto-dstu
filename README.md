# crypto-dstu

Pure Go implementation of Ukrainian national cryptographic standards for digital signature, encryption, and tax office document exchange.

## Standards implemented

| Standard | Description |
|----------|-------------|
| DSTU 4145-2002 | Digital signature over elliptic curves GF(2^m); all 10 named curves |
| DSTU 7564:2014 | Kupyna hash function (256 / 384 / 512-bit) |
| DSTU 7624:2014 | Kalyna block cipher (all 5 variants) |
| GOST 28147-89 | Block cipher, Ukrainian S-box; ECB / CFB / MAC / key-wrap |
| GOST 34.311-95 | Hash function |
| DSTU ISO/IEC 15946-3 | Elliptic-curve key agreement (ECDH) |
| CMS / PKCS#7 | SignedData (CAdES-BES) + EnvelopedData |
| RFC 3161 | Timestamp Protocol (TSP) |
| Order #499 | Ukrainian tax office transport container format |

No CGo. No external cryptographic dependencies.

Aligned with the [cryptonite](https://github.com/privat-it/cryptonite) reference implementation (PrivatBank C library).

---

## Installation

### CLI tool

Clone the repository and build:

```bash
git clone https://github.com/your-org/crypto-dstu
cd crypto-dstu
go build -o dstu ./cmd/dstu
```

Once the module is published to a Go proxy:

```bash
go install github.com/your-org/crypto-dstu/cmd/dstu@latest
```

### Library

```bash
go get github.com/your-org/crypto-dstu
```

> **Note:** The module is currently named `crypto-dstu` (local). Replace `github.com/your-org/crypto-dstu` with the actual published module path.

Requires Go 1.21 or later.

---

## CLI reference — `dstu`

### Sign a document

**Sign and encrypt for the tax office email gate** (produces a transport container ready for submission):

```bash
dstu sign \
  -key Key-6.dat:password \
  -cert cert.sign.der -cert cert.cryp.der \
  -crypt otrimano.cer \
  -tsp https://tsp.gov.ua/ -tsp-level all \
  -email me@example.com \
  -input zvit.xml \
  -output zvit.xml.sign.enc
```

**Sign only — raw CMS (for `czo.gov.ua/verify`):**

```bash
dstu sign \
  -key Key-6.dat:password \
  -cert cert.sign.der \
  -no-tax \
  -tsp https://tsp.gov.ua/ -tsp-level all \
  -input text.pdf \
  -output text.pdf.p7s
```

**Detached signature:**

```bash
dstu sign \
  -key Key-6.dat:password \
  -cert cert.sign.der \
  -no-tax -detached \
  -input zvit.xml \
  -output zvit.xml.sig
```

**JKS key (PrivatBank) with role selection:**

```bash
dstu sign \
  -key pb_1234567890.jks:password \
  -no-tax \
  -role stamp \
  -input zvit.xml \
  -output zvit.xml.sign
```

**Include full certificate chain (CAdES-X-Long):**

```bash
dstu sign \
  -key Key-6.dat:password \
  -cert cert.sign.der \
  -no-tax \
  -include-chain full \
  -input text.pdf \
  -output text.pdf.p7s
```

> **Note:** `-tsp-level` and `-include-chain` flags are accepted by the CLI but TSP stamping and CAdES-C/X chain embedding are not yet wired into the output — they are reserved for a future release.

#### `dstu sign` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-key path[:password]` | required | Key container; formats: Key-6.dat, .jks, .p12, .der, .pem |
| `-cert path` | | Signing certificate (repeatable) |
| `-ca path` | | CA bundle (.p7b or directory) |
| `-input path` | stdin | Input file (`-` for stdin) |
| `-output path` | stdout | Output file (`-` for stdout) |
| `-no-tax` | false | Raw CMS output; omit transport header and UA_SIGN1 prefix |
| `-detached` | false | Produce detached signature (content not embedded) |
| `-crypt path` | | Recipient certificate: sign then encrypt |
| `-tsp url` | | TSP server URL (repeatable) |
| `-tsp-level value` | none | Timestamp level: `none` \| `signature` \| `content` \| `all` |
| `-role value` | | Key role for multi-key stores: `personal` \| `fop` \| `director` \| `stamp` \| `other` |
| `-email addr` | | Sender email for transport header |
| `-filename name` | | Attachment filename for transport header |
| `-include-chain value` | none | Certificate chain inclusion: `none` \| `ref` \| `full` |

---

### Decrypt and verify an incoming document

```bash
dstu decrypt \
  -key fop_acsk.raw.der \
  -ca CACertificates.p7b \
  -input incoming.sign.enc \
  -output clear.xml \
  -v
```

Automatically detects transport container, raw CMS, and encrypted formats. With `-v`, prints signer information to stderr.

#### `dstu decrypt` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-key path[:password]` | required | Key container |
| `-ca path` | | CA bundle for chain verification |
| `-input path` | stdin | Input file |
| `-output path` | stdout | Output file |
| `-role value` | | Key role |
| `-v` | false | Print signer info to stderr |

---

### Encrypt only

```bash
dstu encrypt \
  -key Key-6.dat:password \
  -cert cert.sign.der -cert cert.cryp.der \
  -crypt otrimano.cer \
  -input zvit.xml \
  -output zvit.xml.enc
```

#### `dstu encrypt` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-key path[:password]` | required | Sender key container |
| `-cert path` | | Sender certificate (repeatable) |
| `-crypt path` | required | Recipient certificate |
| `-input path` | stdin | Input file |
| `-output path` | stdout | Output file |

---

### Print certificate information

```bash
dstu certinfo -cert cert.sign.der
```

```
Subject:      CN=Іваненко Іван Іванович, O=ДПС України, C=UA
CommonName:   Іваненко Іван Іванович
Organization: ДПС України
Title:        Головний бухгалтер
EDRPOU:       12345678
DRFO:         1234567890
Email:        ivan@example.com
Serial:       0102030405060708090a0b0c0d0e0f10
NotBefore:    2024-01-01T00:00:00Z
NotAfter:     2025-01-01T00:00:00Z
Role:         director
Algorithm:    DSTU4145WithGOST34311
Curve:        DSTU_PB_257
IsCA:         false
```

**JSON output:**

```bash
dstu certinfo -cert cert.sign.der -json
```

#### `dstu certinfo` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-cert path` | required | Certificate file (.cer, .der, .pem) |
| `-json` | false | Output as JSON |

---

### Remove password from key container

```bash
# Output PEM (default)
dstu unprotect -key Key-6.dat:password -output key.pem

# Output DER
dstu unprotect -key Key-6.dat:password -der -output key.der

# Write to stdout (pipe-friendly)
dstu unprotect -key Key-6.dat:password > key.pem
```

#### `dstu unprotect` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-key path:password` | required | Encrypted key container with password |
| `-output path` | stdout | Output file |
| `-der` | false | Output DER instead of PEM |

---

### Supported key formats

| Format | Extension | Notes |
|--------|-----------|-------|
| Key-6.dat | `.dat` | PBES2 + PBKDF2-GOST + GOST28147-CFB; Ukrainian tax office standard |
| JKS | `.jks` | Java KeyStore; PrivatBank Privat24, may contain multiple keys |
| PKCS#12 / PFX | `.p12`, `.pfx` | GOST-encrypted container |
| Raw PKCS#8 | `.der`, `.raw` | Unencrypted DER-encoded private key |
| PEM | `.pem` | PEM-wrapped DER |

Format is auto-detected when loading via `box.LoadKeyFile` / `box.LoadKey`.

---

## Library usage

### Load a key and sign a document

```go
import (
    "crypto-dstu/ua"
)

box := ua.NewBox()

// Load key (any supported format, auto-detected)
if err := box.LoadKeyFile("Key-6.dat", "password"); err != nil {
    log.Fatal(err)
}
// Load signing certificate
if err := box.AddCertFile("cert.sign.der"); err != nil {
    log.Fatal(err)
}

// Sign — raw CMS (no transport header)
signed, err := box.SignDocument(content, ua.SignOptions{NoTax: true})
if err != nil {
    log.Fatal(err)
}
```

### Verify / unsign a document

```go
box := ua.NewBox()
if err := box.LoadCABundleFile("CACertificates.p7b"); err != nil {
    log.Fatal(err)
}

result, err := box.UnsignDocument(signed)
if err != nil {
    log.Fatal(err)
}

fmt.Println(string(result.Content))
for _, s := range result.Signers {
    name := "<unknown>"
    if s.CertInfo != nil {
        name = s.CertInfo.CommonName
    }
    fmt.Printf("signer: %s valid=%v\n", name, s.Valid)
}
```

### Encrypt for a recipient

```go
box := ua.NewBox()
box.LoadKeyFile("Key-6.dat", "password")
box.AddCertFile("cert.sign.der")
box.AddCertFile("cert.cryp.der")

// recipientDER is the raw DER or PEM bytes of the recipient's certificate
encrypted, err := box.EncryptDocument(content, recipientDER)
```

### Decrypt

```go
box := ua.NewBox()
box.LoadKeyFile("Key-6.dat", "password")

plain, err := box.DecryptDocument(encrypted)
```

### Sign and encrypt in one step (tax office workflow)

```go
// recipientDER is the raw DER or PEM bytes of the recipient's certificate
container, err := box.SignAndEncrypt(content, recipientDER, ua.SignOptions{
    Email:    "me@example.com",
    Filename: "zvit.xml",
})
```

### Certificate information

```go
import "crypto-dstu/ua"

info, err := ua.GetCertInfo(certDER)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("EDRPOU: %s\n", info.EDRPOU)
fmt.Printf("Role:   %s\n", info.Role)
fmt.Printf("Valid:  %s — %s\n", info.NotBefore.Format("2006-01-02"), info.NotAfter.Format("2006-01-02"))
```

### Remove password protection from a key

```go
import "crypto-dstu/ua"

data, _ := os.ReadFile("Key-6.dat")
keyPEM, err := ua.UnprotectKey(data, "password", "pem")
// keyPEM contains the raw unencrypted private key in PEM format
```

---

## Raw primitives

### DSTU 4145 signature

```go
import (
    "crypto/rand"
    "crypto-dstu/pkg/dstu4145"
    "crypto-dstu/pkg/kupyna"
)

params := dstu4145.ParamsByName("DSTU_PB_257")
priv, err := dstu4145.GenerateKey(params.Curve)
pub := priv.Public() // *dstu4145.PublicKey

// Hash with Kupyna-256
h := kupyna.New256()
h.Write([]byte("hello"))
digest := h.Sum(nil)

// Sign (implements crypto.Signer — returns ASN.1-encoded r,s)
sigBytes, err := priv.Sign(rand.Reader, digest, nil)

// Verify
sig, err := dstu4145.UnmarshalSignature(sigBytes, priv.Curve.Words)
ok := dstu4145.Verify(pub, digest, sig)
```

### Kupyna hash

```go
import "crypto-dstu/pkg/kupyna"

h := kupyna.New256()
h.Write(data)
digest := h.Sum(nil) // 32 bytes
```

### GOST 28147-89 encryption

```go
import "crypto-dstu/pkg/gost28147"

block, err := gost28147.NewCipher(key) // 32-byte key, returns cipher.Block
// Use with cipher.NewCFBEncrypter / cipher.NewCFBDecrypter
```

---

## Package reference

### Public API

| Package | Description |
|---------|-------------|
| `ua` | High-level API: `Box`, `SignDocument`, `UnsignDocument`, `EncryptDocument`, `DecryptDocument`, `UnprotectKey` |
| `cmd/dstu` | CLI tool |

### Public primitives (`pkg/`)

Importable by external packages. Suitable for advanced users who need direct access to cryptographic algorithms.

| Package | Description |
|---------|-------------|
| `pkg/gf2m` | Binary field GF(2^m) arithmetic (add, mul, inv, sqr) |
| `pkg/ec` | Elliptic curves over GF(2^m); all 10 DSTU named curves |
| `pkg/kupyna` | DSTU 7564 Kupyna hash: `New256()`, `New384()`, `New512()` |
| `pkg/kalyna` | DSTU 7624 Kalyna block cipher; all 5 key/block variants |
| `pkg/gost28147` | GOST 28147-89 cipher; ECB, CFB, MAC, key-wrap |
| `pkg/gost34311` | GOST 34.311-95 hash |
| `pkg/dstu4145` | DSTU 4145 sign / verify / key generation; `crypto.Signer` |
| `pkg/dstu15946` | EC Diffie-Hellman key agreement + CMS-layer KDF |

### Internal packages (`internal/`)

Protocol and infrastructure layers. Accessible within this module only.

| Package | Description |
|---------|-------------|
| `internal/keystore` | Key container parser: Key-6.dat, JKS, PKCS#12, raw, PEM |
| `internal/oid` | Ukrainian PKI OID registry (1.2.804.2.1.1.1.*) |
| `internal/cert` | X.509v3 certificate parse, chain verify, role detection |
| `internal/transport` | Ukrainian tax office transport container (Order #499) |
| `internal/cms` | CMS/PKCS#7 SignedData + EnvelopedData |
| `internal/tsp` | RFC 3161 Timestamp Protocol client |

---

## CA bundle

The CA certificate bundle (list of trusted Ukrainian CAs) is required for chain verification. Download from:

```bash
wget -O CACertificates.p7b \
  'https://id.gov.ua/verify-widget/v20200922/Data/CACertificates.p7b' \
  --header='User-Agent: '
```

Pass it to the CLI with `-ca CACertificates.p7b` or to the library with `box.LoadCABundleFile(path)`.

---

## Compatibility

- Cryptographic correctness aligned with **[cryptonite](https://github.com/privat-it/cryptonite)** (PrivatBank C library) — the authoritative Ukrainian PKI reference.
- Test suite includes real CZO test samples for CAdES/XAdES/PAdES formats (DSTU and DSTU-7564 algorithm variants), downloaded from [czo.gov.ua/testexamples](https://czo.gov.ua/testexamples).
- Interoperable with documents produced by ME.DOC software.
- **Not** API-compatible with `jkurwa` (JavaScript) — different byte ordering conventions.

---

## License

MIT

# crypto-dstu

Pure Go implementation of Ukrainian national cryptographic standards for digital signature, encryption, and tax office document exchange.

## Standards implemented

| Standard | Description |
|----------|-------------|
| DSTU 4145-2002 | Digital signatures over GF(2^m); ten PB and five ONB named curves (see [ONB limits](docs/onb.md)) |
| DSTU 7564:2014 | Kupyna hash function (256 / 384 / 512-bit) |
| DSTU 7624:2014 | Kalyna block cipher (all 5 variants) |
| GOST 28147-89 | Block cipher, Ukrainian S-box; ECB / CFB / CTR (gamma) / MAC / key-wrap |
| GOST 34.311-95 | Hash function |
| DSTU ISO/IEC 15946-3 | Elliptic-curve key agreement (ECDH) |
| CMS / PKCS#7 | SignedData (CAdES-BES) + EnvelopedData |
| RFC 3161 | Timestamp Protocol (TSP) |
| RFC 2986 | PKCS#10 Certificate Signing Request |
| RFC 6960 | Online Certificate Status Protocol (OCSP) |
| Order #499 | Ukrainian tax office transport container format |

No CGo. No external cryptographic dependencies.

Aligned with the [cryptonite](https://github.com/privat-it/cryptonite) reference implementation (PrivatBank C library).

---

## Installation

### CLI tool

Clone the repository and build:

```bash
git clone https://github.com/amaneshi/crypto-dstu
cd crypto-dstu
go build -o dstu ./cmd/dstu
```

Or install directly from GitHub:

```bash
go install github.com/amaneshi/crypto-dstu/cmd/dstu@latest
```

### Library

```bash
go get github.com/amaneshi/crypto-dstu
```

Requires Go 1.27 or later (see `go.mod`).

---

## CLI reference — `dstu`

### Sign a document

**Sign and encrypt for the tax office email gate** (produces a transport container ready for submission):

```bash
dstu sign \
  -key Key-6.dat:password \
  -cert cert.sign.der -cert cert.cryp.der \
  -crypt otrimano.cer \
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

Timestamp and extended-chain embedding are not implemented. The CLI rejects
`-tsp`, non-`none` `-tsp-level`, and non-`none` `-include-chain`.

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
| `-tsp url` | | Unsupported; returns an error |
| `-tsp-level value` | none | Only `none` is currently supported |
| `-role value` | | Key role for multi-key stores: `personal` \| `fop` \| `director` \| `stamp` \| `other` |
| `-email addr` | | Sender email for transport header |
| `-filename name` | | Attachment filename for transport header |
| `-include-chain value` | none | Only `none` is currently supported |

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
| `-cert path` | | Recipient or sender discovery certificate (repeatable) |
| `-require-ocsp` | false | Require authenticated current OCSP for the certificate path |
| `-ocsp-response path` | | Saved DER OCSP evidence (repeatable; enables required OCSP) |
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

### Generate a Certificate Signing Request

```bash
# Generate a fresh key + CSR for a Ukrainian entity:
dstu csr \
  -cn "Іваненко Іван Іванович" \
  -org "ТОВ Приклад" \
  -country UA \
  -edrpou 12345678 \
  -output request.csr.der

# Use an existing key:
dstu csr \
  -key Key-6.dat:password \
  -cn "Іваненко Іван" \
  -output request.csr.der
```

#### `dstu csr` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-key path[:password]` | | Existing key container (optional; fresh key generated if omitted) |
| `-curve name` | `DSTU_PB_257` | Curve for generated key |
| `-cn value` | | Common name (Subject CN) |
| `-org value` | | Organisation (Subject O) |
| `-country value` | | Country code (Subject C) |
| `-edrpou value` | | EDRPOU code |
| `-drfo value` | | DRFO personal tax number |
| `-output path` | stdout | Output DER file |

---

### Check certificate revocation status (OCSP)

```bash
dstu ocsp \
  -cert cert.sign.der \
  -issuer issuer.cer
```

With explicit responder URL:

```bash
dstu ocsp \
  -cert cert.sign.der \
  -issuer issuer.cer \
  -url http://ocsp.acsk.privatbank.ua
```

Exit codes: `0` = good, `2` = revoked, `3` = unknown.

#### `dstu ocsp` flags

| Flag | Default | Description |
|------|---------|-------------|
| `-cert path` | required | Certificate to check |
| `-issuer path` | required | Issuer certificate |
| `-response path` | | Validate saved DER OCSP evidence instead of fetching |
| `-url url` | | Override OCSP responder URL (default: from AIA extension) |

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
| Key-6.dat | `.dat` | PBES2: HMAC-GOST34311 / GOST28147-CFB or Kupyna MAC-256 / Kalyna-256 CBC |
| JKS | `.jks` | Java KeyStore; PrivatBank Privat24, may contain multiple keys |
| PKCS#12 / PFX | `.p12`, `.pfx` | Reads supported GOST/Kupyna profiles; writes Kalyna-protected keys with SHA-256 integrity |
| Raw PKCS#8 | `.der`, `.raw` | Unencrypted DER-encoded private key |
| PEM | `.pem` | PEM-wrapped DER |

Format is auto-detected when loading via `box.LoadKeyFile` / `box.LoadKey`.

To protect a single unencrypted PKCS#8 DER or PEM key:

```go
protected, err := ua.ProtectKey(rawPKCS8, password)
if err != nil {
    return err
}
return os.WriteFile("Key-6.dat", protected, 0600)
```

This writes Kupyna MAC-256 / Kalyna-256 CBC with 10,000 PBKDF2 iterations
and fresh random 32-byte salt and IV. Passwords must contain 1–32 UTF-8 bytes
and cannot end in NUL. IIT Windows interoperability now includes tested ASCII,
Cyrillic and Ukrainian passwords through its documented CP1251 API boundary;
arbitrary Unicode/provider compatibility remains unverified. Certificates are
supplied separately. See [password compatibility](docs/compatibility.md).

To include matching certificates in an integrity-protected PFX:

```go
pfx, err := ua.ProtectPKCS12(rawPKCS8, certificateDERs, password)
if err != nil {
    return err
}
return os.WriteFile("identity.pfx", pfx, 0600)
```

Use `box.ExportPKCS12(password)` to export all keys and discovery certificates
already loaded into a Box. Both APIs require an unambiguous matching certificate
for every key. Each key
bag uses the modern Kalyna protection above; an HMAC-SHA256 protects the complete
container. Certificates remain public discovery data and do not become trust
anchors. PFX export accepts 1–32 UTF-8 bytes containing BMP characters and no NUL.
The pinned IIT SDK signs with these exports when its certificate discovery store
is also supplied the matching certificate. See [PFX profiles and limits](docs/pkcs12.md).

---

## Library usage

### Load a key and sign a document

```go
import (
    "github.com/amaneshi/crypto-dstu/ua"
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

For a static-originator envelope, load the sender's certificate with `box.AddCert`
when it is not embedded in the envelope. The decrypt CLI accepts `-cert sender.cer`.
These certificates supply agreement keys without becoming trusted roots;
verify the decrypted signed content separately before using it.

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
import "github.com/amaneshi/crypto-dstu/ua"

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
import "github.com/amaneshi/crypto-dstu/ua"

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
    "github.com/amaneshi/crypto-dstu/pkg/dstu4145"
    "github.com/amaneshi/crypto-dstu/pkg/kupyna"
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
import "github.com/amaneshi/crypto-dstu/pkg/kupyna"

h := kupyna.New256()
h.Write(data)
digest := h.Sum(nil) // 32 bytes
```

### GOST 28147-89 encryption

```go
import "github.com/amaneshi/crypto-dstu/pkg/gost28147"

block, err := gost28147.NewCipher(key) // 32-byte key, returns cipher.Block
// CFB mode
stream := cipher.NewCFBEncrypter(block, iv)
// CTR (gamma) mode
stream, err = gost28147.NewCTR(block, iv) // iv must be 8 bytes
```

### HMAC

```go
import "github.com/amaneshi/crypto-dstu/pkg/hmac"

// Generic HMAC (works with any hash.Hash factory)
mac := hmac.New(sha256.New, key)
mac.Write(data)
tag := mac.Sum(nil)

// HMAC-GOST34311 (Ukrainian standard; sync = 32-byte IV, nil → zero)
mac = hmac.NewGOST34311(key, nil)
mac.Write(data)
tag = mac.Sum(nil)

// HMAC-Kupyna
mac = hmac.NewKupyna256(key)
mac = hmac.NewKupyna512(key)
```

### PKCS#10 Certificate Signing Request

```go
import (
    "github.com/amaneshi/crypto-dstu/internal/csr"
    "github.com/amaneshi/crypto-dstu/internal/oid"
    "github.com/amaneshi/crypto-dstu/pkg/dstu4145"
    "github.com/amaneshi/crypto-dstu/pkg/ec"
)

priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())

der, err := csr.Create(&csr.Request{
    Subject: []csr.AttributeTypeAndValue{
        {Type: oid.OIDCommonName, Value: "Іваненко Іван"},
        {Type: oid.EDRPOU,       Value: "12345678"},
    },
}, priv)

// Parse and verify
parsed, err := csr.Parse(der)
err = parsed.Verify()
```

CSR output uses the national compressed-key and signature encodings, including
GOST ONB requests on all five standard ONB curves. Older library CSRs remain
readable. See [CSR encoding and validation](docs/csr.md) for the exact coverage
and compatibility change.

### OCSP certificate status check

```go
result, err := box.UnsignDocumentWithOptions(ctx, signedDER, originalContent, ua.VerificationOptions{
    Revocation:    ua.RevocationRequireOCSP,
    OCSPResponses: savedResponses,
})
if err != nil {
    return err // no verified content is released
}
// result.Content is verified; signer results include the revocation outcome.
```

Saved responses must cover each non-anchor certificate on the validated path.
For application-owned fetching and policy limits, see [revocation verification](docs/revocation.md).

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
| `pkg/ec` | Elliptic curves over GF(2^m); ten PB and five ONB DSTU named curves |
| `pkg/kupyna` | DSTU 7564 Kupyna hash (`New256/384/512`) + KMAC256/384/512 |
| `pkg/kalyna` | DSTU 7624 Kalyna block cipher; all 5 key/block variants + CTR/CBC/CFB/OFB/CMAC/XTS/KW |
| `pkg/gost28147` | GOST 28147-89 cipher; ECB, CFB, CTR (gamma), MAC, key-wrap |
| `pkg/gost34311` | GOST 34.311-95 hash |
| `pkg/dstu4145` | DSTU 4145 sign / verify / key generation; `crypto.Signer` |
| `pkg/dstu15946` | EC Diffie-Hellman key agreement + CMS-layer KDF |
| `pkg/hmac` | HMAC wrapper: generic `New`, `NewGOST34311`, `NewKupyna256`, `NewKupyna512` |

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
| `internal/csr` | PKCS#10 CSR build, sign, parse, verify (DSTU 4145 + EDRPOU/DRFO) |
| `internal/ocsp` | RFC 6960 OCSP request/response + HTTP client with AIA extraction |

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

Optional independent tests verify DSTU 4145/GOST signatures and dynamic-key
encryption in both directions with IIT, including generated test key containers.
See [IIT interoperability tests](docs/iit-interoperability.md) for setup, the tested
SDK version, results, and remaining profile coverage.

See [revocation verification](docs/revocation.md) for explicit OCSP policy,
offline evidence, application-owned fetching and failure behavior.

- Format and algorithm reference: **[cryptonite](https://github.com/privat-it/cryptonite)**. This does not establish complete conformance.
- Test suite includes real CZO test samples for CAdES/XAdES/PAdES formats (DSTU and DSTU-7564 algorithm variants), downloaded from [czo.gov.ua/testexamples](https://czo.gov.ua/testexamples).
- ME.DOC and DPS interoperability require independent fixture validation.
- **Not** API-compatible with `jkurwa` (JavaScript) — different byte ordering conventions.

---

## Pending changes

The core signing, encryption, timestamp and modern Key-6 import/export paths
have independent interoperability checks. The following work remains; passing
the current matrix does not establish production readiness or support for
untested profiles.

- [ ] **ONB provider interoperability:** resolve certificate/CMS failures with
  the pinned IIT SDK; see [ONB coverage](docs/onb.md).
- [ ] **Modern ONB profiles:** independently validate Kupyna/Kalyna encodings
  before enabling them.
- [ ] **Provider passwords:** validate arbitrary Unicode and additional provider
  password profiles beyond the tested Windows CP1251 cases.
- [ ] **Parser fuzzing:** add CMS, Key-6/PKCS#8/JKS and revocation targets;
  extend PFX coverage, add legacy CSR/ONB certificate seeds and run longer
  campaigns. See [current targets and limits](docs/fuzzing.md).
- [ ] **Primitive validation:** broaden primitive fuzzing and independent
  known-answer coverage beyond the current tested profiles.
- [ ] **Independent review:** obtain an external cryptographic/security review.

CI provisioning and native runner execution are deferred while CI is paused;
see [CI setup](docs/ci.md).

Tax-report submission, receipt polling and report-status handling are deferred
to the separate `tax-reporting` project. They are outside this library's current
work scope. See [IIT interoperability](docs/iit-interoperability.md) for the exact
tested profiles and [AGENTS.md](AGENTS.md) for contributor/agent instructions.

CI is paused. Hosted test/race, lint and vulnerability checks and a manual
hash-pinned IIT workflow are retained with `.disabled` filenames in
`.github/workflows`; see [CI setup](docs/ci.md) to reactivate them.

## License

MIT

## Verification and trust

`ua.Box.UnsignDocument` verifies signatures and requires explicitly configured
trust anchors through `LoadCABundle`. `AddCert` supplies certificate discovery
and key association only; imported keystore certificates are never implicitly trusted.
Detached signatures require `UnsignDocumentWithContent` and the original bytes.
Verification failures return an error and no authenticated content. The decrypt CLI
does not write content unless every signer is verified.

The internal CMS API permits mathematical verification without chain trust only
when its roots argument is nil. This is appropriate for archived test vectors,
not for accepting government receipts. Path validation checks supported critical
extensions, validity, CA constraints and key usages; online revocation is a separate
policy step and is not automatically performed.

Load separate signing/agreement certificates with `AddCert`. Use
`SelectKeyByRole` (CLI `-role`) when multiple signing keys are loaded;
ambiguous roles fail rather than selecting an arbitrary key. Windows drive-letter
paths are supported by the `-key path[:password]` parser.

Signed-and-encrypted tax containers expose only the encrypted signed payload,
never an unencrypted sibling copy of the report. CMS signed attributes are emitted
with DER ordering and the implicit field tag. Digest profiles can be selected using
`ua.SignOptions.DigestAlgorithm` or the signing CLI:

```sh
dstu sign -key Key-6.dat:password -cert signer.cer -input document.xml -output document.p7s -no-tax -digest kupyna256
```

`-digest` accepts `auto` (the default), `gost34311`, `kupyna256` and `kupyna512`.
It selects the CMS document-signature digest for attached, detached, transport,
timestamped and signed-and-encrypted output. Unknown values fail before reading
keys or writing output. The choice does not change the key's curve, encryption
algorithm or timestamp-imprint algorithm.

`auto` follows supported certificate **public-key** algorithm identifiers. A
Kupyna-signed certificate can still declare a GOST public-key identifier, so
use an explicit digest when the required document profile is Kupyna. This
preserves the existing default; the issuer's certificate-signature algorithm
does not select the document digest. See the independently checked
[IIT profile matrix](docs/iit-interoperability.md#limits) for curve/profile coverage.

`dstu encrypt` and `dstu sign -crypt` accept `-cipher gost28147-cfb` (default),
`kalyna256-cfb` or `kalyna256-ofb`. The Kalyna profiles select Kupyna-256 key
derivation and the national Kalyna CMAC/CFB key wrapper together. Decryption
selects the profile from the envelope's declared algorithms.

```sh
dstu sign -key Key-6.dat:password -cert signer.cer -crypt recipient.cer -input document.xml -output encrypted.bin -digest kupyna256 -cipher kalyna256-cfb
```

Go callers can use `EncryptDocumentWithOptions(content, recipientDER,
ua.EncryptionOptions{Algorithm: ua.EncryptionKalyna256CFB})`. For
`SignAndEncrypt`, set `SignOptions.Encryption` to those options. The OFB constant
is `ua.EncryptionKalyna256OFB`; zero options preserve GOST CFB. Unknown cipher
names fail explicitly. Select encryption independently from the signature digest.

For raw `pkg/kalyna.KW`, `Wrap` and `Unwrap` now require whole cipher blocks
and check the full integrity block before releasing plaintext. Non-aligned keys
use `WrapPadded` and `UnwrapPadded(wrapped, originalByteLength)`; migrate callers
that previously relied on implicit padding. Trailing zero bytes are preserved.

This is an experimental cryptographic implementation: these fixes are not an
independent timing-resistance audit or proof of DPS production interoperability.
Validate emitted containers and the selected profile against an independent provider
before using real taxpayer keys or submitting reports.

Signature timestamp creation and verification are opt-in; see [timestamp policy and CAdES-T interoperability](docs/timestamps.md).

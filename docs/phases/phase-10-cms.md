# Phase 10 — CMS/PKCS#7 `cms`

## Goal
Implement CMS (Cryptographic Message Syntax) / PKCS#7 for creating and parsing signed and enveloped (encrypted) messages using Ukrainian DSTU algorithms. This is the core format for digital signatures (CAdES) and encrypted documents in the tax office protocol.

## Prerequisites
- **Phase 5** (`dstu4145`) — signature algorithm
- **Phase 8** (`cert`, `oid`) — certificate parsing and OID definitions
- **Phase 6** (`dstu15946`) — key agreement for EnvelopedData
- **Phase 4** (`gost28147`) — symmetric cipher for EnvelopedData

## Package
`github.com/amaneshi/crypto-dstu/cms`

## JS Reference
- `jkurwa/lib/spec/dstszi.js` — ASN.1 schema definitions for CMS structures
- `jkurwa/lib/models/Message.js` — CMS message parsing and creation (if exists)
- `jkurwa/lib/app/ctx.js` — signing and encrypting logic
- `dstucrypt/agent/index.js` — high-level sign/encrypt workflow showing CMS construction

## Standards
- RFC 5652 — Cryptographic Message Syntax (CMS)
- RFC 5911 — CMS ASN.1 module updates
- ETSI EN 319 122 — CAdES (CMS Advanced Electronic Signatures)

## Files to Create

| File | Purpose |
|------|---------|
| `cms/signed.go` | `SignedData` creation and parsing (CAdES-BES and higher) |
| `cms/enveloped.go` | `EnvelopedData` creation and parsing |
| `cms/attrs.go` | Signed and unsigned attributes (content type, digest, time, TSP token, cert refs) |
| `cms/cms_test.go` | Tests |

## Step-by-Step Instructions

### 1. Core ASN.1 structures
Define Go structs matching RFC 5652 ASN.1:

```go
// ContentInfo — top-level CMS wrapper
type ContentInfo struct {
    ContentType asn1.ObjectIdentifier
    Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData (RFC 5652 §5)
type SignedData struct {
    Version          int
    DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
    EncapContentInfo EncapsulatedContentInfo
    Certificates     asn1.RawValue              `asn1:"optional,implicit,tag:0"`
    CRLs             asn1.RawValue              `asn1:"optional,implicit,tag:1"`
    SignerInfos      []SignerInfo               `asn1:"set"`
}

// SignerInfo (RFC 5652 §5.3)
type SignerInfo struct {
    Version            int
    SID                IssuerAndSerialNumber
    DigestAlgorithm    pkix.AlgorithmIdentifier
    SignedAttrs        []Attribute `asn1:"optional,implicit,tag:0,set"`
    SignatureAlgorithm pkix.AlgorithmIdentifier
    Signature          []byte
    UnsignedAttrs      []Attribute `asn1:"optional,implicit,tag:1,set"`
}

// EnvelopedData (RFC 5652 §6)
type EnvelopedData struct {
    Version              int
    RecipientInfos       []RecipientInfo `asn1:"set"`
    EncryptedContentInfo EncryptedContentInfo
}

// RecipientInfo — KeyAgreeRecipientInfo for DSTU ECDH
type KeyAgreeRecipientInfo struct {
    Version                int
    Originator             asn1.RawValue `asn1:"explicit,tag:0"`
    UKM                    []byte        `asn1:"explicit,optional,tag:1"`
    KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
    RecipientEncryptedKeys []RecipientEncryptedKey
}
```

### 2. SignedData creation (`signed.go`)

```go
type SignOptions struct {
    Detached    bool          // don't include content in SignedData
    AddTSP      bool          // add timestamp (requires Phase 11)
    IncludeChain string       // "none", "ref", "full"
    ContentType asn1.ObjectIdentifier
}

func Sign(content []byte, key *dstu4145.PrivateKey, cert *cert.Certificate, opts SignOptions) ([]byte, error)
```

Signing workflow:
1. Compute message digest: `hash = Kupyna256(content)` (or GOST34311 depending on cert algorithm)
2. Build signed attributes:
   - Content type: `1.2.840.113549.1.7.1` (id-data)
   - Message digest: hash of content
   - Signing time: current UTC time
3. DER-encode signed attributes (with SET OF tag, not IMPLICIT)
4. Sign the DER-encoded signed attributes: `sig = dstu4145.Sign(key, hash(signedAttrs))`
5. Build `SignerInfo` with cert reference, signature, attributes
6. Build `SignedData` wrapping content (or omit for detached), signer info, certificates
7. Wrap in `ContentInfo` with OID `1.2.840.113549.1.7.2` (id-signedData)
8. DER-encode and return

**UA_SIGN1 prefix**: For tax office format, prepend `"UA_SIGN1\0"` + uint32LE(length) before the DER bytes. This is handled at the transport layer (Phase 9), not here.

### 3. SignedData parsing

```go
type SignedMessage struct {
    Content     []byte           // original content (nil if detached)
    Signers     []SignerResult
    Certificates []*cert.Certificate
}

type SignerResult struct {
    Certificate *cert.Certificate
    SigningTime time.Time
    Valid       bool
    Error       error
}

func ParseSigned(der []byte) (*SignedMessage, error)
func VerifySigned(msg *SignedMessage, content []byte, roots []*cert.Certificate) error
```

Verification workflow:
1. Parse `ContentInfo` → `SignedData`
2. Extract encapsulated content (or use provided content for detached)
3. Parse embedded certificates
4. For each `SignerInfo`:
   a. Find matching certificate (by issuer+serial)
   b. Extract signed attributes, recompute their DER encoding
   c. Verify message digest attribute matches `hash(content)`
   d. Verify signature over signed attributes using signer's public key
   e. Optionally verify certificate chain

### 4. EnvelopedData creation (`enveloped.go`)

```go
func Encrypt(content []byte, recipients []*cert.Certificate, senderKey *dstu4145.PrivateKey) ([]byte, error)
```

Encryption workflow:
1. Generate random CEK (content encryption key, 32 bytes for GOST)
2. Generate random IV (8 bytes for GOST CFB)
3. Encrypt content: `ciphertext = GOST_CFB_Encrypt(CEK, IV, content)`
4. For each recipient:
   a. Compute shared secret via ECDH: `S = senderKey.D · recipientCert.PublicKey.Q`
   b. Derive KEK from shared secret: `KEK = KDF(S, ukm)`
   c. Wrap CEK with KEK: `wrappedCEK = GOST_WrapKey(KEK, CEK, iv)`
5. Build `RecipientInfo` for each recipient (KeyAgreeRecipientInfo)
6. Build `EnvelopedData` with encrypted content + recipient infos
7. Wrap in `ContentInfo`

### 5. EnvelopedData parsing

```go
type EncryptedMessage struct {
    Algorithm     asn1.ObjectIdentifier
    IV            []byte
    CipherText    []byte
    Recipients    []RecipientInfo
}

func ParseEnveloped(der []byte) (*EncryptedMessage, error)
func DecryptEnveloped(msg *EncryptedMessage, key *dstu4145.PrivateKey, cert *cert.Certificate) ([]byte, error)
```

Decryption workflow:
1. Parse `EnvelopedData`
2. Find matching `RecipientInfo` (by cert serial/issuer)
3. Extract originator's ephemeral public key from `RecipientInfo`
4. Compute shared secret: `S = myKey.D · originator.Q`
5. Derive KEK: `KEK = KDF(S, ukm)`
6. Unwrap CEK: `CEK = GOST_UnwrapKey(KEK, wrappedCEK)`
7. Decrypt: `plaintext = GOST_CFB_Decrypt(CEK, IV, ciphertext)`

### 6. Attributes (`attrs.go`)
```go
type Attribute struct {
    Type   asn1.ObjectIdentifier
    Values []asn1.RawValue `asn1:"set"`
}

// Standard CMS attribute OIDs
var (
    OIDContentType   = asn1.ObjectIdentifier{1,2,840,113549,1,9,3}
    OIDMessageDigest = asn1.ObjectIdentifier{1,2,840,113549,1,9,4}
    OIDSigningTime   = asn1.ObjectIdentifier{1,2,840,113549,1,9,5}
    OIDTimestampToken = asn1.ObjectIdentifier{1,2,840,113549,1,9,16,2,14}
    OIDCertificateRefs = asn1.ObjectIdentifier{1,2,840,113549,1,9,16,2,21}
    OIDCertificateValues = asn1.ObjectIdentifier{1,2,840,113549,1,9,16,2,23}
    OIDRevocationRefs = asn1.ObjectIdentifier{1,2,840,113549,1,9,16,2,22}
    OIDRevocationValues = asn1.ObjectIdentifier{1,2,840,113549,1,9,16,2,24}
)

func BuildSignedAttrs(contentType asn1.ObjectIdentifier, digest []byte, signingTime time.Time) ([]Attribute, error)
```

### 7. Write tests
- **Sign + Parse roundtrip**: sign content, parse, verify signature
- **Detached signature**: sign without content, verify with separate content
- **Encrypt + Decrypt roundtrip**: encrypt for recipient, decrypt with their key
- **Multiple signers**: add two SignerInfos
- **Attribute verification**: check signed attributes are correctly DER-encoded
- **Invalid signature**: tampered content → verify fails
- **Cross-compatibility**: if possible, verify against CZO test examples

## Acceptance Criteria
- [ ] `Sign()` produces valid CMS SignedData
- [ ] `ParseSigned()` + `VerifySigned()` correctly validates signatures
- [ ] Detached signature mode works
- [ ] `Encrypt()` produces valid CMS EnvelopedData
- [ ] `DecryptEnveloped()` recovers original content
- [ ] Signed attributes correctly constructed and verified
- [ ] ASN.1 encoding matches expected format (verifiable with `openssl asn1parse`)

## Notes
- CMS is complex — start with the simplest case (single signer, attached, no TSP) and expand
- The DER encoding of signed attributes must use explicit SET OF tag (0x31) not the implicit context tag
- jkurwa uses a "wicked PKCS#7 format" — some deviations from standard CMS may exist
- GOST key wrapping in EnvelopedData has specific parameter encoding — verify against jkurwa
- CAdES-BES = basic CMS signed data; CAdES-T adds timestamp; CAdES-XL adds OCSP and cert chain

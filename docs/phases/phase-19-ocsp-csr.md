# Phase 19 — OCSP Client & PKCS#10 CSR (`internal/ocsp`, `internal/csr`)

## Goal
1. Implement an **OCSP client** (RFC 2560 / RFC 6960) for certificate revocation
   checking against Ukrainian CA OCSP responders, mirroring
   `ocspreq_*` / `ocspresp_*` from cryptonite.
2. Implement **PKCS#10 Certificate Signing Requests** (RFC 2986) — build,
   sign, verify — mirroring `creq_*` from cryptonite.

## Prerequisites
- **Phase 5** (`dstu4145`) — signing CSRs
- **Phase 8** (`cert`, `oid`) — X.509 certificate structures
- **Phase 10** (`cms`) — OCSP responses embed CMS-like structures

## Packages
- `github.com/amaneshi/crypto-dstu/internal/ocsp` — new package
- `github.com/amaneshi/crypto-dstu/internal/csr` — new package

## Reference
- `_ref/cryptonite/src/pkix/c/api/ocsp_request.h`
- `_ref/cryptonite/src/pkix/c/api/ocsp_response.h`
- `_ref/cryptonite/src/pkix/c/api/certification_request.h`
- `_ref/cryptonite/src/pkix/c/engine/ocsp_request_engine.c`
- `_ref/cryptonite/src/pkix/c/engine/ocsp_response_engine.c`
- `_ref/cryptonite/src/pkix/c/engine/certificate_request_engine.c`

## Standards
- RFC 2986 — PKCS#10 Certification Request Syntax
- RFC 6960 — Online Certificate Status Protocol (OCSP)
- DSTU requirements for OCSP responders (Ukrainian CA profiles)

## Files to Create

| File | Action |
|------|--------|
| `internal/ocsp/request.go` | Build and DER-encode OCSP requests |
| `internal/ocsp/response.go` | Parse and verify OCSP responses |
| `internal/ocsp/client.go` | HTTP client; AIA URL extraction |
| `internal/ocsp/ocsp_test.go` | Tests |
| `internal/csr/csr.go` | Build, sign, verify PKCS#10 CSR |
| `internal/csr/csr_test.go` | Tests |

## Step-by-Step Instructions

### 1. OCSP Request (`ocsp/request.go`)

```go
// CertID identifies a certificate in an OCSP request.
type CertID struct {
    HashAlgorithm pkix.AlgorithmIdentifier
    IssuerNameHash []byte
    IssuerKeyHash  []byte
    SerialNumber   *big.Int
}

// NewCertID builds a CertID from the subject certificate and its issuer.
// hashAlg should be Kupyna-256 OID for modern UA PKI.
func NewCertID(cert, issuer *x509.Certificate, hashAlg asn1.ObjectIdentifier) (*CertID, error)

// Request is a DER-encodable OCSP request.
type Request struct { /* RFC 6960 OCSPRequest */ }

// NewRequest creates an OCSP request for the given certificates.
func NewRequest(ids []*CertID) (*Request, error)

// Marshal returns the DER encoding.
func (r *Request) Marshal() ([]byte, error)
```

### 2. OCSP Response (`ocsp/response.go`)

```go
type CertStatus int
const (
    Good    CertStatus = 0
    Revoked CertStatus = 1
    Unknown CertStatus = 2
)

type SingleResponse struct {
    CertID         CertID
    Status         CertStatus
    RevocationTime time.Time  // zero if Status != Revoked
    ThisUpdate     time.Time
    NextUpdate     time.Time
}

type Response struct {
    Status        int            // 0 = successful
    ProducedAt    time.Time
    Responses     []SingleResponse
    Certificates  []*x509.Certificate
}

// ParseResponse decodes a DER-encoded OCSPResponse.
func ParseResponse(der []byte) (*Response, error)

// Verify checks the OCSP response signature against the responder cert or issuer.
func (r *Response) Verify(issuer *x509.Certificate) error
```

### 3. OCSP HTTP Client (`ocsp/client.go`)

```go
// Client performs OCSP requests over HTTP.
type Client struct {
    HTTP    *http.Client
    URL     string // override; if empty, AIA from cert is used
}

// Check fetches and parses the OCSP status for cert issued by issuer.
func (c *Client) Check(cert, issuer *x509.Certificate) (*Response, error)

// AIAOCSPURLs extracts OCSP URLs from the certificate's AIA extension.
func AIAOCSPURLs(cert *x509.Certificate) []string
```

Known Ukrainian OCSP responder URLs (for documentation / default fallback):
- `http://czo.gov.ua/services/ocsp/`
- `http://acskidd.gov.ua/services/ocsp/`

### 4. PKCS#10 CSR (`csr/csr.go`)

```go
// Request is a PKCS#10 CertificationRequest.
type Request struct {
    Subject     pkix.Name
    PublicKey   crypto.PublicKey
    Extensions  []pkix.Extension
    ExtraNames  []pkix.AttributeTypeAndValue
}

// NewRequest builds and signs a CSR using the given private key.
// Uses DSTU 4145 sig-alg OID derived from the key's curve.
func NewRequest(req *Request, priv crypto.Signer) ([]byte, error) // returns DER

// ParseRequest parses a DER-encoded CertificationRequest.
func ParseRequest(der []byte) (*Request, error)

// Verify checks the self-signature on the CSR.
func (r *Request) Verify() error
```

Subject fields must support Ukrainian DN attributes (EDRPOU, DRFO) via
`oid` package OIDs.

### 5. Tests

OCSP:
- Build a request for a synthetic cert → verify DER structure
- Parse a known OCSP response fixture → check status / time fields
- Wrong-signature response → `Verify` returns error
- HTTP client: mock server returning canned response → success path

CSR:
- Generate DSTU 4145 key → build CSR → parse → `Verify` succeeds
- Tampered CSR DER → `Verify` returns error
- Subject round-trip includes EDRPOU attribute

## Acceptance Criteria
- [ ] OCSP request DER matches expected ASN.1 structure
- [ ] OCSP response parser extracts `Good` / `Revoked` / `Unknown` + times
- [ ] Response `Verify` accepts valid signature; rejects tampered
- [ ] HTTP client posts to mock server; parses response correctly
- [ ] CSR `NewRequest` produces DER verifiable by `ParseRequest + Verify`
- [ ] CSR `Verify` returns error on tampered DER
- [ ] Ukrainian EDRPOU/DRFO attributes survive CSR round-trip

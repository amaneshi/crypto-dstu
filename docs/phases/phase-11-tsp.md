# Phase 11 — Timestamp Protocol `tsp`

## Goal
Implement RFC 3161 Timestamp Protocol (TSP) for requesting and verifying timestamps on digital signatures. Timestamps are mandatory for long-term signature storage in Ukrainian PKI since November 2018.

## Prerequisites
- **Phase 3** (`kupyna`/`gost34311`) — hash function for message imprint
- **Phase 10** (`cms`) — TSP responses contain CMS SignedData
- **Phase 8** (`cert`, `oid`) — certificate verification for TSP authority

## Package
`crypto-dstu/tsp`

## JS Reference
- `jkurwa/lib/util/tsp.js` — TSP request building, response parsing
- `jkurwa/lib/spec/dstszi.js` — ASN.1 schemas for TSP
- Agent `--tsp` option: `signature`, `content`, `all`

## Standards
- RFC 3161 — Internet X.509 PKI Time-Stamp Protocol (TSP)
- RFC 5816 — ESSCertIDv2 update

## Files to Create

| File | Purpose |
|------|---------|
| `tsp/request.go` | Build TSP request from message hash |
| `tsp/response.go` | Parse TSP response, extract timestamp token |
| `tsp/verify.go` | Verify timestamp token (signature + time) |
| `tsp/client.go` | HTTP client for TSP server communication |
| `tsp/tsp_test.go` | Tests |

## Step-by-Step Instructions

### 1. TSP Request (`request.go`)
```go
type Request struct {
    Version        int
    MessageImprint MessageImprint
    ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
    Nonce          *big.Int              `asn1:"optional"`
    CertReq        bool                  `asn1:"optional,default:false"`
}

type MessageImprint struct {
    HashAlgorithm pkix.AlgorithmIdentifier
    HashedMessage []byte
}

func NewRequest(hash []byte, hashAlgOID asn1.ObjectIdentifier) (*Request, error)
func (r *Request) Marshal() ([]byte, error)
```

Building a request:
1. Hash the data to be timestamped (signature bytes or content bytes)
2. Set the hash algorithm OID (Kupyna-256 or GOST 34.311)
3. Generate random nonce for replay protection
4. Set `CertReq = true` to request TSA certificate in response
5. DER-encode the request

### 2. TSP Response (`response.go`)
```go
type Response struct {
    Status         PKIStatusInfo
    TimeStampToken asn1.RawValue `asn1:"optional"` // CMS SignedData
}

type PKIStatusInfo struct {
    Status       int
    StatusString []string       `asn1:"optional"`
    FailInfo     asn1.BitString `asn1:"optional"`
}

type TSTInfo struct {
    Version        int
    Policy         asn1.ObjectIdentifier
    MessageImprint MessageImprint
    SerialNumber   *big.Int
    GenTime        time.Time
    Accuracy       Accuracy       `asn1:"optional"`
    Ordering       bool           `asn1:"optional,default:false"`
    Nonce          *big.Int       `asn1:"optional"`
    TSA            asn1.RawValue  `asn1:"optional,explicit,tag:0"`
}

type Accuracy struct {
    Seconds int `asn1:"optional"`
    Millis  int `asn1:"optional,implicit,tag:0"`
    Micros  int `asn1:"optional,implicit,tag:1"`
}

func ParseResponse(der []byte) (*Response, error)
func (r *Response) Token() ([]byte, error)      // extract raw CMS token
func (r *Response) TSTInfo() (*TSTInfo, error)   // parse the inner TSTInfo
```

Parsing flow:
1. Decode `TimeStampResp` ASN.1 structure
2. Check `status` — 0 (granted) or 1 (grantedWithMods) are success
3. Extract `TimeStampToken` which is a CMS `ContentInfo` containing `SignedData`
4. Parse inner `SignedData` to get the `TSTInfo` from encapsulated content
5. `TSTInfo` contains the actual timestamp: `GenTime`, `MessageImprint`, `SerialNumber`

### 3. Verification (`verify.go`)
```go
func VerifyToken(token []byte, originalHash []byte, caCerts []*cert.Certificate) (*TSTInfo, error)
```

Verification steps:
1. Parse token as CMS `SignedData` (using Phase 10 `cms.ParseSigned()`)
2. Verify CMS signature using TSA certificate
3. Verify TSA certificate chain against provided CA list
4. Extract `TSTInfo` from signed content
5. Verify `MessageImprint.HashedMessage == originalHash`
6. Verify `MessageImprint.HashAlgorithm` matches expected algorithm
7. Check nonce matches (if provided in original request)
8. Return `TSTInfo` with verified timestamp

### 4. HTTP Client (`client.go`)
```go
type Client struct {
    URL    string        // TSP server URL
    HTTP   *http.Client
}

func NewClient(url string) *Client

func (c *Client) Timestamp(hash []byte, hashAlgOID asn1.ObjectIdentifier) (*Response, error)
```

Known Ukrainian TSP server URLs:
- `http://czo.gov.ua/services/tsp/` — CZO (Central Certification Authority)
- `http://acskidd.gov.ua/services/tsp/` — ACSK IDD
- Other CAs have their own TSP endpoints

HTTP request:
- Method: `POST`
- Content-Type: `application/timestamp-query`
- Body: DER-encoded TSP request
- Expected response Content-Type: `application/timestamp-reply`

### 5. Integration with CMS signatures
TSP tokens are stored as unsigned attributes in CMS `SignerInfo`:
- **Signature timestamp** (`id-aa-signatureTimeStampToken`, OID 1.2.840.113549.1.9.16.2.14): timestamp of the signature itself
- **Content timestamp** (`id-aa-ets-contentTimestamp`, OID 1.2.840.113549.1.9.16.2.20): timestamp of the content

For CAdES-T level:
1. After signing, hash the signature value
2. Request timestamp from TSP server
3. Add timestamp token as unsigned attribute to SignerInfo

```go
func AddSignatureTimestamp(signerInfo *cms.SignerInfo, tspClient *Client, hashOID asn1.ObjectIdentifier) error
func AddContentTimestamp(signedData *cms.SignedData, tspClient *Client, hashOID asn1.ObjectIdentifier) error
```

### 6. Write tests
- **Request building**: marshal request, verify ASN.1 structure
- **Response parsing**: parse known TSP response bytes
- **TSTInfo extraction**: verify timestamp, hash, nonce
- **Verification**: valid token → success, tampered → failure
- **Nonce mismatch**: different nonce → error
- **HTTP client**: mock server or integration test against CZO TSP (if available)

Test fixtures in `testdata/tsp/`:
- `testdata/tsp/sample_request.der`
- `testdata/tsp/sample_response.der`

## Acceptance Criteria
- [ ] TSP request correctly DER-encoded
- [ ] TSP response parsing extracts TSTInfo with timestamp
- [ ] Token verification checks signature, hash, and certificate
- [ ] HTTP client successfully communicates with TSP server
- [ ] Timestamp tokens can be added as CMS unsigned attributes
- [ ] Invalid/tampered tokens are rejected

## Notes
- TSP is mandatory for signatures created after Nov 7, 2018 (for legal validity)
- Agent supports `--tsp signature` (sign timestamp), `--tsp content` (content timestamp), `--tsp all` (both)
- TSP server availability may vary — handle network errors gracefully
- The `czo.gov.ua/verify` tool checks TSP timestamps when validating signatures
- Some TSP servers may not support Kupyna hash — fall back to GOST 34.311 if needed

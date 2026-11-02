# Timestamp verification

Signature timestamps are opt-in. CMS `signingTime` remains a claimed signer time;
only an authenticated RFC 3161 token produces a valid `TimestampResult`.

```go
result, err := box.UnsignDocumentWithOptions(ctx, signedDER, originalContent,
    ua.VerificationOptions{
        TimestampPolicy: ua.TimestampRequireSignature,
        TSARoots:        [][]byte{explicitlyTrustedTSARootDER},
        Revocation:      ua.RevocationRequireOCSP,
        OCSPResponses:   savedOCSPResponses,
        ResponderCRLs:   savedResponderCRLs,
    })
if err != nil {
    return err // no document content is released
}
for _, timestamp := range result.Timestamps {
    useVerifiedTimestamp(timestamp.SignerIndex, timestamp.Time)
}
```

`TimestampIgnore` is the default and makes no TSA claims.
`TimestampVerifyIfPresent` checks every supplied signature timestamp but permits
an absent timestamp. `TimestampRequireSignature` requires at least one valid
signature timestamp for every document signer. Invalid supplied timestamps fail
both checking policies. TSA trust is selected separately through `TSARoots`,
which accepts DER certificates and is copied before fetch callbacks run.
Certificates from the document and `Box` discovery store may help resolve a TSA
or intermediate, but cannot become trust anchors.

Each `TimestampResult` reports its document signer index, TSA identity, verified
`Time`, and separate `RevocationStatus`. `Valid` establishes the signature,
imprint, TSA authorization and configured revocation policy. With revocation
disabled, its status remains `not-checked`; it does not imply revocation was good.
With required OCSP, evidence is needed for both document and TSA certificate
paths, except their explicit anchors. The same supplied responses or explicit
fetch callback serve both paths. See [revocation policy](revocation.md).

## Acceptance checks

The verifier implements the relevant checks in [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html)
and [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html):

- Require encapsulated `id-ct-TSTInfo`, one TSA signer and authenticated
  SigningCertificate or SigningCertificateV2 binding to that certificate.
- Validate the CMS signature and signed content digest/type attributes.
- Hash the exact parent CMS signature value octets, without an ASN.1 wrapper,
  using the token's supported imprint algorithm. A content timestamp cannot
  substitute for a signature timestamp.
- Require a single critical EKU containing only `id-kp-timeStamping`, signing
  key usage when present, and a path to an explicitly selected anchor.
  Enforce EKU restrictions on issuing certificates as well.
- Validate the TSA path at current time and require every certificate on that
  path to cover `genTime`. Check an optional TSA name against the certificate.
- Reject malformed/noncanonical fields, unsupported critical extensions,
  invalid accuracy/version/serial/nonce values, future times beyond five minutes,
  duplicate signature-timestamp attributes and excessive token values (over 16).
  Tokens and protocol responses are bounded to 4 MiB.

Direct protocol users should retain the original request and call
`VerifyResponse(response, request, roots, now, discovery...)`. This also binds
the algorithm/imprint pair, nonce, requested policy and requested certificate
inclusion. `NewRequest` generates a 128-bit nonce and requests the TSA certificate.
`SendContext` has context support, bounded responses and a default 15-second
HTTP timeout with redirects rejected. A custom HTTP client owns its transport
policy. Fetching/parsing a response alone does not authenticate it. The older
hash-only `VerifyToken` API cannot bind a caller-selected expected algorithm;
use `VerifyImprint`, `VerifyResponse` or `VerifySignatureTimestamp` instead.

## CLI

```text
dstu decrypt -key Key-6.dat:password -cert signer.cer -ca roots.p7b \
  -require-timestamp -tsa-root tsa-root.cer \
  -require-ocsp -ocsp-response signer.ocsp -ocsp-response tsa.ocsp \
  -input receipt.cms -output receipt.xml -v
```

`-tsa-root` is repeatable and verifies present signature timestamps. Add
`-require-timestamp` to require one per signer. Additional TSA certificates can
be supplied through repeatable `-cert`. The same checks apply after decryption;
failed acceptance does not create the output file. Verbose output distinguishes
claimed signer time from verified timestamp results and their revocation status.

## Independent interoperability

On 2026-11-01 a live request to the public CZO test TSA passed full request-bound
verification with a GOST imprint and a Kupyna-256 PB-LE TSA signature. The
request, token, selected root and SHA-256 provenance manifest are retained in
`internal/tsp/testdata/czo-live`.

Both official CZO CAdES-T examples (DSTU and DSTU-7564), dated 2024-03-04, also
pass signature-imprint and TSA-path verification. Their tokens omit the TSA
certificate, so the public CA archive supplies discovery certificates. Copies,
explicit roots and manifests are retained in `internal/tsp/testdata/czo-examples`.
These tests use fixed historical times solely for wire/signature interoperability;
they do not establish historical revocation status or current acceptance.

```text
go test -tags=integration -count=1 ./internal/tsp \
  -run 'TestCapturedCZOTimestamp|TestCZOExampleSignatureTimestamps'
```

A new live request is opt-in: set `TSP_LIVE=1`, `TSP_PUBLIC_URL`, and
`TSP_PUBLIC_ROOTS` (semicolon-separated public DER certificate paths). Optionally
set `TSP_PUBLIC_CAPTURE` to save the request and token, then run
`go test -tags=integration -count=1 ./internal/tsp -run TestLivePublicTimestamp`.
Only fixed public test bytes are timestamped; no taxpayer key is involved.

This milestone does not validate content/archive timestamps, implement
CAdES-LT/LTA, or establish historical
validity of an expired/revoked document signer. Production document and TSA
paths still require current validity. Trusted timestamp evidence alone does not
replace historical revocation evidence or an archival validation policy.

## Creating signature timestamps

Timestamp generation is explicit and fails closed. Add `Timestamp` to signing
options; the default still creates an untimestamped signature without networking.

```go
signed, err := box.SignDocumentWithContext(ctx, content, ua.SignOptions{
    NoTax: true,
    Timestamp: &ua.TimestampSignOptions{
        TSARoots: [][]byte{tsaRootDER},
        Fetch: fetchTimestampResponse,
        RevocationOptions: ua.VerificationOptions{
            Revocation: ua.RevocationRequireOCSP,
            FetchOCSP: fetchOCSPResponse,
        },
    },
})
```

The optional Fetch callback receives `ua.TimestampRequest{DER: ...}` and returns
complete DER TimeStampResp bytes. It receives only a signature imprint and a
fresh nonce; private keys and document content stay local. If Fetch is nil,
explicitly configured `Box.AddTSP` endpoints are used with the bounded TSP client.
The default imprint is GOST 34.311; `ImprintAlgorithm` selects another supported
hash. Request bytes and input content are copied before callbacks run.

Before embedding, the library validates the original request's nonce and exact
algorithm/imprint, response status, certificate inclusion, TSA signature/binding,
TSA usage/path and requested revocation policy. A rejected response never
produces a partially signed output. The original CMS signature octets and signed
attributes are preserved when the unsigned timestamp attribute is appended.
The writer supports fresh single-signer SignedData, including attached, detached,
empty content and tax transport output. Content/archive timestamp creation remains
unsupported. Revocation is not checked unless explicitly required; creation
without it does not imply a qualified or archival validation result.

`SignAndEncryptWithContext` performs the same timestamp step before encryption.
The existing context-free signing methods remain wrappers using a background
context. Cancellation, timestamp failures and encryption failures return no bytes.

The CLI enables the same flow explicitly:

```text
dstu sign -key Key-6.dat:password -cert signer.cer \
  -tsp-level signature -tsp https://explicit-test-tsa.example/tsp \
  -tsa-root tsa-root.cer -input report.xml -output report.cms -no-tax
```

Add `-crypt recipient.cer` for sign/timestamp/encrypt. Both URL and TSA trust
are required for CLI timestamp creation. CLI signing currently authenticates the
TSA path without online revocation; applications needing required TSA revocation
should use `TimestampSignOptions.RevocationOptions`. Content/all timestamp levels
and chain-embedding flags remain rejected.

Live CZO CAdES-T creation and roundtrip verification passed on 2026-11-01 using a
disposable document key and fixed public content. The public CMS, content and
selected document/TSA roots are in `internal/tsp/testdata/created-cades-t` with
SHA-256 manifests. The private key was not retained. The offline regression uses
the recorded timestamp, since the disposable certificate expires after one day.
This proves cryptographic interoperability at that fixed time, not current or
historical revocation status. The older IIT SDK rejects this minimal-certificate control even without its
timestamp. A separate fixture using the established IIT-compatible certificate
profile now passes native CAdES-T verification; see below.

Run the fixed-time creation check with
`go test -tags=integration ./internal/tsp -run TestCapturedCreatedCZOTimestamp`.
A new live creation check is opt-in through `TSP_LIVE_CREATION=1`,
`TSP_PUBLIC_URL` and `TSP_PUBLIC_ROOT` (one explicit public DER root), using
`go test -tags=integration -count=1 ./ua -run TestLiveCreateCZOSignatureTimestamp`.
`TSP_CREATION_CAPTURE` optionally saves public output artifacts only.

## Native IIT timestamp interoperability

The remaining timestamp-specific IIT gap was closed on 2026-11-01 using the
pinned x86 SDK version 1.3.1.224. New tests use an IIT-generated disposable PB257
key and a Go-created certificate with the public CZO domain/DKE parameters and
key-identifier extensions used by the already passing native signing tests.
The untimestamped control is accepted before any timestamp test runs.

Both attached and detached signatures with Go-produced GOST TSA tokens are
accepted. IIT rejects a corrupted TSA signature and a separately valid token
whose imprint belongs to other data. A live public CZO token using a GOST imprint
and Kupyna-256 PB-LE TSA signature is also accepted by IIT when embedded into the
Go-produced CMS. This capture and its untimestamped control are retained with
SHA-256 manifests in `internal/interop/testdata/iit-czo-cades-t`. No private key
is retained. Go verifies this same fixed-time capture independently.

The adapter's optional `require_timestamp: true` mode requires a signature
timestamp for every signer, after native cryptographic verification succeeds.
It reads `EUGetSignTimeInfo` / `EU_TIME_INFO.bSignTimeStampAvail`. The older
`EU_SIGN_INFO.bTimeStamp` field describes a content timestamp and does not
identify the unsigned signature timestamp used by CAdES-T. Tests ensure a claimed
CMS signingTime alone cannot satisfy this requirement.

These native results still use the explicit `offline-no-revocation` policy.
They demonstrate cryptographic acceptance and timestamp recognition, not current
or historical revocation validity, legal qualification, or production CA trust.
Production Go acceptance continues to use its configured current-time policy.
The test adapter does not fetch timestamps or contact a CA; only the separately
opted-in live test sends a public imprint to CZO.

The regular IIT script now runs both CMS and timestamp interoperability tests:

```powershell
./scripts/test-iit.ps1 -SdkDirectory 'C:\path\to\iit-sdk' `
  -ExpectedSDKHash '<sha256-of-EUSignCP.dll>'
```

The retained public capture can be verified without IIT or network access using
`go test -tags=integration ./internal/interop -run TestCapturedIITCZOInGo`.

A new native/live CZO check additionally requires `IIT_LIVE_TSP=1`,
`TSP_PUBLIC_URL` and `TSP_PUBLIC_ROOT` alongside the usual adapter/SDK variables.
Run `go test -tags=integration -count=1 ./internal/interop -run TestIITLiveCZOSignatureTimestamp`.
`IIT_TSP_CAPTURE` optionally saves public artifacts only.

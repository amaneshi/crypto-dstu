# Certificate revocation verification

`Box.UnsignDocumentWithOptions` and `Box.VerifyCertWithOptions` support an explicit
current-time OCSP policy. The existing methods keep offline chain/signature
verification; signer results now report `RevocationNotChecked` in that mode.

```go
ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()

result, err := box.UnsignDocumentWithOptions(ctx, signedDER, nil, ua.VerificationOptions{
    Revocation:    ua.RevocationRequireOCSP,
    OCSPResponses: savedResponses, // [][]byte containing complete DER OCSPResponse values
})
if err != nil {
    return err // result.Content is empty on verification failure
}
useVerifiedContent(result.Content)
```

For detached signatures, pass the original document as the third argument.
The verifier snapshots both inputs before verification and before calling external
fetch code, so later changes to the caller's buffers cannot change verified output.

For live evidence, configure `FetchOCSP func(context.Context, ua.OCSPRequest)
([]byte, error)`. It receives encoded request bytes, the subject and issuer
certificates, and certificate-advertised responder URLs. The application owns
endpoint selection, allowlists, network access, HTTP limits and deadlines.
The library does not automatically contact AIA URLs. A successful callback is
only delivery of bytes: the library still authenticates every matching response.
Supplying responses or a callback while leaving revocation disabled is a
configuration error, so evidence cannot be silently ignored.

Supplied responses are checked first; the callback runs only when there is no
matching supplied response. Invalid matching evidence never falls back to a
different response or to an offline success. Provide evidence for each non-anchor
certificate on the validated leaf-to-root path, including intermediates.

## Acceptance policy

The checker follows the acceptance requirements in
[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html#section-3.2):

- Match the complete CertID: serial number, issuer name hash and issuer key hash.
  The key hash uses the exact subjectPublicKey BIT STRING contents, not an EC
  coordinate reconstructed from the public point.
- Authenticate the responder ID and signature. The issuer may sign directly.
  A delegated signer must be issued directly by that issuer, be currently valid,
  permit signatures, and carry the OCSP signing extended key usage.
- A delegated responder must have a noncritical `id-pkix-ocsp-nocheck` NULL
  extension, or supplied full issuer-signed CRL evidence proving that responder
  is not listed. Set `ResponderCRLs` to complete DER CRLs. CRLs must be current,
  direct, unscoped v2 lists; delta/indirect/scoped lists and unsupported critical
  extensions are rejected. The issuer must permit CRL signing when key usage
  is present. Both inner and outer signature algorithms must match.
- Responder CRLs require `nextUpdate`; `MaxResponderCRLAge` defaults to seven
  days. OCSP clock tolerance also applies to CRLs. Every supplied matching CRL
  must pass; an older clean list cannot override a listed responder. Every listed
  serial is rejected conservatively, including duplicate and `removeFromCRL`
  entries observed in public full lists. Freshest-CRL URLs are advisory; no delta
  is fetched or merged. CRL inputs are bounded to 16 MiB.
- Reject revoked, unknown, malformed, duplicate matching, unauthenticated,
  expired and future-dated evidence. Unsupported critical response extensions
  are rejected.
- Bound both `thisUpdate` and `producedAt` age. Default maximum age is 24 hours;
  default clock tolerance is 5 minutes. `nextUpdate`, when present, is enforced.
  `MaxOCSPAge` and `OCSPClockSkew` override these defaults with positive durations.

Revocation checking excludes the explicit trust anchor. A leaf explicitly pinned
as an anchor reports `RevocationNotApplicable` (`trust-anchor`), not `good`.
Missing evidence or fetch/cancellation failures report `unavailable`, invalidate
the affected signer, and prevent any document content from being returned.

`RevocationGood` means all non-anchor certificates on that validated path passed
this policy. It does not establish that a signer is authorized to represent DPS.
Applications must check the expected signer identity separately.

## CLI

```text
dstu decrypt -key Key-6.dat:password -cert signer.cer -ca roots.p7b \
  -require-ocsp -ocsp-response signer.ocsp -ocsp-response intermediate.ocsp \
  -input receipt.cms -output receipt.xml -v
```

`-ocsp-response` and `-responder-crl` are repeatable and each enables required OCSP. The same policy
is enforced after decryption. The output file is not created on failure.
Verbose output includes the actual revocation status.

The standalone command can also validate saved evidence:

```text
dstu ocsp -cert signer.cer -issuer trusted-issuer.cer -response signer.ocsp \
  -responder-crl issuer-full.crl
```

Without `-response`, that explicitly invoked command fetches from `-url` or the
certificate's AIA. It authenticates the matching status before printing `good`.
`-issuer` is the caller-selected trusted issuer; this command does not discover
a trust path for it. The HTTP client has context/deadline and response-size limits.

## Validation and remaining coverage

Tests cover issuer and delegated responses, both responder ID forms, issuer-key
hash binding, wrong serials, revoked/unknown statuses, stale/future responses,
intermediate revocation, cancellation, callback input mutation, and CLI output
suppression. An optional independent archived Cryptonite DSTU OCSP fixture is
also checked for decoding and signature interoperability:

```text
go test -tags=integration ./internal/ocsp -run TestCryptoniteOCSPFixture
```

Live interoperability passed on 2026-11-01 against the public CZO test CA OCSP
endpoint for GOST and Kupyna-256 PB-LE certificates, including delegated responder
authorization with independently fetched full CRLs. Public captures, source URLs
and SHA-256 manifests are in `internal/ocsp/testdata/czo-{2021,2025}`. The newer
archive uses a 2026 CA name and `TestCSK-2026-Full.crl` despite its 2025 filename.
These fixtures validate at fixed capture times and are not current status evidence.
After optimizing Kupyna's MDS transformation and row shifts, the captured 8.5 MB
Kupyna CRL check takes approximately 1.1 seconds on the development machine, down
from 38–42 seconds. See [performance measurements](kupyna-performance.md).
Validation still authenticates the full CRL on every check; it does not cache or
skip evidence verification.

```text
go test -tags=integration -timeout=120s ./internal/ocsp -run TestCapturedCZOOCSP
```

A live check is opt-in: set `OCSP_LIVE=1`, `OCSP_PUBLIC_SUBJECT`,
`OCSP_PUBLIC_ISSUER`, `OCSP_PUBLIC_URL`, and `OCSP_PUBLIC_RESPONDER_CRL` to
explicit public certificate/CRL files and endpoint, then run
`go test -tags=integration -timeout=120s ./internal/ocsp -run TestLivePublicOCSP`.
`OCSP_PUBLIC_CAPTURE` optionally saves the exact request and response. The test
never obtains or uses taxpayer private keys. The supplied issuer is an explicit
trust selection; this single-certificate live check does not establish a full
application certificate path or trust in a production CA.

General leaf CRL fallback, recursive responder OCSP, delta CRL merging, historical
validation based on trusted timestamps, nonce binding and automatic network
fetching remain unsupported. Cached responses use bounded freshness.

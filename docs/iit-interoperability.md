# Independent IIT interoperability tests

This is an optional development check for the cryptographic library. It does not
submit reports, call the tax API, or add an IIT dependency to library consumers.

The Windows `cmd/iit-oracle` adapter invokes the installed IIT native SDK in a
separate process. Requests and responses are JSON over standard input/output;
binary fields use base64. The adapter supports GOST/Kupyna hashing, attached/detached
CMS signing and verification, disposable PB191/PB257/PB307 key generation, and
CMS encryption/decryption with dynamic or certificate-referenced static originators.
The `key-info` operation returns IIT's opaque public key-information blob without
requiring a signing certificate; tests compare this blob without treating it as DER.
It verifies every signer and returns data only on success. The optional verify
request field `require_timestamp: true` additionally requires a recognized
signature timestamp for every signer. This field is rejected for other operations.

## Run

Provide a compatible IIT SDK directory with `EUSignCP.dll` and its auxiliary DLLs.
The SDK is not redistributed here. IIT publishes its [API documentation](https://iit.com.ua/downloads)
and describes its [libraries and integration examples](https://eu.iit.com.ua/).

From PowerShell on Windows:

```powershell
./scripts/test-iit.ps1 -SdkDirectory 'C:\path\to\iit-sdk'
```

The script detects whether the DLL is x86 or x64, builds a matching adapter,
copies only native DLLs to a temporary directory, and runs the interoperability
tests. It restores process environment variables and removes the temporary copy.
The adapter uses a new configuration/certificate store for each invocation,
disables network services and UI, and does not load application key stores.

To add the archived public CZO example, extract the certificate archive from
[CZO test CA certificates](https://czo.gov.ua/testca-certificates) and supply it:

```powershell
./scripts/test-iit.ps1 `
  -SdkDirectory 'C:\path\to\iit-sdk' `
  -TestCADirectory 'C:\path\to\extracted-CA-FULL' `
  -ExpectedSDKHash '<sha256-of-EUSignCP.dll>'
```

`-GoExecutable` can select a Go executable outside PATH. The SDK hash is printed
and checked on every response; pin `-ExpectedSDKHash` for reproducible CI runs.
The script does not download the SDK or CA bundle. The project's existing CZO
fixture helper may download public examples if they are missing from testdata.

For a prebuilt adapter, set `IIT_ORACLE`, `IIT_SDK_DIR`, optionally
`IIT_TEST_CA_DIR` and `IIT_SDK_SHA256`, then run:

```text
go test -tags=integration -count=1 -v ./internal/cms -run '^TestIIT'
go test -tags=integration -count=1 -v ./internal/interop -run '^TestIIT'
```

The regular suite excludes IIT tests through the `integration` build tag.
With that tag enabled, missing environment configuration explicitly skips them. Selecting a configured adapter that fails is a test failure, not a skip.

## What is checked

- GOST 34.311 hashing: empty input, single byte, and block-boundary/multiblock cases.
- Go-produced attached and detached DSTU 4145/GOST CMS signatures verified by IIT.
- Fresh IIT-produced attached and detached signatures verified by Go, including
  modified-content rejection and wrong-password rejection.
- IIT-generated disposable PFX keys parsed by Go; Go-written PKCS#8/Key-6 keys
  imported by IIT for signing.
- Encryption in both directions with separate sender and recipient keys, for
  payload lengths 1, 7, 8, 9, 31, 32, 33 and 1001 bytes.
- Wrong decryption keys and damaged wrapped content keys rejected by both implementations.
- Static-originator encryption in both directions, resolving issuer/serial references
  against supplied certificates. Missing sender certificates fail in both implementations.
- Go also resolves subject-key-identifier references and embedded originator certificates;
  duplicate identical certificates are allowed, while ambiguous identities are rejected.
- Exact recovery of binary data, including NUL, non-UTF-8 bytes, Cyrillic and CRLF.
- Modified attached or detached content rejected by IIT.
- A public CZO signature accepted by both IIT and Go (when test CA files are supplied).
- Attached/detached CAdES-T signatures accepted by IIT with explicit native
  signature-timestamp recognition. A claimed signingTime alone is rejected when
  a timestamp is required; corrupted tokens and valid tokens for wrong imprints
  are rejected without returning data.
- A retained real CZO timestamp with a Kupyna TSA signature, embedded in Go CMS,
  accepted by both Go and IIT without network access. Live refresh is separate
  and opt-in; see [timestamp interoperability](timestamps.md#native-iit-timestamp-interoperability).

Production checks that do not need IIT include fixed Cryptonite PB257/PB367
signature/public-key vectors, complete point compression/decompression, strict
order-sized raw signature serialization, and certificate binding checks.

The tests generate disposable Go and IIT keys and self-signed end-entity test
certificates for each run. Only public curve/DKE parameters are reused from the
CZO example; its identity and key are not reused. Generated certificates are
trusted only in that invocation's temporary IIT store. Private-key inputs are
in-memory test containers sent over the adapter's standard input; the adapter
does not open key files or emit key material in diagnostics. IIT key generation
returns an encrypted disposable PFX to the test process and makes no CA request.

## Recorded baseline

Validated on 1 November 2026 with the IIT DLL supplied by the local EDZV package:

- File version: `1.3.1.224`, architecture: x86.
- `EUSignCP.dll` SHA256:
  `475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f`.
- Tests use a 32-bit adapter with the Go tests running on amd64.

This baseline led to corrections in DSTU public-key sign convention, r/hash
truncation, compressed-point trace bits, national X.509 signature decoding,
order-sized CMS signatures, and ESS SigningCertificateV2 generation.

The bidirectional tests additionally corrected the Key-6 HMAC/CFB identifiers,
PKCS#8 algorithm parameters, full explicit-curve matching, CMS CFB/wrap/agreement
identifiers, compressed originator keys, KDF explicit tags and NULL parameters,
and GOST MAC word order. A fixed Cryptonite MAC vector runs without the IIT SDK.

The timestamp adapter uses `EUGetSignTimeInfo` and the signature-specific
`EU_TIME_INFO.bSignTimeStampAvail` field after native verification succeeds.
`EU_SIGN_INFO.bTimeStamp` describes a content timestamp. Native metadata
recognition supplements cryptographic positive/negative controls; it does not
add revocation or historical trust guarantees. The `EU_TIME_INFO` ABI size and
field offsets are checked on both Windows Go architectures.

## Limits

All adapter responses are labelled `offline-no-revocation`. IIT's historical
verification API may use the time contained in an archived signature. Acceptance
in these tests does not establish current certificate validity, revocation status,
or authorization to represent DPS.

The document-signing matrix covers these profiles with attached and detached
messages, checks the actual CMS digest identifier, and rejects modified content:

| Profile | Go signs, IIT verifies | IIT signs, Go verifies |
| --- | --- | --- |
| GOST / PB191 | Yes | Yes |
| GOST / PB257 | Yes | Yes |
| GOST / PB307 | Yes | Yes, using IIT PFX and Go Key-6 containers |
| GOST / PB367 | Yes | Yes, using a Go-generated Key-6 container |
| GOST / PB431 | Yes | Yes, using a Go-generated Key-6 container |
| Kupyna-256 / PB257 | Yes | Yes |
| Kupyna-512 / PB431 | Yes | Yes, using explicit native hash/signing APIs |

`TestIITNationalHashProfiles` also compares GOST, Kupyna-256 and Kupyna-512
digests across their block and padding boundaries. `EUCtxSignData` does not
distinguish Kupyna digest sizes and returned Kupyna-256 in the original 512-bit
probe. The adapter now selects Kupyna-512 with `EUCtxHashData` and passes the
64-byte hash to `EUCtxSignHashValue` for detached signatures. Attached output
uses `EUCtxCreateSigner`, `EUCtxCreateEmptySign` and `EUCtxAppendSigner`; the SDK
creates the complete CMS encoding. No Go signature or CMS writer substitutes
for the native writer in this path.

Every explicit native signing request checks the returned container digest set,
signer digest, signature algorithm and attached/detached mode before returning
bytes. A successful SDK call with another profile fails explicitly. Native
Kupyna-512 attached requests require exactly one signer certificate and nonempty
content: IIT's empty-container API omits an empty payload. Detached empty
signatures work. The native tests cover binary, empty and multiblock input, and
both Go and IIT verify the successful results.

The public `internal/interop/testdata/iit-kupyna512` fixtures retain attached and
detached native signatures, their disposable signing certificate, content and
the SDK hash. No private key is retained. `TestCapturedNativeKupyna512` verifies
these vectors without IIT or network access and rejects changed content and
signature bytes. This is a mathematical regression check with a short-lived
test certificate, not a current-time trust assertion. To refresh public fixtures,
set `IIT_CAPTURE_512_DIR` to an explicit absolute directory and run
`TestIITKupyna512HashSigning` with the pinned adapter/SDK configuration.

Fresh IIT Kupyna keys additionally exercise PBES2 with Kupyna MAC-256 as the
PBKDF2 PRF, a password padded with zeros to 32 bytes, and Kalyna-256 CBC with
PKCS#7 padding. The loader supports passwords up to 32 bytes for this profile;
longer values fail explicitly. GOST key containers retain their existing password
behavior. Derived keys and decrypted key bytes are cleared after use. The loader
rejects unknown PRFs/ciphers, invalid parameters, padding, key lengths and work
factors above 1,000,000 iterations.
The algorithm identifiers are listed in the
[national OID registry](https://cip.gov.ua/ua/news/perelik-ob-yektnikh-identifikatoriv-algoritmiv-kriptografichnogo-zakhistu-informaciyi-kriptografichnikh-protokoliv-ta-politik-sertifikaciyi-z-yikh-vikoristannyam).

`ua.ProtectKey(rawPKCS8, password)` writes a Key-6 EncryptedPrivateKeyInfo
using Kupyna MAC-256 PBKDF2 (10,000 iterations), Kalyna-256 CBC and PKCS#7
padding, with a fresh random 32-byte salt and IV on every call. Input is one
unencrypted DER or PEM DSTU key; its PKCS#8 bytes are preserved. Passwords
must contain 1–32 UTF-8 bytes and cannot end in NUL, since the underlying
zero-padding profile equates a password with versions extended by NUL bytes.
The internal deterministic writer is `keystore.MarshalKey6Kalyna`.

`TestIITKalynaKeyExport` checks the public API against IIT on PB257 and PB431:
native public-key information matches the same scalar in a GOST-protected
Key-6 container; attached and detached Kupyna-256 / Kupyna-512 signatures verify
in Go; wrong passwords fail. The native checks cover short and 32-byte ASCII
passwords. UTF-8 passwords round-trip in Go, but a non-ASCII native import failed,
so cross-provider non-ASCII password compatibility is not established.
No PFX writer or certificate embedding is added. This PBES2 format encrypts the
private key without adding a container MAC.

The legacy encryption matrix uses PB257, GOST 34.311, the default Ukrainian DKE,
and GOST28147-CFB with cofactor key agreement and key wrap.
Encryption tests cover dynamic-originator envelopes (with an embedded public key)
and static-originator envelopes (with an issuer/serial reference). The IIT writer
tests the latter reference form; subject-key-identifier parsing has separate Go tests.

`TestIITKalynaEncryptionProfiles` adds PB257 / Kupyna-256 cofactor agreement,
national Kalyna wrapping, and both Kalyna-256/256-CFB-256 and Kalyna-256/256-OFB.
IIT produces static envelopes that Go decrypts, and IIT decrypts Go-produced
dynamic and static envelopes. Both profiles cover 1, 31, 32, 33, 63, 64, 65 and
129-byte payloads. Wrong recipient keys and wrapped-key corruption return no
plaintext. The native modern producer uses the documented explicit cipher
selector in `EUEnvelopDataToRecipientsWithSettingsEx`, in an isolated store.

The profile follows the [national CMS technical specification](https://zakon.rada.gov.ua/laws/show/z1273-20),
including Kupyna KDF with fixed-width shared-secret encoding and the
CMAC/CFB wrapping algorithm identified by `1.2.804.2.1.1.1.1.1.3.11`.
This wrapping algorithm is distinct from the primitive Kalyna KW mode. It wraps
a 32-byte CEK into 96 bytes and validates the full 32-byte CMAC before releasing
the CEK. The parser checks the cipher/IV/DKE, agreement/wrapper pairing and
NULL wrapping parameters. Other modern profile combinations are not established.

The work also corrected the Kalyna streaming CFB feedback after the first block.
Fixed Cryptonite vectors verify encryption and decryption across chunk sizes.
Complete-message CFB additionally right-aligns its short final segment, as
required by DSTU; OFB uses the leading keystream bytes. The public API and CLI
select these complete-message operations for CMS. These tests supplement the
native checks without requiring IIT for each regular test run.

Use `-cipher kalyna256-cfb` or `-cipher kalyna256-ofb` with `dstu encrypt` or
`dstu sign -crypt`. Go callers use `EncryptionOptions` and
`EncryptDocumentWithOptions`, or `SignOptions.Encryption` for signed encryption.
The signature digest and timestamp imprint remain separate selections. GOST CFB
is the default. Unsupported cipher names fail before CLI key/input reads.
Timestamp coverage now includes Go-produced GOST tokens and a real CZO token
with a Kupyna-256 PB-LE TSA signature, including native signature-timestamp
recognition and rejection controls.

The PB307/PB431 Key-6 import failures were isolated on 2 November 2026 to scalar
generation, rather than container encoding. DSTU 4145 section 6.3 samples
`L(n)-1` bits, where `n` is the subgroup order. The earlier generator sampled
all integers below `n`, including scalars with `L(d)=L(n)`, which IIT rejects.
The same narrower sampling now applies to signing nonces. This agrees with
[DSTU 4145-2002, sections 6.3, 9.1 and 11](https://www.ksv.biz.ua/GOST/DSTY_ALL/DSTU2/dstu_4145-2002.pdf)
and Cryptonite's private-key/nonce generation.

Deterministic unit tests cover both private scalar and nonce sampling on all
ten curves. Native `key-info` tests independently check the accepted/rejected
PB307/PB431 scalar boundary without requiring a certificate. A separate test
repackages an IIT PB307 PFX key into Go Key-6, compares native public-key
information, and verifies signatures from both containers. Repeated fresh Go
PB307/PB431 keys pass native signing in both CMS forms. The tests establish
these cases, rather than arbitrary container compatibility.

Existing imported private scalar values are preserved. Do not clear the high
bit or reduce a stored key to make IIT accept it: that changes its public key
and certificate association. Earlier generated keys outside the DSTU sampling
range may need replacement for native-provider use.
These tests require no taxpayer credentials.

For incoming static envelopes, load sender discovery certificates using
`box.AddCert(senderDER)` or repeat `-cert sender.cer` on `dstu decrypt`.
`Box.DecryptDocument` also looks in the envelope's `OriginatorInfo` certificate set.
All lookups use the complete issuer/serial pair or the actual subject-key-identifier
extension. A matching serial alone is insufficient. Discovery and embedded
certificates do not become trusted roots; verify the decrypted signed document
against explicitly configured trust anchors before using its content.

Go callers can request a static originator with
`ua.EncryptionOptions{StaticOriginator: true}`. The writer references the matched
agreement certificate by issuer/serial and embeds it in `OriginatorInfo` for
recipient discovery. The zero value retains the public-key originator profile.
`TestIITStaticOriginatorCertificates/go-to-iit-embedded-certificate` verifies that
IIT decrypts without the sender certificate being separately preloaded. Certificate
discovery does not establish trust or authenticate CFB/OFB content.

Java JKS v2 imports verify the store integrity digest and support standard Java
KeyProtector-protected keys. IIT PKCS#8 attributes can hold a separate agreement
key with big-endian explicit curve coordinates and bit-reversed little-endian
scalar bytes; the loader preserves both keys and matches their certificates by
public key. Tests use an independent keystore-go public-scalar vector and
disposable signing/agreement keys. `Box.SigningCertificate` and `Certificates`
return copies for application adapters without exposing internal packages.

GOST CFB and Kalyna CFB/OFB do not authenticate the content. Wrapped-key corruption is checked;
arbitrary ciphertext changes require a verified signature to detect. Decryption
alone does not establish the sender's identity or the integrity of a report.

The primitive/profile fixes change artifacts produced by the earlier experimental
implementation. Old keys' public points derived with the former `Q=dG` convention,
old x-only compression, and old nonstandard signatures are not interoperability
fixtures and should be regenerated. Private scalar bytes are unchanged.
New Key-6 files use corrected standard identifiers. Files produced earlier with
the experimental, incorrect PRF identifier are not standard interoperability fixtures.

Raw Kalyna KW is a separate primitive from the national CMS CMAC/CFB key wrapper.
`KW.Wrap` / `KW.Unwrap` process whole cipher blocks, preserve trailing zero bytes,
and verify the full zero integrity block in constant time before returning a key.
Non-aligned keys now require `WrapPadded` / `UnwrapPadded(wrapped, originalByteLength)`;
the explicit length removes ambiguity between padding and arbitrary key bytes.
The padded form uses Cryptonite's length trailer and ISO 7816 padding, and checks
its canonical encoding after integrity verification. Earlier implicit unpadding
could truncate aligned keys and did not validate the integrity block.

The raw implementation uses the full 32-bit little-endian round counter, including
rounds above 255. The older Cryptonite C code truncates this counter to one byte;
compatibility with that behavior is not claimed for large raw wrapped keys.
Nine public Cryptonite known-answer vectors cover all five Kalyna block/key size
combinations and aligned/non-aligned cases. Additional tests cover trailing zeros,
every-byte wrapped-key corruption, wrong keys, malformed lengths and padding.
These raw primitive checks do not extend the IIT CMS interoperability matrix.

# Project instructions

## Scope and priorities

`crypto-dstu` is a pure Go implementation of Ukrainian cryptographic primitives,
key containers, CMS signatures/envelopes, timestamps, revocation verification,
and document transport encoding. The public API lives in `ua`; the CLI is
`cmd/dstu`.

Tax-report submission, receipt polling, and report-status orchestration belong
in the separate `tax-reporting` project and remain deferred unless requested.
Do not add an IIT runtime dependency to the library. `cmd/iit-oracle` is an
optional native development/test adapter; the consumer library remains CGo-free.

Use README's **Pending changes** as the maintained backlog. PKCS#12 import now
verifies supported MACs and matches certificates by public key; preserve its
fail-closed handling of missing/unsupported integrity and ambiguous association.
Remaining pending areas are external security review and provisioning/running
the dedicated native CI runner. Workflow setup is documented in `docs/ci.md`.
All ten PB Kalyna CFB/OFB profiles and tested Cyrillic/Ukrainian Windows password
profiles now have independent checks. Five standard ONB curves now use explicit
basis conversions, with Cryptonite point/signature/shared-secret vectors. IIT
named-certificate GOST CMS interoperability now has a strict positive native
matrix on all five curves; synthetic explicit ONB certificates remain outside
that passing profile. Explicit Kupyna-256/512 CMS with GOST ONB certificates now
has native checks and captured independent signatures. Explicit standard-DH
Kalyna CFB/OFB now has native checks on all five ONB curves plus PB257, and
independent standard-DH primitive vectors on all fifteen curves. Modern
certificate/CSR profiles support Kupyna-256/512 signatures with GOST ONB SPKI
and legacy named parameters, checked by IIT/UAPKIC/OpenSSL. Alternate modern
SPKI OIDs remain rejected. See `docs/csr.md` for CSR evidence and limits.
See `docs/onb.md` and `docs/compatibility.md`.
Explicit PBMAC1 PFX now supports UTF-8 passwords beyond CP1251, including
supplementary characters, with OpenSSL integrity and unmodified UAPKI privacy
checks. Preserve the default BMP integrity profile, exact password bytes,
mandatory PBKDF2 keyLength, SHA-2 allowlist and independent KDF work bounds.
PBMAC1 ignores outer legacy MacData salt/iterations as RFC 9879 requires;
its effective salt/iterations come only from PBMAC1 KDF parameters.
Update the backlog when work actually completes; do not mark a profile supported
from a local round-trip alone.

## Repository map

- `pkg/`: cryptographic primitives and curve arithmetic.
- `internal/keystore`: Key-6, PKCS#8, PKCS#12 and JKS loading/writing.
- `internal/cert`, `internal/cms`, `internal/tsp`, `internal/ocsp`: PKI protocols.
- `internal/transport`: document transport containers.
- `ua/`: supported application-facing API and explicit trust policy.
- `cmd/dstu`: CLI; `cmd/iit-oracle`: isolated native interoperability adapter.
- `internal/testiit`, `internal/interop`: shared IIT helpers and integration tests.
- `docs/iit-interoperability.md`: tested matrix, native setup, limitations.
- `docs/timestamps.md`, `docs/revocation.md`: timestamp and revocation policy.
- `_ref/`: optional, ignored reference checkouts; not a runtime/build dependency.

## Working rules

- Use the Go version declared in `go.mod` (currently 1.27). Preserve existing
  dependency versions unless the task requires changing them.
- Preserve unrelated working-tree and staged changes. Do not stage, commit,
  reset, or discard changes unless requested.
- Keep changes scoped and reviewable. Use `gofmt` on modified Go files and follow
  surrounding conventions. If available, apply the Go skills relevant to the
  task, starting with `golang-how-to`.
- Base cryptographic changes on standards, published known-answer vectors, or
  independent provider results. Self-round-trips are insufficient evidence of
  interoperability. Document any encoding or API compatibility change.
- Add regression tests for security fixes and changed cryptographic behavior,
  including malformed-input, wrong-key/password, and corruption cases as relevant.
- Use disposable generated keys in tests. Do not capture real taxpayer private
  keys, passwords, decrypted containers, or secrets in fixtures, logs, or command
  arguments. Retain only intentionally public fixtures with provenance.
- Do not claim constant-time operation, full conformance, DPS/ME.DOC production
  interoperability, or broader curve coverage without evidence.

## Cryptographic and policy constraints

- DSTU 4145 uses `Q = -dG`. Generate private scalars and signature nonces using
  `L(n)-1` random bits. Preserve imported scalar values; masking an imported key
  changes its public key. Use order-sized little-endian signature components.
- Match full curve domains and complete originator identities. Serial numbers
  alone do not identify certificates.
- PB and ONB curves can share field degree and subgroup order. Use complete
  domain/basis equality for key serialization, association and agreement. Curve
  arithmetic and stored coordinates use PB; apply ONB maps at field boundaries,
  digest interpretation and signature-product truncation, never to scalars.
  Preserve independently reproduced Cryptonite vectors, verified ONB Kupyna CMS
  and rejection of unverified ONB cofactor-Kupyna and alternate SPKI profiles. Apply the
  zero-digest substitute after basis conversion; preserve the independent
  zero-digest vectors. CSR output uses
  national compressed points, raw-signature OCTET STRING wrapping and little-endian
  digest interpretation; legacy PB requests remain import-only. ONB compression
  uses bit m-1 for the selector, PB bit 0. Preserve native key-ID fixtures and the
  strict named-certificate CMS matrix. Cryptonite's historical ONB vectors use
  bit 0; keep their original bytes and explicit test-only transcoding. Recognize
  the exact legacy built-in generator in complete explicit domains without
  retrying arbitrary public points under a second compression profile.
  CMS Kupyna signatures use the registered ONB OIDs with GOST ONB certificates.
  IIT's producer emits PB signature tags for these keys; consumers must reject
  that mismatch. Explicit relabeling exists only in the independent test adapter,
  never as an implicit verification fallback.
  Standard-DH Kalyna requires explicit selection and agreement OID .3.8, with
  nonzero prime-order subgroup validation before agreement. IIT's ONB producer
  uses h=1 but labels its envelopes as cofactor DH .3.7. Retain rejection of those
  originals; only the fixture adapter relabels them. Never add an implicit
  cofactor fallback or change the established SharedSecret cofactor behavior.
- PB173's standard cofactor is 4. Preserve the independent cofactor-agreement
  vector and group-cardinality checks; the previous value 2 produced incompatible
  shared secrets. Do not add an implicit legacy-cofactor fallback.
- Java JKS loading verifies store integrity and the SHA-1 KeyProtector checksum.
  Preserve IIT's separate agreement key from PKCS#8 KEP attributes, including
  its distinct parameter/scalar encoding. A single signing identity plus a
  separate agreement key is unambiguous; multiple signing identities still
  require explicit role selection. Never turn embedded certificates into roots.
- Discovery certificates and imported keystore certificates are not trust roots.
  Public verification requires explicitly configured trust. Internal CMS checks
  with nil roots are mathematical fixture checks, not trust validation.
- On verification failure, return no authenticated content. The decrypt CLI must
  not write unverified signed content. Follow the documented explicit timestamp
  and revocation policies; do not silently introduce online fetching.
- Signature digest, content cipher, and timestamp imprint are separate choices.
  `auto` signing follows the subject public-key algorithm, not the issuer's
  certificate-signature digest.
- Modern CMS Kalyna wrapping is the national CMAC/CFB construction (`WrapKey`),
  distinct from raw Kalyna KW. Preserve complete profile binding between content
  cipher, agreement KDF, and key wrap. CFB/OFB do not authenticate content.
- Raw `KW.Wrap`/`Unwrap` process whole blocks and verify a full integrity block.
  Non-aligned input uses explicit padded methods with the original byte length.
  Preserve the independent Bouncy Castle vectors at 246/258/270 rounds for all
  five Kalyna block/key profiles. The raw KW counter is 32-bit little-endian;
  one-byte truncation fails for larger wrapped inputs. See `pkg/kalyna/testdata`.
- Preserve the primitive fuzz regressions and independent fixtures described in
  `docs/primitive-validation.md`. A selector-only encoding must not panic after
  restoring zero x; canonical zero x remains a finite point. KMAC must count every padded
  key block and accommodate multi-block key tails. GOST CFB streams must retain
  their byte offset across calls, matching independent one-shot ciphertext.
- Modern Key-6 protection uses PBKDF2 with Kupyna MAC-256, not HMAC-Kupyna,
  zero-padded password bytes, Kalyna-256 CBC and strict PKCS#7 padding.
  `ua.ProtectKey` generates fresh salt/IV; it writes Key-6, not PFX. Its 1–32-byte
  password API rejects trailing NUL. IIT Windows compatibility now includes the
  tested Cyrillic/Ukrainian passwords: the isolated adapter must convert logical
  UTF-8 to the documented CP1251 native string boundary, rejecting lossy input.
  This is test-adapter behavior, not a new consumer-library encoding policy.
- PKCS#12 import verifies SHA-1/SHA-2 HMAC, GOST HMAC, and independently tested
  IIT Kupyna-256 KMAC before releasing keys. Missing MACs, SignedData integrity,
  unsupported profiles, duplicate keys and ambiguous distinct certificates are
  rejected. Exact duplicate certificates are deduplicated. Association uses the
  full supported curve domain and derived public key; unmatched certificates
  remain discovery data, never trust roots. See `docs/pkcs12.md` for size/KDF,
  password and profile limits. PFX export encrypts every PKCS#8 key bag with the
  modern Kalyna profile and authenticates the container with HMAC-SHA256, fresh
  salts/IVs and 10,000 iterations. Explicit PBMAC1 export uses PBKDF2/HMAC-SHA256
  with raw UTF-8 instead of the default BMP integrity KDF; no normalization or
  lossy code-page fallback is allowed. Require an unambiguous matching certificate
  for every contained key; preserve secondary IIT agreement-key attributes.
  Native signing checks supply matching certificates to the SDK discovery store;
  do not claim automatic native discovery from the embedded certificate bags.
  Preserve the Kupyna
  message-padding two-block buffer regression coverage.

## Validation

For Go changes, run appropriate focused tests, then the full suite and vet:

```sh
go test -mod=readonly -count=1 -timeout=120s ./...
go vet -mod=readonly ./...
```

Use `gopls` diagnostics when available. Run targeted fuzzing or race checks when
the change warrants them. Local HTTP mock tests require loopback networking;
distinguish sandbox socket restrictions from actual test failures.
See `docs/fuzzing.md` for fuzz targets, invariants and remaining coverage gaps.
The initial parser-fuzzing backlog item is complete: twelve targets passed
three-minute campaigns, including the named legacy/ONB, multi-signer/static
originator, encrypted PFX and revocation gaps. Preserve the public fixed keys,
identities and policy times needed for subprocess replay. The local runner is
`scripts/test-fuzz.ps1`; its KDF/input budgets are harness limits, not changes
to runtime security policy. The primitive matrix also passed seven three-minute
campaigns, with independent symmetric and all-PB curve fixtures. External review
and provider limitations remain separate pending work.
Parsing certificates does not establish trust; unsupported discovery algorithms
may intentionally have no DSTU public key. Preserve that distinction in tests.

The Taskfile's `lint`/`lint-fix` paths invoke a `go.mod` task that stages files and
runs `go mod tidy`. Avoid those paths when staging/dependency changes are outside
the authorized task. `task lint-only` runs the configured linter without that
staging step; it may require downloading the pinned tool.

`task lint-ci` runs the correctness baseline in `.golangci-ci.yml`
without staging or tidying. CI is paused: workflow definitions are retained as
`.yml.disabled` files. Do not reactivate them unless requested. When enabled,
hosted CI also runs Linux race tests and govulncheck;
use the current patch of the Go minor version declared in `go.mod`. The optional
native workflow is manual/default-branch-only and requires a dedicated runner
and pinned SDK variables. Do not run untrusted PR code on that runner.

For changes affecting native interoperability, use the isolated Windows runner:

```powershell
./scripts/test-iit.ps1 `
  -SdkDirectory 'C:\path\to\iit-sdk' `
  -TestCADirectory 'C:\path\to\public-CA-bundle' `
  -ExpectedSDKHash '<sha256-of-EUSignCP.dll>'
```

The SDK is not redistributed. Pin its hash, build the adapter for its architecture,
and use fresh temporary settings/stores with network services and UI disabled.
Never point the adapter at a real application's key store/settings. See the
interoperability document for prebuilt-adapter environment variables and focused
`-tags=integration` commands. A configured adapter failure must fail the test;
missing configuration may explicitly skip it. Report skips and limits honestly.

Documentation-only changes need link/content and whitespace checks, not a full
cryptographic test rerun. Report what changed, validation performed, and material
remaining limits; keep the README and profile documentation consistent.

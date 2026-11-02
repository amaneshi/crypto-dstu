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
Remaining pending areas are broader modern-profile coverage, ONB curves,
non-ASCII password interoperability, PFX export, security review, fuzzing, and CI.
PB307/PB367/PB431 Kalyna CFB/OFB and tested Cyrillic/Ukrainian Windows password
profiles now have independent checks. ONB was evaluated but remains unsupported;
its implementation requires basis conversions. See `docs/compatibility.md`.
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
  password and profile limits. PFX export remains pending. Preserve the Kupyna
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

The Taskfile's `lint`/`lint-fix` paths invoke a `go.mod` task that stages files and
runs `go mod tidy`. Avoid those paths when staging/dependency changes are outside
the authorized task. `task lint-only` runs the configured linter without that
staging step; it may require downloading the pinned tool.

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

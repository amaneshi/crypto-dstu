# Parser fuzzing

Fuzzing is a local development check while CI is paused. These targets run their
seed corpora during ordinary `go test`; active mutation requires `-fuzz`.

| Target | Coverage and assertions |
| --- | --- |
| `internal/csr/FuzzParseAndVerify` | National PB257/ONB173 GOST, PB257 Kupyna-256/PB431 Kupyna-512, ONB173 Kupyna-256/ONB431 Kupyna-512 and legacy PB257 seeds; malformed DER, input immutability, nil results on parse errors, trailing-data rejection, signature verification and rejection of modified signed information/signatures |
| `internal/cert/FuzzParseCertificates` | PB257 and all five named ONB curves (GOST and Kupyna-256/512 certificate signatures), concatenated DER and PEM bundles, malformed encodings; input immutability, reparsing accepted certificates and no partial output after a malformed bundle tail |
| `internal/cms/FuzzParseAndVerifySigned` | PB257 GOST/Kupyna-256/Kupyna-512, native ONB173/ONB431 Kupyna-256/512 attached/detached seeds (original and explicitly relabeled test forms), CZO examples and two-signer valid/partially invalid messages; no authenticated flags from parsing, trailing-data rejection, input immutability, mathematical signature checks and clearing flags after content changes |
| `internal/cms/FuzzParseAndDecryptEnveloped` | PB257 GOST CFB and Kalyna-256 CFB/OFB plus ONB173 standard-DH CFB/OFB (original/mislabeled native data, explicit test relabeling, dynamic and embedded-static forms); input immutability, trailing-data rejection and no plaintext on decryption errors |
| `internal/keystore/FuzzParseRawKey` | Public scalar 2 on all fifteen PB/ONB domains, scalar range/domain preservation after canonical serialization, nil results on errors and unchanged caller input |
| `internal/keystore/FuzzParseKey6` | Legacy GOST and modern Kalyna encrypted PKCS#8, malformed parameters/ciphertext, no key on errors and unchanged caller input |
| `internal/keystore/FuzzParseJKSAuthenticated` | Independent public Java KeyProtector fixture; reauthenticated arbitrary store bodies reach entry/protected-key parsing, with corrupted store digests always rejected |
| `internal/keystore/FuzzParsePKCS12` | Traditional and PBMAC1 outer PFX integrity/structure mutations; effective inner PBMAC1 KDF work budget, unchanged input, no keys on errors and deliberate MAC-digest corruption rejected |
| `internal/keystore/FuzzPKCS12AuthenticatedSafe` | Reauthenticated arbitrary SafeContents, raw/shrouded keys, GOST/Kalyna key privacy, certificate association, duplicate keys and encrypted SafeContents; no keys on errors |
| `internal/ocsp/FuzzParseAndCheckResponse` | Issuer-signed good/revoked/unknown responses, responder-name/key-hash IDs and unsuccessful responses; parsing/CertID/signature/freshness checks, unchanged input and no good status on authentication errors |
| `internal/ocsp/FuzzCheckResponderCRL` | Issuer-signed full CRLs with/without revoked responder, signature/freshness/extension parsing and unchanged input; accepted CRLs reject trailing data and corrupted signatures |
| `internal/transport/FuzzDecode` | Malformed and valid transport-container seeds; panic detection |
| `pkg/kalyna/FuzzKWUnwrap` | Empty/malformed and valid wrapped-key seeds; no plaintext on integrity errors and exact rewrapping after successful unwrap |

The local runner selects the twelve parser targets; KW is listed for reference
as a separate primitive target, outside this parser completion matrix.
`-Suite primitives` selects the separate [primitive validation](primitive-validation.md)
matrix; omitting `-Suite` retains the parser default.

No operational keys are loaded. Known private scalars 1, 2 and 7 are intentional
public test inputs. Other seeds use disposable generated keys and retain only
public certificates/signatures/envelopes. CMS decryption and revocation checks
use fixed test keys, issuer/serial identities and policy times so subprocess
workers can authenticate transported seeds. Test certificate signature nonces
may differ without changing their public identities or keys.
Cryptographic seed generation runs once before mutation, not for every candidate.
CSR/certificate/CMS/keystore/revocation candidates are limited to 64 KiB.
Password-container targets skip otherwise valid KDF work factors above 256;
malformed/out-of-policy factors still reach production validation. This keeps
mutation budgets practical, changes no production limit and does not measure
worst-case CPU/memory use. Normal regression tests also cover excessive KDF
factors. Transport retains its existing fuzz harness.

CSR parsing is distinct from authenticating its self-signature. Certificate
parsing is distinct from signature or chain/trust verification. The certificate
parser deliberately permits unsupported key algorithms for discovery, with a
nil DSTU public key. A minimized input covering that path is retained under
`internal/cert/testdata/fuzz/FuzzParseCertificates`. It corrected an overly strict
initial harness assertion; it did not establish a production parser bug.

CMS verification uses nil roots for mathematical checks only, never identity
trust, and performs no online certificate/timestamp fetching. `ParseSigned`
returns unauthenticated content by design; the harness checks signer flags,
not absence of parsed content. Decryption errors must return no plaintext, but
CFB/OFB ciphertext is not authenticated and altered ciphertext may decrypt
successfully. These targets do not claim stronger content integrity.

Run one target at a time, for example:

```sh
go test -mod=readonly -run '^$' -fuzz '^FuzzParseAndVerify$' -fuzztime=60s -parallel=2 ./internal/csr
go test -mod=readonly -run '^$' -fuzz '^FuzzParseCertificates$' -fuzztime=60s -parallel=2 ./internal/cert
go test -mod=readonly -run '^$' -fuzz '^FuzzParseAndVerifySigned$' -fuzztime=60s -parallel=2 ./internal/cms
go test -mod=readonly -run '^$' -fuzz '^FuzzParseAndDecryptEnveloped$' -fuzztime=60s -parallel=2 ./internal/cms
```

The local PowerShell runner selects all twelve parser targets by default, with
three minutes of mutation and two workers per target:

```powershell
./scripts/test-fuzz.ps1 -Duration 3m -Workers 2 -OutputDirectory 'C:\temp\parser-fuzz'
```

`-GoExecutable` selects a patched Go executable; `-Targets` selects named targets
for a focused rerun. The script uses `-mod=readonly`, fresh executions and a
per-target timeout of the requested duration plus two minutes. It stops on the
first failure and retains logs and `results.json` in the selected output folder.
It does not configure or enable CI. Reports contain public test data only.

Initial mutation ran for 60 seconds per target on Windows with Go 1.27.3 and two
workers: 257,017 CSR executions and 778,441 certificate executions, both passing
after the harness correction described above. These short campaigns are smoke checks,
not an exhaustive security review or evidence of independent interoperability.
The known-answer and provider tests remain separate evidence.

The initial CMS campaigns used the same toolchain and worker/time limits:
661,613 SignedData executions and 521,817 EnvelopedData executions, both passing.

## Completion campaign

The README parser-fuzzing task covers adding the twelve parser targets above,
closing its named seed gaps, retaining regressions and running the expanded
matrix for three minutes per target. The campaign report is recorded below.

On 3 November 2026, all twelve targets passed on Windows/amd64 with Go 1.27.3,
three minutes requested per target and two workers each. No crashes or failed
invariants were found in these campaigns. Total executions: **42,058,791**.

| Target | Executions | Result |
| --- | ---: | --- |
| `FuzzParseRawKey` | 4,248,748 | PASS |
| `FuzzParseKey6` | 4,079,616 | PASS |
| `FuzzParseJKSAuthenticated` | 5,810,852 | PASS |
| `FuzzParsePKCS12` | 6,113,249 | PASS |
| `FuzzPKCS12AuthenticatedSafe` | 2,578,925 | PASS |
| `FuzzParseAndCheckResponse` | 203,960 | PASS |
| `FuzzCheckResponderCRL` | 756,628 | PASS |
| `FuzzParseAndVerify` | 997,619 | PASS |
| `FuzzParseCertificates` | 4,249,932 | PASS |
| `FuzzParseAndVerifySigned` | 2,061,830 | PASS |
| `FuzzParseAndDecryptEnveloped` | 5,066,544 | PASS |
| `FuzzDecode` | 5,890,888 | PASS |

Execution counts include rejected/malformed inputs; they are not counts of
independently authenticated valid documents. Setup assertions verify that valid
privacy, signature and revocation seeds reach their intended operations. The
full regression suite, vet, correctness lint and gopls diagnostics also passed.

After adding modern ONB certificate/CSR seeds, two further three-minute campaigns
passed on the same toolchain with two workers: 982,081 CSR executions and
6,431,579 certificate executions. The full Go suite, vet, correctness lint,
gopls diagnostics, isolated native suite and independent UAPKIC replay also passed.
See [modern ONB fixtures](../internal/testvectors/testdata/modern-onb-pki/README.md)
for the separate interoperability evidence and its scope.

The PBMAC1 expansion passed a further three-minute PFX parsing campaign with
two workers and Go 1.27.3: 7,888,417 executions. Its valid PBMAC1 seed must reach
private-key import; the harness bounds the effective inner KDF iterations,
independently of ignored legacy outer MacData fields. Separate OpenSSL and UAPKI
checks cover the UTF-8 password profile and national-key privacy.

Fuzzing remains ongoing maintenance. These bounded campaigns cannot establish
the absence of bugs, exhaust every ASN.1 variant, measure maximum-size resource
exhaustion or replace an external cryptographic/security review. Primitive
fuzzing and independent known-answer validation are documented separately in
[primitive validation](primitive-validation.md). Retain minimized inputs and add
focused regressions for actual defects discovered by future runs.

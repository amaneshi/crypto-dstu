# Fuzzing coverage and remaining work

Fuzzing is a local development check while CI is paused. These targets run their
seed corpora during ordinary `go test`; active mutation requires `-fuzz`.

| Target | Coverage and assertions |
| --- | --- |
| `internal/csr/FuzzParseAndVerify` | National PB257/ONB173 GOST and PB257 Kupyna-256/PB431 Kupyna-512 seeds; malformed DER, parser input immutability, nil results on parse errors, trailing-data rejection, signature verification and rejection of modified signed information/signatures |
| `internal/cert/FuzzParseCertificates` | Disposable named-PB257 certificate, concatenated DER and PEM bundles, malformed encodings; input immutability, reparsing accepted certificates and no partial output after a malformed bundle tail |
| `internal/keystore/FuzzPKCS12AuthenticatedSafe` | Authenticated arbitrary SafeContents using a public password, reaching parsers behind the MAC gate; no keys returned on error |
| `internal/transport/FuzzDecode` | Malformed and valid transport-container seeds; panic detection |
| `pkg/kalyna/FuzzKWUnwrap` | Empty/malformed and valid wrapped-key seeds; no plaintext on integrity errors and exact rewrapping after successful unwrap |

No operational keys are loaded. The CSR seeds use the intentionally public
scalar 2; certificate seeds use disposable generated keys and retain only the
public certificate. Cryptographic seed generation runs once before mutation,
not for every candidate. CSR/certificate candidates are limited to 64 KiB to
bound each campaign; this is a harness limit, not a new runtime parser limit.

CSR parsing is distinct from authenticating its self-signature. Certificate
parsing is distinct from signature or chain/trust verification. The certificate
parser deliberately permits unsupported key algorithms for discovery, with a
nil DSTU public key. A minimized input covering that path is retained under
`internal/cert/testdata/fuzz/FuzzParseCertificates`. It corrected an overly strict
initial harness assertion; it did not establish a production parser bug.

Run one target at a time, for example:

```sh
go test -mod=readonly -run '^$' -fuzz '^FuzzParseAndVerify$' -fuzztime=60s -parallel=2 ./internal/csr
go test -mod=readonly -run '^$' -fuzz '^FuzzParseCertificates$' -fuzztime=60s -parallel=2 ./internal/cert
```

Initial mutation ran for 60 seconds per target on Windows with Go 1.27.3 and two
workers: 257,017 CSR executions and 778,441 certificate executions, both passing
after the harness correction described above. These short campaigns are smoke checks,
not an exhaustive security review or evidence of independent interoperability.
The known-answer and provider tests remain separate evidence.

Remaining work includes CMS, Key-6/PKCS#8/JKS and revocation parser targets,
additional PFX paths, legacy CSR and ONB certificate seeds, primitive targets,
larger-input/resource-limit checks and substantially longer campaigns. Keep
minimized inputs and add focused regressions when an actual defect is found.

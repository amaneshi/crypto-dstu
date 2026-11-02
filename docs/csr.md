# CSR encoding and validation

The CSR module and CLI now write national DSTU requests with the GOST PB/ONB
algorithm appropriate to the complete curve domain. All ten PB and five ONB
curves are covered by GOST request tests. Modern PB signature overrides remain
available; ONB Kupyna signatures remain explicitly unsupported.

## Wire-format correction

New requests contain version 0 and an explicit empty `[0]` attributes set, as
specified by [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986.html#section-4.1).
The public-key BIT STRING wraps an OCTET STRING containing the compressed point
in little-endian order. Algorithm parameters contain the named curve and, for
GOST, the supported DKE. The signature BIT STRING wraps an OCTET STRING containing
fixed order-sized `r LE || s LE`. The CRI hash is interpreted in little-endian
order by DSTU signing. Signature algorithm parameters are omitted on output.

This corrects the earlier library writer, which emitted raw uncompressed `X BE ||
Y BE`, omitted attributes, used its own ASN.1 signature sequence, and interpreted
the digest differently. Those old PB requests remain readable and verifiable.
Legacy verification is selected by the old bare-curve parameters and public-key
encoding; a failed national
signature never falls back to legacy rules. New output always uses national encoding.

The parser requires complete DER, version 0, byte-aligned key/signature bit
strings, consistent algorithms/basis, a valid signing-subgroup point, and supported
DKE. It validates the subject and attribute structure. Bounds are 1 MiB per request
and 256 attributes. Unsupported profiles, malformed values, trailing fields and
bytes fail. Verification authenticates the signed CRI; parsing alone does not
authenticate subject claims or constitute certificate issuance.

## Independent evidence and limits

`TestCSRIndependentVerification` sends only synthetic public requests to two
local tools. OpenSSL 3.5.9 parses the request and subject. A separate C test
utility reads the DER, hashes the exact original CRI, decompresses its public key,
and verifies its signature using unmodified Cryptonite primitive APIs at commit
`3618d340d22e27a6becf97d89c453f8e64068a39`. It covers GOST on all fifteen curves
and Kupyna-256 on PB257, with modified-subject rejection. It is not the Cryptonite
PKIX CSR parser and does not establish CA acceptance or IIT CSR interoperability.

The pinned Cryptonite DSTU verification API requires exactly 32 digest bytes.
Kupyna-512 is covered by local roundtrips, not this independent CSR signature
check. During diagnosis its independently computed CRI digest matched Go; the
reference verifier rejected the digest length. No wider claim is made from that.

The generator/verifier uses intentionally public `d=2` fixture keys. No taxpayer
keys, passwords, external submissions, CA requests or runtime C dependencies are
involved. Ordinary tests include national-format, corruption, malformed-input,
unsupported-profile and old-format import regressions without external tools.

## Reproducing the independent check

Build the C test utility on Linux with the pinned Cryptonite checkout:

```sh
ref=/path/to/cryptonite
test "$(git -C "$ref" rev-parse HEAD)" = 3618d340d22e27a6becf97d89c453f8e64068a39 || exit 1
cc -O0 -DCRYPTONITE_EXPORT=extern \
  -I"$ref/src/cryptonite/c" -I"$ref/src/pthread/c" \
  "$ref"/src/cryptonite/c/*.c "$ref"/src/pthread/c/pthread_impl.c \
  internal/csr/testdata/cryptonite-verify.c -pthread -lm -o /tmp/csr-verify
```

For the optional Windows/Ubuntu-WSL Go check, set `CSR_CRYPTONITE_WSL` to its Linux
executable path and `PKCS12_OPENSSL` to the Windows OpenSSL executable, then run:

```powershell
go test -mod=readonly -count=1 ./internal/csr -run '^TestCSRIndependentVerification$' -v
```

Keep those opt-ins unset for ordinary tests. The source in `testdata` is a bounded
test adapter for generated requests, not a production DER parser.

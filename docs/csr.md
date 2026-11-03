# CSR encoding and validation

The CSR module and CLI now write national DSTU requests with the GOST PB/ONB
algorithm appropriate to the complete curve domain. All ten PB and five ONB
curves are covered by GOST request tests. PB and ONB support explicit Kupyna-256/512
signatures. For example:

```sh
dstu csr -curve DSTU_ONB_173 -cn Example -digest kupyna512 -output request.der
```

The default remains GOST.

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

ONB point output now uses the IIT-compatible selector at bit `m-1`; PB uses bit 0.
Earlier bit-0 ONB requests should be regenerated. See [ONB compatibility](onb.md).

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
For ONB, the test adapter explicitly restores x using coefficient parity and
moves the selector from `m-1` to bit 0 before invoking Cryptonite's legacy
decompressor. Hashing and signature arithmetic remain independent and unmodified;
this adapter is not evidence that Cryptonite accepts the new wire bytes directly.

The pinned Cryptonite API requires exactly 32 digest bytes. The additional
UAPKIC reference at `1996c0fe56dbbc69f5b00d67784a5bc3033b57fe` supports the full
64-byte Kupyna-512 digest. All five ONB curves now have exact CRI signature checks
with both digest sizes, plus modified-subject and signature rejection. OpenSSL
parses every request; IIT accepts the identical SPKI in matching certificates and
uses their keys. IIT CSR import/CA issuance is not claimed. The ONB public-key
identifier remains GOST ONB (`1.2.804.2.1.1.1.1.3.1.2`), with legacy named curve
parameters and DKE; only the self-signature uses the modern ONB OID. Alternate
modern SPKI OIDs remain rejected. Public fixtures, provenance and reproduction
are in [modern ONB PKI fixtures](../internal/testvectors/testdata/modern-onb-pki/README.md).

The original Cryptonite generator uses public `d=2` keys; the modern ONB matrix
uses public full-width scalars documented with its fixtures. No taxpayer
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

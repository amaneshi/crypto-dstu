`jks-public-scalar.json` is an independent JKS v2 / Java KeyProtector test vector
produced with `github.com/pavlo-v-chernykh/keystore-go/v4` v4.5.0.

It deliberately uses public scalar `d=1`, a public test password, fixed creation
time and fixed test salt. It contains no operational credentials or certificates.
The plaintext is named-curve PB257 PKCS#8 DER. The fixture exercises the standard
entry layout, store integrity digest, key-protection checksum and auto-detection.
Wrong passwords and mutations are tested without adding a runtime dependency on
the independent fixture producer.

`pkcs12-mac-openssl.json` contains deterministic, entirely public PKCS#12
diversifier-3 MAC-key/HMAC vectors produced with OpenSSL 3.5.9. The adjacent
`generate-pkcs12-vectors.ps1` script reproduces them. Cases cover SHA-1 and
SHA-224/256/384/512, empty and BMP Cyrillic passwords, and password expansion over
multiple input blocks. They contain no private keys or operational credentials;
all passwords are intentionally public. Ordinary Go tests read the saved vectors
without invoking OpenSSL. National GOST/Kupyna PFX MACs are checked separately
against disposable native IIT-generated containers in tagged integration tests.

`pkcs12-pbmac1-openssl.json` contains sixteen public PFX fixtures for RFC 9879
UTF-8 password integrity, produced/checked with OpenSSL 3.5.9. Eight Go-generated
national-key containers use intentionally public scalar `d=2`; OpenSSL verifies
their complete PBMAC1 integrity and bag structure. Eight OpenSSL-generated
certificate-only containers provide independent SHA-224/256/384/512 PRF/MAC
inputs, including a mixed SHA-256 MAC/SHA-512 PRF. Certificate-only fixtures are
used to check MAC authentication; the key importer correctly returns no keys.
Passwords cover CJK, Arabic, Devanagari, Greek, emoji, composed/decomposed Latin,
and the 32-byte UTF-8 export boundary. They are intentionally public, not secrets.

The optional `verify-unicode-key6.c` adapter includes the original UAPKI
`cm-pkcs12/src/crypto/pkcs5.c` from commit
`1996c0fe56dbbc69f5b00d67784a5bc3033b57fe` and calls its original
`pbkdf2_dstu7564kmac` plus UAPKIC Kalyna-CBC decryption. No source is patched or
copied into the consumer library. The bounded public test frame carries exact
UTF-8 password bytes, KDF parameters, ciphertext and expected public-scalar PKCS#8.
It proves independent key privacy for all eight retained Go containers, with
wrong-password rejection, separately from OpenSSL's MAC checks. It is not a
UAPKI PFX parser/whole-container import test. No reference SDK/binary is shipped.

Reproduce OpenSSL checks/capture on Windows (only disposable public test inputs):

```powershell
$env:PKCS12_OPENSSL='C:\path\to\openssl.exe'
$env:PKCS12_CAPTURE_PBMAC1=(Join-Path (Get-Location) 'internal/keystore/testdata/pkcs12-pbmac1-openssl.json')
go test -mod=readonly -count=1 ./internal/keystore -run '^TestPBMAC1OpenSSL$' -v
```

The tests use UTF-8 password files without a BOM for the OpenSSL CLI, avoiding
shell/code-page conversion. Recapture changes random salts, IVs and validity
metadata. No operational key or password may be supplied to these capture tests.

For the independent privacy replay, first build the UAPKIC archive at the pinned
commit as described in [modern ONB fixtures](../../testvectors/testdata/modern-onb-pki/README.md).
Then, from this repository on Linux:

```sh
ref=/path/to/UAPKI/library
out=/tmp/modern-onb-uapkic
test "$(git -C "$ref" rev-parse HEAD)" = 1996c0fe56dbbc69f5b00d67784a5bc3033b57fe || exit 1
gcc -O0 -ffunction-sections -fdata-sections \
  -DUAPKIC_LIBRARY -DUAPKIF_LIBRARY -DCM_LIBRARY \
  -DUAPKI_PKCS5_SOURCE="\"$ref/cm-pkcs12/src/crypto/pkcs5.c\"" \
  -I"$ref/uapkic/include" -I"$ref/uapkic/src" \
  -I"$ref/uapkif/include" -I"$ref/uapkif/src/asn1" \
  -I"$ref/common/cm-api" -I"$ref/common/pkix" -I"$ref/common/macros" \
  -I"$ref/cm-pkcs12/src/crypto" \
  internal/keystore/testdata/verify-unicode-key6.c "$out/libuapkic.a" \
  -Wl,--gc-sections -pthread -lm -o "$out/verify-unicode-key6"
```

The test adapter's inclusion of the original file exposes its static KDF without
changing it; dead-section elimination discards unused ASN.1/other-cipher helpers.
On Windows/Ubuntu WSL, run:

```powershell
$env:UNICODE_KEY6_UAPKI_WSL='/tmp/modern-onb-uapkic/verify-unicode-key6'
go test -mod=readonly -count=1 ./internal/keystore -run '^TestPBMAC1RetainedFixtures$' -v
```

Unset optional tool/capture variables for ordinary tests. Configured tool failures
fail tests; missing optional tools explicitly skip only their external checks.
The Go fixture regressions still check all MACs, full Go-key import, wrong
passwords, mutations and no released keys on failure without external software.

# Modern ONB PKI fixtures

Five JSON files retain ten disposable, public self-signed certificates and ten
matching PKCS#10 requests: ONB173/179/191/233/431, Kupyna-256 and Kupyna-512.
Go generated the DER and signatures. Each certificate's subject SPKI uses GOST
ONB, legacy named curve parameters and the national DKE; the signature uses the
corresponding modern ONB OID. CSRs contain the identical SPKI.

The deliberately public scalar is `d = 2^(bitlen(n)-2) + 0x12345`. Never use these
keys operationally. Signatures, serials and validity dates can change on recapture.
Tests validate at the retained certificate's `NotBefore + 1h`, not the current time.

Independent checks on 2026-11-03:

- IIT x86 1.3.1.224 parses each certificate and uses its matching key for native
  CMS signing and verification. SDK SHA256:
  `475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f`.
- OpenSSL 3.5.9 parses each request and subject; it does not verify DSTU signatures.
- Unmodified UAPKIC primitives from UAPKI commit
  `1996c0fe56dbbc69f5b00d67784a5bc3033b57fe` hash the exact original signed
  TBSCertificate/CRI DER and verify both digest sizes. The bounded test reader
  [verify-modern-onb.c](../verify-modern-onb.c) explicitly moves the point selector
  from the native high bit to the reference decompressor's legacy bit 0, restoring
  x through coefficient parity first. It swaps decoded LE coordinates for the
  generic EC verifier's BE boundary. No crypto implementation is patched.

This establishes signature arithmetic and tested wire/profile behavior, not
reference PKIX parser conformance, IIT CSR import, CA issuance, identity trust,
constant-time behavior or a security audit. Alternate modern SPKI identifiers
remain unsupported. The reference is an optional test tool, never a consumer
build or runtime dependency. No native SDK or reference binary is redistributed.

## Reproduction

On Linux, check out https://github.com/specinfo-ua/UAPKI at the pinned commit.
From this Go repository, build the reference and bounded adapter:

```sh
ref=/path/to/UAPKI/library/uapkic
out=/tmp/modern-onb-uapkic
mkdir -p "$out"
test "$(git -C "$ref" rev-parse HEAD)" = 1996c0fe56dbbc69f5b00d67784a5bc3033b57fe || exit 1
for src in "$ref"/src/*.c; do
  gcc -O0 -DUAPKIC_LIBRARY -DJENT_CONF_ENABLE_INTERNAL_TIMER \
    -DUAPKIC_VERSION_STRING='"3.0.0-dev"' \
    -I"$ref/include" -I"$ref/src" -c "$src" -o "$out/$(basename "$src" .c).o" || exit 1
done
ar rcs "$out/libuapkic.a" "$out"/*.o
gcc -O2 -I"$ref/include" internal/testvectors/testdata/verify-modern-onb.c \
  "$out/libuapkic.a" -pthread -lm -o "$out/verify-modern-onb"
```

Windows/Ubuntu WSL independent replay, including signature/subject corruption:

```powershell
$env:MODERN_ONB_UAPKIC_WSL='/tmp/modern-onb-uapkic/verify-modern-onb'
go test -mod=readonly -count=1 ./internal/testvectors -run '^TestModernONBPKIFixtures$' -v
```

Recapture requires the isolated, hash-pinned IIT adapter configuration from
[the interoperability guide](../../../../docs/iit-interoperability.md), plus:

```powershell
$env:PKCS12_OPENSSL='C:\path\to\openssl.exe'
$env:IIT_CAPTURE_MODERN_ONB_PKI_DIR=(Join-Path (Get-Location) 'internal/testvectors/testdata/modern-onb-pki')
go test -tags=integration -mod=readonly -count=1 -timeout=120s ./internal/interop -run '^TestIITModernONBPKI$' -v
```

Leave opt-ins unset for ordinary tests. A configured tool failure fails the check;
missing optional tools explicitly skip only their external subchecks. Capture
requires both digests and all independent tools; a partial test filter fails
rather than emitting an incomplete fixture. Ordinary retained-fixture tests need
only Go and include wrong-key, wrong-basis, inconsistent certificate identifiers,
unsupported modern SPKI, and signed-data/signature corruption regressions.

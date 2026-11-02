# Extended compatibility checks

## Kalyna CMS beyond PB257

`TestIITKalynaAdditionalCurves` independently checks PB307, PB367 and PB431 with
the pinned IIT Windows SDK (SHA256
`475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f`).

For each curve, Kalyna-256 CFB and OFB cover 1-, 33- and 65-byte payloads:

- IIT produces a static-originator envelope; Go derives/unwraps the key and
  decrypts the original bytes.
- IIT decrypts Go-produced dynamic-originator and static-reference envelopes.
- IIT decrypts embedded-static-originator envelopes without separately
  preloading the sender certificate.
- Wrong recipient private keys and modified wrapped keys release no plaintext.

The tests assert the actual content-cipher/agreement OIDs and wrapped-key size.
PB307/PB367 test certificates use Kupyna-256; PB431 uses Kupyna-512 certificate
signatures. Certificate signatures, CMS agreement KDF and content cipher remain
separate choices. The encryption profile still uses Kupyna-256 derivation and
national Kalyna CMAC/CFB wrapping. Smaller PB curves and other modern combinations
are not established by this matrix; see [the full limits](iit-interoperability.md#limits).

No cryptographic implementation change was needed for these additional curves.
The new tests are included by the existing `^TestIIT` CMS native runner.

## Windows non-ASCII password boundary

The earlier failed non-ASCII import used UTF-8 bytes directly with IIT's Windows
`CHAR` API. The recovered vendor manual `EUSignMSWCPPAppendixA.doc`, section A.4,
states that strings received/returned by that API default to CP1251.

The isolated `cmd/iit-oracle` adapter now converts logical UTF-8 passwords to
CP1251 at that native boundary, for generation, private-key reading, key-info and
context signing. It uses Windows
[WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
with `WC_NO_BEST_FIT_CHARS` and checks default-character substitution. Invalid
UTF-8, embedded NUL, unrepresentable characters and overlong encoded passwords
fail instead of silently becoming a different password.

The consumer Go library remains pure Go and continues using UTF-8 strings.
No IIT dependency or CP1251 conversion was added to `ua.ProtectKey` or the
PKCS#12 parser. Their existing byte-length/password policies remain in force.

Independent native checks now include:

- Go-produced modern Key-6 with Cyrillic passwords on PB257 and Ukrainian letters
  on PB431, plus a PB257 password exactly at the 32 UTF-8-byte limit.
- IIT-generated GOST and Kupyna PFX with Cyrillic/Ukrainian passwords, verified
  and decrypted by Go, then reprotected as modern Key-6 and read by IIT.
- Native signatures over public test data from both the original PFX and the
  reprotected key, verified in Go against the derived public key.
- Wrong-password rejection and native conversion unit tests for lossy inputs.

Tests compare cryptographic signatures/public-key correspondence rather than
requiring equality of profile-dependent opaque `EUGetKeyInfoBinary` identifiers.
The evidence covers the tested CP1251-representable strings on this Windows SDK;
it does not establish arbitrary Unicode passwords or other providers/platforms.

## ONB evaluation

The library currently implements polynomial-basis (PB) binary fields and ten
built-in PB curves. Optimal-normal-basis (ONB) support cannot be implemented by
aliasing a named OID or choosing a PB curve with the same field degree.

The inspected independent Cryptonite implementation has ONB-specific domain
parameters, conversion matrices/roots, and `onb_to_pb`/`pb_to_onb` transformations.
Conversions occur around curve coefficients, public-point compression/expansion,
signing and shared-secret handling. Its public named/explicit ONB parameters for
degrees 173, 179, 191, 233 and 431 are retained as rejection fixtures with
provenance in `pkg/dstu4145/testdata/onb-cryptonite.json`. No private material or
reference implementation code is included in that fixture.

Regressions ensure those named/explicit ONB parameters remain unresolved and ONB
PKCS#8 keys fail import. This preserves explicit unsupported behavior; it does
not implement ONB arithmetic. Follow-up work needs basis conversions and domain
representation, key/certificate/CMS encoding support, independent point/signature
and key-agreement vectors, and native cross-checks before enabling ONB profiles.

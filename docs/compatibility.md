# Extended compatibility checks

## Kalyna CMS beyond PB257

`TestIITKalynaAdditionalCurves` independently checks PB163, PB167, PB173, PB179,
PB191, PB233, PB307, PB367 and PB431 with
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
All additional curves except PB431 use Kupyna-256 test certificates; PB431 uses Kupyna-512 certificate
signatures. Certificate signatures, CMS agreement KDF and content cipher remain
separate choices. The encryption profile still uses Kupyna-256 derivation and
national Kalyna CMAC/CFB wrapping. Together with the existing PB257 profile test,
this covers Kalyna CFB/OFB on all ten standard PB curves. Other combinations
remain limited to [the documented matrix](iit-interoperability.md#limits).

The PB173 checks exposed its incorrectly configured cofactor of 2. The standard
cofactor is 4; correcting it resolved native-to-Go wrapped-key integrity failures.
The independent public-key/cofactor shared-secret fixture in
`pkg/dstu15946/testdata/pb173-cryptonite.json` comes from the pinned Cryptonite
revision and intentionally public scalars 2 and 7. `TestPB173CryptoniteSharedSecret`
checks the result, and `TestStandardDomainCofactors` checks all fifteen domains'
order/cofactor products against the group-cardinality bound.

This changes PB173 agreement output, including the legacy GOST envelope path.
Old envelopes produced with the incorrect cofactor cannot be recovered by the
corrected profile; there is no silent fallback to cofactor 2. Key scalars and
signature arithmetic do not change. The extended matrix is part of the existing
`^TestIIT` CMS native runner. To reproduce the PB173 fixture, build the generator
described in [ONB vector reproduction](onb.md#reproducing-operation-vectors) and
invoke it with `pb173`.

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

## ONB coverage

Five standard ONB domains now have basis conversions and independent Cryptonite
point, signature and cofactor-agreement vectors. Named/complete explicit
parameters, GOST ONB PKCS#8, certificates, GOST CMS and PFX paths are covered.
PB/ONB algorithm mismatches fail, and complete domain comparisons distinguish
domains that share field degree and subgroup order.

ONB point compression now stores the selector at bit `m-1`, matching the pinned
IIT SDK; PB stays at bit 0. This changes earlier ONB point bytes and key identifiers.
Named-curve GOST certificates and attached/detached CMS now pass a strict native
matrix on all five curves. Synthetic explicit-parameter ONB certificates and
tiny-scalar certificate fixtures remain outside that passing profile.
Explicit Kupyna-256/512 CMS with GOST ONB certificates is independently checked.
Native CMS carrying PB signature tags on ONB keys remains rejected; test adapters
alone normalize that known SDK quirk. Kalyna CFB/OFB also supports explicitly
selected standard DH (OID ending in `.8`), with full prime-order subgroup checks.
The native ONB producer's `.7`-tagged non-cofactor envelopes remain rejected;
there is no implicit cofactor fallback. Named ONB certificates/CSRs support
Kupyna-256/512 signatures with GOST ONB SPKI and legacy named parameters.
Alternate modern SPKI identifiers remain rejected. See
[CSR encoding](csr.md). See [ONB coverage](onb.md) for
the exact evidence, retained public fixtures, reproduction commands and limits.

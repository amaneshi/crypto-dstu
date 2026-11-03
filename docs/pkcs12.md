# PKCS#12 profiles and policy

PKCS#12/PFX imports now require password integrity protection. The loader verifies
the MAC over the original AuthenticatedSafe octets **before** decrypting or
returning private keys. Wrong passwords and modified contents return an error
with no partial import. Format auto-detection preserves recognized PFX integrity
errors instead of trying to reinterpret a failed container as another format.

This is a compatibility change: PFX files without a MAC, with SignedData integrity,
or with unsupported integrity algorithms are rejected. There is no implicit
unverified-import fallback.

## Export

`ua.ProtectPKCS12(rawKey, certificateDERs, password)` accepts an unencrypted
PKCS#8 DER/PEM blob and DER/PEM certificates. It preserves the original PKCS#8
bytes, including a separate IIT agreement key. `box.ExportPKCS12(password)`
exports every loaded key and discovery certificate, regardless of selected key
roles. It preserves scalars but re-encodes PKCS#8 using the supported named PB/ONB profile;
original algorithm metadata is not retained by `Box`.

Every key must have exactly one distinct certificate matching its derived public
key and full curve domain. Exact duplicate certificates are deduplicated. Missing
matches, ambiguous certificates and duplicate keys fail without returning output.
Matching certificate/key bags share an opaque SHA-256-derived `localKeyId`.
For a single PKCS#8 bag containing IIT's separate agreement key, no one-to-one
key-bag ID is invented; association still checks both public keys.

The writer emits version-3 PFX with Data safe contents. Every private-key bag is
a PKCS8ShroudedKeyBag protected with PBES2, PBKDF2/Kupyna MAC-256 and Kalyna-256
CBC with strict PKCS#7 padding. Each bag has independent random 32-byte salt and
IV and 10,000 KDF iterations. Public certificate bags remain unencrypted. The
complete AuthenticatedSafe is authenticated with HMAC-SHA256, an independent
random 32-byte salt, 10,000 PKCS#12 KDF iterations, and a BMP-formatted password.
No private key is emitted in an unencrypted bag.

Export passwords must contain 1–32 UTF-8 bytes, valid BMP characters and no NUL.
The explicit PBMAC1 profile below also accepts supplementary Unicode characters
within the same byte limit. The default export profile remains unchanged.
Export limits are 64 keys, 512 input certificates, 512 total bags, 8 MiB combined
input data and 16 MiB output. These limits are deliberately stricter than import.
Neither export nor import promotes certificates to trust anchors or validates
their trust chains.

The pinned IIT SDK successfully signs attached/detached GOST PB257, Kupyna PB257
and Kupyna PB431 CMS with Go-written PFX, including tested Cyrillic/Ukrainian
passwords. The SDK requires the matching certificate supplied to its discovery
store separately; embedding it in PFX does not establish automatic native
certificate discovery. Native multi-key selection and other providers remain
unverified. OpenSSL independently verifies the complete HMAC-SHA256 and bag
structure; that check does not claim OpenSSL supports Kalyna key decryption.

## Integrity profiles

| Digest identifier | MAC construction | Independent evidence |
| --- | --- | --- |
| SHA-1 | HMAC, legacy import | OpenSSL 3.5.9 KDF/MAC vectors |
| SHA-224/256/384/512 | HMAC | OpenSSL 3.5.9 KDF/MAC vectors |
| GOST 34.311-95 (`1.2.804.2.1.1.1.1.2.1`) | HMAC | Disposable IIT-generated PB257 PFX |
| Kupyna-256 (`1.2.804.2.1.1.1.1.2.2.1`) | National Kupyna KMAC-256 | Disposable IIT-generated modern PB257 PFX |
| PBMAC1 (`1.2.840.113549.1.5.14`) | PBKDF2 with SHA-2 HMAC PRF and SHA-2 HMAC | OpenSSL 3.5.9 PFX, including mixed SHA-256 MAC/SHA-512 PRF |

Traditional MAC key derivation uses [RFC 7292 Appendix B](https://www.rfc-editor.org/rfc/rfc7292.html#appendix-B),
diversifier ID 3, producing one digest-sized MAC key. The native Kupyna profile
uses KMAC, not HMAC; its hash OID does not authorize other untested constructions.
Kupyna-512 PFX MACs and other unlisted integrity profiles remain unsupported.

Traditional MAC passwords use terminated UTF-16BE/BMP encoding. Invalid UTF-8, supplementary
Unicode characters, and passwords over 4096 UTF-8 bytes are explicitly rejected.
An empty caller password supports both the standard terminator and the historical
zero-byte password representation, but only if the corresponding MAC verifies.
OpenSSL vectors cover empty, ASCII, Cyrillic BMP and long passwords. Separate
native GOST/Kupyna PFX checks now cover Cyrillic/Ukrainian passwords with the
corrected Windows CP1251 adapter boundary; this is limited to the tested profiles.
The existing Key-6 password limits/policies still apply to privacy protection.
See [password compatibility](compatibility.md).

### Explicit UTF-8 PBMAC1 profile

[RFC 9879](https://www.rfc-editor.org/rfc/rfc9879.html#section-6) specifies raw
UTF-8 passwords for PBMAC1, without a terminator or added BOM. The implementation
preserves exact bytes and performs no Unicode normalization. CJK, Arabic,
Devanagari, Greek, emoji, supplementary letters, and distinct composed/decomposed
spellings are covered. Import accepts valid UTF-8 up to 4096 bytes; existing
privacy-profile limits still apply to encrypted bags. Export accepts 1–32 UTF-8
bytes without NUL, including supplementary characters.

```go
options := ua.PKCS12ExportOptions{Integrity: ua.PKCS12IntegrityPBMAC1SHA256}
pfx, err := ua.ProtectPKCS12WithOptions(rawKey, certificates, "密碼🔑", options)
// Or export loaded keys and certificates:
pfx, err = box.ExportPKCS12WithOptions("密碼🔑", options)
```

Export uses PBKDF2/HMAC-SHA256 and HMAC-SHA256, an explicit 32-byte key length,
a fresh 32-byte salt and 10,000 iterations. The national encrypted key bags are
unchanged. Import supports SHA-224/256/384/512 HMAC independently for PRF and MAC,
with absent/NULL algorithm parameters. PBKDF2 salt must contain 1–1024 bytes,
iterations 1–1,000,000 and explicit keyLength 20–64 bytes. Missing keyLength,
SHA-1/default PRF, unsupported algorithms, malformed/trailing parameters and
wrong-length digests fail before releasing keys. The outer legacy MacData salt
and iteration fields are ignored for PBMAC1; the effective KDF parameters are
inside PBMAC1-params. There is no BMP/UTF-8 retry on a failed MAC.

Sixteen retained PFX fixtures cover eight password/hash cases. OpenSSL verifies
complete Go-produced national-key PFX integrity and independently generates
certificate-only PBMAC1 PFX. A bounded test adapter invokes the original,
unmodified UAPKI Kupyna password KDF and Kalyna-CBC implementation to decrypt
the Go fixtures' key bags, with wrong-password rejection. OpenSSL itself does
not decrypt Kalyna. IIT acceptance of PBMAC1 or non-CP1251 passwords is not
claimed. See [fixture provenance and reproduction](../internal/keystore/testdata/README.md).

The parser accepts absent or NULL digest parameters, iteration counts from 1 to
1,000,000 (omitted means 1), and salt lengths from 1 to 1024 bytes. PFX input is
limited to 16 MiB, with at most 64 safe contents, 512 bags per safe, 64 keys and
512 certificates. Unsupported safe/bag/certificate types and malformed/trailing
contents fail explicitly instead of silently producing a partial import. Privacy
continues to use the existing supported PBES2 profiles; old PKCS#12-specific
RC2/3DES privacy algorithms are not newly implemented by this change.

## Certificate association and trust

Certificates are matched to each key's derived public point and full supported
curve domain. Certificate order, `localKeyId`, and friendly names cannot force a
different association. Exact duplicate certificate DER is deduplicated; multiple
distinct certificates for the same key are ambiguous and rejected. Duplicate
private keys are rejected too. A key with no matching certificate can still be
imported with `Cert=nil`, without borrowing an unrelated certificate by index.

`KeyCertPair.CertChain` retains additional unmatched certificates for discovery;
the name does **not** mean that a chain has been validated. Imported certificates
never become trust anchors. Verification still requires explicit application trust.
Separate IIT agreement-key attributes inside PKCS#8 bags are retained.

## Validation

The tests include reversed certificate/key bag order, multiple keys, duplicate and
ambiguous association, encrypted and plain bags, wrong passwords, MAC/content
mutations, missing/unsupported integrity, malformed authenticated contents and
excessive MAC parameters. OpenSSL vector generation is reproducible through
`internal/keystore/testdata/generate-pkcs12-vectors.ps1`; OpenSSL is not a runtime
dependency. Its [PKCS12KDF documentation](https://docs.openssl.org/3.5/man7/EVP_KDF-PKCS12KDF/)
describes the independent derivation interface used by the fixture generator.

`TestIITPKCS12Integrity` is tagged `integration` and is included in the pinned,
isolated `scripts/test-iit.ps1` runner. It generates disposable GOST/Kupyna keys,
verifies the real provider MACs, and checks password/content-mutation rejection.
`TestIITPKCS12NonASCII` additionally imports native GOST/Kupyna containers with
Cyrillic/Ukrainian passwords and verifies signatures from the original and
reprotected key against the public key derived in Go.
`TestIITPKCS12Export` verifies native signing with Go-written PFX, plus native
wrong-password and modified-container rejection. Ordinary export tests cover
multiple keys, reordered certificates, agreement-key preservation, fresh salts
and IVs, invalid input and corruption rejection. To run the independent complete
PFX MAC/structure check, set `PKCS12_OPENSSL` to a local OpenSSL executable and
run `go test ./internal/keystore -run '^TestPKCS12ExportOpenSSL$' -v`.
The new modern PFX test also exposed and now covers a Kupyna KMAC message-padding
buffer bug where a two-block suffix previously panicked. Boundary regressions
exercise every message length through two blocks for KMAC-256/384/512.

`FuzzPKCS12AuthenticatedSafe` wraps arbitrary synthetic inner contents in a valid
MAC, exercising parsing beyond the integrity gate. A short smoke run is useful
regression evidence, not a substitute for the broader parser/security review.

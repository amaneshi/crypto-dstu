# PKCS#12 import policy

PKCS#12/PFX imports now require password integrity protection. The loader verifies
the MAC over the original AuthenticatedSafe octets **before** decrypting or
returning private keys. Wrong passwords and modified contents return an error
with no partial import. Format auto-detection preserves recognized PFX integrity
errors instead of trying to reinterpret a failed container as another format.

This is a compatibility change: PFX files without a MAC, with SignedData integrity,
or with unsupported integrity algorithms are rejected. There is no implicit
unverified-import fallback. PFX export remains unimplemented.

## Integrity profiles

| Digest identifier | MAC construction | Independent evidence |
| --- | --- | --- |
| SHA-1 | HMAC, legacy import | OpenSSL 3.5.9 KDF/MAC vectors |
| SHA-224/256/384/512 | HMAC | OpenSSL 3.5.9 KDF/MAC vectors |
| GOST 34.311-95 (`1.2.804.2.1.1.1.1.2.1`) | HMAC | Disposable IIT-generated PB257 PFX |
| Kupyna-256 (`1.2.804.2.1.1.1.1.2.2.1`) | National Kupyna KMAC-256 | Disposable IIT-generated modern PB257 PFX |

Key derivation uses [RFC 7292 Appendix B](https://www.rfc-editor.org/rfc/rfc7292.html#appendix-B),
diversifier ID 3, producing one digest-sized MAC key. The native Kupyna profile
uses KMAC, not HMAC; its hash OID does not authorize other untested constructions.
Kupyna-512 PFX MACs, PBMAC1 and other integrity profiles remain unsupported.

MAC passwords use terminated UTF-16BE/BMP encoding. Invalid UTF-8, supplementary
Unicode characters, and passwords over 4096 UTF-8 bytes are explicitly rejected.
An empty caller password supports both the standard terminator and the historical
zero-byte password representation, but only if the corresponding MAC verifies.
OpenSSL vectors cover empty, ASCII, Cyrillic BMP and long passwords. Separate
native GOST/Kupyna PFX checks now cover Cyrillic/Ukrainian passwords with the
corrected Windows CP1251 adapter boundary; this is limited to the tested profiles.
The existing Key-6 password limits/policies still apply to privacy protection.
See [password compatibility](compatibility.md).

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
The new modern PFX test also exposed and now covers a Kupyna KMAC message-padding
buffer bug where a two-block suffix previously panicked. Boundary regressions
exercise every message length through two blocks for KMAC-256/384/512.

`FuzzPKCS12AuthenticatedSafe` wraps arbitrary synthetic inner contents in a valid
MAC, exercising parsing beyond the integrity gate. A short smoke run is useful
regression evidence, not a substitute for the broader parser/security review.

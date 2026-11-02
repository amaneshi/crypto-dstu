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

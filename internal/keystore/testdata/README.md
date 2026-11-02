`jks-public-scalar.json` is an independent JKS v2 / Java KeyProtector test vector
produced with `github.com/pavlo-v-chernykh/keystore-go/v4` v4.5.0.

It deliberately uses public scalar `d=1`, a public test password, fixed creation
time and fixed test salt. It contains no operational credentials or certificates.
The plaintext is named-curve PB257 PKCS#8 DER. The fixture exercises the standard
entry layout, store integrity digest, key-protection checksum and auto-detection.
Wrong passwords and mutations are tested without adding a runtime dependency on
the independent fixture producer.

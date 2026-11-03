# Native ONB Kalyna envelopes

Ten unmodified envelopes were produced by IIT x86 `EUSignCP.dll` 1.3.1.224,
SHA256 `475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f`.
They cover CFB/OFB on ONB173/179/191/233/431 with static originators.
The 65-byte plaintext is `00..40`. Certificates are disposable Go-generated,
self-signed GOST ONB named-curve certificates. The intentionally public recipient
scalar is `2^(bitlen(n)-2)+0x12345`; the sender adds `0x13579`.
No operational credentials or encrypted key containers are retained.

This SDK uses non-cofactor agreement (`h=1`) for these ONB envelopes but writes
the cofactor-DH OID ending in `.7`. The consumer rejects the original mismatched
profile. Only the test adapter explicitly relabels the known fixture header to
standard-DH `.8`; no ciphertext, IV, UKM or wrapped key is changed. Go and IIT then
decrypt the same bytes. The consumer never retries with a different cofactor or
rewrites incoming data automatically. Standard DH validates nonzero prime-order
subgroup membership before deriving a key.

`TestStandardDHNativeEnvelopes` checks these retained files without IIT or network
access, including rejection of the originals, wrong keys and corrupted wrapped
keys. `TestIITStandardDHKalyna` additionally validates fresh Go `.8` output in IIT
for all five ONB curves and PB257, CFB/OFB, 1/33/65-byte payloads, and dynamic,
referenced-static and embedded-static originators. Regenerate with:

```powershell
# Configure IIT_ORACLE, IIT_SDK_DIR and IIT_SDK_SHA256 as in docs/iit-interoperability.md.
$env:IIT_CAPTURE_STANDARD_DH_DIR = 'C:\absolute\public-fixture-output'
go test -tags=integration -mod=readonly -count=1 -timeout=180s -v ./internal/interop -run '^TestIITStandardDHKalyna$'
Remove-Item Env:IIT_CAPTURE_STANDARD_DH_DIR
```

Certificates, IVs, CEKs and UKM are freshly generated, so reproduction compares
profile coverage and successful cryptographic checks rather than identical bytes.
These fixtures establish no sender identity trust or revocation status. Content
CFB/OFB remains unauthenticated; signed plaintext needs separate verification.

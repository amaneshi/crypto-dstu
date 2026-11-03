# Primitive validation

Primitive validation combines independent known answers with bounded fuzz
campaigns. The fixtures are public algorithm inputs, not operational credentials.
Go builds/tests read JSON only and require neither Cryptonite nor Java.

## Independent known answers

`internal/testvectors/testdata/cryptonite-primitives.json` contains 309 cases
generated through the unmodified public APIs of `privat-it/cryptonite` at
commit `3618d340d22e27a6becf97d89c453f8e64068a39`:

| Primitive | Cases |
| --- | ---: |
| GOST 34.311 with S-box 1, zero sync | 22 |
| GOST 28147 MAC-64 with S-box 1 | 21 |
| GOST 28147 CFB with S-box 1 | 21 |
| HMAC-GOST with 1/32/65/129-byte keys | 88 |
| Kupyna 256/384/512 | 66 |
| Kupyna KMAC 256/384/512 with 32/48/64-byte keys | 66 |
| Kalyna ECB/CBC/CTR/CFB/OFB on all five block/key profiles | 25 |

Message sizes include 0/1, cipher/hash block boundaries, 51/52 and 111/112
padding boundaries, and 1024 bytes. GOST MAC/CFB omit the empty input because
the corresponding Cryptonite operation rejects it. Kalyna mode cases use three
complete blocks; message-level short-tail CFB remains covered by the existing
Cryptonite/IIT fixtures. Test keys and IVs are ascending bytes; message byte `i`
is `(29*i+7) mod 256`. Hash tests vary write chunk sizes; GOST CFB also checks
fragmented encryption/decryption against independently generated ciphertext.

`bouncycastle-kmac.json` adds 360 KMAC cases from unmodified
`org.bouncycastle:bcprov-jdk18on:1.86`. It covers all three tag sizes, key lengths
0/1/31/32/51/52/63/64/65/115/116/127/128/129/256 and message lengths
0/1/51/52/64/111/112/128, including reset and byte-wise updates. The Java producer
checks the loaded JAR SHA256:
`2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f`.
This broadens direct KMAC API validation; it does not establish provider
interoperability for arbitrary password encodings or key sizes.

`pkg/dstu4145/testdata/pb-operations-cryptonite.json` adds public-key coordinates,
compression, GOST signatures and cofactor ECDH outputs for all ten standard PB
curves, using public scalars 2 and 7. The existing five ONB operation and
zero-digest fixtures remain independently checked. The reference signature PRNG
seed is public bytes `00..27`, with the PRNG clock fixed to Unix time
1793707200 (3 November 2026, 12:00 UTC); these deterministic fixtures must never be used
for operational signing. Curve math evidence does not resolve the separate IIT
ONB certificate/CMS limitations.

## Reproduction

Build the unmodified Cryptonite static library at the pinned revision using its
upstream build instructions. With a C compiler, its headers and that archive:

```sh
gcc -O2 -DCRYPTONITE_EXPORT= -I/path/to/cryptonite/src/cryptonite/c internal/testvectors/testdata/generate-primitives.c /path/to/libcryptonite.a -lm -o /tmp/primitive-vectors
/tmp/primitive-vectors > /tmp/cryptonite-primitives.json
gcc -O2 -DCRYPTONITE_EXPORT= -DFIXED_REFERENCE_TIME=1793707200 -Wl,--wrap=time -I/path/to/cryptonite/src/cryptonite/c pkg/dstu4145/testdata/generate-onb-vectors.c /path/to/libcryptonite.a -lm -o /tmp/curve-vectors
/tmp/curve-vectors pb > /tmp/pb-operations-cryptonite.json
```

The producer checks that the test-only `time` wrapper was actually called;
Cryptonite's cryptographic source remains unmodified. The existing default,
`zero` and `pb173` modes remain available without the fixed-clock flags, but
their signature bytes depend on the PRNG clock as well as the seed.
For KMAC, use a JDK and the checksum-verified Bouncy Castle JAR:

```sh
javac -cp /path/to/bcprov-jdk18on-1.86.jar -d /tmp internal/testvectors/testdata/GenerateKMACVectors.java
java -cp /tmp:/path/to/bcprov-jdk18on-1.86.jar GenerateKMACVectors /tmp/bouncycastle-kmac.json
```

Use `;` instead of `:` in the Java classpath on Windows. The new producers use
LF line endings. SHA256 values for the checked-in JSON files are:

| Fixture | SHA256 |
| --- | --- |
| `cryptonite-primitives.json` | `afc3433b824085498ba9072dd22d148484d2a6dd3581777664f9aa6464e39427` |
| `bouncycastle-kmac.json` | `94e080b20bb98b9e0907749ac0b17b176f496929f9fe5c9499d58624b84b05a7` |
| `pb-operations-cryptonite.json` | `d1643591febc4075cce48f1e2d0b3f438cb266d83659b1751b1260635fa01ce5` |

## Fuzz targets and regression fixes

`scripts/test-fuzz.ps1 -Suite primitives -Duration 3m -Workers 2` runs:

| Target | Properties |
| --- | --- |
| `FuzzPrimitiveHashes` | GOST/Kupyna/KMAC/HMAC streaming, Sum state/prefix behavior, reset and caller-buffer immutability |
| `FuzzPrimitiveBlocks` | All five Kalyna profiles and GOST blocks, in-place encryption/decryption, CBC comparison with the standard library and fragmented CTR/CFB/OFB streams |
| `FuzzFieldArithmetic` | All fifteen curve domains; carryless multiplication/reduction against a separate `math/big` polynomial oracle, addition, squaring and inverse identity checked through that oracle |
| `FuzzCurveEncodings` | All fifteen domains; malformed compressed input, valid point/basis roundtrips and unchanged input |
| `FuzzSignaturesAndAgreement` | All fifteen domains; valid/malformed raw signatures, zero-s rejection and symmetric cofactor ECDH using candidate-derived public scalars |
| `FuzzCMSKeyWrap` | National Kalyna CMAC/CFB wrapping, corruption rejection and no plaintext on unwrap errors |
| `FuzzKWUnwrap` | Raw DSTU 7624 KW parsing/integrity, independently anchored by the existing Cryptonite/Bouncy Castle vectors |

Bounds are 4096 message bytes/256 key bytes for hashes, 2048 message bytes for
block/stream tests, 64-byte field operands, 128-byte compressed/signature inputs
and 64-byte digests. Agreement scalars are derived from up to eight public input
bytes plus one. Signing nonces come from a fixed public byte stream. These are
test budgets and deterministic test inputs, not production policy or key
generation practices.

The initial campaigns exposed three defects. Their minimized inputs remain in
`internal/testvectors/testdata/fuzz` and run as ordinary regression seeds:

- A nonzero compressed point `01` can restore x=0 on A=0 curves and panic in
  inversion. Expansion now rejects that noncanonical encoding while preserving
  the canonical finite zero-x point. A focused regression covers all domains.
  After the ONB wire correction, its selector-only regression uses bit `m-1`;
  PB continues to use `01`.
- KMAC's key/tail padding assumed a single block. A 52-byte KMAC-256 key panicked;
  longer keys could also lose bytes or use the wrong message length. Every padded
  key block is now counted, and the complemented-key tail has enough blocks.
  Standard provider key outputs remain unchanged; boundary outputs match the
  independent Bouncy Castle fixtures.
- GOST CFB restarted its byte offset on every stream call. It now preserves the
  offset, so fragmented and one-shot calls match independent ciphertext. Existing
  one-shot ciphertext is unchanged.

## Completion campaign

On 3 November 2026, the final seven campaigns passed on Windows/amd64 with
Go 1.27.3, three minutes per target and two workers. The totals below use the
successful reruns after the fixes, and the strengthened candidate-derived
agreement target. The initial failing runs remain represented by regression seeds.

| Target | Executions | Result |
| --- | ---: | --- |
| `FuzzPrimitiveHashes` | 74,527 | PASS |
| `FuzzPrimitiveBlocks` | 113,014 | PASS |
| `FuzzFieldArithmetic` | 2,538,421 | PASS |
| `FuzzCurveEncodings` | 127,947 | PASS |
| `FuzzSignaturesAndAgreement` | 5,243 | PASS |
| `FuzzCMSKeyWrap` | 18,812 | PASS |
| `FuzzKWUnwrap` | 251,829 | PASS |

Total: **3,129,793 executions**. Counts include rejected malformed inputs and
are not counts of independently verified valid cryptographic operations.
Full regression tests, vet, correctness lint and gopls diagnostics passed. The
pinned IIT matrix passed after the point/KMAC fixes, and focused native GOST
encryption/static-originator checks passed after the CFB fix. Known ONB diagnostic
errors in that native matrix remain documented limitations, not ONB support.

Passing these bounded campaigns is not proof of full conformance, constant-time
execution, maximum-input resource safety or production readiness. An external
cryptographic/security review remains a separate README task. HMAC-Kupyna has
streaming checks and independently validated underlying hashes here, without a
new independent HMAC-Kupyna tag fixture.

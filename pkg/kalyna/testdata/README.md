`cryptonite-kw.json` transcribes the nine public `kw_data` cases in
[`privat-it/cryptonite`, `atest_dstu7624.c`](https://github.com/privat-it/cryptonite/blob/master/src/cryptoniteAtest/c/atest_dstu7624.c).
Hex strings preserve the byte order of the C fixtures. These are public algorithm
test keys, not operational credentials.

The vectors cover Kalyna 128/128, 128/256, 256/256, 256/512 and 512/512,
including the Cryptonite padding extension for non-aligned input. Their round
counters remain below 256. The Go implementation uses a 32-bit little-endian
counter, as in
[`DSTU7624WrapEngine`](https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/engines/DSTU7624WrapEngine.java),
rather than Cryptonite's one-byte truncation for larger keys.

`bouncycastle-kw-large.json` was generated with the unmodified Maven Central
artifact [`org.bouncycastle:bcprov-jdk18on:1.86`](https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/).
The JAR's SHA256, also recorded in the fixture and enforced by the generator, is
`2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f`.
No JAR is redistributed or required to run the Go tests.

The fifteen vectors cover all five block/key profiles above with 20, 21 and 22
plaintext blocks. Including the appended integrity block, the wrap and unwrap
counters reach 246, 258 and 270. Public key bytes are `00,01,...`; plaintext
byte `i` is `(29*i+7) mod 256`, except the last two bytes are zero. Both wrap
and unwrap are compared directly to these independent outputs, with wrong-key
and beginning/middle/end corruption checks releasing no plaintext.

Reproduce with a JDK (8 or newer), from the repository root. Download and verify
the JAR against the SHA256 above, then run (use `;` instead of `:` in the runtime
classpath on Windows):

```sh
mkdir -p /tmp/kalyna-kw-reference
javac -cp /path/to/bcprov-jdk18on-1.86.jar -d /tmp/kalyna-kw-reference pkg/kalyna/testdata/GenerateKWVectors.java
java -cp /tmp/kalyna-kw-reference:/path/to/bcprov-jdk18on-1.86.jar GenerateKWVectors /tmp/bouncycastle-kw-large.json
cmp pkg/kalyna/testdata/bouncycastle-kw-large.json /tmp/bouncycastle-kw-large.json
```

The generator first checks the loaded JAR hash and independently unwraps every
output with Bouncy Castle. The generated fixture SHA256 is
`ed5740586192410a38841ea6ceb2a4da7094bab28ecda0c723b1459e814286e2`.
Initial reproduction used Java 8u511 with Eclipse ECJ 3.26.0 as the compiler;
generation is deterministic and does not use randomness or the Go implementation.
A Go source-overlay mutation truncating the counter to one byte caused all ten
above-255 wrap comparisons and all ten above-255 unwrap checks to fail, while
all five 246-round controls passed. The overlay was external to the checkout.

These are aligned raw KW cases, distinct from the national CMS CMAC/CFB wrapper
and from the Cryptonite non-aligned padding extension. They do not establish
conformance at every possible 32-bit counter value or provide a timing audit.

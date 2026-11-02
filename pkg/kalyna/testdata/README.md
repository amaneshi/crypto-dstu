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

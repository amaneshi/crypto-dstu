# Kupyna performance

The captured CZO Kupyna OCSP/CRL check exposed slow hashing of an 8.5 MB full CRL.
A CPU profile attributed 98% of hashing CPU time to `mixColumns`, including 83%
in byte-wise GF(2^8) multiplication.

The MDS transformation now packs each eight-byte column into a uint64. Masked
shifts implement multiplication by x independently in every byte lane; fixed
rotations and XOR combine the circulant matrix coefficients. Row shifts use a
mask for the algorithm's two power-of-two state widths, 8 and 16 columns.
No new data-dependent lookup tables are used by the optimized MDS operation.
This is not a constant-time claim for the whole hash or KMAC implementation:
existing S-box lookups remain data-dependent.

Local measurements on Windows amd64, Intel Core Ultra 9 275HX, Go 1.26.4:

| Check | Before | After |
| --- | ---: | ---: |
| Kupyna-256 hashing, 1 MiB | 8.6–11.5 s | 67–70 ms |
| Captured CZO 2025 OCSP + full CRL validation | 38–42 s | 1.14 s |
| Both captured CZO profiles | 38.58 s | 1.70 s |

Hash timings are three one-operation benchmark samples; the initial run also
collected a CPU profile. These are local observations, not portable latency
promises. Whole-fixture timings exclude Go test compilation/startup. The CRL
still receives full signature, issuer, scope and freshness validation every time.
No evidence cache or validation shortcut was introduced. Allocation behavior
was not changed by this optimization.

Reproduce hashing measurements:

```text
go test ./pkg/kupyna -run '^$' -bench '^BenchmarkKupyna256$' -benchtime=1x -count=3 -benchmem
```

Reproduce the complete captured check without network access:

```text
go test -tags=integration -count=1 -v -timeout=30s ./internal/ocsp -run '^TestCapturedCZOOCSP$'
```

Correctness checks exhaust all byte values in every MDS input lane against the
original byte-wise calculation, compare deterministic random states at both
widths, and verify row shifts against their modulo definition. Known Cryptonite
single- and multi-block vectors, existing hash/KMAC vectors, streaming/padding
boundaries across 256/384/512-bit hashes, and the independently generated CZO
signature/CRL captures also pass. Archived fixtures use fixed capture times;
they are not evidence of current certificate status.

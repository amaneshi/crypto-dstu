# CZO Test Examples

Reference: https://czo.gov.ua/testexamples  
Signature verification tool: https://czo.gov.ua/verify

## Status

Real CZO test files require manual download from https://czo.gov.ua/testexamples.
Until real files are placed here, all tests in `cms/czo_test.go` and `ua/czo_test.go`
use **synthetic test data** generated with our own DSTU keys, which exercises the same
code paths and validates correctness of the implementation.

## Directory Layout

```
testdata/czo/
├── README.md               — this file
├── cades/
│   ├── bes.p7s             — CAdES-BES (synthetic or real)
│   ├── t.p7s               — CAdES-T (with timestamp token)
│   └── detached.p7s        — CAdES-BES detached signature
├── certs/
│   ├── ca.cer              — CA certificate (synthetic or real CZO CA)
│   └── signer.cer          — Test signer certificate
└── content/
    └── doc.txt             — Signed document content (for detached tests)
```

## Updating with Real CZO Files

1. Visit https://czo.gov.ua/testexamples
2. Download all CAdES test examples (.p7s files)
3. Download the CA certificate bundle (CACertificates.p7b)
4. Place files according to the layout above
5. Update `cms/czo_test.go` to load from these paths instead of generating synthetic data
6. Verify results match https://czo.gov.ua/verify

## Notes

- CZO test files may use GOST 34.311-95 hash (older) or Kupyna-256 (newer)
- The `cms` package handles both hash algorithms
- XAdES and PAdES are not in scope for the current implementation (CAdES only)
- Last updated: see git log

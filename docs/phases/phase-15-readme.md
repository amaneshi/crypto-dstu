# Phase 15 — Root README

## Goal
Write a comprehensive `README.md` in the repository root that serves two audiences:
1. **CLI users** — how to install and use the `dstu` command-line tool
2. **Library users** — how to import and use the Go packages in their own code

## Prerequisites
- **Phase 14** (`cmd/dstu`) — CLI must be implemented first
- **All other phases** — README documents the complete API surface

## Files to Create

| File | Purpose |
|------|---------|
| `README.md` | Root documentation file |

## Content Outline

### 1. Header
- Project name and one-line description
- Badges: Go version, license, test status

### 2. Overview
- What standards are implemented (DSTU 4145, Kupyna, Kalyna, GOST, CMS, TSP)
- Primary use case: Ukrainian tax office document exchange (MDOC, cabinet.tax.gov.ua)
- Pure Go, no CGo

### 3. Installation
```bash
# CLI tool
go install github.com/amaneshi/crypto-dstu/cmd/dstu@latest

# Library
go get github.com/amaneshi/crypto-dstu
```

### 4. CLI Usage (complete reference)
Mirror the dstucrypt/agent README style. Cover:
- `dstu sign` — all flags with examples
- `dstu decrypt` — unwrap/verify incoming documents
- `dstu encrypt` — encrypt for recipient
- `dstu certinfo` — parse and display certificate fields
- `dstu unprotect` — remove key password

### 5. Library Usage
Short, idiomatic Go snippets for each major use case:
- Sign a document
- Verify/unsign a document
- Encrypt for a recipient
- Decrypt
- Load a key store
- Parse certificate info
- Direct primitives (hash, sign, verify)

### 6. Supported Key Formats
Table of formats: Key-6.dat, JKS, PKCS#12, raw DER, PEM

### 7. Package Reference
Table with one-line description per package

### 8. Compatibility
- Tested against CZO test examples
- Compatible with cryptonite reference implementation
- NOT compatible with jkurwa (different byte ordering)

### 9. License

## Acceptance Criteria
- [ ] All CLI examples in README are copy-pastable and produce correct results
- [ ] All library snippets compile (`go vet` clean)
- [ ] Package reference table matches actual package list

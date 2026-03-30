# Phase 13 — CZO Test Examples `testdata/czo`

## Goal
Download, integrate, and verify all test examples from the Central Certification Authority (CZO) test page. These examples cover CAdES, XAdES, and PAdES signature formats and serve as the ultimate compliance test for the library.

## Prerequisites
- **Phase 10** (`cms`) — CMS/PKCS#7 parsing and verification
- **Phase 11** (`tsp`) — timestamp verification
- **Phase 8** (`cert`) — certificate handling
- **Phase 12** (`ua`) — high-level API for end-to-end verification

## Package
No new package — tests live in existing packages, test data in `testdata/czo/`.

## Reference
- Test examples page: https://czo.gov.ua/testexamples
- Signature verification tool: https://czo.gov.ua/verify
- Technical format specs: https://czo.gov.ua/formattechspecs

## Files to Create

| File | Purpose |
|------|---------|
| `testdata/czo/README.md` | Description of test files, how to update them |
| `testdata/czo/cades/` | CAdES test example files (.p7s) |
| `testdata/czo/xades/` | XAdES test example files (.xml) |
| `testdata/czo/pades/` | PAdES test example files (.pdf) |
| `testdata/czo/certs/` | CA certificates and test signer certs from CZO |
| `cms/czo_test.go` | CAdES verification tests |
| `ua/czo_test.go` | End-to-end verification tests using high-level API |

## Step-by-Step Instructions

### 1. Download test examples
Visit https://czo.gov.ua/testexamples and download all available test files:
- **CAdES-BES** — basic signed data
- **CAdES-T** — with timestamp
- **CAdES-C** — with certificate references
- **CAdES-X-Long** — with full OCSP responses and cert values
- **XAdES-BES** — XML-based signature
- **XAdES-T** — XML with timestamp
- **PAdES-BES** — PDF-based signature
- **PAdES-T** — PDF with timestamp

Also download:
- The original unsigned content files (if provided separately)
- Signer certificates used in the test examples
- CA certificate bundle from CZO

Place files in organized directories under `testdata/czo/`.

### 2. Document test files (`testdata/czo/README.md`)
```markdown
# CZO Test Examples

Downloaded from https://czo.gov.ua/testexamples on YYYY-MM-DD.

## Files
- cades/test-bes.p7s — CAdES-BES signed document
- cades/test-t.p7s — CAdES-T (with timestamp)
- cades/test-xl.p7s — CAdES-X-Long
- xades/test-bes.xml — XAdES-BES
- pades/test-bes.pdf — PAdES-BES
- certs/CACertificates.p7b — CA certificate bundle
- certs/signer.cer — test signer certificate

## Verification
All files can be verified at https://czo.gov.ua/verify
```

### 3. Write CAdES verification tests (`cms/czo_test.go`)

```go
func TestCZO_CAdES_BES(t *testing.T) {
    // Load test file
    data := loadTestFile(t, "testdata/czo/cades/test-bes.p7s")

    // Parse CMS SignedData
    msg, err := cms.ParseSigned(data)
    require.NoError(t, err)

    // Verify structure
    assert.NotEmpty(t, msg.Signers)
    assert.NotNil(t, msg.Content)

    // Verify signature
    // Load CA certs for chain verification
    caCerts := loadCACerts(t, "testdata/czo/certs/CACertificates.p7b")
    err = cms.VerifySigned(msg, nil, caCerts)
    assert.NoError(t, err)
}

func TestCZO_CAdES_T(t *testing.T) {
    // Similar to BES but also verify timestamp
    // Check that unsigned attributes contain timestamp token
    // Verify timestamp token
}

func TestCZO_CAdES_XLong(t *testing.T) {
    // Verify signature
    // Check certificate references in unsigned attributes
    // Check OCSP responses in unsigned attributes
    // Verify the full CAdES-X-Long structure
}
```

### 4. Write high-level verification tests (`ua/czo_test.go`)

```go
func TestCZO_FullVerification(t *testing.T) {
    box := ua.NewBox()

    // Load CA bundle
    err := box.LoadCABundleFile("testdata/czo/certs/CACertificates.p7b")
    require.NoError(t, err)

    // Unsign CAdES-BES
    data := loadTestFile(t, "testdata/czo/cades/test-bes.p7s")
    result, err := box.UnsignDocument(data)
    require.NoError(t, err)

    // Verify all signers are valid
    for _, signer := range result.Signers {
        assert.True(t, signer.Valid, "signer %s should be valid", signer.CertInfo.CommonName)
    }

    // Verify content was extracted
    assert.NotEmpty(t, result.Content)
}

func TestCZO_TransportContainer(t *testing.T) {
    // If transport container test files are available
    // Parse transport container
    // Extract and verify signed content
    // Extract and decrypt encrypted content
}
```

### 5. Cross-validation workflow
For each test file:
1. Parse with our library
2. Extract signer info, timestamps, content
3. Verify signatures and certificate chains
4. Compare results with what `czo.gov.ua/verify` reports
5. Document any discrepancies

### 6. XAdES and PAdES (stretch goals)

**XAdES** (XML Advanced Electronic Signatures):
- Parse XML document
- Find `<ds:Signature>` element
- Extract signed data and signature value
- Verify using DSTU 4145

**PAdES** (PDF Advanced Electronic Signatures):
- Parse PDF to find signature dictionary
- Extract PKCS#7 signature from `/Contents` field
- Verify as CMS SignedData

These are stretch goals — CAdES is the priority for tax office interaction.

### 7. Regression test script
Create a test that can be run to verify all CZO examples:
```go
func TestAllCZOExamples(t *testing.T) {
    examples, err := filepath.Glob("testdata/czo/*/*.p7s")
    require.NoError(t, err)

    box := setupTestBox(t)

    for _, example := range examples {
        t.Run(filepath.Base(example), func(t *testing.T) {
            data, err := os.ReadFile(example)
            require.NoError(t, err)

            result, err := box.UnsignDocument(data)
            require.NoError(t, err)
            assert.True(t, result.Signers[0].Valid)
        })
    }
}
```

## Acceptance Criteria
- [ ] All CZO CAdES test examples downloaded and organized
- [ ] CAdES-BES examples parse and verify correctly
- [ ] CAdES-T examples have timestamps verified
- [ ] CAdES-X-Long examples have full chain verification
- [ ] CA certificate bundle loads correctly
- [ ] All tests pass consistently
- [ ] Results match `czo.gov.ua/verify` output

## Notes
- CZO test examples may be updated — document the download date and version
- The CA certificate bundle from CZO contains all trusted Ukrainian CAs
- Some test examples may use older algorithms (GOST) while newer ones use Kupyna — handle both
- XAdES and PAdES are lower priority than CAdES for tax office interaction
- If test examples are not freely downloadable, create synthetic test data using our own keys
- The `czo.gov.ua/verify` tool is the authoritative reference for correctness

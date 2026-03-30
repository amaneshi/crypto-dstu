# Phase 9 — Transport Container `transport`

## Goal
Implement the binary transport container format defined by Order #499 (12.07.2010) used for document exchange with the Ukrainian tax office. This includes encoding/decoding the TRANSPORTABLE header, section-based binary format, and CRC32 checksums.

## Prerequisites
None strictly — the transport format is a binary container independent of crypto primitives. However, meaningful integration tests need Phase 5+ for actual signed/encrypted content.

## Package
`crypto-dstu/transport`

## JS Reference
- `jkurwa/lib/util/transport.js` — `transport_encode()`, `transport_decode()`, `header_decode()`
- `jkurwa/lib/util/packed_xml.js` — PACKED_XML format handling
- Transport format spec: https://zakon.rada.gov.ua/rada/show/v0499225-10

## Files to Create

| File | Purpose |
|------|---------|
| `transport/header.go` | TRANSPORTABLE header build/parse, `Header` struct |
| `transport/section.go` | Section encode/decode: `label\0` + `uint32LE(len)` + `data` |
| `transport/container.go` | Full container: `Encode()`, `Decode()`, `Container` struct |
| `transport/crc32.go` | CRC32 checksum computation for CRC32_SIGN / CRC32_FILE |
| `transport/transport_test.go` | Tests |

## Step-by-Step Instructions

### 1. Section format (`section.go`)
Each section in the container is:
```
[label bytes]\0[4 bytes uint32 LE length][data bytes]
```

```go
type Section struct {
    Label    string  // e.g. "UA_SIGN1", "TRANSPORTABLE", "XXX_CRYPT"
    Contents []byte
}

func EncodeSection(s Section) []byte {
    // label + \0 + uint32LE(len(contents)) + contents
}

func DecodeSections(data []byte) ([]Section, error) {
    // scan for null-terminated labels, read length, extract contents
}
```

Port the decoding logic from jkurwa `transport_decode()`:
- Read bytes until `\0` to get label (max 20 chars)
- Read next 4 bytes as uint32 LE for content length
- Validate length doesn't exceed remaining buffer
- Extract content slice
- Special cases:
  - `USC_SIGN` / `USC_CRYPT` — skip (label only, no length/data)
  - `QLB_SIGN` / `QLB_CRYPT` — nested internal format with sub-sections
  - `PACKED_XML` — different internal format (XML-based)

### 2. Header format (`header.go`)
The TRANSPORTABLE header is key=value pairs:

```go
type Header struct {
    Filename  string  // FILENAME
    SndName   string  // SND_NAME — sender name
    SndEmail  string  // SND_EMAIL — sender email
    RcvName   string  // RCV_NAME — recipient name
    RcvEmail  string  // RCV_EMAIL — recipient email
    PrgType   string  // PRG_TYPE — program type
    PrgVer    string  // PRG_VER — program version
    SndDate   string  // SND_DATE — YYYYMMDDHHNNSS
    CerType   string  // CERTYPE — CA identifier (e.g., "UA1")
    CRC32Sign string  // CRC32_SIGN — CRC32 of signed data
    CRC32File string  // CRC32_FILE — CRC32 of original file
    Subject   string  // SUBJECT
    GetStamp  string  // GET_STAMP — request timestamp (0 or 1)
    Result    string  // RESULT — processing result
}
```

Encoding (from jkurwa `transport_header()`):
```
"TRANSPORTABLE\0" + uint32LE(header_len) + header_data
```
Where `header_data` = `"KEY=VALUE\r\n"` for each field + `"\0"` terminator.

Decoding (from jkurwa `header_decode()`):
- Split on `=` for key, `\r\n` for value terminator
- Stop at null byte

```go
func EncodeHeader(h *Header) []byte
func DecodeHeader(data []byte) (*Header, error)
```

### 3. CRC32 checksum (`crc32.go`)
```go
func CRC32(data []byte) uint32
func CRC32Hex(data []byte) string  // hex string for header fields
```

Use Go's standard `hash/crc32` with IEEE polynomial (same as CRC-32/ISO-HDLC used in the tax office protocol).

### 4. Full container (`container.go`)
```go
type Container struct {
    Header   *Header
    Sections []Section  // ordered list: signs, encrypted data, stamps
}

func Encode(c *Container) []byte
func Decode(data []byte) (*Container, error)
```

**Encode** (from jkurwa `transport_encode()`):
1. If header present, write TRANSPORTABLE header section
2. For each document section, write: `label\0 + uint32LE(len) + data`
3. Return concatenated buffer

**Decode** (from jkurwa `transport_decode()`):
1. Check if starts with `PACKED_XML` → handle XML container format
2. Otherwise scan sections:
   - Read label (until `\0`)
   - If label is `TRANSPORTABLE` or `ZPOSTTRANSPORTABLE` → parse as header
   - If label is `QLB_SIGN` → parse QLB internal format (data + hash sub-sections)
   - If label is `QLB_CRYPT` → parse QLB internal format (cert + data + hash)
   - Otherwise → store as regular section with label + contents
3. Return parsed container

**Section types encountered in practice:**
- `TRANSPORTABLE` — header section
- `ZPOSTTRANSPORTABLE` — alternative header label
- `UA_SIGN1` — CMS signed data (most common sign label)
- `UA1_SIGN` — another sign variant (CA-specific prefix)
- `UA1_CRYPT` — encrypted data
- `UA1_STAMP` — timestamp token
- `QLB_SIGN` — signed data (QLB format)
- `QLB_CRYPT` — encrypted data (QLB format)
- `PACKED_XML` — XML-wrapped container
- `USC_SIGN`, `USC_CRYPT` — label-only markers (skip)

### 5. Convenience functions
```go
// Find first section of given type
func (c *Container) FindSection(label string) *Section

// Find all sign sections
func (c *Container) SignSections() []Section

// Find encrypted section
func (c *Container) CryptSection() *Section

// Find stamp section
func (c *Container) StampSection() *Section
```

### 6. Write tests
- **Roundtrip**: `Decode(Encode(container)) == container`
- **Header encode/decode**: verify key=value\r\n format
- **Section encode/decode**: verify label\0 + length + data
- **CRC32**: verify against known values
- **Empty container**: just header, no sections
- **Multi-section**: header + 2 signs + 1 crypt + 1 stamp
- **Real container**: if possible, parse a real tax office container file

Place test fixtures in `testdata/transport/`:
- `testdata/transport/sample.bin` — sample container binary (if available)

## Acceptance Criteria
- [ ] Header encode/decode roundtrip preserves all fields
- [ ] Section encode/decode handles all label types
- [ ] CRC32 computation matches expected values
- [ ] Full container roundtrip works
- [ ] QLB format sections parsed correctly
- [ ] PACKED_XML detection works
- [ ] Invalid/truncated data returns clear errors

## Notes
- The format is binary, not text — use `encoding/binary` for uint32 LE
- Null bytes (`\0`) are significant — they terminate labels and headers
- The tax office response containers use `ZPOSTTRANSPORTABLE` header label
- CRC32 values in the header are hex-encoded strings
- Tax office filename format has strict requirements (see agent README for structure)
- The QLB format is an older variant — UA_SIGN1 is more common now

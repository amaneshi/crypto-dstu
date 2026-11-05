package transport

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ---- CRC32 tests ----

func TestCRC32Empty(t *testing.T) {
	require.Equal(t, uint32(0x00000000), CRC32([]byte{}))
}

func TestCRC32KnownValue(t *testing.T) {
	// CRC-32/IEEE of "123456789" = 0xCBF43926
	require.Equal(t, uint32(0xCBF43926), CRC32([]byte("123456789")))
}

func TestCRC32Hex(t *testing.T) {
	require.Equal(t, "CBF43926", CRC32Hex([]byte("123456789")))
}

func TestCRC32HexPadded(t *testing.T) {
	// CRC32 of empty = 0 → must be 8 chars
	require.Equal(t, "00000000", CRC32Hex([]byte{}))
}

// ---- Section tests ----

func TestEncodeSectionRoundtrip(t *testing.T) {
	s := Section{Label: "UA_SIGN1", Contents: []byte{0x01, 0x02, 0x03}}
	encoded := EncodeSection(s)

	sections, err := DecodeSections(encoded)
	require.NoError(t, err)
	require.Len(t, sections, 1)
	require.Equal(t, "UA_SIGN1", sections[0].Label)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, sections[0].Contents)
}

func TestEncodeSectionEmpty(t *testing.T) {
	s := Section{Label: "UA_SIGN1", Contents: []byte{}}
	encoded := EncodeSection(s)

	sections, err := DecodeSections(encoded)
	require.NoError(t, err)
	require.Len(t, sections, 1)
	require.Equal(t, "UA_SIGN1", sections[0].Label)
	require.Empty(t, sections[0].Contents)
}

func TestEncodeSectionLabelOnly(t *testing.T) {
	s := Section{Label: "USC_SIGN"}
	encoded := EncodeSection(s)
	// Should be just "USC_SIGN\0"
	require.Equal(t, append([]byte("USC_SIGN"), 0x00), encoded)

	sections, err := DecodeSections(encoded)
	require.NoError(t, err)
	require.Len(t, sections, 1)
	require.Equal(t, "USC_SIGN", sections[0].Label)
	require.Nil(t, sections[0].Contents)
}

func TestDecodeMultipleSections(t *testing.T) {
	s1 := Section{Label: "UA_SIGN1", Contents: []byte("sigdata")}
	s2 := Section{Label: "UA1_STAMP", Contents: []byte("stampdata")}
	s3 := Section{Label: "UA1_CRYPT", Contents: []byte("cryptdata")}

	var buf []byte
	buf = append(buf, EncodeSection(s1)...)
	buf = append(buf, EncodeSection(s2)...)
	buf = append(buf, EncodeSection(s3)...)

	sections, err := DecodeSections(buf)
	require.NoError(t, err)
	require.Len(t, sections, 3)
	require.Equal(t, "UA_SIGN1", sections[0].Label)
	require.Equal(t, []byte("sigdata"), sections[0].Contents)
	require.Equal(t, "UA1_STAMP", sections[1].Label)
	require.Equal(t, "UA1_CRYPT", sections[2].Label)
}

func TestDecodeTruncatedLength(t *testing.T) {
	// label\0 + only 2 bytes instead of 4 for length
	data := append([]byte("UA_SIGN1"), 0x00, 0x01, 0x02)
	_, err := DecodeSections(data)
	require.Error(t, err)
}

func TestDecodeTruncatedData(t *testing.T) {
	s := Section{Label: "UA_SIGN1", Contents: []byte{0x01, 0x02, 0x03, 0x04, 0x05}}
	encoded := EncodeSection(s)
	// Truncate the data portion
	_, err := DecodeSections(encoded[:len(encoded)-2])
	require.Error(t, err)
}

// ---- Header tests ----

func TestHeaderEncodeDecodeRoundtrip(t *testing.T) {
	h := &Header{
		Filename:  "test.xml",
		SndName:   "Іваненко Іван",
		SndEmail:  "ivan@example.com",
		RcvName:   "ДПС України",
		RcvEmail:  "dps@tax.gov.ua",
		PrgType:   "iFin",
		PrgVer:    "1.0",
		SndDate:   "20240101120000",
		CerType:   "UA1",
		CRC32Sign: "AABBCCDD",
		CRC32File: "11223344",
		Subject:   "Декларація",
		GetStamp:  "1",
		Result:    "",
	}

	encoded := EncodeHeader(h)
	decoded, err := DecodeHeader(encoded)
	require.NoError(t, err)
	require.Equal(t, h.Filename, decoded.Filename)
	require.Equal(t, h.SndName, decoded.SndName)
	require.Equal(t, h.SndEmail, decoded.SndEmail)
	require.Equal(t, h.RcvName, decoded.RcvName)
	require.Equal(t, h.RcvEmail, decoded.RcvEmail)
	require.Equal(t, h.PrgType, decoded.PrgType)
	require.Equal(t, h.PrgVer, decoded.PrgVer)
	require.Equal(t, h.SndDate, decoded.SndDate)
	require.Equal(t, h.CerType, decoded.CerType)
	require.Equal(t, h.CRC32Sign, decoded.CRC32Sign)
	require.Equal(t, h.CRC32File, decoded.CRC32File)
	require.Equal(t, h.Subject, decoded.Subject)
	require.Equal(t, h.GetStamp, decoded.GetStamp)
	require.Empty(t, decoded.Result) // empty → not encoded → decoded as ""
}

func TestHeaderEmptyFields(t *testing.T) {
	h := &Header{Filename: "only.xml"}
	encoded := EncodeHeader(h)
	decoded, err := DecodeHeader(encoded)
	require.NoError(t, err)
	require.Equal(t, "only.xml", decoded.Filename)
	require.Empty(t, decoded.SndName)
}

func TestHeaderNullTerminator(t *testing.T) {
	// DecodeHeader must stop at null even without \r\n after last field
	data := []byte("FILENAME=test.xml\r\nSND_NAME=Ivan\r\n\x00garbage after null")
	h, err := DecodeHeader(data)
	require.NoError(t, err)
	require.Equal(t, "test.xml", h.Filename)
	require.Equal(t, "Ivan", h.SndName)
}

func TestHeaderEncodedFormat(t *testing.T) {
	h := &Header{Filename: "a.xml", SndDate: "20240101000000"}
	data := EncodeHeader(h)
	// Must contain KEY=VALUE\r\n pairs and end with \0
	require.Contains(t, string(data), "FILENAME=a.xml\r\n")
	require.Contains(t, string(data), "SND_DATE=20240101000000\r\n")
	require.Equal(t, byte(0x00), data[len(data)-1])
}

// ---- Container tests ----

func TestContainerEncodeDecodeEmpty(t *testing.T) {
	c := &Container{Header: &Header{Filename: "f.xml"}}
	encoded := Encode(c)
	decoded, err := Decode(encoded)
	require.NoError(t, err)
	require.NotNil(t, decoded.Header)
	require.Equal(t, "f.xml", decoded.Header.Filename)
	require.Empty(t, decoded.Sections)
}

func TestContainerEncodeDecodeWithSections(t *testing.T) {
	c := &Container{
		Header: &Header{Filename: "doc.xml", CerType: "UA1"},
		Sections: []Section{
			{Label: "UA_SIGN1", Contents: []byte("signaturedata")},
			{Label: "UA1_CRYPT", Contents: []byte("encrypteddata")},
			{Label: "UA1_STAMP", Contents: []byte("timestampdata")},
		},
	}

	encoded := Encode(c)
	decoded, err := Decode(encoded)
	require.NoError(t, err)
	require.NotNil(t, decoded.Header)
	require.Equal(t, "doc.xml", decoded.Header.Filename)
	require.Equal(t, "UA1", decoded.Header.CerType)
	require.Len(t, decoded.Sections, 3)
	require.Equal(t, "UA_SIGN1", decoded.Sections[0].Label)
	require.Equal(t, []byte("signaturedata"), decoded.Sections[0].Contents)
	require.Equal(t, "UA1_CRYPT", decoded.Sections[1].Label)
	require.Equal(t, "UA1_STAMP", decoded.Sections[2].Label)
}

func TestContainerNoHeader(t *testing.T) {
	c := &Container{
		Sections: []Section{
			{Label: "UA_SIGN1", Contents: []byte("sig")},
		},
	}
	encoded := Encode(c)
	decoded, err := Decode(encoded)
	require.NoError(t, err)
	require.Nil(t, decoded.Header)
	require.Len(t, decoded.Sections, 1)
}

func TestContainerZPOSTTRANSPORTABLE(t *testing.T) {
	// ZPOSTTRANSPORTABLE is also a valid header label (tax office response)
	headerData := EncodeHeader(&Header{Filename: "resp.xml", Result: "OK"})
	raw := EncodeSection(Section{Label: "ZPOSTTRANSPORTABLE", Contents: headerData})
	raw = append(raw, EncodeSection(Section{Label: "UA1_SIGN", Contents: []byte("sig")})...)

	c, err := Decode(raw)
	require.NoError(t, err)
	require.NotNil(t, c.Header)
	require.Equal(t, "resp.xml", c.Header.Filename)
	require.Equal(t, "OK", c.Header.Result)
	require.Len(t, c.Sections, 1)
}

func TestContainerEmpty(t *testing.T) {
	_, err := Decode([]byte{})
	require.Error(t, err)
}

// ---- Convenience method tests ----

func TestContainerFindSection(t *testing.T) {
	c := &Container{Sections: []Section{
		{Label: "UA_SIGN1", Contents: []byte("s1")},
		{Label: "UA1_CRYPT", Contents: []byte("c1")},
	}}
	s := c.FindSection("UA1_CRYPT")
	require.NotNil(t, s)
	require.Equal(t, []byte("c1"), s.Contents)

	require.Nil(t, c.FindSection("NOTEXIST"))
}

func TestContainerSignSections(t *testing.T) {
	c := &Container{Sections: []Section{
		{Label: "UA_SIGN1", Contents: []byte("s1")},
		{Label: "UA1_SIGN", Contents: []byte("s2")},
		{Label: "UA1_CRYPT", Contents: []byte("c1")},
	}}
	signs := c.SignSections()
	require.Len(t, signs, 2)
	require.Equal(t, "UA_SIGN1", signs[0].Label)
	require.Equal(t, "UA1_SIGN", signs[1].Label)
}

func TestContainerCryptSection(t *testing.T) {
	c := &Container{Sections: []Section{
		{Label: "UA_SIGN1", Contents: []byte("s1")},
		{Label: "CERTCRYPT", Contents: []byte("certificate")},
		{Label: "UA1_CRYPT", Contents: []byte("c1")},
	}}
	crypt := c.CryptSection()
	require.NotNil(t, crypt)
	require.Equal(t, "UA1_CRYPT", crypt.Label)
}

func TestContainerStampSection(t *testing.T) {
	c := &Container{Sections: []Section{
		{Label: "UA_SIGN1", Contents: []byte("s1")},
		{Label: "UA1_STAMP", Contents: []byte("ts")},
	}}
	stamp := c.StampSection()
	require.NotNil(t, stamp)
	require.Equal(t, "UA1_STAMP", stamp.Label)
}

func TestContainerMissingCrypt(t *testing.T) {
	c := &Container{Sections: []Section{
		{Label: "UA_SIGN1", Contents: []byte("s1")},
	}}
	require.Nil(t, c.CryptSection())
	require.Nil(t, c.StampSection())
}

// ---- PACKED_XML detection ----

func TestDecodePackedXML(t *testing.T) {
	data := append([]byte("PACKED_XML"), 0x00)
	data = append(data, []byte("<root/>")...)

	c, err := Decode(data)
	require.NoError(t, err)
	require.Len(t, c.Sections, 1)
	require.Equal(t, "PACKED_XML", c.Sections[0].Label)
}

// ---- USC label-only roundtrip ----

func TestUSCLabelOnlyRoundtrip(t *testing.T) {
	c := &Container{
		Sections: []Section{
			{Label: "USC_SIGN"},
			{Label: "UA_SIGN1", Contents: []byte("data")},
			{Label: "USC_CRYPT"},
		},
	}
	encoded := Encode(c)
	decoded, err := Decode(encoded)
	require.NoError(t, err)
	require.Len(t, decoded.Sections, 3)
	require.Equal(t, "USC_SIGN", decoded.Sections[0].Label)
	require.Equal(t, "UA_SIGN1", decoded.Sections[1].Label)
	require.Equal(t, "USC_CRYPT", decoded.Sections[2].Label)
}

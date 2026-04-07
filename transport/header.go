package transport

import (
	"bytes"
	"strings"
)

// Header holds the fields of a TRANSPORTABLE header section.
// Wire format inside the section content:
//
//	KEY=VALUE\r\n  (for each non-empty field)
//	\0             (null terminator)
type Header struct {
	Filename  string // FILENAME
	SndName   string // SND_NAME
	SndEmail  string // SND_EMAIL
	RcvName   string // RCV_NAME
	RcvEmail  string // RCV_EMAIL
	PrgType   string // PRG_TYPE
	PrgVer    string // PRG_VER
	SndDate   string // SND_DATE — YYYYMMDDHHNNSS
	CerType   string // CERTYPE
	CRC32Sign string // CRC32_SIGN
	CRC32File string // CRC32_FILE
	Subject   string // SUBJECT
	GetStamp  string // GET_STAMP
	Result    string // RESULT
}

// headerFields defines the canonical key order for encoding.
var headerFields = []struct {
	key string
	get func(*Header) string
	set func(*Header, string)
}{
	{"FILENAME", func(h *Header) string { return h.Filename }, func(h *Header, v string) { h.Filename = v }},
	{"SND_NAME", func(h *Header) string { return h.SndName }, func(h *Header, v string) { h.SndName = v }},
	{"SND_EMAIL", func(h *Header) string { return h.SndEmail }, func(h *Header, v string) { h.SndEmail = v }},
	{"RCV_NAME", func(h *Header) string { return h.RcvName }, func(h *Header, v string) { h.RcvName = v }},
	{"RCV_EMAIL", func(h *Header) string { return h.RcvEmail }, func(h *Header, v string) { h.RcvEmail = v }},
	{"PRG_TYPE", func(h *Header) string { return h.PrgType }, func(h *Header, v string) { h.PrgType = v }},
	{"PRG_VER", func(h *Header) string { return h.PrgVer }, func(h *Header, v string) { h.PrgVer = v }},
	{"SND_DATE", func(h *Header) string { return h.SndDate }, func(h *Header, v string) { h.SndDate = v }},
	{"CERTYPE", func(h *Header) string { return h.CerType }, func(h *Header, v string) { h.CerType = v }},
	{"CRC32_SIGN", func(h *Header) string { return h.CRC32Sign }, func(h *Header, v string) { h.CRC32Sign = v }},
	{"CRC32_FILE", func(h *Header) string { return h.CRC32File }, func(h *Header, v string) { h.CRC32File = v }},
	{"SUBJECT", func(h *Header) string { return h.Subject }, func(h *Header, v string) { h.Subject = v }},
	{"GET_STAMP", func(h *Header) string { return h.GetStamp }, func(h *Header, v string) { h.GetStamp = v }},
	{"RESULT", func(h *Header) string { return h.Result }, func(h *Header, v string) { h.Result = v }},
}

// EncodeHeader serialises a Header to the key=value\r\n...\0 byte format
// used as the Contents of a TRANSPORTABLE section.
func EncodeHeader(h *Header) []byte {
	var buf bytes.Buffer
	for _, f := range headerFields {
		if v := f.get(h); v != "" {
			buf.WriteString(f.key)
			buf.WriteByte('=')
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}
	buf.WriteByte(0x00)
	return buf.Bytes()
}

// DecodeHeader parses the Contents of a TRANSPORTABLE section into a Header.
// Format: KEY=VALUE\r\n ... \0.
func DecodeHeader(data []byte) (*Header, error) {
	h := &Header{}
	// Trim at null terminator
	if idx := bytes.IndexByte(data, 0x00); idx >= 0 {
		data = data[:idx]
	}
	for line := range strings.SplitSeq(string(data), "\r\n") {
		line = strings.TrimRight(line, "\n")
		if line == "" {
			continue
		}
		before, after, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := before
		val := after
		for _, f := range headerFields {
			if f.key == key {
				f.set(h, val)
				break
			}
		}
	}
	return h, nil
}

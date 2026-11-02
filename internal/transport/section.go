package transport

import (
	"encoding/binary"
	"errors"
)

// Section represents a named data section in a transport container.
// Wire format: label\0 + uint32LE(len(Contents)) + Contents.
type Section struct {
	Label    string
	Contents []byte
}

// labelOnly contains section labels that have no length or data following them.
var labelOnly = map[string]bool{
	"USC_SIGN":  true,
	"USC_CRYPT": true,
}

// EncodeSection serialises a Section to its wire format.
func EncodeSection(s Section) []byte {
	if labelOnly[s.Label] {
		return append([]byte(s.Label), 0x00)
	}
	buf := make([]byte, len(s.Label)+1+4+len(s.Contents))
	n := copy(buf, s.Label)
	buf[n] = 0x00
	binary.LittleEndian.PutUint32(buf[n+1:], uint32(len(s.Contents)))
	copy(buf[n+5:], s.Contents)
	return buf
}

// DecodeSections parses a concatenated byte stream into ordered Sections.
// It stops when no more complete sections can be read.
func DecodeSections(data []byte) ([]Section, error) {
	var sections []Section
	i := 0
	for i < len(data) {
		// Read null-terminated label (max 64 bytes to avoid runaway)
		j := i
		for j < len(data) && data[j] != 0x00 {
			j++
			if j-i > 64 {
				return nil, errors.New("transport: label exceeds 64 bytes")
			}
		}
		if j >= len(data) {
			return nil, errors.New("transport: unterminated section label")
		}
		label := string(data[i:j])
		i = j + 1 // skip null

		if label == "" {
			// Empty label — skip (trailing nulls)
			continue
		}

		// Label-only sections (no length/data)
		if labelOnly[label] {
			sections = append(sections, Section{Label: label})
			continue
		}

		// Read uint32 LE length
		if i+4 > len(data) {
			return nil, errors.New("transport: truncated length for section " + label)
		}
		wireLength := binary.LittleEndian.Uint32(data[i:])
		i += 4

		if uint64(wireLength) > uint64(len(data)-i) {
			return nil, errors.New("transport: truncated data for section " + label)
		}
		length := int(wireLength)
		contents := make([]byte, length)
		copy(contents, data[i:i+length])
		i += length

		sections = append(sections, Section{Label: label, Contents: contents})
	}
	return sections, nil
}

package transport

import (
	"bytes"
	"errors"
	"strings"
)

// headerLabels are the section labels that contain a TRANSPORTABLE header.
var headerLabels = map[string]bool{
	"TRANSPORTABLE":      true,
	"ZPOSTTRANSPORTABLE": true,
}

// Container is a parsed transport container.
type Container struct {
	Header   *Header   // nil if no TRANSPORTABLE section present
	Sections []Section // non-header sections in order
}

// Encode serialises a Container to its wire representation.
// If Header is non-nil it is written first as a TRANSPORTABLE section.
// Then all Sections are appended in order.
func Encode(c *Container) []byte {
	var buf bytes.Buffer
	if c.Header != nil {
		headerData := EncodeHeader(c.Header)
		buf.Write(EncodeSection(Section{Label: "TRANSPORTABLE", Contents: headerData}))
	}
	for _, s := range c.Sections {
		buf.Write(EncodeSection(s))
	}
	return buf.Bytes()
}

// Decode parses a raw transport container byte slice.
// Handles TRANSPORTABLE/ZPOSTTRANSPORTABLE header sections,
// QLB_SIGN/QLB_CRYPT nested formats, and PACKED_XML detection.
func Decode(data []byte) (*Container, error) {
	if len(data) == 0 {
		return nil, errors.New("transport: empty data")
	}

	// PACKED_XML detection
	if bytes.HasPrefix(data, []byte("PACKED_XML")) {
		return &Container{
			Sections: []Section{{Label: "PACKED_XML", Contents: data[len("PACKED_XML")+1:]}},
		}, nil
	}

	raw, err := DecodeSections(data)
	if err != nil {
		return nil, err
	}

	c := &Container{}
	var h *Header
	var sub []Section
	for _, s := range raw {
		if headerLabels[s.Label] {
			h, err = DecodeHeader(s.Contents)
			if err != nil {
				return nil, err
			}
			c.Header = h
			continue
		}
		switch s.Label {
		case "QLB_SIGN", "QLB_CRYPT":
			// QLB internal format: nested sub-sections within the section contents
			sub, err = decodeQLB(s.Label, s.Contents)
			if err != nil {
				// Non-fatal: store as-is
				c.Sections = append(c.Sections, s)
			} else {
				c.Sections = append(c.Sections, sub...)
			}
		default:
			c.Sections = append(c.Sections, s)
		}
	}
	return c, nil
}

// decodeQLB parses a QLB_SIGN or QLB_CRYPT section's internal sub-section format.
// QLB internal layout: concatenated sub-sections with label\0 + uint32LE + data.
// The outer label is kept as a prefix on each inner label (e.g. "QLB_SIGN/data").
func decodeQLB(outerLabel string, data []byte) ([]Section, error) {
	subs, err := DecodeSections(data)
	if err != nil {
		return nil, err
	}
	prefix := outerLabel + "/"
	result := make([]Section, len(subs))
	for i, s := range subs {
		result[i] = Section{
			Label:    prefix + s.Label,
			Contents: s.Contents,
		}
	}
	return result, nil
}

// FindSection returns the first Section with the given label, or nil.
func (c *Container) FindSection(label string) *Section {
	for i := range c.Sections {
		if c.Sections[i].Label == label {
			return &c.Sections[i]
		}
	}
	return nil
}

// SignSections returns all sections whose labels contain "SIGN".
func (c *Container) SignSections() []Section {
	var out []Section
	for _, s := range c.Sections {
		if strings.Contains(s.Label, "SIGN") {
			out = append(out, s)
		}
	}
	return out
}

// CryptSection returns the first section whose label contains "CRYPT", or nil.
func (c *Container) CryptSection() *Section {
	for i := range c.Sections {
		if strings.Contains(c.Sections[i].Label, "CRYPT") {
			return &c.Sections[i]
		}
	}
	return nil
}

// StampSection returns the first section whose label contains "STAMP", or nil.
func (c *Container) StampSection() *Section {
	for i := range c.Sections {
		if strings.Contains(c.Sections[i].Label, "STAMP") {
			return &c.Sections[i]
		}
	}
	return nil
}

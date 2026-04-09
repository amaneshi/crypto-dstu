package gf2m

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Element represents an element in GF(2^m) as a polynomial over GF(2).
// Stored as little-endian uint32 words: words[0] contains bits 0-31.
type Element struct { //nolint:recvcheck // value receivers for read-only methods, pointer receivers for mutations — intentional
	words []uint32
}

// NewElement creates a zero element with the specified number of words.
func NewElement(wordCount int) Element {
	return Element{words: make([]uint32, wordCount)}
}

// FromHex parses a hex string (big-endian) into an Element.
// The hex string represents the polynomial with MSB first.
func FromHex(s string, wordCount int) (Element, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimPrefix(s, "0x")

	if len(s) == 0 {
		return NewElement(wordCount), nil
	}

	// Decode hex to bytes (big-endian)
	if len(s)%2 != 0 {
		s = "0" + s
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return Element{}, fmt.Errorf("invalid hex string: %w", err)
	}

	return FromBytes(bytes, wordCount), nil
}

// FromBytes creates an Element from a big-endian byte slice.
func FromBytes(b []byte, wordCount int) Element {
	e := NewElement(wordCount)

	// Convert big-endian bytes to little-endian uint32 words
	for i := 0; i < len(b) && i/4 < wordCount; i++ {
		byteIdx := len(b) - 1 - i
		wordIdx := i / 4
		bytePos := i % 4
		e.words[wordIdx] |= uint32(b[byteIdx]) << (bytePos * 8)
	}

	return e
}

// FromWords creates an Element from a uint32 slice (little-endian).
func FromWords(words []uint32) Element {
	w := make([]uint32, len(words))
	copy(w, words)
	return Element{words: w}
}

// Bytes returns the element as a big-endian byte slice.
func (e Element) Bytes() []byte {
	// Find the actual bit length to avoid leading zeros
	bitLen := e.BitLen()
	if bitLen == 0 {
		return []byte{0}
	}

	byteLen := (bitLen + 7) / 8
	result := make([]byte, byteLen)

	for i := range byteLen {
		wordIdx := i / 4
		bytePos := i % 4
		if wordIdx < len(e.words) {
			result[byteLen-1-i] = byte(e.words[wordIdx] >> (bytePos * 8))
		}
	}

	return result
}

// String returns the hex representation of the element.
func (e Element) String() string {
	if e.IsZero() {
		return "0"
	}
	return hex.EncodeToString(e.Bytes())
}

// BitLen returns the position of the highest set bit (1-indexed).
// Returns 0 for zero element.
func (e Element) BitLen() int {
	// Find the highest non-zero word
	nz := len(e.words) - 1
	for nz >= 0 && e.words[nz] == 0 {
		nz--
	}

	if nz < 0 {
		return 0
	}

	// Find the highest bit in that word
	x := e.words[nz]
	r := 1

	var t uint32
	if t = x >> 16; t != 0 {
		x = t
		r += 16
	}
	if t = x >> 8; t != 0 {
		x = t
		r += 8
	}
	if t = x >> 4; t != 0 {
		x = t
		r += 4
	}
	if t = x >> 2; t != 0 {
		x = t
		r += 2
	}
	if t = x >> 1; t != 0 {
		r++
	}

	return r + nz*32
}

// TestBit returns true if the bit at position n is set.
func (e Element) TestBit(n int) bool {
	wordIdx := n / 32
	bitPos := n % 32

	if wordIdx >= len(e.words) {
		return false
	}

	mask := uint32(1) << bitPos
	return (e.words[wordIdx] & mask) != 0
}

// SetBit sets the bit at position n to 1.
func (e *Element) SetBit(n int) {
	wordIdx := n / 32
	bitPos := n % 32

	if wordIdx >= len(e.words) {
		return
	}

	mask := uint32(1) << bitPos
	e.words[wordIdx] |= mask
}

// ClearBit sets the bit at position n to 0.
func (e *Element) ClearBit(n int) {
	wordIdx := n / 32
	bitPos := n % 32

	if wordIdx >= len(e.words) {
		return
	}

	mask := uint32(1) << bitPos
	e.words[wordIdx] &^= mask
}

// IsZero returns true if the element is zero.
func (e Element) IsZero() bool {
	for _, w := range e.words {
		if w != 0 {
			return false
		}
	}
	return true
}

// Equal returns true if two elements are equal.
func (e Element) Equal(other Element) bool {
	// Compare up to the length of the shorter element
	minLen := min(len(other.words), len(e.words))

	for i := range minLen {
		if e.words[i] != other.words[i] {
			return false
		}
	}

	// Check remaining words are zero
	for i := minLen; i < len(e.words); i++ {
		if e.words[i] != 0 {
			return false
		}
	}
	for i := minLen; i < len(other.words); i++ {
		if other.words[i] != 0 {
			return false
		}
	}

	return true
}

// Clone creates a deep copy of the element.
func (e Element) Clone() Element {
	words := make([]uint32, len(e.words))
	copy(words, e.words)
	return Element{words: words}
}

// Words returns the underlying word slice (for internal use).
func (e Element) Words() []uint32 {
	return e.words
}

// WordCount returns the number of words in the element.
func (e Element) WordCount() int {
	return len(e.words)
}

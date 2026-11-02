package transport

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMalformedContainersReturnErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"packed prefix", []byte("PACKED_XML")},
		{"packed separator", []byte("PACKED_XML!data")},
		{"missing label terminator", []byte("UA1_SIGN")},
		{"oversized length", []byte{'X', 0, 255, 255, 255, 255}},
		{"empty container", []byte{0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) { require.NotPanics(t, func() { _, err := Decode(tc.data); require.Error(t, err) }) })
	}
}

func FuzzDecode(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("PACKED_XML"), []byte("PACKED_XML\x00<root/>"), Encode(&Container{Sections: []Section{{Label: "UA1_SIGN", Contents: []byte("test")}}})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Decode(data) })
}

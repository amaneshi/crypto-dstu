package kupyna

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

// A separate spec construction: ordinary Kupyna hashes PAD(K)||PAD(M)||~K.
// Existing Cryptonite known-answer tests and native IIT PFX MAC verification
// independently anchor the primitive and the national KMAC profile.
func kmacReference(newHash func() hash.Hash, key, message []byte) []byte {
	h := newHash()
	pad := func(input []byte) []byte {
		out := append(bytes.Clone(input), 0x80)
		for (len(out)+12)%h.BlockSize() != 0 {
			out = append(out, 0)
		}
		out = binary.LittleEndian.AppendUint64(out, uint64(len(input))*8)
		return append(out, 0, 0, 0, 0)
	}
	h.Write(pad(key))
	h.Write(pad(message))
	inverted := bytes.Clone(key)
	for i := range inverted {
		inverted[i] = ^inverted[i]
	}
	h.Write(inverted)
	return h.Sum(nil)
}

func TestKMACMessagePaddingBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		newHash   func() hash.Hash
		newMAC    func([]byte) hash.Hash
		keyLength int
	}{
		{"256", New256, NewKMAC256, 32},
		{"384", New384, NewKMAC384, 48},
		{"512", New512, NewKMAC512, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x4b}, tc.keyLength)
			for length := 0; length <= 2*tc.newHash().BlockSize(); length++ {
				t.Run(fmt.Sprint(length), func(t *testing.T) {
					message := bytes.Repeat([]byte{0x61}, length)
					want := kmacReference(tc.newHash, key, message)
					h := tc.newMAC(key)
					h.Write(message[:length/2])
					h.Write(message[length/2:])
					require.Equal(t, want, h.Sum(nil))
					require.Equal(t, want, h.Sum(nil))
				})
			}
		})
	}
}

package kupyna

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

type testVector struct {
	input  string
	output string
}

var vectors256 = []testVector{
	{
		"",
		"cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6",
	},
	{
		"The quick brown fox jumps over the lazy dog",
		"996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6",
	},
	{
		"The quick brown fox jumps over the lazy dog.",
		"88ea8ce988fe67eb83968cdc0f6f3ca693baa502612086c0dcec761a98e2fb1f",
	},
}

var vectors512 = []testVector{
	{
		"",
		"656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538",
	},
}

func hash256(input string) string {
	h := New256()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

func hash512(input string) string {
	h := New512()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

func TestKupyna256(t *testing.T) {
	for _, v := range vectors256 {
		got := hash256(v.input)
		require.Equal(t, v.output, got, "Kupyna-256(%q)", v.input)
	}
}

func TestKupyna512(t *testing.T) {
	for _, v := range vectors512 {
		got := hash512(v.input)
		require.Equal(t, v.output, got, "Kupyna-512(%q)", v.input)
	}
}

func TestReset(t *testing.T) {
	h := New256()
	h.Write([]byte("hello"))
	h.Reset()
	h.Write([]byte(""))
	got := hex.EncodeToString(h.Sum(nil))
	require.Equal(t, vectors256[0].output, got, "Reset")
}

func TestIncrementalWrite(t *testing.T) {
	input := "The quick brown fox jumps over the lazy dog"
	// Single write
	h1 := New256()
	h1.Write([]byte(input))
	sum1 := h1.Sum(nil)

	// Multiple writes
	h2 := New256()
	for _, c := range []byte(input) {
		h2.Write([]byte{c})
	}
	sum2 := h2.Sum(nil)

	require.Equal(t, hex.EncodeToString(sum1), hex.EncodeToString(sum2), "incremental write")
}

func TestSumDoesNotMutate(t *testing.T) {
	h := New256()
	h.Write([]byte("test"))
	sum1 := h.Sum(nil)
	sum2 := h.Sum(nil)
	require.Equal(t, hex.EncodeToString(sum1), hex.EncodeToString(sum2), "Sum must not mutate state")
}

// TestKMAC256_CryptoniteVector uses the exact test vector from
// _ref/cryptonite/src/cryptoniteUtest/c/utest_dstu7564.c test_dstu7564_hmac.
func TestKMAC256_CryptoniteVector(t *testing.T) {
	key, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f80818283")
	require.NoError(t, err)
	msg := []byte("Hello World")
	exp, err := hex.DecodeString("ac9b3027afaa041cb623b098d51200801432290afa30311d11b2450f3d95d98a")
	require.NoError(t, err)

	h := NewKMAC256(key)
	_, err = h.Write(msg)
	require.NoError(t, err)
	got := h.Sum(nil)
	require.Equal(t, exp, got)
}

func TestKMAC256_SumDoesNotMutate(t *testing.T) {
	key := []byte("secretkey")
	msg := []byte("test message")
	h := NewKMAC256(key)
	h.Write(msg)
	s1 := h.Sum(nil)
	s2 := h.Sum(nil)
	require.Equal(t, s1, s2, "Sum must not mutate KMAC state")
}

func TestKMAC256_ResetPreservesKey(t *testing.T) {
	key, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f80818283")
	msg := []byte("Hello World")
	exp, _ := hex.DecodeString("ac9b3027afaa041cb623b098d51200801432290afa30311d11b2450f3d95d98a")

	h := NewKMAC256(key)
	h.Write([]byte("something else entirely"))
	h.Reset()
	h.Write(msg)
	got := h.Sum(nil)
	require.Equal(t, exp, got, "Reset must restore keyed initial state")
}

func TestKMAC256_DifferentKeysDifferentMAC(t *testing.T) {
	key1 := []byte("key1")
	key2 := []byte("key2")
	msg := []byte("same message")

	h1 := NewKMAC256(key1)
	h1.Write(msg)
	h2 := NewKMAC256(key2)
	h2.Write(msg)
	require.NotEqual(t, h1.Sum(nil), h2.Sum(nil), "different keys must produce different MACs")
}

func TestKMAC256_EmptyKey(t *testing.T) {
	h := NewKMAC256([]byte{})
	_, err := h.Write([]byte("msg"))
	require.NoError(t, err)
	got := h.Sum(nil)
	require.Len(t, got, 32)
}

func TestKMAC512_Size(t *testing.T) {
	key := []byte("key")
	h := NewKMAC512(key)
	h.Write([]byte("data"))
	got := h.Sum(nil)
	require.Len(t, got, 64)
}

func TestKMAC384_Size(t *testing.T) {
	key := []byte("key")
	h := NewKMAC384(key)
	h.Write([]byte("data"))
	got := h.Sum(nil)
	require.Len(t, got, 48)
}

func BenchmarkKupyna256_1K(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		h := New256()
		h.Write(data)
		h.Sum(nil)
	}
}

// Nonempty single- and multi-block vectors from Cryptonite utest_dstu7564.c.
func TestKupyna256CryptoniteBlocks(t *testing.T) {
	for _, tc := range []struct {
		size     int
		expected string
	}{
		{64, "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875"},
		{128, "0a9474e645a7d25e255e9e89fff42ec7eb31349007059284f0b182e452bda882"},
	} {
		input := make([]byte, tc.size)
		for i := range input {
			input[i] = byte(i)
		}
		h := New256()
		h.Write(input)
		require.Equal(t, tc.expected, hex.EncodeToString(h.Sum(nil)))
	}
}

func TestAllWidthsStreamingBoundaries(t *testing.T) {
	for _, hashSize := range []int{32, 48, 64} {
		for _, size := range []int{0, 1, 51, 52, 63, 64, 65, 115, 116, 127, 128, 129, 255, 256, 257, 4096} {
			input := make([]byte, size)
			for i := range input {
				input[i] = byte(i*7 + 3)
			}
			oneShot := newDigest(hashSize)
			oneShot.Write(input)
			expected := oneShot.Sum(nil)
			for _, chunkSize := range []int{1, 7, 64, 127, 128, 129} {
				h := newDigest(hashSize)
				for offset := 0; offset < len(input); offset += chunkSize {
					h.Write(input[offset:min(offset+chunkSize, len(input))])
				}
				require.Equal(t, expected, h.Sum(nil), "size=%d hash=%d chunk=%d", size, hashSize, chunkSize)
				// Sum must leave the streaming state usable for later input.
				h.Write([]byte{0xa5})
				oneShot.Reset()
				oneShot.Write(input)
				oneShot.Write([]byte{0xa5})
				require.Equal(t, oneShot.Sum(nil), h.Sum(nil))
			}
		}
	}
}

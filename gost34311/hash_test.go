package gost34311

import (
	"encoding/hex"
	"testing"

	"crypto-dstu/gost28147"

	"github.com/stretchr/testify/require"
)

// unhex decodes a lowercase hex string to bytes.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("unhex(%q): %v", s, err)
	}
	return b
}

// TestVector1 — cryptonite gost34_311_test_1
// sync=zeros, SBOX_ID_1 (SboxDSTU), single 32-byte message.
func TestVector1(t *testing.T) {
	sync := make([]byte, 32)
	data := unhex(t, "ad26f436f0b627880038727d22e02c97d081ef85260fc96718395091ce224dd7")
	expected := unhex(t, "02d7e8a3c111788bb1b8a489c5e330288728f1c308c2cec08e09265bfa395599")

	h := NewWithParams(gost28147.SboxDSTU, sync)
	h.Write(data)
	got := h.Sum(nil)

	require.Equal(t, hex.EncodeToString(expected), hex.EncodeToString(got), "test1")
}

// TestVector2 — cryptonite gost34_311_test_2
// non-zero sync, SBOX_ID_1, single 32-byte message.
func TestVector2(t *testing.T) {
	sync := unhex(t, "975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a")
	data := unhex(t, "cd944dc9951b5e1eea4a9ebca4e30e4568d48f640d9b228e2df398f767b4eaab")
	expected := unhex(t, "30667bae2a36245ce8abd0e8f84812df7ffd7dfee6289ef6d79624d709f97208")

	h := NewWithParams(gost28147.SboxDSTU, sync)
	h.Write(data)
	got := h.Sum(nil)

	require.Equal(t, hex.EncodeToString(expected), hex.EncodeToString(got), "test2")
}

// TestVector3 — cryptonite gost34_311_test_3
// non-zero sync, SBOX_ID_1, 48-byte message (1.5 blocks).
func TestVector3(t *testing.T) {
	sync := unhex(t, "975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a")
	data := unhex(t, "9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691d9e4abc889632959d73e0bf139cd71813ebee679e930")
	expected := unhex(t, "9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30")

	h := NewWithParams(gost28147.SboxDSTU, sync)
	h.Write(data)
	got := h.Sum(nil)

	require.Equal(t, hex.EncodeToString(expected), hex.EncodeToString(got), "test3")
}

// TestVector3Streaming — same as test3 but fed in three separate Write calls
// (mirrors cryptonite gost34_311_test_4 split-write test).
func TestVector3Streaming(t *testing.T) {
	sync := unhex(t, "975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a")
	data1 := unhex(t, "9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691")
	data2 := unhex(t, "d9e4abc889632959d73e0bf139cd71813ebee679e9")
	data3 := unhex(t, "30")
	expected := unhex(t, "9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30")

	h := NewWithParams(gost28147.SboxDSTU, sync)
	h.Write(data1)
	h.Write(data2)
	h.Write(data3)
	got := h.Sum(nil)

	require.Equal(t, hex.EncodeToString(expected), hex.EncodeToString(got), "test3-streaming")
}

// TestEmptyMessage — cryptonite gost34_311_test_5
// zero sync, SBOX_ID_11 (GostR341194TestParamSet), empty message.
func TestEmptyMessage(t *testing.T) {
	sync := make([]byte, 32)
	expected := unhex(t, "891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd")

	sbox := &gost28147.Sbox{
		{0x4, 0xa, 0x9, 0x2, 0xd, 0x8, 0x0, 0xe, 0x6, 0xb, 0x1, 0xc, 0x7, 0xf, 0x5, 0x3},
		{0xe, 0xb, 0x4, 0xc, 0x6, 0xd, 0xf, 0xa, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9},
		{0x5, 0x8, 0x1, 0xd, 0xa, 0x3, 0x4, 0x2, 0xe, 0xf, 0xc, 0x7, 0x6, 0x0, 0x9, 0xb},
		{0x7, 0xd, 0xa, 0x1, 0x0, 0x8, 0x9, 0xf, 0xe, 0x4, 0x6, 0xc, 0xb, 0x2, 0x5, 0x3},
		{0x6, 0xc, 0x7, 0x1, 0x5, 0xf, 0xd, 0x8, 0x4, 0xa, 0x9, 0xe, 0x0, 0x3, 0xb, 0x2},
		{0x4, 0xb, 0xa, 0x0, 0x7, 0x2, 0x1, 0xd, 0x3, 0x6, 0x8, 0x5, 0x9, 0xc, 0xf, 0xe},
		{0xd, 0xb, 0x4, 0x1, 0x3, 0xf, 0x5, 0x9, 0x0, 0xa, 0xe, 0x7, 0x6, 0x8, 0x2, 0xc},
		{0x1, 0xf, 0xd, 0x0, 0x5, 0x7, 0xa, 0x4, 0x9, 0x2, 0x3, 0xe, 0x6, 0xb, 0x8, 0xc},
	}

	h := NewWithParams(sbox, sync)
	got := h.Sum(nil)

	require.Equal(t, hex.EncodeToString(expected), hex.EncodeToString(got), "test-empty")
}

// TestReset verifies that Reset() produces the same result on re-use.
func TestReset(t *testing.T) {
	sync := make([]byte, 32)
	data := unhex(t, "ad26f436f0b627880038727d22e02c97d081ef85260fc96718395091ce224dd7")

	h := NewWithParams(gost28147.SboxDSTU, sync)
	h.Write(data)
	first := h.Sum(nil)

	h.Reset()
	h.Write(data)
	second := h.Sum(nil)

	require.Equal(t, hex.EncodeToString(first), hex.EncodeToString(second), "Reset must produce same result")
}

// TestSize checks the digest and block sizes.
func TestSize(t *testing.T) {
	h := New()
	require.Equal(t, 32, h.Size())
	require.Equal(t, 32, h.BlockSize())
}

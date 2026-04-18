package hmac

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestNew_SHA256 verifies that New works with any [hash.Hash] factory (RFC 2104 example).
// Reference: RFC 2202 test vector 1 adapted for SHA-256.
func TestNew_SHA256(t *testing.T) {
	key := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")
	exp := mustHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

	h := New(sha256.New, key)
	_, err := h.Write(data)
	require.NoError(t, err)
	got := h.Sum(nil)
	require.Equal(t, exp, got, "HMAC-SHA256")
}

// TestEqual verifies constant-time MAC comparison.
func TestEqual(t *testing.T) {
	require.True(t, Equal([]byte{1, 2, 3}, []byte{1, 2, 3}))
	require.False(t, Equal([]byte{1, 2, 3}, []byte{1, 2, 4}))
	require.False(t, Equal([]byte{1, 2}, []byte{1, 2, 3}))
}

// TestGOST34311 verifies HMAC-GOST34311 against cryptonite reference.
// Reference: cryptonite utest_hmac.c gost34311_hmac (SBOX_ID_1, zero sync).
func TestGOST34311(t *testing.T) {
	data1 := mustHex("CF818CADDFBDCDC940C8A530947427ED1A27949062602DA471ADA0D5CBFF32D8")
	data2 := mustHex("00000001")
	key := mustHex("646e333130373836646d6931")
	sync := make([]byte, 32)
	exp := mustHex("20df9d6f41f32160b77b4d9394257bee5f71adf35025083e52bfa680296a2f15")

	h := NewGOST34311(key, sync)
	_, err := h.Write(data1)
	require.NoError(t, err)
	_, err = h.Write(data2)
	require.NoError(t, err)
	got := h.Sum(nil)
	require.Equal(t, exp, got, "HMAC-GOST34311")
}

// TestGOST34311Reset verifies that Reset restores the keyed state.
// Reference: cryptonite utest_hmac.c gost34311_hmac_2 — re-call update+final after reset.
func TestGOST34311Reset(t *testing.T) {
	data1 := mustHex("CF818CADDFBDCDC940C8A530947427ED1A27949062602DA471ADA0D5CBFF32D8")
	data2 := mustHex("00000001")
	key := mustHex("646e333130373836646d6931")
	sync := make([]byte, 32)
	exp := mustHex("20df9d6f41f32160b77b4d9394257bee5f71adf35025083e52bfa680296a2f15")

	h := NewGOST34311(key, sync)
	_, _ = h.Write(data1)
	_, _ = h.Write(data2)
	first := h.Sum(nil)
	require.Equal(t, exp, first, "first HMAC-GOST34311")

	h.Reset()
	_, _ = h.Write(data1)
	_, _ = h.Write(data2)
	got := h.Sum(nil)
	require.Equal(t, exp, got, "HMAC-GOST34311 after Reset")
}

// TestKupyna256 verifies HMAC-Kupyna-256 is self-consistent (no cryptonite reference available).
func TestKupyna256(t *testing.T) {
	key := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")

	h1 := NewKupyna256(key)
	_, _ = h1.Write(data)
	mac1 := h1.Sum(nil)
	require.Len(t, mac1, 32)

	h2 := NewKupyna256(key)
	_, _ = h2.Write(data)
	mac2 := h2.Sum(nil)
	require.Equal(t, mac1, mac2, "HMAC-Kupyna256 deterministic")

	h3 := NewKupyna256([]byte("different key"))
	_, _ = h3.Write(data)
	mac3 := h3.Sum(nil)
	require.NotEqual(t, mac1, mac3, "different keys produce different MACs")
}

// TestKupyna512 verifies HMAC-Kupyna-512 is self-consistent.
func TestKupyna512(t *testing.T) {
	key := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")

	h1 := NewKupyna512(key)
	_, _ = h1.Write(data)
	mac1 := h1.Sum(nil)
	require.Len(t, mac1, 64)

	h2 := NewKupyna512(key)
	_, _ = h2.Write(data)
	mac2 := h2.Sum(nil)
	require.Equal(t, mac1, mac2, "HMAC-Kupyna512 deterministic")
}

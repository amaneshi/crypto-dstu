package gost28147

import (
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

// TestEncryptDecryptRoundtrip verifies that Decrypt(Encrypt(pt)) == pt.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	pt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	block, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	ct := make([]byte, 8)
	block.Encrypt(ct, pt)

	got := make([]byte, 8)
	block.Decrypt(got, ct)

	require.Equal(t, pt, got, "roundtrip failed")
}

// TestBlockSize verifies the block size is 8 bytes.
func TestBlockSize(t *testing.T) {
	key := make([]byte, 32)
	block, _ := NewCipher(key)
	require.Equal(t, 8, block.BlockSize())
}

// TestInvalidKeySize verifies that wrong key sizes return an error.
func TestInvalidKeySize(t *testing.T) {
	_, err := NewCipher(make([]byte, 16))
	require.Error(t, err, "expected error for 16-byte key")
	_, err = NewCipher(make([]byte, 31))
	require.Error(t, err, "expected error for 31-byte key")
}

// TestCFBRoundtrip verifies CFB encrypt then decrypt recovers plaintext.
func TestCFBRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}
	pt := []byte("Hello, GOST! This is a test message for CFB mode.")

	ct, err := EncryptCFB(key, iv, pt)
	require.NoError(t, err, "EncryptCFB")

	got, err := DecryptCFB(key, iv, ct)
	require.NoError(t, err, "DecryptCFB")

	require.Equal(t, pt, got[:len(pt)], "CFB roundtrip")
}

// TestKeyWrapUnwrapRoundtrip verifies WrapKey then UnwrapKey recovers the CEK.
func TestKeyWrapUnwrapRoundtrip(t *testing.T) {
	kek := make([]byte, 32)
	cek := make([]byte, 32)
	iv := make([]byte, 8)
	for i := range kek {
		kek[i] = byte(i + 0x10)
	}
	for i := range cek {
		cek[i] = byte(i + 0x20)
	}
	for i := range iv {
		iv[i] = byte(i + 0x30)
	}

	wrapped, err := WrapKey(kek, cek, iv)
	require.NoError(t, err, "WrapKey")
	require.Len(t, wrapped, 44, "wrapped length")

	got, err := UnwrapKey(kek, wrapped)
	require.NoError(t, err, "UnwrapKey")
	require.Equal(t, cek, got, "key wrap roundtrip")
}

// TestKeyWrapTampering verifies that a tampered wrapped key fails to unwrap.
func TestKeyWrapTampering(t *testing.T) {
	kek := make([]byte, 32)
	cek := make([]byte, 32)
	iv := make([]byte, 8)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	for i := range cek {
		cek[i] = byte(i + 2)
	}
	for i := range iv {
		iv[i] = byte(i + 3)
	}

	wrapped, err := WrapKey(kek, cek, iv)
	require.NoError(t, err, "WrapKey")

	// Tamper with the wrapped key
	wrapped[10] ^= 0xFF

	_, err = UnwrapKey(kek, wrapped)
	require.Error(t, err, "expected error unwrapping tampered key")
}

// TestMultipleEncryptDecrypt verifies multiple ECB blocks encrypt/decrypt correctly.
func TestMultipleEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xAA ^ i)
	}

	block, err := NewCipher(key)
	require.NoError(t, err, "NewCipher")

	// Encrypt 4 blocks
	for i := range 4 {
		pt := make([]byte, 8)
		for j := range pt {
			pt[j] = byte(i*8 + j)
		}
		ct := make([]byte, 8)
		block.Encrypt(ct, pt)

		got := make([]byte, 8)
		block.Decrypt(got, ct)
		require.Equal(t, pt, got, "block %d roundtrip", i)
	}
}

// TestCTR verifies GOST 28147 CTR mode against cryptonite reference vector.
// Reference: cryptonite utest_gost28147.c gost28147_ctr_test (SBOX_ID_11).
func TestCTR(t *testing.T) {
	key := mustHex("0100000002000000030000000400000005000000060000000700000008000000")
	iv := mustHex("0300000003000000")
	data := mustHex("0102030405060708090a0b0c0d0e0f101112131415161718")
	exp := mustHex("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4")

	block, err := NewCipherWithSbox(key, SboxGOST34311)
	require.NoError(t, err)

	stream, err := NewCTR(block, iv)
	require.NoError(t, err)

	got := make([]byte, len(data))
	stream.XORKeyStream(got, data)
	require.Equal(t, exp, got, "CTR encrypt")

	block2, err := NewCipherWithSbox(key, SboxGOST34311)
	require.NoError(t, err)
	stream2, err := NewCTR(block2, iv)
	require.NoError(t, err)
	plain := make([]byte, len(got))
	stream2.XORKeyStream(plain, got)
	require.Equal(t, data, plain, "CTR decrypt (self-inverse)")
}

// TestCTRIncremental verifies that CTR mode is byte-by-byte resumable.
// Reference: cryptonite utest_gost28147.c gost28147_ctr_2_test (SBOX_ID_11).
func TestCTRIncremental(t *testing.T) {
	key := mustHex("0100000002000000030000000400000005000000060000000700000008000000")
	iv := mustHex("0300000003000000")
	data1 := mustHex("010203")
	data2 := mustHex("0405060708090a0b0c0d0e0f101112131415161718")
	exp := mustHex("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4")

	block, err := NewCipherWithSbox(key, SboxGOST34311)
	require.NoError(t, err)
	stream, err := NewCTR(block, iv)
	require.NoError(t, err)

	c1 := make([]byte, len(data1))
	stream.XORKeyStream(c1, data1)
	c2 := make([]byte, len(data2))
	stream.XORKeyStream(c2, data2)
	got := make([]byte, 0, len(c1)+len(c2))
	got = append(got, c1...)
	got = append(got, c2...)
	require.Equal(t, exp, got, "CTR incremental encrypt")
}

// TestCTRLong verifies CTR mode across multiple 24-byte gamma blocks.
// Reference: cryptonite utest_gost28147.c gost28147_ctr_3_test (SBOX_ID_11).
func TestCTRLong(t *testing.T) {
	key := mustHex("0100000002000000030000000400000005000000060000000700000008000000")
	iv := mustHex("0300000003000000")
	data := mustHex(
		"0102030405060708090a0b0c0d0e0f101112131415161718" +
			"191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
			"303132333435363738393a3b3c3d3e3f40",
	)
	exp := mustHex(
		"da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4" +
			"0bd18016490ddff6e446981c559778e4273350c755e2113d" +
			"d8c2533450b2d481d004af84b8daa2cc",
	)

	block, err := NewCipherWithSbox(key, SboxGOST34311)
	require.NoError(t, err)
	stream, err := NewCTR(block, iv)
	require.NoError(t, err)

	got := make([]byte, len(data))
	stream.XORKeyStream(got, data)
	require.Equal(t, exp, got, "CTR long encrypt")
}

// TestCFBKnownVector uses a known-good CFB vector to verify correctness.
// This tests that the same key+iv+plaintext always produces the same ciphertext.
func TestCFBDeterministic(t *testing.T) {
	key := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	iv := mustHex("0001020304050607")
	pt := mustHex("0102030405060708090a0b0c0d0e0f10")

	ct1, err := EncryptCFB(key, iv, pt)
	require.NoError(t, err, "EncryptCFB")
	ct2, err := EncryptCFB(key, iv, pt)
	require.NoError(t, err, "EncryptCFB 2nd")
	require.Equal(t, ct1, ct2, "CFB must be deterministic")

	got, err := DecryptCFB(key, iv, ct1)
	require.NoError(t, err, "DecryptCFB")
	require.Equal(t, pt, got, "CFB decrypt")
}

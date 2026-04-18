package kalyna

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

// ─── CTR ─────────────────────────────────────────────────────────────────────

func TestCTR_16_16(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748")
	exp := mustHex("A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	stream, err := NewCTR(block, iv)
	require.NoError(t, err)
	got := make([]byte, len(data))
	stream.XORKeyStream(got, data)
	require.Equal(t, exp, got)
}

func TestCTR_16_16_Decrypt(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748")
	exp := mustHex("A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	stream, err := NewCTR(block, iv)
	require.NoError(t, err)
	got := make([]byte, len(exp))
	stream.XORKeyStream(got, exp)
	require.Equal(t, data, got)
}

func TestCTR_32_32(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F" +
		"000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F" +
		"101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748")
	exp := mustHex("8a355857d43e1e12ddc9ab7c07f9c350" +
		"a4a946eddce74246bd9756c14db38e82" +
		"d82da491af959c79bc225bd9acaf1428" +
		"f15cb321e1eae2a3a6aa12c417949677" +
		"d5f930367f40241b9c7c4e8d771a56b7eba1")

	block, err := NewCipher256_256(key)
	require.NoError(t, err)
	stream, err := NewCTR(block, iv)
	require.NoError(t, err)
	got := make([]byte, len(data))
	stream.XORKeyStream(got, data)
	require.Equal(t, exp, got)
}

func TestCTR_Incremental(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data1 := mustHex("202122232425262728292A2B2C2D2E2F30313233343536")
	data2 := mustHex("3738393A3B3C3D3E3F404142434445464748")
	exp := mustHex("A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A")

	block, err := NewCipher128_128(key)
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
	require.Equal(t, exp, got)
}

// ─── CBC ─────────────────────────────────────────────────────────────────────

// iso7816Pad pads data to a multiple of blockSize using ISO/IEC 7816-4.
func iso7816Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data)+1)%blockSize
	if padLen == blockSize {
		padLen = 0
	}
	padded := make([]byte, len(data)+1+padLen)
	copy(padded, data)
	padded[len(data)] = 0x80
	return padded
}

func iso7816Unpad(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i]
		}
		if data[i] != 0x00 {
			return data
		}
	}
	return data
}

func TestCBC_16_16_Encrypt(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748")
	exp := mustHex("a73625d7be994e85469a9faabcedaab6dbc5f65dd77bb35e06bd7d1d8eafc86261df4b314b80436f5434e0efa80be0ed")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	padded := iso7816Pad(data, block.BlockSize())
	enc, err := NewCBCEncrypter(block, iv)
	require.NoError(t, err)
	got := make([]byte, len(padded))
	enc.CryptBlocks(got, padded)
	require.Equal(t, exp, got)
}

func TestCBC_16_16_Decrypt(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748")
	ciphertext := mustHex("a73625d7be994e85469a9faabcedaab6" +
		"dbc5f65dd77bb35e06bd7d1d8eafc862" +
		"61df4b314b80436f5434e0efa80be0ed")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	dec, err := NewCBCDecrypter(block, iv)
	require.NoError(t, err)
	got := make([]byte, len(ciphertext))
	dec.CryptBlocks(got, ciphertext)
	got = iso7816Unpad(got)
	require.Equal(t, data, got)
}

func TestCBC_32_32_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748")

	block, err := NewCipher256_256(key)
	require.NoError(t, err)
	padded := iso7816Pad(data, block.BlockSize())
	enc, err := NewCBCEncrypter(block, iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(padded))
	enc.CryptBlocks(ciphertext, padded)

	block2, _ := NewCipher256_256(key)
	dec, _ := NewCBCDecrypter(block2, iv)
	plain := make([]byte, len(ciphertext))
	dec.CryptBlocks(plain, ciphertext)
	plain = iso7816Unpad(plain)
	require.Equal(t, data, plain)
}

// ─── OFB ─────────────────────────────────────────────────────────────────────

func TestOFB_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	enc, err := NewOFB(block, iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(data))
	enc.XORKeyStream(ciphertext, data)

	block2, _ := NewCipher128_128(key)
	dec, _ := NewOFB(block2, iv)
	plain := make([]byte, len(ciphertext))
	dec.XORKeyStream(plain, ciphertext)
	require.Equal(t, data, plain)
}

// ─── CFB ─────────────────────────────────────────────────────────────────────

func TestCFB_16_16_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	enc, err := NewCFBEncrypter(block, iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(data))
	enc.XORKeyStream(ciphertext, data)

	block2, _ := NewCipher128_128(key)
	dec, _ := NewCFBDecrypter(block2, iv)
	plain := make([]byte, len(ciphertext))
	dec.XORKeyStream(plain, ciphertext)
	require.Equal(t, data, plain)
}

func TestCFB_32_32_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748")

	block, err := NewCipher256_256(key)
	require.NoError(t, err)
	enc, err := NewCFBEncrypter(block, iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(data))
	enc.XORKeyStream(ciphertext, data)

	block2, _ := NewCipher256_256(key)
	dec, _ := NewCFBDecrypter(block2, iv)
	plain := make([]byte, len(ciphertext))
	dec.XORKeyStream(plain, ciphertext)
	require.Equal(t, data, plain)
}

// ─── CMAC ────────────────────────────────────────────────────────────────────

func TestCMAC_16_16(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748494A4B4C4D4E4F")
	exp := mustHex("123B4EAB8E63ECF3E645A99C1115E241")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	mac, err := NewCMAC(block, 16)
	require.NoError(t, err)
	_, err = mac.Write(data)
	require.NoError(t, err)
	got := mac.MAC()
	require.Equal(t, exp, got)
}

func TestCMAC_32_32(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F")
	exp := mustHex("5df20d04735bab6d5351082da6ad8d41")

	block, err := NewCipher256_256(key)
	require.NoError(t, err)
	mac, err := NewCMAC(block, 16)
	require.NoError(t, err)
	mac.Write(data)
	got := mac.MAC()
	require.Equal(t, exp, got)
}

func TestCMAC_64_64(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F" +
		"000102030405060708090A0B0C0D0E0F" +
		"000102030405060708090A0B0C0D0E0F" +
		"000102030405060708090A0B0C0D0E0F")
	data := mustHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F")
	exp := mustHex("7d0d5fd504115264ea173266f3267a89")

	block, err := NewCipher512_512(key)
	require.NoError(t, err)
	mac, err := NewCMAC(block, 16)
	require.NoError(t, err)
	mac.Write(data)
	got := mac.MAC()
	require.Equal(t, exp, got)
}

func TestCMAC_Reset(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748494A4B4C4D4E4F")
	exp := mustHex("123B4EAB8E63ECF3E645A99C1115E241")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	mac, err := NewCMAC(block, 16)
	require.NoError(t, err)
	mac.Write([]byte("garbage"))
	mac.Reset()
	mac.Write(data)
	got := mac.MAC()
	require.Equal(t, exp, got)
}

// ─── XTS ─────────────────────────────────────────────────────────────────────

func TestXTS_16_16_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F")
	// Use block-aligned data (multiple of 16 bytes)
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748494A4B4C4D4E4F" +
		"505152535455565758595A5B5C5D5E5F")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	enc, err := NewXTSEncrypter(block, iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(data))
	enc.CryptBlocks(ciphertext, data)

	block2, _ := NewCipher128_128(key)
	dec, _ := NewXTSDecrypter(block2, iv)
	plain := make([]byte, len(ciphertext))
	dec.CryptBlocks(plain, ciphertext)
	require.Equal(t, data, plain)
}

func TestXTS_32_32_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
	iv := mustHex("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F")
	// Use block-aligned data (multiple of 32 bytes)
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748494A4B4C4D4E4F" +
		"505152535455565758595A5B5C5D5E5F")

	block, err := NewCipher256_256(key)
	require.NoError(t, err)
	enc, err := NewXTSEncrypter(block, iv)
	require.NoError(t, err)
	ciphertext := make([]byte, len(data))
	enc.CryptBlocks(ciphertext, data)

	block2, _ := NewCipher256_256(key)
	dec, _ := NewXTSDecrypter(block2, iv)
	plain := make([]byte, len(ciphertext))
	dec.CryptBlocks(plain, ciphertext)
	require.Equal(t, data, plain)
}

// ─── KW ──────────────────────────────────────────────────────────────────────

func TestKW_16_16_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748")

	block, err := NewCipher128_128(key)
	require.NoError(t, err)
	kw := NewKWEncrypter(block)
	wrapped, err := kw.Wrap(data)
	require.NoError(t, err)

	block2, _ := NewCipher128_128(key)
	kw2 := NewKWDecrypter(block2)
	plain, err := kw2.Unwrap(wrapped)
	require.NoError(t, err)
	require.Equal(t, data, plain)
}

func TestKW_32_32_Roundtrip(t *testing.T) {
	key := mustHex("000102030405060708090A0B0C0D0E0F" +
		"000102030405060708090A0B0C0D0E0F")
	data := mustHex("202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748" +
		"202122232425262728292A2B2C2D2E2F" +
		"303132333435363738393A3B3C3D3E3F" +
		"404142434445464748")

	block, err := NewCipher256_256(key)
	require.NoError(t, err)
	kw := NewKWEncrypter(block)
	wrapped, err := kw.Wrap(data)
	require.NoError(t, err)

	block2, _ := NewCipher256_256(key)
	kw2 := NewKWDecrypter(block2)
	plain, err := kw2.Unwrap(wrapped)
	require.NoError(t, err)
	require.Equal(t, data, plain)
}

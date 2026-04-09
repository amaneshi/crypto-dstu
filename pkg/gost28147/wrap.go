package gost28147

import "errors"

const (
	wrapKeySize    = 44
	wrapMACBits    = 32
	wrapIVSize     = 8
	wrapCEKICVSize = 40
)

// wrapIV is the fixed IV used in the outer CFB encryption step of key wrapping.
var wrapIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// WrapKey wraps a 32-byte content encryption key (cek) using a 32-byte key-encryption
// key (kek) and an 8-byte IV. Returns a 44-byte wrapped key.
// Protocol matches CryptoPro key wrapping as used in privat-it/cryptonite.
func WrapKey(kek, cek, iv []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, errors.New("gost28147: kek must be 32 bytes")
	}
	if len(cek) != 32 {
		return nil, errors.New("gost28147: cek must be 32 bytes")
	}
	if len(iv) != 8 {
		return nil, errors.New("gost28147: iv must be 8 bytes")
	}

	block, err := NewCipher(kek)
	if err != nil {
		return nil, err
	}
	g, ok := block.(*gostCipher)
	if !ok {
		return nil, errors.New("gost28147: internal error: unexpected cipher type")
	}

	// Compute 4-byte MAC over cek
	icv := g.MAC(cek, wrapMACBits) // 32 bits = 4 bytes

	// cekicv = cek || icv (40 bytes)
	cekicv := make([]byte, wrapCEKICVSize)
	copy(cekicv, cek)
	copy(cekicv[32:], icv)

	// temp1 = CFB-encrypt(iv, cekicv)
	temp1, err := EncryptCFB(kek, iv, cekicv)
	if err != nil {
		return nil, err
	}

	// temp2 = iv || temp1 (8 + 36 = 44 bytes)
	temp2 := make([]byte, wrapKeySize)
	copy(temp2, iv)
	copy(temp2[wrapIVSize:], temp1)

	// temp3 = reverse(temp2)
	temp3 := make([]byte, wrapKeySize)
	for i := range wrapKeySize {
		temp3[i] = temp2[wrapKeySize-1-i]
	}

	// result = CFB-encrypt(wrapIV, temp3), take first 44 bytes
	result, err := EncryptCFB(kek, wrapIV, temp3)
	if err != nil {
		return nil, err
	}

	return result[:wrapKeySize], nil
}

// UnwrapKey unwraps a 44-byte wrapped key using a 32-byte key-encryption key (kek).
// Returns the original 32-byte content encryption key.
// Protocol matches CryptoPro key unwrapping as used in privat-it/cryptonite.
func UnwrapKey(kek, wcek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, errors.New("gost28147: kek must be 32 bytes")
	}
	if len(wcek) != 44 {
		return nil, errors.New("gost28147: wrapped key must be 44 bytes")
	}

	block, err := NewCipher(kek)
	if err != nil {
		return nil, err
	}
	g, ok := block.(*gostCipher)
	if !ok {
		return nil, errors.New("gost28147: internal error: unexpected cipher type")
	}

	// temp3 = CFB-decrypt(wrapIV, wcek)
	temp3, err := DecryptCFB(kek, wrapIV, wcek)
	if err != nil {
		return nil, err
	}

	// temp2 = reverse(temp3)
	temp2 := make([]byte, wrapKeySize)
	for i := range wrapKeySize {
		temp2[i] = temp3[wrapKeySize-1-i]
	}

	// iv = temp2[0:8], temp1 = temp2[8:44] (36 bytes of cekicv)
	iv := temp2[:8]
	temp1 := temp2[8:44]

	// cekicv = CFB-decrypt(iv, temp1)
	cekicv, err := DecryptCFB(kek, iv, temp1)
	if err != nil {
		return nil, err
	}

	// Verify MAC: last 4 bytes of cekicv should match MAC(cek)
	cek := cekicv[:32]
	icv := cekicv[32:36]
	icvCheck := g.MAC(cek, 32)

	var errBits byte
	for i := range 4 {
		errBits |= icv[i] ^ icvCheck[i]
	}
	if errBits != 0 {
		return nil, errors.New("gost28147: key unwrap failed: checksum mismatch")
	}

	return cek, nil
}

package gost28147

import "crypto/cipher"

type cfbStream struct {
	block cipher.Block
	iv    [BlockSize]byte
	gamma [BlockSize]byte
}

// NewCFBEncrypter returns a CFB stream encrypter with the given IV.
func NewCFBEncrypter(block cipher.Block, iv []byte) cipher.Stream {
	s := &cfbStream{block: block}
	copy(s.iv[:], iv)
	return &cfbEncrypter{cfbStream: s}
}

// NewCFBDecrypter returns a CFB stream decrypter with the given IV.
func NewCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream {
	s := &cfbStream{block: block}
	copy(s.iv[:], iv)
	return &cfbDecrypter{cfbStream: s}
}

type cfbEncrypter struct{ *cfbStream }
type cfbDecrypter struct{ *cfbStream }

func (c *cfbEncrypter) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if i%BlockSize == 0 {
			c.block.Encrypt(c.gamma[:], c.iv[:])
		}
		j := i % BlockSize
		dst[i] = src[i] ^ c.gamma[j]
		c.iv[j] = dst[i]
		if j == BlockSize-1 {
			// iv is now fully updated; next encrypt will use it
		}
	}
}

func (c *cfbDecrypter) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if i%BlockSize == 0 {
			c.block.Encrypt(c.gamma[:], c.iv[:])
		}
		j := i % BlockSize
		c.iv[j] = src[i]
		dst[i] = src[i] ^ c.gamma[j]
	}
}

// EncryptCFB encrypts src with the given key and IV using GOST CFB mode.
func EncryptCFB(key, iv, src []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// DecryptCFB decrypts src with the given key and IV using GOST CFB mode.
func DecryptCFB(key, iv, src []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

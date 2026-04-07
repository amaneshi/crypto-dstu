// Package gost28147 implements the GOST 28147-89 block cipher (Ukrainian DSTU variant).
// Reference: privat-it/cryptonite src/cryptonite/c/gost28147.c
package gost28147

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const BlockSize = 8 // 64-bit block

type gostCipher struct {
	k    [8]uint32
	sbox *Sbox
}

// NewCipher returns a new GOST 28147-89 cipher using SboxDSTU (cryptonite GOST28147_SBOX_1).
func NewCipher(key []byte) (cipher.Block, error) {
	return NewCipherWithSbox(key, SboxDSTU)
}

// NewCipherWithSbox returns a new GOST 28147-89 cipher with the given 32-byte key and S-box.
func NewCipherWithSbox(key []byte, sbox *Sbox) (cipher.Block, error) {
	if len(key) != 32 {
		return nil, errors.New("gost28147: key must be 32 bytes")
	}
	c := &gostCipher{sbox: sbox}
	for i := range 8 {
		c.k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	return c, nil
}

func (g *gostCipher) BlockSize() int { return BlockSize }

// Encrypt encrypts one 64-bit block: 3× forward key order + 1× reverse key order.
func (g *gostCipher) Encrypt(dst, src []byte) {
	n0 := binary.LittleEndian.Uint32(src[0:])
	n1 := binary.LittleEndian.Uint32(src[4:])

	s := g.sbox
	// 3 rounds forward: k0..k7
	for range 3 {
		n1 ^= s.pass(n0 + g.k[0])
		n0 ^= s.pass(n1 + g.k[1])
		n1 ^= s.pass(n0 + g.k[2])
		n0 ^= s.pass(n1 + g.k[3])
		n1 ^= s.pass(n0 + g.k[4])
		n0 ^= s.pass(n1 + g.k[5])
		n1 ^= s.pass(n0 + g.k[6])
		n0 ^= s.pass(n1 + g.k[7])
	}
	// 1 round reverse: k7..k0
	n1 ^= s.pass(n0 + g.k[7])
	n0 ^= s.pass(n1 + g.k[6])
	n1 ^= s.pass(n0 + g.k[5])
	n0 ^= s.pass(n1 + g.k[4])
	n1 ^= s.pass(n0 + g.k[3])
	n0 ^= s.pass(n1 + g.k[2])
	n1 ^= s.pass(n0 + g.k[1])
	n0 ^= s.pass(n1 + g.k[0])

	// Output: n1 in bytes 0-3, n0 in bytes 4-7
	binary.LittleEndian.PutUint32(dst[0:], n1)
	binary.LittleEndian.PutUint32(dst[4:], n0)
}

// Decrypt decrypts one 64-bit block: 1× forward key order + 3× reverse key order.
func (g *gostCipher) Decrypt(dst, src []byte) {
	n0 := binary.LittleEndian.Uint32(src[0:])
	n1 := binary.LittleEndian.Uint32(src[4:])

	s := g.sbox
	// 1 round forward: k0..k7
	n1 ^= s.pass(n0 + g.k[0])
	n0 ^= s.pass(n1 + g.k[1])
	n1 ^= s.pass(n0 + g.k[2])
	n0 ^= s.pass(n1 + g.k[3])
	n1 ^= s.pass(n0 + g.k[4])
	n0 ^= s.pass(n1 + g.k[5])
	n1 ^= s.pass(n0 + g.k[6])
	n0 ^= s.pass(n1 + g.k[7])

	// 3 rounds reverse: k7..k0
	for range 3 {
		n1 ^= s.pass(n0 + g.k[7])
		n0 ^= s.pass(n1 + g.k[6])
		n1 ^= s.pass(n0 + g.k[5])
		n0 ^= s.pass(n1 + g.k[4])
		n1 ^= s.pass(n0 + g.k[3])
		n0 ^= s.pass(n1 + g.k[2])
		n1 ^= s.pass(n0 + g.k[1])
		n0 ^= s.pass(n1 + g.k[0])
	}

	binary.LittleEndian.PutUint32(dst[0:], n1)
	binary.LittleEndian.PutUint32(dst[4:], n0)
}

// MAC computes a GOST 28147 MAC over data using 2 forward rounds (16 passes).
// Returns first nbits/8 bytes of the MAC buffer.
func (g *gostCipher) MAC(data []byte, nbits int) []byte {
	buf := make([]byte, 8)
	for i := 0; i+8 <= len(data); i += 8 {
		for j := range 8 {
			buf[j] ^= data[i+j]
		}
		g.mac64(buf)
	}
	rem := len(data) % 8
	if rem != 0 {
		block := make([]byte, 8)
		copy(block, data[len(data)-rem:])
		for j := range 8 {
			buf[j] ^= block[j]
		}
		g.mac64(buf)
	}
	nbytes := nbits / 8
	return buf[:nbytes]
}

// mac64 applies 2 rounds (16 passes) of the cipher to the MAC accumulator.
// Output convention matches cryptonite MAC_KEY_ORDER: buf[0:4]=n1, buf[4:8]=n0
// (same swap as Encrypt output, so MAC result is consistent with block output).
func (g *gostCipher) mac64(buf []byte) {
	s := g.sbox
	n0 := binary.LittleEndian.Uint32(buf[0:])
	n1 := binary.LittleEndian.Uint32(buf[4:])

	n1 ^= s.pass(n0 + g.k[0])
	n0 ^= s.pass(n1 + g.k[1])
	n1 ^= s.pass(n0 + g.k[2])
	n0 ^= s.pass(n1 + g.k[3])
	n1 ^= s.pass(n0 + g.k[4])
	n0 ^= s.pass(n1 + g.k[5])
	n1 ^= s.pass(n0 + g.k[6])
	n0 ^= s.pass(n1 + g.k[7])

	n1 ^= s.pass(n0 + g.k[0])
	n0 ^= s.pass(n1 + g.k[1])
	n1 ^= s.pass(n0 + g.k[2])
	n0 ^= s.pass(n1 + g.k[3])
	n1 ^= s.pass(n0 + g.k[4])
	n0 ^= s.pass(n1 + g.k[5])
	n1 ^= s.pass(n0 + g.k[6])
	n0 ^= s.pass(n1 + g.k[7])

	binary.LittleEndian.PutUint32(buf[0:], n1)
	binary.LittleEndian.PutUint32(buf[4:], n0)
}

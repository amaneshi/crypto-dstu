// Package kalyna implements the Kalyna block cipher (DSTU 7624:2014).
// Reference: Roman-Oliynykov/Kalyna-reference
package kalyna

import (
	"crypto/cipher"
	"errors"
)

type kalynaBlock struct {
	roundKeys [][]uint64
	blockSize int // in bytes
	nb        int // block words
	nr        int // rounds
}

// NewCipher128_128 returns a Kalyna-128/128 cipher (16-byte block, 16-byte key).
func NewCipher128_128(key []byte) (cipher.Block, error) {
	return newKalyna(key, kBlock128/8, kKey128/8, kBlock128/bitsInWord, kKey128/bitsInWord, kNR128)
}

// NewCipher128_256 returns a Kalyna-128/256 cipher (16-byte block, 32-byte key).
func NewCipher128_256(key []byte) (cipher.Block, error) {
	return newKalyna(key, kBlock128/8, kKey256/8, kBlock128/bitsInWord, kKey256/bitsInWord, kNR256)
}

// NewCipher256_256 returns a Kalyna-256/256 cipher (32-byte block, 32-byte key).
func NewCipher256_256(key []byte) (cipher.Block, error) {
	return newKalyna(key, kBlock256/8, kKey256/8, kBlock256/bitsInWord, kKey256/bitsInWord, kNR256)
}

// NewCipher256_512 returns a Kalyna-256/512 cipher (32-byte block, 64-byte key).
func NewCipher256_512(key []byte) (cipher.Block, error) {
	return newKalyna(key, kBlock256/8, kKey512/8, kBlock256/bitsInWord, kKey512/bitsInWord, kNR512)
}

// NewCipher512_512 returns a Kalyna-512/512 cipher (64-byte block, 64-byte key).
func NewCipher512_512(key []byte) (cipher.Block, error) {
	return newKalyna(key, kBlock512/8, kKey512/8, kBlock512/bitsInWord, kKey512/bitsInWord, kNR512)
}

func newKalyna(key []byte, blockBytes, keyBytes, nb, nk, nr int) (cipher.Block, error) {
	if len(key) != keyBytes {
		return nil, errors.New("kalyna: invalid key size")
	}
	keyWords := bytesToWords(key)
	rk := expandKey(keyWords, nb, nk, nr)
	return &kalynaBlock{
		roundKeys: rk,
		blockSize: blockBytes,
		nb:        nb,
		nr:        nr,
	}, nil
}

func (k *kalynaBlock) BlockSize() int { return k.blockSize }

func (k *kalynaBlock) Encrypt(dst, src []byte) {
	state := bytesToWords(src[:k.blockSize])

	// Round 0: modular add
	addWords(state, k.roundKeys[0])

	// Rounds 1..nr-1: EncipherRound + XOR
	for r := 1; r < k.nr; r++ {
		encipherRound(state)
		xorWords(state, k.roundKeys[r])
	}

	// Final round: EncipherRound + modular add
	encipherRound(state)
	addWords(state, k.roundKeys[k.nr])

	out := wordsToBytes(state)
	copy(dst, out[:k.blockSize])
}

func (k *kalynaBlock) Decrypt(dst, src []byte) {
	state := bytesToWords(src[:k.blockSize])

	// Undo final modular add
	subWords(state, k.roundKeys[k.nr])

	// Rounds nr-1..1: DecipherRound + XOR
	for r := k.nr - 1; r > 0; r-- {
		decipherRound(state)
		xorWords(state, k.roundKeys[r])
	}

	// Undo round 0: DecipherRound + modular sub
	decipherRound(state)
	subWords(state, k.roundKeys[0])

	out := wordsToBytes(state)
	copy(dst, out[:k.blockSize])
}

package kalyna

import (
	"encoding/binary"
)

// multiplyGF multiplies two bytes in GF(2^8) with reduction poly 0x11d.
func multiplyGF(x, y byte) byte {
	var r byte
	for range 8 {
		if y&1 == 1 {
			r ^= x
		}
		hbit := x & 0x80
		x <<= 1
		if hbit != 0 {
			x ^= 0x1d
		}
		y >>= 1
	}
	return r
}

// subBytes applies forward S-boxes to all bytes of state (in-place).
// State is nb uint64 words in little-endian byte order.
// Byte index b within a word uses sbox[b%4].
func subBytes(state []uint64) {
	for i := range state {
		w := state[i]
		state[i] = uint64(sboxesEnc[0][w&0xff]) |
			uint64(sboxesEnc[1][(w>>8)&0xff])<<8 |
			uint64(sboxesEnc[2][(w>>16)&0xff])<<16 |
			uint64(sboxesEnc[3][(w>>24)&0xff])<<24 |
			uint64(sboxesEnc[0][(w>>32)&0xff])<<32 |
			uint64(sboxesEnc[1][(w>>40)&0xff])<<40 |
			uint64(sboxesEnc[2][(w>>48)&0xff])<<48 |
			uint64(sboxesEnc[3][(w>>56)&0xff])<<56
	}
}

// invSubBytes applies inverse S-boxes.
func invSubBytes(state []uint64) {
	for i := range state {
		w := state[i]
		state[i] = uint64(sboxesDec[0][w&0xff]) |
			uint64(sboxesDec[1][(w>>8)&0xff])<<8 |
			uint64(sboxesDec[2][(w>>16)&0xff])<<16 |
			uint64(sboxesDec[3][(w>>24)&0xff])<<24 |
			uint64(sboxesDec[0][(w>>32)&0xff])<<32 |
			uint64(sboxesDec[1][(w>>40)&0xff])<<40 |
			uint64(sboxesDec[2][(w>>48)&0xff])<<48 |
			uint64(sboxesDec[3][(w>>56)&0xff])<<56
	}
}

// wordsToBytes converts nb uint64 words to a flat byte slice (LE).
func wordsToBytes(state []uint64) []byte {
	b := make([]byte, len(state)*8)
	for i, w := range state {
		binary.LittleEndian.PutUint64(b[i*8:], w)
	}
	return b
}

// bytesToWords converts a flat LE byte slice to uint64 words.
func bytesToWords(b []byte) []uint64 {
	nb := len(b) / 8
	w := make([]uint64, nb)
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(b[i*8:])
	}
	return w
}

// shiftRows shifts rows of the state matrix left.
// State is treated as an 8×nb byte matrix stored column-wise in nb uint64 words.
// Row i is shifted left by shift_i columns.
// shift increments every (8/nb) rows.
func shiftRows(state []uint64) {
	nb := len(state)
	flat := wordsToBytes(state)
	nflat := make([]byte, len(flat))
	shift := -1
	for row := range 8 {
		if row%(8/nb) == 0 {
			shift++
		}
		for col := range nb {
			nflat[row+((col+shift)%nb)*8] = flat[row+col*8]
		}
	}
	copy(state, bytesToWords(nflat))
}

// invShiftRows shifts rows right (inverse of shiftRows).
func invShiftRows(state []uint64) {
	nb := len(state)
	flat := wordsToBytes(state)
	nflat := make([]byte, len(flat))
	shift := -1
	for row := range 8 {
		if row%(8/nb) == 0 {
			shift++
		}
		for col := range nb {
			nflat[row+col*8] = flat[row+((col+shift)%nb)*8]
		}
	}
	copy(state, bytesToWords(nflat))
}

// matrixMultiply multiplies each column of state by an 8×8 matrix in GF(2^8).
func matrixMultiply(state []uint64, matrix [8][8]byte) {
	nb := len(state)
	flat := wordsToBytes(state)
	for col := range nb {
		var result uint64
		for row := 7; row >= 0; row-- {
			var product byte
			for b := 7; b >= 0; b-- {
				product ^= multiplyGF(flat[b+col*8], matrix[row][b])
			}
			result |= uint64(product) << (row * 8)
		}
		state[col] = result
	}
}

// mixColumns applies the MDS matrix multiply for encryption.
func mixColumns(state []uint64) {
	matrixMultiply(state, mdsMatrix)
}

// invMixColumns applies the inverse MDS matrix multiply for decryption.
func invMixColumns(state []uint64) {
	matrixMultiply(state, mdsInvMatrix)
}

// encipherRound performs SubBytes → ShiftRows → MixColumns.
func encipherRound(state []uint64) {
	subBytes(state)
	shiftRows(state)
	mixColumns(state)
}

// decipherRound performs InvMixColumns → InvShiftRows → InvSubBytes.
func decipherRound(state []uint64) {
	invMixColumns(state)
	invShiftRows(state)
	invSubBytes(state)
}

// addWords adds two word arrays modulo 2^64 element-wise (in-place to dst).
func addWords(dst, src []uint64) {
	for i := range dst {
		dst[i] += src[i]
	}
}

// subWords subtracts src from dst modulo 2^64 (in-place to dst).
func subWords(dst, src []uint64) {
	for i := range dst {
		dst[i] -= src[i]
	}
}

// xorWords XORs src into dst in-place.
func xorWords(dst, src []uint64) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// rotateLeft rotates the round key bytes left by (2*nb+3) bytes.
// This matches the reference RotateLeft function.
func rotateLeft(rk []uint64) {
	nb := len(rk)
	rotateBytes := 2*nb + 3
	bytesNum := nb * 8
	flat := wordsToBytes(rk)
	buf := make([]byte, rotateBytes)
	copy(buf, flat[:rotateBytes])
	copy(flat, flat[rotateBytes:])
	copy(flat[bytesNum-rotateBytes:], buf)
	copy(rk, bytesToWords(flat))
}

// shiftLeft shifts all words left by 1 bit (multiplies by 2).
func shiftLeft(tmv []uint64) {
	for i := range tmv {
		tmv[i] <<= 1
	}
}

// rotate moves element [0] to the end and shifts everything left by one position.
func rotate(data []uint64) {
	first := data[0]
	copy(data, data[1:])
	data[len(data)-1] = first
}

// keyExpandKt computes the pre-round key kt.
func keyExpandKt(key []uint64, nb, nk int) []uint64 {
	state := make([]uint64, nb)
	state[0] = uint64(nb + nk + 1)

	k0 := make([]uint64, nb)
	k1 := make([]uint64, nb)
	copy(k0, key[:nb])
	if nk == nb {
		copy(k1, key[:nb])
	} else {
		copy(k1, key[nb:2*nb])
	}

	addWords(state, k0)
	encipherRound(state)
	xorWords(state, k1)
	encipherRound(state)
	addWords(state, k0)
	encipherRound(state)

	kt := make([]uint64, nb)
	copy(kt, state)
	return kt
}

// keyExpandEven computes the even-indexed round keys.
func keyExpandEven(key []uint64, kt []uint64, nb, nk, nr int) [][]uint64 {
	roundKeys := make([][]uint64, nr+1)
	for i := range roundKeys {
		roundKeys[i] = make([]uint64, nb)
	}

	initialData := make([]uint64, nk)
	copy(initialData, key)

	tmv := make([]uint64, nb)
	for i := range tmv {
		tmv[i] = 0x0001000100010001
	}

	ktRound := make([]uint64, nb)
	state := make([]uint64, nb)

	round := 0
	for {
		// kt_round = kt + tmv
		copy(state, kt)
		addWords(state, tmv)
		copy(ktRound, state)

		// state = initialData[0:nb]
		copy(state, initialData[:nb])
		addWords(state, ktRound)
		encipherRound(state)
		xorWords(state, ktRound)
		encipherRound(state)
		addWords(state, ktRound)
		copy(roundKeys[round], state)

		if round == nr {
			break
		}

		if nk != nb {
			round += 2
			shiftLeft(tmv)

			copy(state, kt)
			addWords(state, tmv)
			copy(ktRound, state)

			copy(state, initialData[nb:2*nb])
			addWords(state, ktRound)
			encipherRound(state)
			xorWords(state, ktRound)
			encipherRound(state)
			addWords(state, ktRound)
			copy(roundKeys[round], state)

			if round == nr {
				break
			}
		}

		round += 2
		shiftLeft(tmv)
		rotate(initialData)
	}

	return roundKeys
}

// keyExpandOdd derives the odd-indexed round keys from the even ones by RotateLeft.
func keyExpandOdd(roundKeys [][]uint64, nr int) {
	for i := 1; i < nr; i += 2 {
		copy(roundKeys[i], roundKeys[i-1])
		rotateLeft(roundKeys[i])
	}
}

// expandKey runs the full Kalyna key schedule and returns all round keys.
func expandKey(key []uint64, nb, nk, nr int) [][]uint64 {
	kt := keyExpandKt(key, nb, nk)
	roundKeys := keyExpandEven(key, kt, nb, nk, nr)
	keyExpandOdd(roundKeys, nr)
	return roundKeys
}

// Package gost34311 implements the GOST 34.311-95 hash function (256-bit digest).
// Reference: privat-it/cryptonite src/cryptonite/c/gost34_311.c
package gost34311

import (
	"encoding/binary"
	"hash"

	"crypto-dstu/gost28147"
)

const Size = 32
const BlockSize = 32

// digest holds the GOST 34.311-95 hash state.
type digest struct {
	sbox  *gost28147.Sbox
	sync  [32]byte  // initialization vector / sync vector
	hash  [32]byte  // current hash value
	sigma [8]uint32 // checksum accumulator
	mLen  [8]uint32 // processed bit length (256-bit LE counter)
	buf   [32]byte  // partial block buffer
	bufN  int       // bytes in buf
}

// New returns a GOST 34.311-95 hash using SboxDSTU and a zero sync vector.
func New() hash.Hash {
	return NewWithParams(gost28147.SboxDSTU, make([]byte, 32))
}

// NewWithParams returns a GOST 34.311-95 hash with the given S-box and 32-byte sync vector.
func NewWithParams(sbox *gost28147.Sbox, sync []byte) hash.Hash {
	d := &digest{sbox: sbox}
	copy(d.sync[:], sync)
	d.Reset()
	return d
}

func (d *digest) Size() int      { return Size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	d.hash = d.sync
	d.sigma = [8]uint32{}
	d.mLen = [8]uint32{}
	d.buf = [32]byte{}
	d.bufN = 0
}

func (d *digest) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		n := copy(d.buf[d.bufN:], p)
		d.bufN += n
		p = p[n:]
		// Only flush a full block if there is more data to process.
		// Matches cryptonite: update() is called only when more bytes remain
		// after filling the buffer (m32_ind reset to 0 only then).
		if d.bufN == 32 && len(p) > 0 {
			d.update()
			d.bufN = 0
		}
	}
	return total, nil
}

func (d *digest) Sum(in []byte) []byte {
	d0 := *d
	h := d0.checkSum()
	return append(in, h[:]...)
}

func (d *digest) checkSum() [32]byte {
	// Add bit length of remaining bytes
	bit := uint32(d.bufN) << 3
	old := d.mLen[0]
	d.mLen[0] += bit
	if d.mLen[0] < old {
		for i := 1; i < 8; i++ {
			d.mLen[i]++
			if d.mLen[i] != 0 {
				break
			}
		}
	}

	// Zero-pad the remaining buffer and add to sigma
	for i := d.bufN; i < 32; i++ {
		d.buf[i] = 0
	}
	var m32 [8]uint32
	for i := range 8 {
		m32[i] = binary.LittleEndian.Uint32(d.buf[i*4:])
	}
	add256(&d.sigma, &m32)

	// Hash the partial block
	d.hashStep(d.buf[:])

	// Hash the bit-length block
	var lenBlock [32]byte
	for i := range 8 {
		binary.LittleEndian.PutUint32(lenBlock[i*4:], d.mLen[i])
	}
	d.hashStep(lenBlock[:])

	// Hash the sigma (checksum) block
	var sigmaBlock [32]byte
	for i := range 8 {
		binary.LittleEndian.PutUint32(sigmaBlock[i*4:], d.sigma[i])
	}
	d.hashStep(sigmaBlock[:])

	return d.hash
}

// update processes d.buf as a full 32-byte block and advances state.
func (d *digest) update() {
	d.hashStep(d.buf[:])

	// Increment bit-length counter by 256
	old := d.mLen[0]
	d.mLen[0] += 256
	if d.mLen[0] < old {
		for i := 1; i < 8; i++ {
			d.mLen[i]++
			if d.mLen[i] != 0 {
				break
			}
		}
	}

	// Add block to sigma
	var m32 [8]uint32
	for i := range 8 {
		m32[i] = binary.LittleEndian.Uint32(d.buf[i*4:])
	}
	add256(&d.sigma, &m32)
}

// hashStep performs one compression: generate_keys → base_cycle32 → mix_transform.
func (d *digest) hashStep(m []byte) {
	var h32 [8]uint32
	var m32 [8]uint32
	for i := range 8 {
		h32[i] = binary.LittleEndian.Uint32(d.hash[i*4:])
		m32[i] = binary.LittleEndian.Uint32(m[i*4:])
	}

	// Generate 32 subkeys from h and m
	var keys [32]uint32
	generateKeys(&h32, &m32, &keys)

	// base_cycle32: encrypt 4 Feistel pairs using keys[0..7], keys[8..15], keys[16..23], keys[24..31]
	// Each pair is (h32[2i], h32[2i+1]) treated as a 64-bit block.
	// The 32 keys are split into 4 sets of 8 (one per pair).
	// Encryption uses 3× forward + 1× reverse (same as standard GOST ECB).
	// After all 4 pairs, each pair is byte-swapped (cryptonite XOR-swap at the end).
	var state [8]uint32
	copy(state[:], h32[:])

	// Perform base_cycle32: 24 forward half-steps then 8 reverse half-steps.
	// In each step, both halves use the same key index (unlike standard GOST ECB).
	// Pairs: (src[0],src[1]) with k1, (src[2],src[3]) with k2,
	//        (src[4],src[5]) with k3, (src[6],src[7]) with k4.
	for i := 0; i < 24; {
		j := i & 7
		state[1] ^= d.sbox.Pass(state[0] + keys[j])
		state[3] ^= d.sbox.Pass(state[2] + keys[8+j])
		state[5] ^= d.sbox.Pass(state[4] + keys[16+j])
		state[7] ^= d.sbox.Pass(state[6] + keys[24+j])
		i++
		j = i & 7
		state[0] ^= d.sbox.Pass(state[1] + keys[j])
		state[2] ^= d.sbox.Pass(state[3] + keys[8+j])
		state[4] ^= d.sbox.Pass(state[5] + keys[16+j])
		state[6] ^= d.sbox.Pass(state[7] + keys[24+j])
		i++
	}
	for i := 7; i >= 0; {
		state[1] ^= d.sbox.Pass(state[0] + keys[i])
		state[3] ^= d.sbox.Pass(state[2] + keys[8+i])
		state[5] ^= d.sbox.Pass(state[4] + keys[16+i])
		state[7] ^= d.sbox.Pass(state[6] + keys[24+i])
		i--
		state[0] ^= d.sbox.Pass(state[1] + keys[i])
		state[2] ^= d.sbox.Pass(state[3] + keys[8+i])
		state[4] ^= d.sbox.Pass(state[5] + keys[16+i])
		state[6] ^= d.sbox.Pass(state[7] + keys[24+i])
		i--
	}
	// XOR-swap each pair (cryptonite final step in base_cycle32)
	state[0], state[1] = state[1], state[0]
	state[2], state[3] = state[3], state[2]
	state[4], state[5] = state[5], state[4]
	state[6], state[7] = state[7], state[6]

	// s = uint32→bytes of state
	var s [32]byte
	for i := range 8 {
		binary.LittleEndian.PutUint32(s[i*4:], state[i])
	}

	// mix_transform(old_hash, m, s) → new_hash
	var newHash [32]byte
	mixTransform(d.hash[:], m, s[:], newHash[:])
	d.hash = newHash
}

// copyKeys implements cryptonite's copy_keys macro:
// interleaves bytes of (x1,x2,x3,x4) into (y1,y2,y3,y4).
func copyKeys(x1, x2, x3, x4 uint32) (uint32, uint32, uint32, uint32) {
	v1 := (x1 & 0x000000ff) | (x2&0x000000ff)<<8 | (x3&0x000000ff)<<16 | (x4&0x000000ff)<<24
	v2 := (x1&0x0000ff00)>>8 | (x2 & 0x0000ff00) | (x3&0x0000ff00)<<8 | (x4&0x0000ff00)<<16
	v3 := (x1&0x00ff0000)>>16 | (x2&0x00ff0000)>>8 | (x3 & 0x00ff0000) | (x4&0x00ff0000)<<8
	v4 := (x1&0xff000000)>>24 | (x2&0xff000000)>>16 | (x3&0xff000000)>>8 | (x4 & 0xff000000)
	return v1, v2, v3, v4
}

// generateKeys generates 32 uint32 subkeys from h and m.
// Directly ported from cryptonite generate_keys().
func generateKeys(h *[8]uint32, m *[8]uint32, k *[32]uint32) { //nolint:funlen
	h0, h1, h2, h3 := h[0], h[1], h[2], h[3]
	h4, h5, h6, h7 := h[4], h[5], h[6], h[7]
	m0, m1, m2, m3 := m[0], m[1], m[2], m[3]
	m4, m5, m6, m7 := m[4], m[5], m[6], m[7]

	k0 := h0 ^ m0
	k1 := h2 ^ m2
	k2 := h4 ^ m4
	k3 := h6 ^ m6
	k[0], k[1], k[2], k[3] = copyKeys(k0, k1, k2, k3)

	k0 = h1 ^ m1
	k1 = h3 ^ m3
	k2 = h5 ^ m5
	k3 = h7 ^ m7
	k[4], k[5], k[6], k[7] = copyKeys(k0, k1, k2, k3)

	k0 = h2 ^ m4
	k1 = h4 ^ m6
	k2 = h6 ^ m0 ^ m2
	k3 = h0 ^ m2 ^ k0
	k[8], k[9], k[10], k[11] = copyKeys(k0, k1, k2, k3)

	k0 = h3 ^ m5
	k1 = h5 ^ m7
	k2 = h7 ^ m1 ^ m3
	k3 = h1 ^ m3 ^ k0
	k[12], k[13], k[14], k[15] = copyKeys(k0, k1, k2, k3)

	k0 = h4 ^ m0 ^ m2
	k1 = h2 ^ m6
	k2 = k1 ^ h0 ^ m4 ^ 0x00ffff00
	k3 = k0 ^ k1 ^ 0x000000ff
	k0 ^= 0xff00ff00
	k1 = h6 ^ m2 ^ m4 ^ 0x00ff00ff
	k[16], k[17], k[18], k[19] = copyKeys(k0, k1, k2, k3)

	k0 = h5 ^ m1 ^ m3
	k1 = h3 ^ m7
	k2 = k1 ^ h1 ^ m5 ^ 0xff0000ff
	k3 = k0 ^ k1 ^ 0xff00ffff
	k0 ^= 0xff00ff00
	k1 = h7 ^ m3 ^ m5 ^ 0x00ff00ff
	k[20], k[21], k[22], k[23] = copyKeys(k0, k1, k2, k3)

	k0 = h6 ^ m6
	k3 = k0 ^ h4 ^ m2 ^ 0xffffffff
	k0 ^= m4 ^ 0x00ff00ff
	k1 = h2 ^ m0
	k2 = k1 ^ h4 ^ m4 ^ 0x000000ff
	k1 ^= h0 ^ m2 ^ m6 ^ 0x00ffff00
	k[24], k[25], k[26], k[27] = copyKeys(k0, k1, k2, k3)

	k0 = h7 ^ m7
	k3 = k0 ^ h5 ^ m3 ^ 0xffffffff
	k0 ^= m5 ^ 0x00ff00ff
	k1 = h3 ^ m1
	k2 = k1 ^ h5 ^ m5 ^ 0xff00ffff
	k1 ^= h1 ^ m3 ^ m7 ^ 0xff0000ff
	k[28], k[29], k[30], k[31] = copyKeys(k0, k1, k2, k3)
}

// add256 adds b into a as a 256-bit little-endian integer (8×uint32 words).
func add256(a *[8]uint32, b *[8]uint32) {
	var carry uint64
	for i := range 8 {
		sum := uint64(a[i]) + uint64(b[i]) + carry
		a[i] = uint32(sum)
		carry = sum >> 32
	}
}

// mixTransform implements cryptonite mix_transform operating on uint16 words.
// a, b, c are 32-byte inputs; out is 32-byte output.
func mixTransform(a, b, c, out []byte) { //nolint:funlen
	// Read as 16 uint16 LE words each
	var av, bv, cv [16]uint16
	for i := range 16 {
		av[i] = binary.LittleEndian.Uint16(a[i*2:])
		bv[i] = binary.LittleEndian.Uint16(b[i*2:])
		cv[i] = binary.LittleEndian.Uint16(c[i*2:])
	}

	a0 := av[0]
	a1 := av[1]
	a2 := av[2]
	a3 := av[3]
	a4 := av[4]
	a5 := av[5]
	a6 := av[6]
	a7 := av[7]
	a8 := av[8]
	a9 := av[9]
	a10 := av[10]
	a11 := av[11]
	a12 := av[12]
	a13 := av[13]
	a14 := av[14]
	a15 := av[15]

	b0 := bv[0]
	b1 := bv[1]
	b2 := bv[2]
	b3 := bv[3]
	b4 := bv[4]
	b5 := bv[5]
	b6 := bv[6]
	b7 := bv[7]
	b8 := bv[8]
	b9 := bv[9]
	b10 := bv[10]
	b11 := bv[11]
	b12 := bv[12]
	b13 := bv[13]
	b14 := bv[14]
	b15 := bv[15]

	c0 := cv[0]
	c1 := cv[1]
	c2 := cv[2]
	c3 := cv[3]
	c4 := cv[4]
	c5 := cv[5]
	c6 := cv[6]
	c7 := cv[7]
	c8 := cv[8]
	c9 := cv[9]
	c10 := cv[10]
	c11 := cv[11]
	c12 := cv[12]
	c13 := cv[13]
	c14 := cv[14]
	c15 := cv[15]

	p1 := a1 ^ a4 ^ b1 ^ b5
	p2 := a3 ^ a5 ^ a6 ^ a12 ^ b4 ^ b6 ^ b7 ^ b13
	p3 := a6 ^ a13 ^ b3 ^ b7 ^ b14
	p4 := a0 ^ a4 ^ a8 ^ a13 ^ a14 ^ b1 ^ b5 ^ b9 ^ b14 ^ b15 ^ c2 ^ c3 ^ c7 ^ c10 ^ c12 ^ c15
	p5 := a1 ^ a7 ^ a10 ^ a13 ^ a14 ^ b8 ^ b11 ^ b14 ^ c5 ^ c13
	p6 := p1 ^ a8 ^ a11 ^ a14 ^ b9 ^ c6 ^ c7 ^ c10 ^ c13 ^ c14
	p7 := p5 ^ a3 ^ a11 ^ b1 ^ b4 ^ c1 ^ c6 ^ c9 ^ c12 ^ c14
	p8 := p3 ^ a1 ^ a5 ^ a10 ^ b6 ^ b11 ^ b12 ^ c0 ^ c10
	p1 ^= a5 ^ a9 ^ a15 ^ b0 ^ b6 ^ b10 ^ b12 ^ c1 ^ c2 ^ c4 ^ c8 ^ c11 ^ c15
	p3 ^= a3 ^ a7 ^ a12 ^ a15 ^ b0 ^ b2 ^ b4 ^ b8 ^ b13 ^ c2 ^ c14
	p5 ^= a5 ^ a9 ^ a12 ^ a15 ^ b0 ^ b6 ^ b10 ^ b13

	var ov [16]uint16
	ov[0] = p7 ^ a15 ^ b0 ^ b3 ^ c7 ^ c10 ^ c11 ^ c15
	ov[1] = p6 ^ a0 ^ a3 ^ b2 ^ b4 ^ b12 ^ b15 ^ c0 ^ c1 ^ c3 ^ c8 ^ c11
	ov[2] = p1 ^ a2 ^ a12 ^ b13 ^ b15 ^ c7 ^ c9 ^ c12 ^ c14
	ov[3] = p8 ^ a0 ^ a12 ^ a15 ^ b0 ^ b13 ^ b15 ^ c1 ^ c5 ^ c8 ^ c9 ^ c13
	ov[4] = p3 ^ a0 ^ a11 ^ a14 ^ c1 ^ c6 ^ c9 ^ c10 ^ c11
	ov[5] = p4 ^ a2 ^ a3 ^ a7 ^ b3 ^ b4 ^ b8 ^ c11
	ov[6] = p1 ^ a3 ^ a8 ^ a14 ^ b3 ^ b4 ^ b9 ^ c0 ^ c13
	ov[7] = p2 ^ a0 ^ a1 ^ a4 ^ a9 ^ a10 ^ b1 ^ b2 ^ b5 ^ b10 ^ b11 ^ c0 ^ c5 ^ c9 ^ c14 ^ c15
	ov[8] = p8 ^ a2 ^ a4 ^ a7 ^ a11 ^ b2 ^ b5 ^ b8 ^ c2 ^ c3 ^ c6 ^ c12
	ov[9] = p2 ^ a2 ^ a7 ^ a8 ^ a11 ^ a14 ^ b3 ^ b8 ^ b9 ^ b12 ^ b15 ^ c1 ^ c3 ^ c4 ^ c7 ^ c11 ^ c13
	ov[10] = p3 ^ a4 ^ a8 ^ a9 ^ b1 ^ b5 ^ b9 ^ b10 ^ b12 ^ b15 ^ c4 ^ c5 ^ c8 ^ c12
	ov[11] = p5 ^ a0 ^ a2 ^ a3 ^ a4 ^ a8 ^ b4 ^ b5 ^ b9 ^ b12 ^ c3 ^ c6 ^ c9 ^ c15
	ov[12] = p4 ^ a5 ^ a6 ^ a9 ^ a10 ^ a11 ^ a12 ^ b6 ^ b7 ^ b10 ^ b11 ^ b12 ^ b13 ^ c0 ^ c1 ^ c4 ^ c6 ^ c14
	ov[13] = p5 ^ a6 ^ a11 ^ b1 ^ b3 ^ b7 ^ c0 ^ c4 ^ c7 ^ c8 ^ c11 ^ c12
	ov[14] = p7 ^ a0 ^ a6 ^ a8 ^ b2 ^ b7 ^ b9 ^ b12 ^ b15 ^ c8
	ov[15] = p6 ^ a2 ^ a7 ^ a9 ^ a12 ^ a15 ^ b0 ^ b8 ^ b10 ^ b13 ^ c2 ^ c9 ^ c15

	for i := range 16 {
		binary.LittleEndian.PutUint16(out[i*2:], ov[i])
	}
}

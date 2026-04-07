// Package kupyna implements the Kupyna hash function (DSTU 7564:2014).
// Reference: Roman-Oliynykov/Kupyna-reference
package kupyna

import (
	"encoding/binary"
	"hash"
	"slices"
)

// digest holds the internal state for a Kupyna hash computation.
type digest struct {
	state     [][rows]byte // column-major state: [cols][8]byte
	buf       []byte       // partial block buffer
	totalBits uint64       // total message length in bits
	hashSize  int          // output size in bytes (32, 48, or 64)
	blockSize int          // input block size in bytes (64 or 128)
	cols      int          // number of columns (8 or 16)
	rounds    int          // number of rounds (10 or 14)
}

// New256 returns a new Kupyna-256 hash.
func New256() hash.Hash { return newDigest(32) }

// New384 returns a new Kupyna-384 hash.
func New384() hash.Hash { return newDigest(48) }

// New512 returns a new Kupyna-512 hash.
func New512() hash.Hash { return newDigest(64) }

func newDigest(hashBytes int) *digest {
	d := &digest{hashSize: hashBytes}
	if hashBytes <= 32 {
		d.blockSize = stateSize512
		d.cols = nb512
		d.rounds = nr512
	} else {
		d.blockSize = stateSize1024
		d.cols = nb1024
		d.rounds = nr1024
	}
	d.Reset()
	return d
}

func (d *digest) Reset() {
	d.state = make([][rows]byte, d.cols)
	// Initial value: state[0][0] = blockSize (number of bytes in state)
	d.state[0][0] = byte(d.blockSize)
	d.buf = d.buf[:0]
	d.totalBits = 0
}

func (d *digest) Size() int      { return d.hashSize }
func (d *digest) BlockSize() int { return d.blockSize }

func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	d.totalBits += uint64(n) * 8
	// Append to buffer
	d.buf = append(d.buf, p...)
	// Process complete blocks
	for len(d.buf) >= d.blockSize {
		compress(d.state, d.buf[:d.blockSize], d.rounds)
		d.buf = d.buf[d.blockSize:]
	}
	return n, nil
}

func (d *digest) Sum(in []byte) []byte {
	// Work on a copy so Sum can be called multiple times
	d0 := d.clone()
	hash := d0.checkSum()
	return append(in, hash...)
}

func (d *digest) clone() *digest {
	d2 := &digest{
		hashSize:  d.hashSize,
		blockSize: d.blockSize,
		cols:      d.cols,
		rounds:    d.rounds,
		totalBits: d.totalBits,
		buf:       make([]byte, len(d.buf)),
	}
	d2.state = make([][rows]byte, d.cols)
	copy(d2.state, d.state)
	copy(d2.buf, d.buf)
	return d2
}

func (d *digest) checkSum() []byte {
	// Padding: append 0x80, then zeros, then 12-byte (96-bit) LE message length.
	// Total padded length must be a multiple of blockSize.
	msgBits := d.totalBits
	pad := make([]byte, 1, d.blockSize+13)
	pad[0] = 0x80
	// Number of zero bytes needed:
	// (blockSize - (len(buf) + 1 + 12) % blockSize) % blockSize
	padLen := (d.blockSize - (len(d.buf)+1+12)%d.blockSize) % d.blockSize
	pad = append(pad, make([]byte, padLen)...)
	// Append 96-bit (12-byte) message length in bits, little-endian
	var lenBytes [12]byte
	binary.LittleEndian.PutUint64(lenBytes[0:], msgBits)
	// upper 32 bits are zero for messages < 2^64 bits
	pad = append(pad, lenBytes[:]...)

	// Process remaining buf + padding as complete blocks
	remaining := slices.Concat(d.buf, pad)
	for len(remaining) >= d.blockSize {
		compress(d.state, remaining[:d.blockSize], d.rounds)
		remaining = remaining[d.blockSize:]
	}

	// Output transformation
	outputTransform(d.state, d.rounds)

	// Truncate: take last hashSize bytes of state (in flat byte order)
	flat := stateToBytes(d.state)
	return flat[len(flat)-d.hashSize:]
}

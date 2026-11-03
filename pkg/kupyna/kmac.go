package kupyna

import (
	"encoding/binary"
	"hash"
)

// kmacDigest implements KMAC (Keyed MAC) mode of Kupyna (DSTU 7564:2014).
//
// Construction per cryptonite dstu7564.c:
//
//	KMAC(K, M) = H(PAD(K) || PAD(M) || ~K)
//
// where:
//
//	PAD(x) = x || 0x80 || 0x00...0x00 || LE96(|x|_bits)  padded to blockSize multiple
//	~K      = bitwise complement of original key bytes (only keyLen bytes, NOT padded)
//	The final padding of the whole message wraps PAD(K)||PAD(M)||~K together.
//
// Reference: cryptonite src/cryptonite/c/dstu7564.c — dstu7564_init_kmac,
//
//	dstu7564_update_kmac, dstu7564_final_kmac.
type kmacDigest struct {
	// hash state (same fields as digest)
	state     [][rows]byte
	blockSize int
	cols      int
	rounds    int
	hashSize  int

	// C equivalent: last_block, last_block_el, msg_tot_len
	lastBlock   []byte // partial block buffer, length == blockSize
	lastBlockEl int    // bytes currently in lastBlock
	msgTotLen   uint64 // total bits processed (PAD(K) + message so far)

	// KMAC-specific
	key       []byte
	invertKey []byte
	keyLen    int
	keyPadLen uint64
}

// NewKMAC256 returns a Kupyna-256 KMAC keyed with key (mac_len = 32).
func NewKMAC256(key []byte) hash.Hash { return newKMAC(key, 32) }

// NewKMAC384 returns a Kupyna-384 KMAC keyed with key (mac_len = 48).
func NewKMAC384(key []byte) hash.Hash { return newKMAC(key, 48) }

// NewKMAC512 returns a Kupyna-512 KMAC keyed with key (mac_len = 64).
func NewKMAC512(key []byte) hash.Hash { return newKMAC(key, 64) }

func newKMAC(key []byte, macLen int) *kmacDigest {
	var bs, cols, nr int
	if macLen <= 32 {
		bs, cols, nr = stateSize512, nb512, nr512
	} else {
		bs, cols, nr = stateSize1024, nb1024, nr1024
	}
	k := &kmacDigest{
		blockSize: bs,
		cols:      cols,
		rounds:    nr,
		hashSize:  macLen,
		keyLen:    len(key),
		key:       make([]byte, len(key)),
		invertKey: make([]byte, len(key)),
	}
	copy(k.key, key)
	for i, b := range key {
		k.invertKey[i] = ^b
	}
	k.initState()
	return k
}

// initState resets the hash state and feeds PAD(K) as the first block(s).
// Standard provider keys occupy one block; longer keys may need more blocks.
func (k *kmacDigest) initState() {
	// Reset state to IV (state[0] = blockSize, rest zero)
	k.state = make([][rows]byte, k.cols)
	k.state[0][0] = byte(k.blockSize)
	k.lastBlock = make([]byte, k.blockSize)
	k.lastBlockEl = 0
	k.msgTotLen = 0

	// Build PAD(K): key_buf || 0x80 || zeros || LE96(keyLen*8)
	// padded to a multiple of blockSize.
	keyBuf := kmacPadded(k.key, uint64(k.keyLen)*8, k.blockSize)
	defer clear(keyBuf)
	k.keyPadLen = uint64(len(keyBuf))

	// Feed each padded key block through digest(), advancing msg_tot_len.
	for i := 0; i < len(keyBuf); i += k.blockSize {
		compress(k.state, keyBuf[i:i+k.blockSize], k.rounds)
		k.msgTotLen += uint64(k.blockSize) * 8
	}
}

// Reset resets the MAC to its initial keyed state (key is preserved).
func (k *kmacDigest) Reset() { k.initState() }

// Size returns the MAC output size in bytes.
func (k *kmacDigest) Size() int { return k.hashSize }

// BlockSize returns the input block size in bytes.
func (k *kmacDigest) BlockSize() int { return k.blockSize }

// Write feeds message bytes into the KMAC (mirrors dstu7564_update).
func (k *kmacDigest) Write(p []byte) (int, error) {
	n := len(p)
	k.msgTotLen += uint64(n) * 8

	if k.lastBlockEl+n < k.blockSize {
		copy(k.lastBlock[k.lastBlockEl:], p)
		k.lastBlockEl += n
		return n, nil
	}

	// Fill rest of lastBlock and compress it
	fill := k.blockSize - k.lastBlockEl
	copy(k.lastBlock[k.lastBlockEl:], p[:fill])
	compress(k.state, k.lastBlock, k.rounds)
	k.lastBlock = make([]byte, k.blockSize)
	p = p[fill:]

	// Process full blocks from p
	for len(p) >= k.blockSize {
		compress(k.state, p[:k.blockSize], k.rounds)
		p = p[k.blockSize:]
	}

	k.lastBlockEl = len(p)
	if k.lastBlockEl != 0 {
		copy(k.lastBlock, p)
	}
	return n, nil
}

// Sum appends the current MAC to in without modifying state.
func (k *kmacDigest) Sum(in []byte) []byte {
	k2 := k.cloneKMAC()
	mac := k2.finalise()
	return append(in, mac...)
}

func (k *kmacDigest) cloneKMAC() *kmacDigest {
	k2 := &kmacDigest{
		blockSize:   k.blockSize,
		cols:        k.cols,
		rounds:      k.rounds,
		hashSize:    k.hashSize,
		keyLen:      k.keyLen,
		keyPadLen:   k.keyPadLen,
		lastBlockEl: k.lastBlockEl,
		msgTotLen:   k.msgTotLen,
		key:         make([]byte, len(k.key)),
		invertKey:   make([]byte, len(k.invertKey)),
		lastBlock:   make([]byte, len(k.lastBlock)),
	}
	copy(k2.key, k.key)
	copy(k2.invertKey, k.invertKey)
	copy(k2.lastBlock, k.lastBlock)
	k2.state = make([][rows]byte, k.cols)
	copy(k2.state, k.state)
	return k2
}

// finalise applies Kupyna KMAC padding, including keys spanning multiple blocks.
func (k *kmacDigest) finalise() []byte {
	// msg_len = total message bytes (excluding every padded key block).
	msgLen := (k.msgTotLen >> 3) - k.keyPadLen
	// Undo the last partial block's bits from msg_tot_len
	k.msgTotLen -= uint64(k.lastBlockEl) * 8

	// --- PAD(M): pad lastBlock in-place at lastBlockEl offset ---
	// padding() uses: buf_len_out = lastBlockEl (offset into buf),
	//                 buf_len_out_bit = msgLen*8 (bit count of message only)
	// A partial block with fewer than 13 free bytes needs two blocks for
	// the marker and 96-bit length. Write retains only one input block.
	paddingBlocks := make([]byte, 2*k.blockSize)
	copy(paddingBlocks, k.lastBlock)
	paddedLen := kmacPaddingInPlace(paddingBlocks, k.lastBlockEl, msgLen*8, k.blockSize)
	for i := 0; i < paddedLen; i += k.blockSize {
		k.msgTotLen += uint64(k.blockSize) * 8
		compress(k.state, paddingBlocks[i:i+k.blockSize], k.rounds)
	}

	// --- Append ~K, then PAD the whole (PAD(K)||PAD(M)||~K) ---
	tail := kmacPadded(k.invertKey, k.msgTotLen+uint64(k.keyLen)*8, k.blockSize)
	defer clear(tail)
	for i := 0; i < len(tail); i += k.blockSize {
		compress(k.state, tail[i:i+k.blockSize], k.rounds)
	}

	// Output transformation
	outputTransform(k.state, k.rounds)
	flat := stateToBytes(k.state)
	return flat[len(flat)-k.hashSize:]
}

// kmacPadded retains every input block and appends the 96-bit length trailer.
// Prefix data already compressed by the caller is reflected in totalBits.
func kmacPadded(data []byte, totalBits uint64, blockSize int) []byte {
	size := (len(data) + 13 + blockSize - 1) / blockSize * blockSize
	output := make([]byte, size)
	copy(output, data)
	output[len(data)] = 0x80
	binary.LittleEndian.PutUint64(output[size-12:], totalBits)
	return output
}

// kmacPaddingInPlace pads buf in-place starting at offset bufLenOut.
// Mirrors the C padding() function:
//
//	buf[bufLenOut] = 0x80
//	buf[bufLenOut+1 .. bufLenOut+zeroN] = 0x00
//	buf[bufLenOut+zeroN+1 .. +12]  = LE96(bufLenOutBit)
//
// Returns total padded bytes added (always a multiple of blockSize when
// added to bufLenOut % blockSize, giving full blocks).
func kmacPaddingInPlace(buf []byte, bufLenOut int, bufLenOutBit uint64, blockSize int) int {
	curPos := bufLenOut % blockSize
	zeroN := int(^(bufLenOutBit+97)%(uint64(blockSize)*8)) >> 3
	buf[curPos] = 0x80
	curPos++
	for i := range zeroN {
		buf[curPos+i] = 0
	}
	curPos += zeroN
	var lenBytes [12]byte
	binary.LittleEndian.PutUint64(lenBytes[0:], bufLenOutBit)
	copy(buf[curPos:], lenBytes[:])
	return zeroN + 1 + 12
}

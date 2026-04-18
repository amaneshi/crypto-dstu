package kalyna

import (
	"crypto/cipher"
	"errors"
)

// NewCTR returns a CTR mode stream cipher using the given block cipher and IV.
// The IV length must equal the block size.
//
// Cryptonite behaviour: the IV is encrypted immediately to produce the first
// keystream block (gamma).  Before each subsequent block the feed counter is
// incremented (little-endian byte increment) and re-encrypted.
func NewCTR(block cipher.Block, iv []byte) (cipher.Stream, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("kalyna/ctr: IV length must equal block size")
	}
	// Cryptonite init_ctr:
	//   gamma = Encrypt(iv)
	//   feed  = gamma   (counter starts at Encrypt(iv), NOT iv)
	//   used_gamma_len = block_len  (whole gamma block already "used")
	// So on the first call to XORKeyStream the offset==bs branch fires,
	// increments feed and re-encrypts: keystream[0] = Encrypt(Encrypt(iv)+1).
	gamma := make([]byte, bs)
	block.Encrypt(gamma, iv)
	feed := make([]byte, bs)
	copy(feed, gamma)
	return &ctrStream{
		block: block,
		feed:  feed,
		gamma: gamma,
		off:   bs, // mark as exhausted so first use triggers gamma_gen+encrypt
	}, nil
}

type ctrStream struct {
	block cipher.Block
	feed  []byte // current counter (LE increment)
	gamma []byte // current keystream block
	off   int    // bytes consumed from gamma
}

func (c *ctrStream) XORKeyStream(dst, src []byte) {
	bs := c.block.BlockSize()
	for i := range src {
		if c.off == bs {
			leIncrement(c.feed)
			c.block.Encrypt(c.gamma, c.feed)
			c.off = 0
		}
		dst[i] = src[i] ^ c.gamma[c.off]
		c.off++
	}
}

// leIncrement increments a little-endian byte slice by 1.
func leIncrement(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

// NewCBCEncrypter returns a CBC mode block-mode encrypter.
// Input to Encrypt must already be block-aligned and padded by the caller.
func NewCBCEncrypter(block cipher.Block, iv []byte) (cipher.BlockMode, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("kalyna/cbc: IV length must equal block size")
	}
	gamma := make([]byte, bs)
	copy(gamma, iv)
	return cipher.NewCBCEncrypter(block, gamma), nil
}

// NewCBCDecrypter returns a CBC mode block-mode decrypter.
func NewCBCDecrypter(block cipher.Block, iv []byte) (cipher.BlockMode, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("kalyna/cbc: IV length must equal block size")
	}
	gamma := make([]byte, bs)
	copy(gamma, iv)
	return cipher.NewCBCDecrypter(block, gamma), nil
}

// NewOFBStream is the ofbStream type used by NewOFB.
type ofbStream struct {
	block  cipher.Block
	gamma  []byte
	offset int
}

// NewOFB returns an OFB mode stream cipher.
func NewOFB(block cipher.Block, iv []byte) (cipher.Stream, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("kalyna/ofb: IV length must equal block size")
	}
	g := make([]byte, bs)
	copy(g, iv)
	return &ofbStream{block: block, gamma: g, offset: bs}, nil
}

func (o *ofbStream) XORKeyStream(dst, src []byte) {
	bs := o.block.BlockSize()
	for i := range src {
		if o.offset == bs {
			o.block.Encrypt(o.gamma, o.gamma)
			o.offset = 0
		}
		dst[i] = src[i] ^ o.gamma[o.offset]
		o.offset++
	}
}

// cfbStream is the internal type used by NewCFBEncrypter / NewCFBDecrypter.
type cfbStream struct {
	block   cipher.Block
	gamma   []byte
	feed    []byte
	offset  int
	decrypt bool
}

// NewCFBEncrypter returns a CFB mode stream encrypter.
func NewCFBEncrypter(block cipher.Block, iv []byte) (cipher.Stream, error) {
	return newCFB(block, iv, false)
}

// NewCFBDecrypter returns a CFB mode stream decrypter.
func NewCFBDecrypter(block cipher.Block, iv []byte) (cipher.Stream, error) {
	return newCFB(block, iv, true)
}

func newCFB(block cipher.Block, iv []byte, decrypt bool) (cipher.Stream, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("kalyna/cfb: IV length must equal block size")
	}
	feed := make([]byte, bs)
	copy(feed, iv)
	gamma := make([]byte, bs)
	block.Encrypt(gamma, feed)
	return &cfbStream{block: block, gamma: gamma, feed: feed, offset: 0, decrypt: decrypt}, nil
}

func (c *cfbStream) XORKeyStream(dst, src []byte) {
	bs := c.block.BlockSize()
	for i := range src {
		if c.offset == bs {
			copy(c.feed, c.gamma)
			c.block.Encrypt(c.gamma, c.feed)
			c.offset = 0
		}
		if c.decrypt {
			c.feed[c.offset] = src[i]
			dst[i] = src[i] ^ c.gamma[c.offset]
		} else {
			dst[i] = src[i] ^ c.gamma[c.offset]
			c.feed[c.offset] = dst[i]
		}
		c.offset++
	}
}

// CMAC implements the Cryptonite CMAC (DSTU 7624) MAC.
type CMAC struct {
	block     cipher.Block
	bs        int
	q         int
	state     []byte // running CBC-MAC state
	lastBlock []byte // partial/last block buffer
}

// NewCMAC returns a CMAC authenticator for a Kalyna block cipher.
// q is the output MAC length in bytes (must be 1..blockSize).
//
// Cryptonite CMAC construction (dstu7624.c cmac_update / cmac_final):
//   - Accumulate CBC-MAC over input blocks (all but last, >= 1 block at a time)
//   - Final block: zero-extend with 0x80…, XOR with rkey (Encrypt([paddingFlag,0…0])),
//     XOR current state, encrypt → truncate to q bytes.
func NewCMAC(block cipher.Block, q int) (*CMAC, error) {
	bs := block.BlockSize()
	if q <= 0 || q > bs {
		return nil, errors.New("kalyna/cmac: invalid MAC length")
	}
	state := make([]byte, bs)
	return &CMAC{block: block, bs: bs, q: q, state: state}, nil
}

func (c *CMAC) Write(p []byte) (int, error) {
	n := len(p)
	bs := c.bs

	c.lastBlock = append(c.lastBlock, p...)

	// Process all complete blocks except the final one (reserved for MAC()).
	off := 0
	for len(c.lastBlock)-off > bs {
		xorBytes(c.state, c.state, c.lastBlock[off:off+bs], bs)
		c.block.Encrypt(c.state, c.state)
		off += bs
	}
	if off > 0 {
		c.lastBlock = c.lastBlock[off:]
	}
	return n, nil
}

func (c *CMAC) MAC() []byte {
	bs := c.bs

	// Mirror cmac_final: pad last_block in-place, capture whether padding was added.
	// padding() returns 1 if padding was added (data not block-aligned), 0 otherwise.
	lb := make([]byte, bs)
	lbLen := len(c.lastBlock)
	if lbLen > 0 {
		copy(lb, c.lastBlock)
	}
	var paddingFlag byte
	if lbLen%bs != 0 {
		// Pad: append 0x80 + zeros to fill block
		lb[lbLen] = 0x80
		// zeros already in lb (make initialized to 0)
		paddingFlag = 1
	}

	// rkey = [paddingFlag, 0, 0, ..., 0] encrypted
	rkey := make([]byte, bs)
	rkey[0] = paddingFlag
	c.block.Encrypt(rkey, rkey)

	// cipher_data = current state XOR last_block, then XOR rkey, then encrypt
	tmp := make([]byte, bs)
	xorBytes(tmp, c.state, lb, bs)
	xorBytes(tmp, tmp, rkey, bs)
	c.block.Encrypt(tmp, tmp)

	out := make([]byte, c.q)
	copy(out, tmp[:c.q])
	return out
}

func (c *CMAC) Reset() {
	for i := range c.state {
		c.state[i] = 0
	}
	c.lastBlock = nil
}

// xorBytes XORs n bytes from a and b into dst.
func xorBytes(dst, a, b []byte, n int) {
	for i := range n {
		dst[i] = a[i] ^ b[i]
	}
}

// XTS implements XTS mode encryption/decryption.
type XTS struct {
	block   cipher.Block
	bs      int
	gamma   []byte
	encrypt bool
}

// NewXTSEncrypter returns an XTS mode encrypter for a block cipher.
// The IV (tweak) length must equal the block size.
//
// Cryptonite XTS: encrypt IV to get gamma, then for each block:
//
//	gamma = gf2m_mul(gamma, 2)
//	block = Encrypt(plaintext XOR gamma) XOR gamma
//
// GF(2^m) polynomials per block size:
//
//	128-bit: x^128 + x^7 + x^2 + x + 1
//	256-bit: x^256 + x^10 + x^5 + x^2 + 1
//	512-bit: x^512 + x^8 + x^5 + x^2 + 1
func NewXTSEncrypter(block cipher.Block, iv []byte) (*XTS, error) {
	return newXTS(block, iv, true)
}

// NewXTSDecrypter returns an XTS mode decrypter for a block cipher.
// The IV (tweak) length must equal the block size.
func NewXTSDecrypter(block cipher.Block, iv []byte) (*XTS, error) {
	return newXTS(block, iv, false)
}

func newXTS(block cipher.Block, iv []byte, encrypt bool) (*XTS, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, errors.New("kalyna/xts: IV length must equal block size")
	}
	gamma := make([]byte, bs)
	block.Encrypt(gamma, iv)
	return &XTS{block: block, bs: bs, gamma: gamma, encrypt: encrypt}, nil
}

// CryptBlocks encrypts or decrypts src into dst (both must be block-aligned).
func (x *XTS) CryptBlocks(dst, src []byte) {
	bs := x.bs
	two := make([]byte, bs)
	two[0] = 2

	for len(src) >= bs {
		xtsGF2MMul(x.gamma, x.gamma, two, bs)
		tmp := make([]byte, bs)
		xorBytes(tmp, src[:bs], x.gamma, bs)
		if x.encrypt {
			x.block.Encrypt(tmp, tmp)
		} else {
			x.block.Decrypt(tmp, tmp)
		}
		xorBytes(dst[:bs], tmp, x.gamma, bs)
		src = src[bs:]
		dst = dst[bs:]
	}
}

// xtsGF2MMul multiplies a by b in GF(2^m) with the appropriate reduction polynomial.
// Both a and b are m/8-byte arrays in LE order.  Result stored in out.
func xtsGF2MMul(out, a, b []byte, blockSize int) {
	n := blockSize // bytes
	result := make([]byte, n)
	aa := make([]byte, n)
	copy(aa, a)

	for i := range n {
		if b[i/8]>>(i%8)&1 == 1 {
			xorBytes(result, result, aa, n)
		}
		// shift aa left 1 bit (LE), reduce if needed
		carry := aa[n-1] >> 7
		for j := n - 1; j > 0; j-- {
			aa[j] = (aa[j] << 1) | (aa[j-1] >> 7)
		}
		aa[0] <<= 1
		if carry != 0 {
			// XOR reduction polynomial (constant term only, byte 0)
			switch blockSize {
			case 16: // x^128 + x^7 + x^2 + x + 1 → 0x87
				aa[0] ^= 0x87
			case 32: // x^256 + x^10 + x^5 + x^2 + 1 → bytes [0]=0x25, [1]=0x04
				aa[0] ^= 0x25
				aa[1] ^= 0x04
			case 64: // x^512 + x^8 + x^5 + x^2 + 1 → bytes [0]=0x25, [1]=0x01
				aa[0] ^= 0x25
				aa[1] ^= 0x01
			}
		}
	}
	copy(out, result)
}

// KW implements the Kalyna key wrapping mode.
type KW struct {
	block   cipher.Block
	encrypt bool
}

// NewKWEncrypter returns a KW key-wrap encrypter following the cryptonite
// dstu7624 KW construction (a custom Feistel-like key wrapping scheme).
func NewKWEncrypter(block cipher.Block) *KW {
	return &KW{block: block, encrypt: true}
}

// NewKWDecrypter returns a KW key-wrap decrypter.
func NewKWDecrypter(block cipher.Block) *KW {
	return &KW{block: block, encrypt: false}
}

// Wrap encrypts (wraps) src and returns the wrapped ciphertext.
// The input data length must be a multiple of the block size.
func (kw *KW) Wrap(src []byte) ([]byte, error) {
	bs := kw.block.BlockSize()
	halfBS := bs >> 1

	data := make([]byte, len(src))
	copy(data, src)

	// If not block-aligned, apply KW padding (LE bit-length + 0x80 padding)
	if len(data)%bs != 0 {
		data = kwPad(data, bs)
	}

	r := len(data) / bs
	n := 2 * (r + 1)
	v := (n - 1) * 6

	regB := make([]byte, halfBS)

	// regB = first halfBS bytes of data, bSlice = rest
	copy(regB, data[:halfBS])
	bSlice := make([]byte, (n-1)*halfBS)
	copy(bSlice, data[halfBS:])

	swap := make([]byte, bs)
	bLastEl := (n - 2) * halfBS

	for i := 1; i <= v; i++ {
		copy(swap[:halfBS], regB)
		copy(swap[halfBS:], bSlice[:halfBS])
		kw.block.Encrypt(swap, swap)
		swap[halfBS] ^= byte(i)
		copy(regB, swap[halfBS:halfBS+halfBS])
		// shift bSlice left by halfBS
		shift := make([]byte, (n-1)*halfBS)
		copy(shift, bSlice[halfBS:])
		copy(bSlice, shift[:(n-1)*halfBS-halfBS])
		copy(bSlice[bLastEl:], swap[:halfBS])
	}

	result := make([]byte, halfBS+len(bSlice))
	copy(result, regB)
	copy(result[halfBS:], bSlice)
	return result, nil
}

// Unwrap decrypts (unwraps) src and returns the original plaintext.
func (kw *KW) Unwrap(src []byte) ([]byte, error) {
	bs := kw.block.BlockSize()
	halfBS := bs >> 1

	data := make([]byte, len(src))
	copy(data, src)

	r := (len(data) / bs) - 1
	n := 2 * (r + 1)
	v := (n - 1) * 6

	regB := make([]byte, halfBS)
	copy(regB, data[:halfBS])
	bSlice := make([]byte, len(data)-halfBS)
	copy(bSlice, data[halfBS:])

	bLastEl := (n - 2) * halfBS
	swap := make([]byte, bs)

	for i := v; i >= 1; i-- {
		copy(swap, bSlice[bLastEl:bLastEl+halfBS])
		regB[0] ^= byte(i)
		copy(swap[halfBS:], regB)
		kw.block.Decrypt(swap, swap)
		copy(regB, swap[:halfBS])
		shift := make([]byte, len(bSlice))
		copy(shift, bSlice)
		copy(bSlice[halfBS:], shift[:bLastEl])
		copy(bSlice[:halfBS], swap[halfBS:halfBS+halfBS])
	}

	result := make([]byte, halfBS+len(bSlice))
	copy(result, regB)
	copy(result[halfBS:], bSlice)

	// Unpad
	result = kwUnpad(result, bs)
	return result, nil
}

// kwPad pads data for KW mode, mirroring the C encrypt_kw branch:
//  1. Append LE byte-encoding of bitLen (while bitLen != 0)
//  2. plain_data_size_byte += halfBS
//  3. Call ISO7816 padding to next blockSize multiple
func kwPad(data []byte, blockSize int) []byte {
	halfBS := blockSize >> 1
	orig := len(data)
	bitLen := orig * 8
	buf := make([]byte, orig+halfBS+blockSize) // large enough
	copy(buf, data)
	i := orig
	for bitLen != 0 {
		buf[i] = byte(bitLen & 0xFF)
		i++
		bitLen >>= 8
	}
	// plain_data_size_byte += halfBS (i now points to i, advance by remaining halfBS bytes)
	size := orig + halfBS
	// ISO7816-4 padding: append 0x80 then zeros to multiple of blockSize
	if size%blockSize != 0 {
		buf[size] = 0x80
		// zeros already zeroed
		padBytes := blockSize - (size % blockSize)
		size += padBytes
	}
	return buf[:size]
}

// kwUnpad reverses KW padding, mirroring the C decrypt_kw logic:
//  1. unpadding(): strip trailing zeros, find 0x80, return size = index_of_0x80 + 1
//  2. if size % blockSize != 0: size -= halfBS + 1
func kwUnpad(data []byte, blockSize int) []byte {
	halfBS := blockSize >> 1

	// unpadding(): walk backwards past zeros, find 0x80
	i := len(data) - 1
	for i > 0 && data[i] == 0 {
		i--
	}
	// i now points to 0x80 (or last non-zero byte if no padding)
	size := i + 1 // C: *data_size_byte = i + 1

	if size%blockSize != 0 {
		size -= halfBS + 1
	}
	if size < 0 {
		size = 0
	}
	return data[:size]
}

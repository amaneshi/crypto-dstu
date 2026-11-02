package kalyna

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// KW implements DSTU 7624 key wrapping with a full zero integrity block.
// This is distinct from the national CMS CMAC/CFB wrapper (WrapKey).
type KW struct{ block cipher.Block }

// NewKWEncrypter returns a key wrapper for a Kalyna block cipher.
func NewKWEncrypter(block cipher.Block) *KW { return &KW{block: block} }

// NewKWDecrypter returns a key unwrapper for a Kalyna block cipher.
func NewKWDecrypter(block cipher.Block) *KW { return &KW{block: block} }

// Wrap wraps whole cipher blocks, appending one integrity block.
// Use WrapPadded for non-aligned input.
func (kw *KW) Wrap(src []byte) ([]byte, error) {
	bs, err := kw.blockSize()
	if err != nil {
		return nil, err
	}
	if len(src)%bs != 0 {
		return nil, errors.New("kalyna/kw: input must be block-aligned")
	}
	if !kwLengthOK(uint64(len(src))+uint64(bs), bs) {
		return nil, errors.New("kalyna/kw: input too large")
	}
	data := make([]byte, len(src)+bs)
	copy(data, src)
	kw.transform(data, true)
	return data, nil
}

// Unwrap authenticates the entire integrity block before returning whole blocks.
// Trailing zero bytes in the key are preserved. Failures return no plaintext.
func (kw *KW) Unwrap(src []byte) ([]byte, error) {
	bs, err := kw.blockSize()
	if err != nil {
		return nil, err
	}
	if len(src) < bs || len(src)%bs != 0 {
		return nil, errors.New("kalyna/kw: invalid wrapped length")
	}
	if !kwLengthOK(uint64(len(src)), bs) {
		return nil, errors.New("kalyna/kw: input too large")
	}
	data := append([]byte(nil), src...)
	defer clear(data)
	kw.transform(data, false)
	end := len(data) - bs
	if subtle.ConstantTimeCompare(data[end:], make([]byte, bs)) != 1 {
		return nil, errors.New("kalyna/kw: integrity check failed")
	}
	return append([]byte{}, data[:end]...), nil
}

// WrapPadded applies the Cryptonite length trailer and ISO 7816 padding to
// non-aligned input before wrapping. Its original byte length must be retained
// separately for UnwrapPadded; padding cannot be inferred from arbitrary keys.
func (kw *KW) WrapPadded(src []byte) ([]byte, error) {
	bs, err := kw.blockSize()
	if err != nil {
		return nil, err
	}
	if len(src)%bs == 0 {
		return nil, errors.New("kalyna/kw: use Wrap for block-aligned input")
	}
	if !kwLengthOK(uint64(len(src))+uint64(3*bs), bs) {
		return nil, errors.New("kalyna/kw: input too large")
	}
	data := kwPad(src, bs)
	defer clear(data)
	return kw.Wrap(data)
}

// UnwrapPadded verifies the integrity block and canonical padding for byteLength.
func (kw *KW) UnwrapPadded(src []byte, byteLength int) ([]byte, error) {
	bs, err := kw.blockSize()
	if err != nil {
		return nil, err
	}
	if byteLength <= 0 || byteLength%bs == 0 || byteLength >= len(src) {
		return nil, errors.New("kalyna/kw: invalid original length")
	}
	data, err := kw.Unwrap(src)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if byteLength > len(data) {
		return nil, errors.New("kalyna/kw: invalid original length")
	}
	expected := kwPad(data[:byteLength], bs)
	defer clear(expected)
	if subtle.ConstantTimeCompare(data, expected) != 1 {
		return nil, errors.New("kalyna/kw: invalid padding")
	}
	return append([]byte(nil), data[:byteLength]...), nil
}

func (kw *KW) blockSize() (int, error) {
	if kw == nil || kw.block == nil {
		return 0, errors.New("kalyna/kw: missing block cipher")
	}
	bs := kw.block.BlockSize()
	if bs != 16 && bs != 32 && bs != 64 {
		return 0, errors.New("kalyna/kw: invalid block size")
	}
	return bs, nil
}

// Keep allocation arithmetic and the 32-bit round counter representable,
// including on 32-bit platforms.
func kwLengthOK(size uint64, bs int) bool {
	return size <= uint64(int(^uint(0)>>1))/6 && 6*(size/uint64(bs/2)-1) <= 1<<32-1
}

func (kw *KW) transform(data []byte, encrypt bool) {
	bs := kw.block.BlockSize()
	half := bs / 2
	b := append([]byte(nil), data[:half]...)
	defer clear(b)
	r := data[half:]
	tmp := make([]byte, bs)
	defer clear(tmp)
	var counter [4]byte
	rounds := 6 * (len(data)/half - 1)
	for step := 1; step <= rounds; step++ {
		i := step
		if !encrypt {
			i = rounds - step + 1
		}
		binary.LittleEndian.PutUint32(counter[:], uint32(i))
		if encrypt {
			copy(tmp, b)
			copy(tmp[half:], r[:half])
			kw.block.Encrypt(tmp, tmp)
			for j := range counter {
				tmp[half+j] ^= counter[j]
			}
			copy(b, tmp[half:])
			copy(r, r[half:])
			copy(r[len(r)-half:], tmp[:half])
		} else {
			copy(tmp, r[len(r)-half:])
			copy(tmp[half:], b)
			for j := range counter {
				tmp[half+j] ^= counter[j]
			}
			kw.block.Decrypt(tmp, tmp)
			copy(b, tmp[:half])
			copy(r[half:], r[:len(r)-half])
			copy(r, tmp[half:])
		}
	}
	copy(data, b)
}

func kwPad(src []byte, bs int) []byte {
	size := len(src) + bs/2
	padded := (size + bs - 1) / bs * bs
	data := make([]byte, padded)
	copy(data, src)
	binary.LittleEndian.PutUint64(data[len(src):], uint64(len(src))*8)
	if size != padded {
		data[size] = 0x80
	}
	return data
}

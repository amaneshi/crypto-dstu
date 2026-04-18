package gost28147

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	ctrC1 = uint32(0x01010101)
	ctrC2 = uint32(0x01010104)
)

// ctrStream implements GOST 28147-89 CTR (gamma) mode.
// Reference: cryptonite gost28147_init_ctr / gost28147_ctr_crypt.
//
// The feed is 6 uint32 words (24 bytes = 3 GOST blocks).
// Init: IV (8 bytes) → feed[4:6], encrypt those 2 words → feed[4:6] updated.
// offset=24 (gamma exhausted) so first XORKeyStream call generates new feed.
//
// ctr_next_feed: derives new feed[0..5] from previous feed[4..5] using C1/C2:
//
//	feed[0] = feed[4] + C1
//	feed[1] = feed[5] + C2  (+ 1 if overflow)
//	feed[2] = feed[0] + C1
//	feed[3] = feed[1] + C2  (+ 1 if overflow)
//	feed[4] = feed[2] + C1
//	feed[5] = feed[3] + C2  (+ 1 if overflow)
type ctrStream struct {
	block *gostCipher
	feed  [6]uint32
	gamma [24]byte
	off   int
}

// NewCTR returns a GOST 28147-89 CTR stream cipher.
// block must be a cipher created by NewCipher or NewCipherWithSbox.
// iv must be exactly BlockSize (8) bytes.
func NewCTR(block cipher.Block, iv []byte) (cipher.Stream, error) {
	g, ok := block.(*gostCipher)
	if !ok {
		return nil, errors.New("gost28147/ctr: block must be a GOST 28147 cipher")
	}
	if len(iv) != BlockSize {
		return nil, errors.New("gost28147/ctr: IV length must equal block size (8)")
	}
	s := &ctrStream{block: g}
	s.feed[4] = binary.LittleEndian.Uint32(iv[0:])
	s.feed[5] = binary.LittleEndian.Uint32(iv[4:])
	s.block.encrypt2(&s.feed[4], &s.feed[5])
	s.off = 24
	return s, nil
}

// ctrNextFeed advances feed using GOST CTR counter increment.
func (s *ctrStream) ctrNextFeed() {
	prev4 := s.feed[4]
	prev5 := s.feed[5]

	s.feed[0] = prev4 + ctrC1
	s.feed[1] = prev5 + ctrC2
	if s.feed[1] < ctrC2 {
		s.feed[1]++
	}
	s.feed[2] = s.feed[0] + ctrC1
	s.feed[3] = s.feed[1] + ctrC2
	if s.feed[3] < ctrC2 {
		s.feed[3]++
	}
	s.feed[4] = s.feed[2] + ctrC1
	s.feed[5] = s.feed[3] + ctrC2
	if s.feed[5] < ctrC2 {
		s.feed[5]++
	}
}

// generateGamma encrypts the current feed into gamma.
func (s *ctrStream) generateGamma() {
	var tmp [6]uint32
	copy(tmp[:], s.feed[:])
	s.block.encryptWords(tmp[:])
	for i := range 6 {
		binary.LittleEndian.PutUint32(s.gamma[i*4:], tmp[i])
	}
}

func (s *ctrStream) XORKeyStream(dst, src []byte) {
	for i := range src {
		if s.off == 24 {
			s.ctrNextFeed()
			s.generateGamma()
			s.off = 0
		}
		dst[i] = src[i] ^ s.gamma[s.off]
		s.off++
	}
}

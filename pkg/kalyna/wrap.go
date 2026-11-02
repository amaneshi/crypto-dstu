package kalyna

import (
	"crypto/subtle"
	"errors"
	"slices"
)

// CMS wrap is the CMAC/CFB construction in z1273-20 section 4, not Kalyna KW.
var cmsWrapIV = []byte{
	0x69, 0x73, 0x27, 0x1d, 0x6e, 0x61, 0x1d, 0x06, 0x61, 0x67, 0x15, 0x04, 0x6c, 0x65, 0x50, 0x4c,
	0x20, 0x20, 0x00, 0x4f, 0x6d, 0x68, 0x01, 0x1f, 0x65, 0x61, 0x0c, 0x0c, 0x73, 0x73, 0x47, 0x14,
}

// WrapKey protects a 32-byte CEK using Kalyna-256 CMAC and two CFB passes.
// The supplied random IV must be 32 bytes. The returned wrapped key is 96 bytes.
func WrapKey(kek, cek, iv []byte) ([]byte, error) {
	if len(kek) != 32 || len(cek) != 32 || len(iv) != 32 {
		return nil, errors.New("kalyna: CMS wrap requires 32-byte keys and IV")
	}
	block, err := NewCipher256_256(kek)
	if err != nil {
		return nil, err
	}
	mac, err := NewCMAC(block, 32)
	if err != nil {
		return nil, err
	}
	mac.Write(cek)
	payload := make([]byte, 64)
	defer clear(payload)
	copy(payload, cek)
	copy(payload[32:], mac.MAC())
	inner, err := NewCFBEncrypter(block, iv)
	if err != nil {
		return nil, err
	}
	inner.XORKeyStream(payload, payload)
	temporary := make([]byte, 96)
	defer clear(temporary)
	copy(temporary, iv)
	copy(temporary[32:], payload)
	slices.Reverse(temporary)
	outer, err := NewCFBEncrypter(block, cmsWrapIV)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 96)
	outer.XORKeyStream(result, temporary)
	return result, nil
}

// UnwrapKey returns the CEK only after validating the full 32-byte CMAC.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != 32 || len(wrapped) != 96 {
		return nil, errors.New("kalyna: invalid CMS wrapped key length")
	}
	block, err := NewCipher256_256(kek)
	if err != nil {
		return nil, err
	}
	outer, err := NewCFBDecrypter(block, cmsWrapIV)
	if err != nil {
		return nil, err
	}
	temporary := make([]byte, 96)
	defer clear(temporary)
	outer.XORKeyStream(temporary, wrapped)
	slices.Reverse(temporary)
	inner, err := NewCFBDecrypter(block, temporary[:32])
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 64)
	defer clear(payload)
	inner.XORKeyStream(payload, temporary[32:])
	mac, err := NewCMAC(block, 32)
	if err != nil {
		return nil, err
	}
	mac.Write(payload[:32])
	if subtle.ConstantTimeCompare(mac.MAC(), payload[32:]) != 1 {
		return nil, errors.New("kalyna: CMS wrapped key integrity check failed")
	}
	return slices.Clone(payload[:32]), nil
}

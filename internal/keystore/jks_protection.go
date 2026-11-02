package keystore

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

var oidJavaKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}

func javaPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(out[2*i:], u)
	}
	clear(units)
	return out
}

// JKS requires SHA-1 here for format compatibility, not for new signatures.
func verifyJKSDigest(data []byte, password string) error {
	if len(data) < sha1.Size {
		return errors.New("keystore: JKS: missing store integrity digest")
	}
	p := javaPassword(password)
	defer clear(p)
	h := sha1.New()
	h.Write(p)
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(data[:len(data)-sha1.Size])
	digest := h.Sum(nil)
	defer clear(digest)
	if subtle.ConstantTimeCompare(digest, data[len(data)-sha1.Size:]) != 1 {
		return errors.New("keystore: JKS: wrong password or invalid store integrity")
	}
	return nil
}

func decryptJavaKey(data []byte, password string) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(data, &info)
	if err != nil || len(rest) != 0 || !info.Algorithm.Algorithm.Equal(oidJavaKeyProtector) {
		return nil, errors.New("keystore: JKS: unsupported key protection")
	}
	if len(info.EncryptedData) <= 2*sha1.Size {
		return nil, errors.New("keystore: JKS: invalid protected key length")
	}
	p := javaPassword(password)
	defer clear(p)
	encrypted := info.EncryptedData[sha1.Size : len(info.EncryptedData)-sha1.Size]
	plain := make([]byte, len(encrypted))
	digest := append([]byte(nil), info.EncryptedData[:sha1.Size]...)
	defer func() { clear(digest) }()
	for offset := 0; offset < len(encrypted); {
		h := sha1.New()
		h.Write(p)
		h.Write(digest)
		clear(digest)
		digest = h.Sum(nil)
		for _, b := range digest {
			if offset == len(encrypted) {
				break
			}
			plain[offset] = encrypted[offset] ^ b
			offset++
		}
	}
	h := sha1.New()
	h.Write(p)
	h.Write(plain)
	check := h.Sum(nil)
	defer clear(check)
	if subtle.ConstantTimeCompare(check, info.EncryptedData[len(info.EncryptedData)-sha1.Size:]) != 1 {
		clear(plain)
		return nil, errors.New("keystore: JKS: wrong key password or integrity failure")
	}
	return plain, nil
}

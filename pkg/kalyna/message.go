package kalyna

import "errors"

// EncryptCFB encrypts a complete message with Kalyna-256/256-CFB-256.
// Unlike the streaming interface, DSTU right-aligns a short final segment.
func EncryptCFB(key, iv, content []byte) ([]byte, error) {
	return cryptMessage(key, iv, content, false, true)
}

// DecryptCFB decrypts a complete Kalyna-256/256-CFB-256 message.
func DecryptCFB(key, iv, content []byte) ([]byte, error) {
	return cryptMessage(key, iv, content, true, true)
}

// CryptOFB transforms a complete Kalyna-256/256-OFB message in either direction.
func CryptOFB(key, iv, content []byte) ([]byte, error) {
	return cryptMessage(key, iv, content, false, false)
}

func cryptMessage(key, iv, content []byte, decrypt, cfb bool) ([]byte, error) {
	if len(iv) != 32 {
		return nil, errors.New("kalyna: message IV must be 32 bytes")
	}
	block, err := NewCipher256_256(key)
	if err != nil {
		return nil, err
	}
	var feedback, gamma [32]byte
	copy(feedback[:], iv)
	defer clear(feedback[:])
	defer clear(gamma[:])
	output := make([]byte, len(content))
	for offset := 0; offset < len(content); {
		block.Encrypt(gamma[:], feedback[:])
		count := min(32, len(content)-offset)
		gammaOffset := 0
		if cfb {
			gammaOffset = 32 - count
		}
		for i := 0; i < count; i++ {
			output[offset+i] = content[offset+i] ^ gamma[gammaOffset+i]
		}
		if cfb {
			if decrypt {
				copy(feedback[:], content[offset:offset+count])
			} else {
				copy(feedback[:], output[offset:offset+count])
			}
		} else {
			copy(feedback[:], gamma[:])
		}
		offset += count
	}
	return output, nil
}

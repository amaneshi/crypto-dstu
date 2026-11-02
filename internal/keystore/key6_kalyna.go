package keystore

import (
	"encoding/asn1"
	"errors"

	"github.com/amaneshi/crypto-dstu/pkg/kalyna"
)

// MarshalKey6Kalyna wraps raw PKCS#8 DER with the IIT Kupyna MAC-256 /
// Kalyna-256 CBC PBES2 profile. Callers supply fresh salt and a fresh 32-byte IV.
// Passwords are UTF-8 bytes, zero-padded to 32 bytes by the KDF; longer values
// are rejected. Work factors follow the same bounds as the reader.
func MarshalKey6Kalyna(rawKeyDER []byte, password string, salt []byte, iterations int, iv []byte) ([]byte, error) {
	if len(rawKeyDER) == 0 || len(iv) != 32 {
		return nil, errors.New("keystore: Kalyna key container requires nonempty key data and a 32-byte IV")
	}
	kdf := pbkdf2Params{
		Salt: salt, Iterations: iterations,
		PRF: algorithmIdentifier{Algorithm: oidKupynaKMAC256, Parameters: asn1.RawValue{Tag: asn1.TagNull}},
	}
	key, err := pbkdf2ForPRF([]byte(password), kdf, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	padding := 32 - len(rawKeyDER)%32
	plain := make([]byte, len(rawKeyDER)+padding)
	copy(plain, rawKeyDER)
	for i := len(rawKeyDER); i < len(plain); i++ {
		plain[i] = byte(padding)
	}
	defer clear(plain)
	block, err := kalyna.NewCipher256_256(key)
	if err != nil {
		return nil, err
	}
	mode, err := kalyna.NewCBCEncrypter(block, iv)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(plain))
	mode.CryptBlocks(encrypted, plain)
	kdfDER, err := asn1.Marshal(kdf)
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(struct{ IV []byte }{iv})
	if err != nil {
		return nil, err
	}
	parameters, err := asn1.Marshal(pbes2Params{
		KDF:       algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfDER}},
		EncScheme: algorithmIdentifier{Algorithm: oidKalyna256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: parameters}},
		EncryptedData: encrypted,
	})
}

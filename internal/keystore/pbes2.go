package keystore

import (
	"bytes"
	"encoding/asn1"
	"errors"

	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
	"github.com/amaneshi/crypto-dstu/pkg/kalyna"
)

var oidKalyna256CBC = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 3, 5, 2}

func parsePBES2Parameters(algorithm algorithmIdentifier) (pbes2Params, pbkdf2Params, error) {
	var parameters pbes2Params
	var kdf pbkdf2Params
	if !algorithm.Algorithm.Equal(oidPBES2) {
		return parameters, kdf, errors.New("keystore: unsupported encryption algorithm (expected PBES2)")
	}
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &parameters)
	canonical, marshalErr := asn1.Marshal(parameters)
	if err != nil || marshalErr != nil || len(rest) != 0 || !bytes.Equal(canonical, algorithm.Parameters.FullBytes) {
		return parameters, kdf, errors.New("keystore: invalid PBES2 parameters")
	}
	if !parameters.KDF.Algorithm.Equal(oidPBKDF2) {
		return parameters, kdf, errors.New("keystore: unsupported PBES2 KDF")
	}
	rest, err = asn1.Unmarshal(parameters.KDF.Parameters.FullBytes, &kdf)
	canonical, marshalErr = asn1.Marshal(kdf)
	if err != nil || marshalErr != nil || len(rest) != 0 || !bytes.Equal(canonical, parameters.KDF.Parameters.FullBytes) {
		return parameters, kdf, errors.New("keystore: invalid PBKDF2 parameters")
	}
	return parameters, kdf, nil
}

func decryptPBES2Data(parameters pbes2Params, kdf pbkdf2Params, encrypted, password []byte) ([]byte, error) {
	key, err := pbkdf2ForPRF(password, kdf, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if parameters.EncScheme.Algorithm.Equal(oidGost28147CFB) {
		iv, err := extractGOSTCFBIV(parameters.EncScheme)
		if err != nil {
			return nil, err
		}
		return gost28147.DecryptCFB(key, iv, encrypted)
	}
	if !parameters.EncScheme.Algorithm.Equal(oidKalyna256CBC) {
		return nil, errors.New("keystore: unsupported PBES2 cipher: " + parameters.EncScheme.Algorithm.String())
	}
	var parametersCBC struct{ IV []byte }
	rest, err := asn1.Unmarshal(parameters.EncScheme.Parameters.FullBytes, &parametersCBC)
	canonical, marshalErr := asn1.Marshal(parametersCBC)
	if err != nil || marshalErr != nil || len(rest) != 0 || len(parametersCBC.IV) != 32 || !bytes.Equal(canonical, parameters.EncScheme.Parameters.FullBytes) {
		return nil, errors.New("keystore: invalid Kalyna-256 CBC parameters")
	}
	if len(encrypted) == 0 || len(encrypted)%32 != 0 {
		return nil, errors.New("keystore: invalid Kalyna-256 CBC ciphertext length")
	}
	block, err := kalyna.NewCipher256_256(key)
	if err != nil {
		return nil, err
	}
	mode, err := kalyna.NewCBCDecrypter(block, parametersCBC.IV)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(encrypted))
	mode.CryptBlocks(plaintext, encrypted)
	// IIT PBES2 containers use PKCS#7 padding with the 32-byte block size.
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > 32 {
		clear(plaintext)
		return nil, errors.New("keystore: invalid Kalyna CBC padding")
	}
	for _, b := range plaintext[len(plaintext)-padding:] {
		if int(b) != padding {
			clear(plaintext)
			return nil, errors.New("keystore: invalid Kalyna CBC padding")
		}
	}
	clear(plaintext[len(plaintext)-padding:])
	return plaintext[:len(plaintext)-padding], nil
}

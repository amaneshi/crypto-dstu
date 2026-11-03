package keystore

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"
	"unicode/utf8"
)

var oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
var oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

type pbmac1Params struct {
	KDF algorithmIdentifier
	MAC algorithmIdentifier
}

func sha2HMAC(algorithm algorithmIdentifier) (func() hash.Hash, error) {
	if len(algorithm.Parameters.FullBytes) != 0 && !bytes.Equal(algorithm.Parameters.FullBytes, []byte{5, 0}) {
		return nil, ErrPKCS12UnsupportedMAC
	}
	switch algorithm.Algorithm.String() {
	case "1.2.840.113549.2.8":
		return sha256.New224, nil
	case "1.2.840.113549.2.9":
		return sha256.New, nil
	case "1.2.840.113549.2.10":
		return sha512.New384, nil
	case "1.2.840.113549.2.11":
		return sha512.New, nil
	default:
		return nil, ErrPKCS12UnsupportedMAC
	}
}

// RFC 9879 uses original UTF-8, without BMP conversion, normalization or a terminator.
func verifyPBMAC1(data pkcs12MacData, safe []byte, password string) error {
	if !utf8.ValidString(password) || len(password) > 4096 {
		return errors.New("keystore: PBMAC1: invalid or oversized UTF-8 password")
	}
	var parameters pbmac1Params
	rest, err := asn1.Unmarshal(data.MAC.Algorithm.Parameters.FullBytes, &parameters)
	canonical, marshalErr := asn1.Marshal(parameters)
	if err != nil || marshalErr != nil || len(rest) != 0 || !bytes.Equal(canonical, data.MAC.Algorithm.Parameters.FullBytes) {
		return errors.New("keystore: PBMAC1: invalid parameters")
	}
	if !parameters.KDF.Algorithm.Equal(oidPBKDF2) {
		return ErrPKCS12UnsupportedMAC
	}
	var kdf pbkdf2Params
	rest, err = asn1.Unmarshal(parameters.KDF.Parameters.FullBytes, &kdf)
	canonical, marshalErr = asn1.Marshal(kdf)
	if err != nil || marshalErr != nil || len(rest) != 0 || !bytes.Equal(canonical, parameters.KDF.Parameters.FullBytes) {
		return errors.New("keystore: PBMAC1: invalid PBKDF2 parameters")
	}
	prf, err := sha2HMAC(kdf.PRF)
	if err != nil {
		return err
	}
	macHash, err := sha2HMAC(parameters.MAC)
	if err != nil {
		return err
	}
	// keyLength is mandatory in RFC 9879; zero also covers a missing optional field.
	if kdf.KeyLength < 20 || kdf.KeyLength > 64 || kdf.Iterations < 1 || kdf.Iterations > 1_000_000 || len(kdf.Salt) == 0 || len(kdf.Salt) > 1024 || len(data.MAC.Digest) != macHash().Size() {
		return errors.New("keystore: PBMAC1: invalid or excessive KDF/MAC parameters")
	}
	key, err := pbkdf2.Key(prf, password, kdf.Salt, kdf.Iterations, kdf.KeyLength)
	if err != nil {
		return err
	}
	defer clear(key)
	mac := hmac.New(macHash, key)
	mac.Write(safe)
	if !hmac.Equal(data.MAC.Digest, mac.Sum(nil)) {
		return ErrPKCS12Integrity
	}
	// RFC 9879 explicitly ignores outer MacData salt/iterations for PBMAC1.
	return nil
}

func makePBMAC1(safe []byte, password string, salt []byte, iterations int) (pkcs12MacData, error) {
	data := pkcs12MacData{Salt: salt, Iterations: 1}
	aid := algorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.RawValue{Tag: asn1.TagNull}}
	kdfDER, err := asn1.Marshal(pbkdf2Params{Salt: salt, Iterations: iterations, KeyLength: 32, PRF: aid})
	if err != nil {
		return data, err
	}
	parameters, err := asn1.Marshal(pbmac1Params{KDF: algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfDER}}, MAC: aid})
	if err != nil {
		return data, err
	}
	data.MAC.Algorithm = algorithmIdentifier{Algorithm: oidPBMAC1, Parameters: asn1.RawValue{FullBytes: parameters}}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return data, err
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(safe)
	data.MAC.Digest = mac.Sum(nil)
	return data, nil
}

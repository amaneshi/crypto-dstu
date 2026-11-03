package keystore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"hash"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

var (
	ErrPKCS12MissingMAC     = errors.New("keystore: PKCS12: password integrity MAC required")
	ErrPKCS12UnsupportedMAC = errors.New("keystore: PKCS12: unsupported integrity algorithm")
	ErrPKCS12Integrity      = errors.New("keystore: PKCS12: incorrect password or integrity check failed")
)

type pkcs12MacData struct {
	MAC struct {
		Algorithm algorithmIdentifier
		Digest    []byte
	}
	Salt       []byte
	Iterations int `asn1:"optional,default:1"`
}

func pkcs12Hash(algorithm algorithmIdentifier) (func() hash.Hash, error) {
	if len(algorithm.Parameters.FullBytes) != 0 && !bytes.Equal(algorithm.Parameters.FullBytes, []byte{5, 0}) {
		return nil, ErrPKCS12UnsupportedMAC
	}
	switch algorithm.Algorithm.String() {
	case "1.2.804.2.1.1.1.1.2.1":
		return gost34311.New, nil
	case "1.2.804.2.1.1.1.1.2.2.1":
		return kupyna.New256, nil
	case "1.3.14.3.2.26":
		return sha1.New, nil // Legacy import only.
	case "2.16.840.1.101.3.4.2.4":
		return sha256.New224, nil
	case "2.16.840.1.101.3.4.2.1":
		return sha256.New, nil
	case "2.16.840.1.101.3.4.2.2":
		return sha512.New384, nil
	case "2.16.840.1.101.3.4.2.3":
		return sha512.New, nil
	default:
		return nil, ErrPKCS12UnsupportedMAC
	}
}

// RFC 7292 B.1 uses terminated UTF-16BE (BMPString). Supplementary Unicode
// characters cannot be represented by BMPString; reject instead of silently
// substituting runes or accepting a provider-specific surrogate convention.
func pkcs12Password(password string) ([]byte, error) {
	if !utf8.ValidString(password) || len(password) > 4096 {
		return nil, errors.New("keystore: PKCS12: invalid or oversized password")
	}
	result := make([]byte, 0, 2*len(password)+2)
	for _, r := range password {
		if r > 0xffff || utf16.IsSurrogate(r) {
			return nil, errors.New("keystore: PKCS12: password must contain only BMP characters")
		}
		result = binary.BigEndian.AppendUint16(result, uint16(r))
	}
	return append(result, 0, 0), nil
}

// pkcs12MACKey implements RFC 7292 B.2/B.4, diversifier ID=3, returning one
// digest-sized MAC key. Password bytes are already formatted per B.1; nil is
// reserved for the independently used historical zero-length-password encoding.
func pkcs12MACKey(newHash func() hash.Hash, password, salt []byte, iterations int) []byte {
	h := newHash()
	v := h.BlockSize()
	diversifier := bytes.Repeat([]byte{3}, v)
	repeat := func(input []byte) []byte {
		if len(input) == 0 {
			return nil
		}
		out := make([]byte, v*((len(input)+v-1)/v))
		for i := range out {
			out[i] = input[i%len(input)]
		}
		return out
	}
	material := append(repeat(salt), repeat(password)...)
	defer clear(material)
	h.Write(diversifier)
	h.Write(material)
	a := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(a)
		a = h.Sum(a[:0])
	}
	// B.2 adjustment is unnecessary here: the requested key is exactly one
	// hash output, so no second A_i block is generated.
	return a
}

func verifyPKCS12MAC(raw asn1.RawValue, authenticatedSafe []byte, password string) error {
	if len(raw.FullBytes) == 0 {
		return ErrPKCS12MissingMAC
	}
	var data pkcs12MacData
	if rest, err := asn1.Unmarshal(raw.FullBytes, &data); err != nil || len(rest) != 0 {
		return errors.New("keystore: PKCS12: malformed MAC data")
	}
	canonical, err := asn1.Marshal(data)
	if err != nil || !bytes.Equal(canonical, raw.FullBytes) {
		return errors.New("keystore: PKCS12: noncanonical MAC data")
	}
	if data.MAC.Algorithm.Algorithm.Equal(oidPBMAC1) {
		return verifyPBMAC1(data, authenticatedSafe, password)
	}
	newHash, err := pkcs12Hash(data.MAC.Algorithm)
	if err != nil {
		return err
	}
	if data.Iterations < 1 || data.Iterations > 1_000_000 || len(data.Salt) == 0 || len(data.Salt) > 1024 || len(data.MAC.Digest) != newHash().Size() {
		return errors.New("keystore: PKCS12: invalid or excessive MAC parameters")
	}
	encoded, err := pkcs12Password(password)
	if err != nil {
		return err
	}
	defer clear(encoded)
	check := func(encoded []byte) bool {
		key := pkcs12MACKey(newHash, encoded, data.Salt, data.Iterations)
		defer clear(key)
		var mac hash.Hash
		if data.MAC.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1}) {
			mac = kupyna.NewKMAC256(key)
		} else {
			mac = hmac.New(newHash, key)
		}
		mac.Write(authenticatedSafe)
		return hmac.Equal(data.MAC.Digest, mac.Sum(nil))
	}
	if check(encoded) {
		return nil
	}
	// Both encodings occur in independent PKCS#12 producers. Accept the
	// legacy zero-byte form only for an actually empty caller password, and
	// only when its MAC authenticates the complete original content.
	if password == "" && check(nil) {
		return nil
	}
	return ErrPKCS12Integrity
}

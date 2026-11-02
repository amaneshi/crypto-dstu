package keystore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

const pfxExportIterations = 10000

// MarshalPKCS12 exports DER PKCS#8 keys with matching certificates. Each key is
// independently protected by PBES2/Kupyna MAC-256 PBKDF2/Kalyna-256 CBC. A fresh
// SHA-256 password MAC authenticates the entire PFX. Certificates remain public
// discovery data; this function neither validates nor establishes their trust.
func MarshalPKCS12(rawKeys, certificates [][]byte, password string) ([]byte, error) {
	return marshalPKCS12(rawKeys, certificates, password, rand.Reader)
}

func marshalPKCS12(rawKeys, certificates [][]byte, password string, random io.Reader) ([]byte, error) {
	if len(password) == 0 || len(password) > 32 || strings.ContainsRune(password, 0) {
		return nil, errors.New("keystore: PKCS12 export: password must contain 1..32 UTF-8 bytes without NUL")
	}
	encodedPassword, err := pkcs12Password(password)
	if err != nil {
		return nil, err
	}
	defer clear(encodedPassword)
	if len(rawKeys) == 0 || len(rawKeys) > 64 || len(certificates) == 0 || len(certificates) > 512 {
		return nil, errors.New("keystore: PKCS12 export: require 1..64 keys and 1..512 certificates")
	}
	var keys []*dstu4145.PrivateKey
	var rawKeySizes []int
	total := 0
	for _, raw := range rawKeys {
		total += len(raw)
		if len(raw) == 0 || total > 8<<20 {
			return nil, errors.New("keystore: PKCS12 export: excessive key data")
		}
		parsed, err := parseRawKeys(raw)
		if err != nil {
			return nil, fmt.Errorf("keystore: PKCS12 export: invalid PKCS8: %w", err)
		}
		keys = append(keys, parsed...)
		rawKeySizes = append(rawKeySizes, len(parsed))
		if len(keys) > 64 {
			return nil, errors.New("keystore: PKCS12 export: too many private keys")
		}
	}
	var certs [][]byte
	seen := map[string]bool{}
	for _, der := range certificates {
		total += len(der)
		if total > 8<<20 {
			return nil, errors.New("keystore: PKCS12 export: excessive certificate data")
		}
		if !seen[string(der)] {
			seen[string(der)] = true
			certs = append(certs, der)
		}
	}
	if len(rawKeys)+len(certs) > 512 {
		return nil, errors.New("keystore: PKCS12 export: too many bags")
	}
	pairs, err := associatePKCS12(keys, certs)
	if err != nil {
		return nil, err
	}
	certIDs := map[string][]byte{}
	for _, pair := range pairs {
		if len(pair.Cert) == 0 {
			return nil, errors.New("keystore: PKCS12 export: each key requires a matching certificate")
		}
		id := sha256.Sum256(pair.Cert)
		certIDs[string(pair.Cert)] = id[:]
	}
	explicit := func(der []byte) asn1.RawValue { return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der} }
	attributes := func(id []byte) (asn1.RawValue, error) {
		if len(id) == 0 {
			return asn1.RawValue{}, nil
		}
		value, err := asn1.Marshal(id)
		if err != nil {
			return asn1.RawValue{}, err
		}
		der, err := asn1.MarshalWithParams([]keyAttribute{{
			OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}, Values: []asn1.RawValue{{FullBytes: value}},
		}}, "set")
		return asn1.RawValue{FullBytes: der}, err
	}
	var bags []safeBag
	pairIndex := 0
	for i, raw := range rawKeys {
		salt, iv := make([]byte, 32), make([]byte, 32)
		if _, err = io.ReadFull(random, salt); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(random, iv); err != nil {
			return nil, err
		}
		protected, err := MarshalKey6Kalyna(raw, password, salt, pfxExportIterations, iv)
		if err != nil {
			return nil, err
		}
		// A PKCS#8 key carrying IIT's second agreement key has one bag but
		// multiple certificate matches. Do not invent a one-to-one localKeyId.
		var attrs asn1.RawValue
		if rawKeySizes[i] == 1 {
			attrs, err = attributes(certIDs[string(pairs[pairIndex].Cert)])
			if err != nil {
				return nil, err
			}
		}
		bags = append(bags, safeBag{BagID: oidPKCS8ShroudedKeyBag, BagValue: explicit(protected), BagAttrs: attrs})
		pairIndex += rawKeySizes[i]
	}
	for _, der := range certs {
		octets, err := asn1.Marshal(der)
		if err != nil {
			return nil, err
		}
		certificateBag, err := asn1.Marshal(struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue
		}{oidX509Certificate, explicit(octets)})
		if err != nil {
			return nil, err
		}
		attrs, err := attributes(certIDs[string(der)])
		if err != nil {
			return nil, err
		}
		bags = append(bags, safeBag{BagID: oidCertBag, BagValue: explicit(certificateBag), BagAttrs: attrs})
	}
	contents, err := asn1.Marshal(bags)
	if err != nil {
		return nil, err
	}
	octets, err := asn1.Marshal(contents)
	if err != nil {
		return nil, err
	}
	safe, err := asn1.Marshal([]contentInfo{{ContentType: oidDataContentType, Content: explicit(octets)}})
	if err != nil {
		return nil, err
	}
	mac := pkcs12MacData{Salt: make([]byte, 32), Iterations: pfxExportIterations}
	if _, err = io.ReadFull(random, mac.Salt); err != nil {
		return nil, err
	}
	mac.MAC.Algorithm = algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.RawValue{Tag: asn1.TagNull}}
	macKey := pkcs12MACKey(sha256.New, encodedPassword, mac.Salt, mac.Iterations)
	defer clear(macKey)
	authenticator := hmac.New(sha256.New, macKey)
	authenticator.Write(safe)
	mac.MAC.Digest = authenticator.Sum(nil)
	macDER, err := asn1.Marshal(mac)
	if err != nil {
		return nil, err
	}
	safeOctets, err := asn1.Marshal(safe)
	if err != nil {
		return nil, err
	}
	pfx, err := asn1.Marshal(pfxASN{Version: 3, AuthSafe: contentInfo{ContentType: oidDataContentType, Content: explicit(safeOctets)}, MacData: asn1.RawValue{FullBytes: macDER}})
	if err != nil {
		return nil, err
	}
	if len(pfx) > 16<<20 {
		return nil, errors.New("keystore: PKCS12 export: container too large")
	}
	return pfx, nil
}

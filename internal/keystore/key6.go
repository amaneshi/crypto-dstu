package keystore

import (
	"bytes"
	"crypto/sha1"

	"encoding/asn1"
	"errors"

	"crypto-dstu/pkg/dstu4145"
	"crypto-dstu/pkg/gost28147"
	"crypto-dstu/pkg/gost34311"
	"crypto-dstu/pkg/kupyna"
)

// OIDs used in Key-6.dat / PKCS#8 encrypted containers (Ukrainian PKI profile).
// Source: cryptonite storage_errors.h, pkcs5.c, and Ukrainian PKI OID registry.
var (
	// PBES2 (RFC 2898).
	oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

	// PBKDF2 (RFC 2898).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// Kupyna MAC-256 and HMAC-GOST34311 PBKDF2 PRF identifiers.
	oidKupynaKMAC256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 4}
	oidHMACGost34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 2}

	// cryptonite OID_GOST28147_CFB_ID (the mode-specific identifier).
	oidGost28147CFB = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}
)

// EncryptedPrivateKeyInfo is the outer PKCS#8 encrypted container structure.
//
//	EncryptedPrivateKeyInfo ::= SEQUENCE {
//	    encryptionAlgorithm  AlgorithmIdentifier,
//	    encryptedData        OCTET STRING
//	}
type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// pbes2Params holds the PBES2 parameters: KDF + encryption scheme.
//
//	PBES2-params ::= SEQUENCE {
//	    keyDerivationFunc  AlgorithmIdentifier,
//	    encryptionScheme   AlgorithmIdentifier
//	}
type pbes2Params struct {
	KDF       algorithmIdentifier
	EncScheme algorithmIdentifier
}

// pbkdf2Params holds PBKDF2 parameters.
//
//	PBKDF2-params ::= SEQUENCE {
//	    salt           OCTET STRING,
//	    iterationCount INTEGER,
//	    prf            AlgorithmIdentifier OPTIONAL
//	}
type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

// ParseKey6 parses and decrypts a Key-6.dat (PBES2-encrypted PKCS#8) container.
// Supports the legacy HMAC-GOST34311/GOST28147-CFB profile and the IIT
// Kupyna MAC-256/Kalyna-256-CBC profile. The latter uses a zero-padded
// password of at most 32 bytes and strict PKCS#7 padding.
func ParseKey6(data []byte, password string) (*dstu4145.PrivateKey, error) {
	// Strip PEM / base64 if needed
	data = MaybePEM(data)
	data = MaybeBase64(data)

	var epki encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(data, &epki)
	if err != nil {
		return nil, errors.New("keystore: Key6: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("keystore: Key6: trailing data in container")
	}

	p2, kdfP, err := parsePBES2Parameters(epki.Algorithm)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptPBES2Data(p2, kdfP, epki.EncryptedData, []byte(password))
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	// Parse decrypted bytes as unencrypted PrivateKeyInfo
	priv, err := ParseRawKey(plaintext)
	if err != nil {
		return nil, errors.New("keystore: Key6: inner key: " + err.Error())
	}
	return priv, nil
}

// extractGOSTCFBIV extracts the 8-byte IV from a GOST 28147 CFB AlgorithmIdentifier.
// The parameters field is typically an OCTET STRING containing the IV directly,
// or a SEQUENCE { OCTET STRING iv }.
func extractGOSTCFBIV(aid algorithmIdentifier) ([]byte, error) {
	if !aid.Algorithm.Equal(oidGost28147CFB) {
		return nil, errors.New("unsupported GOST cipher mode")
	}
	if len(aid.Parameters.FullBytes) == 0 {
		return nil, errors.New("missing GOST CFB parameters")
	}

	// Try: raw OCTET STRING
	var iv []byte
	if rest, err := asn1.Unmarshal(aid.Parameters.FullBytes, &iv); err == nil && len(rest) == 0 && len(iv) == 8 {
		return iv, nil
	}

	// Try: SEQUENCE { OCTET STRING }
	var seq struct {
		IV  []byte
		DKE []byte `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(aid.Parameters.FullBytes, &seq); err == nil && len(rest) == 0 && len(seq.IV) == 8 {
		if len(seq.DKE) != 0 && !bytes.Equal(seq.DKE, gost28147.SboxDSTU.Packed()) {
			return nil, errors.New("unsupported GOST cipher DKE")
		}
		return seq.IV, nil
	}

	return nil, errors.New("cannot extract 8-byte IV from GOST CFB params")
}

// pbkdf2GOST implements PBKDF2 (RFC 2898) using either HMAC-GOST34311 or HMAC-SHA1.
// Matches cryptonite pbkdf2_f() in pkcs5.c.
//
// For HMAC-GOST34311 (Ukrainian profile): uses gost34311.New as the PRF's hash,
// with an HMAC construction over the GOST 34.311-95 hash (zero sync vector, DSTU sbox).
func pbkdf2GOST(password, salt []byte, iterations, keyLen int, useGOST bool) ([]byte, error) {
	if useGOST {
		return pbkdf2WithHMAC(password, salt, iterations, keyLen, hmacGost34311)
	}
	return pbkdf2WithHMAC(password, salt, iterations, keyLen, hmacSHA1)
}

// pbkdf2WithHMAC is a generic PBKDF2 implementation using a supplied HMAC function.
// F(P, S, c, i) = U1 ⊕ U2 ⊕ ... ⊕ Uc
// where U1 = HMAC(P, S || INT(i)), Uj = HMAC(P, U_{j-1}).
func pbkdf2WithHMAC(
	password, salt []byte,
	iterations, keyLen int,
	hmacFn func(key, data []byte) []byte,
) ([]byte, error) {
	if iterations < 1 || keyLen < 1 {
		return nil, errors.New("keystore: invalid PBKDF2 parameters")
	}
	dk := make([]byte, 0, keyLen)
	salted := make([]byte, len(salt)+4)
	copy(salted, salt)
	block := 1
	for len(dk) < keyLen {
		// U1 = HMAC(password, salt || block_counter_BE)
		counter := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		copy(salted[len(salt):], counter)
		u := hmacFn(password, salted)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			u = hmacFn(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
		block++
	}
	return dk[:keyLen], nil
}

// hmacGost34311 computes HMAC-GOST34311 using a zero sync vector and DSTU sbox.
// Matches cryptonite hmac_alloc_gost34_311(GOST28147_SBOX_ID_1, zero_iv).
// HMAC construction: H((K ⊕ opad) || H((K ⊕ ipad) || data))
// Block size for GOST 34.311 = 32 bytes.
func hmacGost34311(key, data []byte) []byte {
	const blockSize = 32

	// Shorten key if longer than block size
	if len(key) > blockSize {
		h := gost34311.New()
		h.Write(key)
		key = h.Sum(nil)
	}

	// Pad key to block size
	k := make([]byte, blockSize)
	copy(k, key)

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := range blockSize {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}

	// inner = H(ipad || data)
	inner := gost34311.New()
	_, _ = inner.Write(ipad)
	_, _ = inner.Write(data)
	innerSum := inner.Sum(nil)

	// outer = H(opad || inner)
	outer := gost34311.New()
	outer.Write(opad)
	outer.Write(innerSum)
	return outer.Sum(nil)
}

// MarshalKey6 encrypts a raw PKCS#8 DER private key into a Key-6.dat
// (PBES2 EncryptedPrivateKeyInfo) container using PBKDF2-HMAC-GOST34311 + GOST28147-CFB.
// salt must be nonempty; iv must be 8 bytes (GOST 28147 block size).
func MarshalKey6(rawKeyDER []byte, password string, salt []byte, iterations int, iv []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("keystore: MarshalKey6: salt is empty")
	}
	if len(iv) != 8 {
		return nil, errors.New("keystore: MarshalKey6: IV must be 8 bytes")
	}

	// Derive 32-byte key
	dk, err := pbkdf2GOST([]byte(password), salt, iterations, 32, true)
	if err != nil {
		return nil, err
	}

	// Encrypt with GOST28147 CFB
	encrypted, err := gost28147.EncryptCFB(dk, iv, rawKeyDER)
	if err != nil {
		return nil, err
	}

	// Ukrainian GOST28147Params carries both IV and the packed S-box (DKE).
	ivDER, err := asn1.Marshal(struct{ IV, DKE []byte }{iv, gost28147.SboxDSTU.Packed()})
	if err != nil {
		return nil, err
	}

	// Build PBKDF2-params
	prfAID := algorithmIdentifier{Algorithm: oidHMACGost34311, Parameters: asn1.RawValue{Tag: asn1.TagNull}}
	prfDER, err := asn1.Marshal(prfAID)
	if err != nil {
		return nil, err
	}

	kdfParamsDER, err := asn1.Marshal(struct {
		Salt       []byte
		Iterations int
		PRF        asn1.RawValue
	}{
		Salt:       salt,
		Iterations: iterations,
		PRF:        asn1.RawValue{FullBytes: prfDER},
	})
	if err != nil {
		return nil, err
	}

	// Build PBES2-params
	p2, err := asn1.Marshal(pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParamsDER},
		},
		EncScheme: algorithmIdentifier{
			Algorithm:  oidGost28147CFB,
			Parameters: asn1.RawValue{FullBytes: ivDER},
		},
	})
	if err != nil {
		return nil, err
	}

	epki := encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2},
		},
		EncryptedData: encrypted,
	}
	return asn1.Marshal(epki)
}

// hmacSHA1 computes HMAC-SHA1 (used as default PRF when prf is absent/SHA1).
func hmacSHA1(key, data []byte) []byte {
	const blockSize = 64
	if len(key) > blockSize {
		h := sha1.Sum(key)
		key = h[:]
	}
	k := make([]byte, blockSize)
	copy(k, key)
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := range blockSize {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	innerArr := sha1.Sum(append(append([]byte(nil), ipad...), data...))
	outerArr := sha1.Sum(append(append([]byte(nil), opad...), innerArr[:]...))
	return outerArr[:]
}

// pbkdf2ForPRF dispatches the declared PRF. Kupyna MAC is the DSTU 7564
// keyed construction with a zero-padded 32-byte password, not HMAC.
func pbkdf2ForPRF(password []byte, parameters pbkdf2Params, length int) ([]byte, error) {
	if parameters.Iterations < 1 || parameters.Iterations > 1_000_000 || len(parameters.Salt) == 0 {
		return nil, errors.New("keystore: unsupported PBKDF2 work factor or salt")
	}
	if parameters.KeyLength != 0 && parameters.KeyLength != length {
		return nil, errors.New("keystore: PBKDF2 key length does not match cipher")
	}
	p := parameters.PRF
	if len(p.Parameters.FullBytes) > 0 && !bytes.Equal(p.Parameters.FullBytes, []byte{5, 0}) {
		return nil, errors.New("keystore: unsupported PBKDF2 PRF parameters")
	}
	var prf func([]byte, []byte) []byte
	switch {
	case p.Algorithm.Equal(oidHMACGost34311):
		prf = hmacGost34311
	case p.Algorithm.Equal(oidKupynaKMAC256):
		if len(password) > 32 {
			return nil, errors.New("keystore: KMAC256 password exceeds supported 32-byte profile")
		}
		prf = func(key, data []byte) []byte {
			padded := make([]byte, 32)
			copy(padded, key)
			defer clear(padded)
			h := kupyna.NewKMAC256(padded)
			h.Write(data)
			return h.Sum(nil)
		}
	case len(p.Algorithm) == 0 || p.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}):
		prf = hmacSHA1
	default:
		return nil, errors.New("keystore: unsupported PBKDF2 PRF: " + p.Algorithm.String())
	}
	return pbkdf2WithHMAC(password, parameters.Salt, parameters.Iterations, length, prf)
}

package keystore

import (
	"crypto/sha1"
	"encoding/asn1"
	"errors"

	"crypto-dstu/dstu4145"
	"crypto-dstu/gost28147"
	"crypto-dstu/gost34311"
)

// OIDs used in Key-6.dat / PKCS#8 encrypted containers (Ukrainian PKI profile).
// Source: cryptonite storage_errors.h, pkcs5.c, and Ukrainian PKI OID registry.
var (
	// PBES2 (RFC 2898).
	oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

	// PBKDF2 (RFC 2898).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// HMAC-GOST34311 PRF OID used in Ukrainian PBKDF2
	// cryptonite: OID_PKI_HMAC_GOST3411_ID → 1.2.804.2.1.1.1.1.1.1.4
	oidHMACGost34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 4}

	// GOST 28147-89 CFB (Ukrainian variant) — parent OID for all CFB mode variants
	// cryptonite: OID_GOST28147_DSTU_ID → 1.2.804.2.1.1.1.1.1.1.1
	oidGost28147CFB = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 1}
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
	PRF        algorithmIdentifier `asn1:"optional"`
}

// ParseKey6 parses and decrypts a Key-6.dat (PBES2-encrypted PKCS#8) container.
// Matches cryptonite pkcs5_decrypt_dstu():
//  1. Parse outer EncryptedPrivateKeyInfo — verify algorithm = PBES2
//  2. Parse PBES2-params → extract PBKDF2 KDF params + GOST28147 encryption params
//  3. Derive 32-byte key: PBKDF2(HMAC-GOST34311, password, salt, iterations)
//  4. Decrypt with GOST28147 CFB
//  5. Parse decrypted bytes as unencrypted PKCS#8 PrivateKeyInfo
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

	if !epki.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New(
			"keystore: Key6: unsupported encryption algorithm (expected PBES2): " + epki.Algorithm.Algorithm.String(),
		)
	}

	// Parse PBES2-params from AlgorithmIdentifier.parameters
	var p2 pbes2Params
	_, err = asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &p2)
	if err != nil {
		return nil, errors.New("keystore: Key6: PBES2-params: " + err.Error())
	}

	if !p2.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("keystore: Key6: unsupported KDF (expected PBKDF2): " + p2.KDF.Algorithm.String())
	}

	// Parse PBKDF2-params
	var kdfP pbkdf2Params
	_, err = asn1.Unmarshal(p2.KDF.Parameters.FullBytes, &kdfP)
	if err != nil {
		return nil, errors.New("keystore: Key6: PBKDF2-params: " + err.Error())
	}
	if kdfP.Iterations < 1 {
		return nil, errors.New("keystore: Key6: invalid iteration count")
	}

	// Determine PRF: HMAC-GOST34311 (Ukrainian) or default SHA1
	useGOST := kdfP.PRF.Algorithm.Equal(oidHMACGost34311)
	if !useGOST && len(kdfP.PRF.Algorithm) > 0 {
		// Unsupported PRF
		return nil, errors.New("keystore: Key6: unsupported PBKDF2 PRF: " + kdfP.PRF.Algorithm.String())
	}

	// Derive 32-byte key
	dk, err := pbkdf2GOST([]byte(password), kdfP.Salt, kdfP.Iterations, 32, useGOST)
	if err != nil {
		return nil, errors.New("keystore: Key6: PBKDF2: " + err.Error())
	}

	// Extract IV from encryption scheme parameters.
	// GOST28147 CFB parameters carry the IV as an OCTET STRING (8 bytes).
	iv, err := extractGOSTCFBIV(p2.EncScheme)
	if err != nil {
		return nil, errors.New("keystore: Key6: IV: " + err.Error())
	}

	// Decrypt with GOST28147 CFB
	plaintext, err := gost28147.DecryptCFB(dk, iv, epki.EncryptedData)
	if err != nil {
		return nil, errors.New("keystore: Key6: decrypt: " + err.Error())
	}

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
	if len(aid.Parameters.FullBytes) == 0 {
		return nil, errors.New("missing GOST CFB parameters")
	}

	// Try: raw OCTET STRING
	var iv []byte
	if _, err := asn1.Unmarshal(aid.Parameters.FullBytes, &iv); err == nil && len(iv) == 8 {
		return iv, nil
	}

	// Try: SEQUENCE { OCTET STRING }
	var seq struct {
		IV []byte
	}
	if _, err := asn1.Unmarshal(aid.Parameters.FullBytes, &seq); err == nil && len(seq.IV) == 8 {
		return seq.IV, nil
	}

	// Try: parameters bytes directly (some encodings embed IV as raw bytes)
	raw := aid.Parameters.Bytes
	if len(raw) == 8 {
		return raw, nil
	}
	// Try nested SEQUENCE inside the tag
	if len(raw) > 2 && raw[0] == 0x04 {
		ivLen := int(raw[1])
		if ivLen == 8 && len(raw) >= 10 {
			return raw[2:10], nil
		}
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
	hashLen := len(hmacFn(password, salt))
	dk := make([]byte, 0, keyLen)
	block := 1
	for len(dk) < keyLen {
		// U1 = HMAC(password, salt || block_counter_BE)
		counter := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		u := hmacFn(password, append(salt, counter...))
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
		_ = hashLen
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
// salt must be 8 bytes, iv must be 8 bytes (GOST 28147 block size).
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

	// Build GOST28147 CFB AlgorithmIdentifier: parameters = OCTET STRING(iv)
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	// Build PBKDF2-params
	prfAID := algorithmIdentifier{Algorithm: oidHMACGost34311}
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

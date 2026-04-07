package keystore

import (
	"encoding/asn1"
	"errors"

	"crypto-dstu/dstu4145"
	"crypto-dstu/gost28147"
)

// PKCS#12 / PFX OIDs.
var (
	// PFX contentType OIDs.
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	// SafeBag OIDs.
	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}

	// CertBag type OID.
	oidX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// KeyCertPair groups a private key with its associated certificate chain.
type KeyCertPair struct {
	PrivateKey *dstu4145.PrivateKey
	Cert       []byte   // DER-encoded leaf certificate
	CertChain  [][]byte // DER-encoded intermediate + root certs
}

// pfxASN is the outer PFX structure.
//
//	PFX ::= SEQUENCE {
//	    version    INTEGER (3),
//	    authSafe   ContentInfo,
//	    macData    MacData OPTIONAL
//	}
type pfxASN struct {
	Version  int
	AuthSafe contentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType         asn1.ObjectIdentifier
	ContentEncAlgorithm algorithmIdentifier
	EncryptedContent    asn1.RawValue `asn1:"implicit,tag:0,optional"`
}

type safeBag struct {
	BagID    asn1.ObjectIdentifier
	BagValue asn1.RawValue `asn1:"explicit,tag:0"`
	BagAttrs asn1.RawValue `asn1:"set,optional"`
}

// ParsePKCS12 parses a PKCS#12 / PFX container and returns key+cert pairs.
// Handles both plain-data and encrypted-data content (GOST or AES/3DES encrypted).
// For encrypted content, password is used via PBES2 / PBKDF2.
//
// Reference: cryptonite src/storage/c/file/pkcs12.c.
func ParsePKCS12(data []byte, password string) ([]*KeyCertPair, error) {
	data = MaybePEM(data)

	var pfx pfxASN
	if rest, err := asn1.Unmarshal(data, &pfx); err != nil {
		return nil, errors.New("keystore: PKCS12: " + err.Error())
	} else if len(rest) != 0 {
		return nil, errors.New("keystore: PKCS12: trailing data")
	}
	if pfx.Version != 3 {
		return nil, errors.New("keystore: PKCS12: unsupported version")
	}

	// authSafe content must be Data (plain) or EncryptedData
	safes, err := parseAuthSafe(pfx.AuthSafe, password)
	if err != nil {
		return nil, err
	}

	// Collect all SafeBags from all ContentInfos
	var keys []*dstu4145.PrivateKey
	var certs [][]byte

	var ks []*dstu4145.PrivateKey
	var cs [][]byte
	for _, safe := range safes {
		ks, cs, err = parseSafeBags(safe, password)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ks...)
		certs = append(certs, cs...)
	}

	if len(keys) == 0 {
		return nil, errors.New("keystore: PKCS12: no private keys found")
	}

	// Pair each key with a cert (by index; detailed matching requires cert parsing)
	pairs := make([]*KeyCertPair, len(keys))
	for i, k := range keys {
		pair := &KeyCertPair{PrivateKey: k}
		if i < len(certs) {
			pair.Cert = certs[i]
		}
		if len(certs) > len(keys) {
			pair.CertChain = certs[len(keys):]
		}
		pairs[i] = pair
	}
	return pairs, nil
}

// parseAuthSafe returns the DER bytes of each inner SafeContents.
func parseAuthSafe(ci contentInfo, password string) ([][]byte, error) {
	if !ci.ContentType.Equal(oidDataContentType) {
		return nil, errors.New("keystore: PKCS12: authSafe is not Data ContentInfo")
	}

	// The Content is [0] EXPLICIT OCTET STRING containing an OCTET STRING
	var outer []byte
	var err error
	_, err = asn1.Unmarshal(ci.Content.Bytes, &outer)
	if err != nil {
		return nil, errors.New("keystore: PKCS12: authSafe content: " + err.Error())
	}

	// outer is a DER SEQUENCE OF ContentInfo
	var safeContents []contentInfo
	_, err = asn1.Unmarshal(outer, &safeContents)
	if err != nil {
		return nil, errors.New("keystore: PKCS12: AuthenticatedSafe: " + err.Error())
	}

	result := make([][]byte, 0, len(safeContents))
	var plain []byte
	for _, sc := range safeContents {
		switch {
		case sc.ContentType.Equal(oidDataContentType):
			_, err = asn1.Unmarshal(sc.Content.Bytes, &plain)
			if err != nil {
				return nil, errors.New("keystore: PKCS12: SafeContents Data: " + err.Error())
			}
			result = append(result, plain)

		case sc.ContentType.Equal(oidEncryptedDataContentType):
			plain, err = decryptPKCS12Content(sc.Content.Bytes, password)
			if err != nil {
				return nil, err
			}
			result = append(result, plain)

		default:
			// skip unknown ContentInfo types
		}
	}
	return result, nil
}

// decryptPKCS12Content decrypts an EncryptedData ContentInfo.
func decryptPKCS12Content(rawContent []byte, password string) ([]byte, error) {
	var ed encryptedData
	var err error
	_, err = asn1.Unmarshal(rawContent, &ed)
	if err != nil {
		return nil, errors.New("keystore: PKCS12: EncryptedData: " + err.Error())
	}

	enc := ed.EncryptedContentInfo.EncryptedContent.Bytes
	if len(enc) == 0 {
		return nil, errors.New("keystore: PKCS12: empty encrypted content")
	}

	// Build a minimal EncryptedPrivateKeyInfo wrapper to reuse ParseKey6 logic
	// by constructing the equivalent EPKI structure.
	epki := encryptedPrivateKeyInfo{
		Algorithm:     ed.EncryptedContentInfo.ContentEncAlgorithm,
		EncryptedData: enc,
	}
	epkiDER, err := asn1.Marshal(epki)
	if err != nil {
		return nil, errors.New("keystore: PKCS12: re-encode EPKI: " + err.Error())
	}

	// Attempt PBES2 decryption
	var outer encryptedPrivateKeyInfo
	var rest []byte
	rest, err = asn1.Unmarshal(epkiDER, &outer)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: PKCS12: EPKI roundtrip failed")
	}

	return decryptEPKI(outer, password)
}

// decryptEPKI decrypts an encryptedPrivateKeyInfo returning raw plaintext bytes.
func decryptEPKI(epki encryptedPrivateKeyInfo, password string) ([]byte, error) {
	if !epki.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("keystore: PKCS12: unsupported encryption: " + epki.Algorithm.Algorithm.String())
	}

	var p2 pbes2Params
	if _, err := asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &p2); err != nil {
		return nil, errors.New("keystore: PKCS12: PBES2-params: " + err.Error())
	}
	if !p2.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("keystore: PKCS12: unsupported KDF: " + p2.KDF.Algorithm.String())
	}

	var kdfP pbkdf2Params
	if _, err := asn1.Unmarshal(p2.KDF.Parameters.FullBytes, &kdfP); err != nil {
		return nil, errors.New("keystore: PKCS12: PBKDF2-params: " + err.Error())
	}

	useGOST := kdfP.PRF.Algorithm.Equal(oidHMACGost34311)
	dk, err := pbkdf2GOST([]byte(password), kdfP.Salt, kdfP.Iterations, 32, useGOST)
	if err != nil {
		return nil, err
	}

	iv, err := extractGOSTCFBIV(p2.EncScheme)
	if err != nil {
		return nil, errors.New("keystore: PKCS12: IV: " + err.Error())
	}

	return gost28147.DecryptCFB(dk, iv, epki.EncryptedData)
}

// parseSafeBags parses a DER-encoded SafeContents (SEQUENCE OF SafeBag).
func parseSafeBags(der []byte, password string) ([]*dstu4145.PrivateKey, [][]byte, error) {
	var bags []safeBag
	if _, err := asn1.Unmarshal(der, &bags); err != nil {
		return nil, nil, errors.New("keystore: PKCS12: SafeContents: " + err.Error())
	}

	var keys []*dstu4145.PrivateKey
	var certs [][]byte

	for _, bag := range bags {
		switch {
		case bag.BagID.Equal(oidKeyBag):
			// Unencrypted PrivateKeyInfo
			priv, err := ParseRawKey(bag.BagValue.Bytes)
			if err == nil {
				keys = append(keys, priv)
			}

		case bag.BagID.Equal(oidPKCS8ShroudedKeyBag):
			// Encrypted PrivateKeyInfo — parse as Key6 format
			priv, err := ParseKey6(bag.BagValue.Bytes, password)
			if err == nil {
				keys = append(keys, priv)
			}

		case bag.BagID.Equal(oidCertBag):
			cert, err := parseCertBag(bag.BagValue.Bytes)
			if err == nil && cert != nil {
				certs = append(certs, cert)
			}
		}
	}
	return keys, certs, nil
}

// parseCertBag extracts the DER-encoded certificate from a CertBag.
//
//	CertBag ::= SEQUENCE {
//	    certId   BAG-TYPE.&id,
//	    certValue [0] EXPLICIT BAG-TYPE.&Type
//	}
func parseCertBag(der []byte) ([]byte, error) {
	var cb struct {
		CertID    asn1.ObjectIdentifier
		CertValue asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &cb); err != nil {
		return nil, err
	}
	if !cb.CertID.Equal(oidX509Certificate) {
		return nil, nil
	}
	// CertValue is an OCTET STRING containing the DER cert
	var cert []byte
	if _, err := asn1.Unmarshal(cb.CertValue.Bytes, &cert); err != nil {
		return nil, err
	}
	return cert, nil
}

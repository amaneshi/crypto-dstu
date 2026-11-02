package keystore

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"slices"
	"strings"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
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
	CertChain  [][]byte // Additional unmatched certificates for discovery; not a validated chain.
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

// Identify a PFX envelope before format guessing can obscure its integrity
// error. Do not reinterpret a recognized but invalid PFX as another key format.
func looksLikePKCS12(data []byte) bool {
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &fields); err != nil || len(fields) < 2 {
		return false
	}
	var version int
	if _, err := asn1.Unmarshal(fields[0].FullBytes, &version); err != nil || version != 3 {
		return false
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(fields[1].FullBytes, &ci); err != nil {
		return false
	}
	return strings.HasPrefix(ci.ContentType.String(), "1.2.840.113549.1.7.")
}

// ParsePKCS12 parses a PKCS#12 / PFX container and returns key+cert pairs.
// Requires a supported password-integrity MAC before decrypting/importing any
// bags. SignedData integrity and missing/unsupported MACs fail closed. Privacy
// uses the supported PBES2 profiles; certificates are associated by public key.
//
// Reference: cryptonite src/storage/c/file/pkcs12.c.
func ParsePKCS12(data []byte, password string) ([]*KeyCertPair, error) {
	if len(data) > 16<<20 {
		return nil, errors.New("keystore: PKCS12: container too large")
	}
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
	canonical, err := asn1.Marshal(pfx)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, errors.New("keystore: PKCS12: noncanonical PFX")
	}
	authenticatedSafe, err := pkcs12AuthenticatedSafe(pfx.AuthSafe)
	if err != nil {
		return nil, err
	}
	if err = verifyPKCS12MAC(pfx.MacData, authenticatedSafe, password); err != nil {
		return nil, err
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
		if len(keys) > 64 || len(certs) > 512 {
			return nil, errors.New("keystore: PKCS12: too many keys or certificates")
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("keystore: PKCS12: no private keys found")
	}

	return associatePKCS12(keys, certs)
}

func associatePKCS12(keys []*dstu4145.PrivateKey, certificates [][]byte) ([]*KeyCertPair, error) {
	var parsed []*cert.Certificate
	unique := map[string]bool{}
	for _, der := range certificates {
		if unique[string(der)] {
			continue
		}
		unique[string(der)] = true
		c, err := cert.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("keystore: PKCS12: malformed certificate")
		}
		parsed = append(parsed, c)
	}
	pairs := make([]*KeyCertPair, len(keys))
	used := make(map[*cert.Certificate]bool)
	for i, key := range keys {
		for _, earlier := range keys[:i] {
			if samePKCS12Domain(key, earlier) && key.D.Cmp(earlier.D) == 0 {
				return nil, errors.New("keystore: PKCS12: duplicate private key")
			}
		}
		pair := &KeyCertPair{PrivateKey: key}
		pub := key.Public()
		for _, c := range parsed {
			if c.PublicKey == nil || c.PublicKey.Q == nil || !samePKCS12Curves(key.Curve, c.PublicKey.Curve) ||
				!pub.Q.X.Equal(c.PublicKey.Q.X) || !pub.Q.Y.Equal(c.PublicKey.Q.Y) {
				continue
			}
			if pair.Cert != nil {
				return nil, errors.New("keystore: PKCS12: ambiguous certificates for private key")
			}
			pair.Cert = bytes.Clone(c.Raw)
			used[c] = true
		}
		pairs[i] = pair
	}
	for _, pair := range pairs {
		for _, c := range parsed {
			if !used[c] {
				pair.CertChain = append(pair.CertChain, bytes.Clone(c.Raw))
			}
		}
	}
	return pairs, nil
}

func samePKCS12Domain(a, b *dstu4145.PrivateKey) bool { return samePKCS12Curves(a.Curve, b.Curve) }
func samePKCS12Curves(a, b *ec.Curve) bool {
	return a != nil && b != nil && a.M == b.M && a.Cofactor == b.Cofactor && slices.Equal(a.ModBits, b.ModBits) &&
		a.A.Equal(b.A) && a.B.Equal(b.B) && bytes.Equal(a.N, b.N) && a.Gx.Equal(b.Gx) && a.Gy.Equal(b.Gy)
}

func pkcs12AuthenticatedSafe(ci contentInfo) ([]byte, error) {
	if !ci.ContentType.Equal(oidDataContentType) {
		return nil, ErrPKCS12UnsupportedMAC
	}
	if ci.Content.Class != 2 || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return nil, errors.New("keystore: PKCS12: invalid explicit content")
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &octets); err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: PKCS12: invalid authenticated content")
	}
	return octets, nil
}

// parseAuthSafe returns the DER bytes of each inner SafeContents.
func parseAuthSafe(ci contentInfo, password string) ([][]byte, error) {
	outer, err := pkcs12AuthenticatedSafe(ci)
	if err != nil {
		return nil, err
	}

	// outer is a DER SEQUENCE OF ContentInfo
	var safeContents []contentInfo
	rest, err := asn1.Unmarshal(outer, &safeContents)
	if err != nil || len(rest) != 0 || len(safeContents) > 64 {
		return nil, errors.New("keystore: PKCS12: malformed or excessive AuthenticatedSafe")
	}

	result := make([][]byte, 0, len(safeContents))
	var plain []byte
	for _, sc := range safeContents {
		switch {
		case sc.ContentType.Equal(oidDataContentType):
			plain, err = pkcs12AuthenticatedSafe(sc)
			if err != nil {
				return nil, err
			}
			result = append(result, plain)

		case sc.ContentType.Equal(oidEncryptedDataContentType):
			plain, err = decryptPKCS12Content(sc.Content.Bytes, password)
			if err != nil {
				return nil, err
			}
			result = append(result, plain)

		default:
			return nil, errors.New("keystore: PKCS12: unsupported safe content type")
		}
	}
	return result, nil
}

// decryptPKCS12Content decrypts an EncryptedData ContentInfo.
func decryptPKCS12Content(rawContent []byte, password string) ([]byte, error) {
	var ed encryptedData
	var err error
	rest, err := asn1.Unmarshal(rawContent, &ed)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: PKCS12: malformed EncryptedData")
	}
	if ed.Version != 0 || !ed.EncryptedContentInfo.ContentType.Equal(oidDataContentType) ||
		ed.EncryptedContentInfo.EncryptedContent.Class != 2 || ed.EncryptedContentInfo.EncryptedContent.Tag != 0 ||
		ed.EncryptedContentInfo.EncryptedContent.IsCompound {
		return nil, errors.New("keystore: PKCS12: unsupported encrypted content")
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
	rest, err = asn1.Unmarshal(epkiDER, &outer)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: PKCS12: EPKI roundtrip failed")
	}

	return decryptEPKI(outer, password)
}

// decryptEPKI decrypts an encryptedPrivateKeyInfo returning raw plaintext bytes.
func decryptEPKI(epki encryptedPrivateKeyInfo, password string) ([]byte, error) {
	p2, kdfP, err := parsePBES2Parameters(epki.Algorithm)
	if err != nil {
		return nil, err
	}

	return decryptPBES2Data(p2, kdfP, epki.EncryptedData, []byte(password))
}

// parseSafeBags parses a DER-encoded SafeContents (SEQUENCE OF SafeBag).
func parseSafeBags(der []byte, password string) ([]*dstu4145.PrivateKey, [][]byte, error) {
	var bags []safeBag
	if rest, err := asn1.Unmarshal(der, &bags); err != nil || len(rest) != 0 || len(bags) > 512 {
		return nil, nil, errors.New("keystore: PKCS12: malformed or excessive SafeContents")
	}

	var keys []*dstu4145.PrivateKey
	var certs [][]byte

	for _, bag := range bags {
		if len(keys) >= 64 || len(certs) >= 512 {
			return nil, nil, errors.New("keystore: PKCS12: too many bags")
		}
		if bag.BagValue.Class != 2 || bag.BagValue.Tag != 0 || !bag.BagValue.IsCompound {
			return nil, nil, errors.New("keystore: PKCS12: invalid bag wrapper")
		}
		switch {
		case bag.BagID.Equal(oidKeyBag):
			// Unencrypted PrivateKeyInfo
			priv, err := parseRawKeys(bag.BagValue.Bytes)
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, priv...)

		case bag.BagID.Equal(oidPKCS8ShroudedKeyBag):
			// Encrypted PrivateKeyInfo — parse as Key6 format
			var epki encryptedPrivateKeyInfo
			if rest, err := asn1.Unmarshal(bag.BagValue.Bytes, &epki); err != nil || len(rest) != 0 {
				return nil, nil, errors.New("keystore: PKCS12: malformed encrypted key bag")
			}
			plain, err := decryptEPKI(epki, password)
			if err != nil {
				return nil, nil, err
			}
			priv, err := parseRawKeys(plain)
			clear(plain)
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, priv...)

		case bag.BagID.Equal(oidCertBag):
			cert, err := parseCertBag(bag.BagValue.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cert)
		default:
			return nil, nil, errors.New("keystore: PKCS12: unsupported safe bag type")
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
	if rest, err := asn1.Unmarshal(der, &cb); err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: PKCS12: malformed certificate bag")
	}
	if !cb.CertID.Equal(oidX509Certificate) {
		return nil, errors.New("keystore: PKCS12: unsupported certificate bag type")
	}
	// CertValue is an OCTET STRING containing the DER cert
	var cert []byte
	if cb.CertValue.Class != 2 || cb.CertValue.Tag != 0 || !cb.CertValue.IsCompound {
		return nil, errors.New("keystore: PKCS12: invalid certificate wrapper")
	}
	if rest, err := asn1.Unmarshal(cb.CertValue.Bytes, &cert); err != nil || len(rest) != 0 || len(cert) == 0 {
		return nil, errors.New("keystore: PKCS12: malformed certificate octets")
	}
	return cert, nil
}

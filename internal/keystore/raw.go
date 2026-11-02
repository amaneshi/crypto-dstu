package keystore

import (
	"encoding/asn1"
	"errors"
	"math/big"

	"crypto-dstu/pkg/dstu4145"
	"crypto-dstu/pkg/ec"
	"crypto-dstu/pkg/gost28147"
)

// PrivateKeyInfo is the ASN.1 structure for an unencrypted PKCS#8 private key
// (RFC 5958 OneAsymmetricKey / RFC 5208 PrivateKeyInfo), used by cryptonite
// pkcs8.c for DSTU keys.
//
//	PrivateKeyInfo ::= SEQUENCE {
//	    version               INTEGER (= 0),
//	    privateKeyAlgorithm   AlgorithmIdentifier,
//	    privateKey            OCTET STRING
//	}
type privateKeyInfo struct {
	Version    int
	Algorithm  pkcs8AlgorithmIdentifier
	PrivateKey []byte
}

// pkcs8AlgorithmIdentifier holds the algorithm OID and optional parameters.
// For DSTU 4145 keys the parameters field contains the curve OID.
type pkcs8AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// ParseRawKey parses an unencrypted PKCS#8 DER-encoded DSTU 4145 private key.
// Matches cryptonite pkcs8_get_privatekey() for PRIVATEKEY_DSTU type:
//   - The privateKey OCTET STRING contains the raw scalar d in little-endian byte order.
//   - The curve is identified by the AlgorithmIdentifier parameters OID.
func ParseRawKey(der []byte) (*dstu4145.PrivateKey, error) {
	var ki privateKeyInfo
	rest, err := asn1.Unmarshal(der, &ki)
	if err != nil {
		return nil, errors.New("keystore: ParseRawKey: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("keystore: ParseRawKey: trailing data")
	}
	if ki.Version != 0 {
		return nil, errors.New("keystore: ParseRawKey: unsupported version")
	}

	// Locate curve domain parameters by algorithm OID.
	// cryptonite uses pkix_check_oid_parent against OID_PKI_DSTU4145_WITH_GOST3411_ID.
	// Our OIDs: OIDCurvePBxxx are direct children of OIDDstu4145WithGost34311.
	// The AlgorithmIdentifier.algorithm is the curve OID itself (the "full" sig OID
	// may also be used; accept both).
	params := dstu4145.ParamsByOID(ki.Algorithm.Algorithm)
	if params == nil && ki.Algorithm.Algorithm.Equal(dstu4145.OIDDstu4145WithGost34311) {
		// Try parameters field (some encodings put the curve OID there)
		var curveOID asn1.ObjectIdentifier
		if rest, err2 := asn1.Unmarshal(ki.Algorithm.Parameters.FullBytes, &curveOID); err2 == nil && len(rest) == 0 {
			params = dstu4145.ParamsByOID(curveOID)
		}
	}
	if params == nil {
		if ki.Algorithm.Algorithm.Equal(dstu4145.OIDDstu4145WithGost34311) {
			params = dstu4145.ParamsFromDER(ki.Algorithm.Parameters.FullBytes)
		}
	}
	if params == nil {
		return nil, errors.New("keystore: ParseRawKey: unrecognised curve OID " + ki.Algorithm.Algorithm.String())
	}

	// DSTU private key d is stored as LE bytes in the OCTET STRING.
	// cryptonite: asn_OCTSTRING2ba() then used directly as d (no byte swap).
	// However, jkurwa and real key files store d in LE convention — reverse to get big-endian.
	raw := ki.PrivateKey
	if len(raw) == 0 {
		return nil, errors.New("keystore: ParseRawKey: empty private key bytes")
	}

	// Reverse bytes: stored LE → big.Int (big-endian)
	reversed := make([]byte, len(raw))
	for i, b := range raw {
		reversed[len(raw)-1-i] = b
	}
	d := new(big.Int).SetBytes(reversed)

	n := new(big.Int).SetBytes(params.Curve.N)
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		return nil, errors.New("keystore: ParseRawKey: private key scalar out of range")
	}

	return &dstu4145.PrivateKey{D: d, Curve: params.Curve}, nil
}

// MarshalRawKey encodes a DSTU 4145 private key as an unencrypted PKCS#8 DER blob.
// AlgorithmIdentifier contains the DSTU PB little-endian algorithm and named curve parameters.
// The private scalar d is stored in little-endian byte order inside the OCTET STRING.
func MarshalRawKey(priv *dstu4145.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.D == nil {
		return nil, errors.New("keystore: MarshalRawKey: missing private key")
	}
	params := paramsByPtr(priv.Curve)
	if params == nil {
		return nil, errors.New("keystore: MarshalRawKey: unknown curve")
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(new(big.Int).SetBytes(params.Curve.N)) >= 0 {
		return nil, errors.New("keystore: MarshalRawKey: private scalar out of range")
	}

	byteLen := (priv.Curve.M + 7) / 8
	be := priv.D.Bytes()
	// Zero-pad to byteLen
	padded := make([]byte, byteLen)
	copy(padded[byteLen-len(be):], be)

	// Reverse to LE
	le := make([]byte, byteLen)
	for i, b := range padded {
		le[byteLen-1-i] = b
	}

	parameters, err := asn1.Marshal(struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte
	}{params.OID, gost28147.SboxDSTU.Packed()})
	if err != nil {
		return nil, err
	}
	ki := privateKeyInfo{
		Version: 0,
		Algorithm: pkcs8AlgorithmIdentifier{
			Algorithm:  dstu4145.OIDDstu4145WithGost34311,
			Parameters: asn1.RawValue{FullBytes: parameters},
		},
		PrivateKey: le,
	}
	return asn1.Marshal(ki)
}

// MarshalPrivateKeyDER encodes a DSTU 4145 private key as unencrypted PKCS#8 DER.
// Alias for MarshalRawKey.
func MarshalPrivateKeyDER(priv *dstu4145.PrivateKey) ([]byte, error) {
	return MarshalRawKey(priv)
}

// MarshalPrivateKeyPEM encodes a DSTU 4145 private key as a PEM-wrapped
// unencrypted PKCS#8 "PRIVATE KEY" block.
func MarshalPrivateKeyPEM(priv *dstu4145.PrivateKey) ([]byte, error) {
	der, err := MarshalRawKey(priv)
	if err != nil {
		return nil, err
	}
	return EncodePEM(der, "PRIVATE KEY"), nil
}

// paramsByPtr returns the DomainParams whose Curve matches by value (M + N bytes).
// ec.DSTUxxx() creates a new *Curve on each call so pointer equality is unreliable.
func paramsByPtr(curve *ec.Curve) *dstu4145.DomainParams {
	for i, p := range dstu4145.AllParams() {
		if p.Curve.M == curve.M && string(p.Curve.N) == string(curve.N) {
			return &dstu4145.AllParams()[i]
		}
	}
	return nil
}

package cert

import (
	"encoding/asn1"
	"errors"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

// VerifyCert verifies cert's signature using issuerCert's public key.
// It also checks the validity period.
// Reference: cryptonite pkix_verify.c.
func VerifyCert(cert *Certificate, issuerCert *Certificate) error {
	return VerifyCertAt(cert, issuerCert, time.Now())
}

// VerifyCertAt verifies a certificate at the supplied validation time.
func VerifyCertAt(cert *Certificate, issuerCert *Certificate, now time.Time) error {
	if issuerCert == nil {
		return errors.New("cert: missing issuer certificate")
	}
	if err := checkValidity(cert, now); err != nil {
		return err
	}
	return verifySignature(cert, issuerCert.PublicKey)
}

// VerifyCertChain verifies cert against a set of trusted root certificates.
// It searches roots for a certificate whose subject matches cert's issuer and
// whose public key verifies cert's signature.
func VerifyCertChain(cert *Certificate, roots []*Certificate) error {
	return VerifyCertChainWithIntermediates(cert, roots, nil)
}

// VerifyCertPKMatch checks that the private key corresponds to the certificate's public key.
// It derives the public key from priv and compares with cert.PublicKey.
func VerifyCertPKMatch(cert *Certificate, priv *dstu4145.PrivateKey) error {
	if cert == nil || priv == nil || priv.Curve == nil || cert.PublicKey == nil || cert.PublicKey.Curve == nil || cert.PublicKey.Q == nil {
		return errors.New("cert: VerifyCertPKMatch: certificate has no public key")
	}
	derived := priv.Public()
	if priv.Curve.M != cert.PublicKey.Curve.M || !derived.Q.X.Equal(cert.PublicKey.Q.X) || !derived.Q.Y.Equal(cert.PublicKey.Q.Y) {
		return errors.New("cert: VerifyCertPKMatch: private key does not match certificate public key")
	}
	return nil
}

// checkValidity returns an error if now is outside [cert.NotBefore, cert.NotAfter].
func checkValidity(cert *Certificate, now time.Time) error {
	if cert == nil {
		return errors.New("cert: missing certificate")
	}
	if now.Before(cert.NotBefore) {
		return errors.New("cert: certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return errors.New("cert: certificate has expired")
	}
	return nil
}

// verifySignature verifies cert's signature over cert.TBSRaw using pub.
// The hash algorithm is determined from cert.SigAlgOID.
func verifySignature(cert *Certificate, pub *dstu4145.PublicKey) error {
	if pub == nil || pub.Curve == nil || pub.Q == nil {
		return errors.New("cert: verifySignature: issuer has no DSTU public key")
	}

	digest, err := hashTBS(cert)
	if err != nil {
		return err
	}

	sig, err := dstu4145.UnmarshalSignature(cert.Signature, pub.Curve.Words)
	if err != nil {
		// National X.509 signatures are an OCTET STRING inside the BIT STRING.
		var raw []byte
		if rest, parseErr := asn1.Unmarshal(cert.Signature, &raw); parseErr == nil && len(rest) == 0 {
			sig, err = dstu4145.UnmarshalSignatureRaw(raw, pub.Curve)
		}
	}
	if err != nil {
		return errors.New("cert: verifySignature: unmarshal signature: " + err.Error())
	}

	if !dstu4145.Verify(pub, digest, sig) {
		return errors.New("cert: verifySignature: signature verification failed")
	}
	return nil
}

// VerifyDataSignature verifies the national signature encoding used by X.509 and OCSP.
func VerifyDataSignature(data, signature []byte, algorithm asn1.ObjectIdentifier, pub *dstu4145.PublicKey) error {
	return verifySignature(&Certificate{TBSRaw: data, Signature: signature, SigAlgOID: algorithm}, pub)
}

// hashTBS hashes cert.TBSRaw with the algorithm indicated by cert.SigAlgOID.
func hashTBS(cert *Certificate) ([]byte, error) {
	sigAlg := cert.SigAlgOID

	switch {
	case sigAlg.Equal(oid.DSTU4145WithGOST34311):
		h := gost34311.New()
		h.Write(cert.TBSRaw)
		digest := h.Sum(nil)
		for i, j := 0, len(digest)-1; i < j; i, j = i+1, j-1 {
			digest[i], digest[j] = digest[j], digest[i]
		}
		return digest, nil

	case sigAlg.Equal(oid.DSTU4145WithKupyna256):
		h := kupyna.New256()
		h.Write(cert.TBSRaw)
		digest := h.Sum(nil)
		for i, j := 0, len(digest)-1; i < j; i, j = i+1, j-1 {
			digest[i], digest[j] = digest[j], digest[i]
		}
		return digest, nil

	case sigAlg.Equal(oid.DSTU4145WithKupyna512):
		h := kupyna.New512()
		h.Write(cert.TBSRaw)
		digest := h.Sum(nil)
		for i, j := 0, len(digest)-1; i < j; i, j = i+1, j-1 {
			digest[i], digest[j] = digest[j], digest[i]
		}
		return digest, nil

	default:
		return nil, errors.New("cert: unsupported signature algorithm: " + sigAlg.String())
	}
}

// rawEqual reports whether two byte slices are equal.
func rawEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

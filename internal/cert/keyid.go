package cert

import "github.com/amaneshi/crypto-dstu/pkg/gost34311"

// KeyID returns the GOST 34.311 hash of the certificate's subjectPublicKey
// contents (the DER OCTET STRING holding the compressed point). This is the
// key identifier jkurwa computes (Pub.keyid) and that many Ukrainian
// applications use to refer to a key. It is not necessarily equal to the
// certificate's SubjectKeyIdentifier extension: newer CZO certificates carry a
// different SKI value.
func KeyID(c *Certificate) []byte {
	if len(c.SubjectPublicKeyBytes) == 0 {
		return nil
	}
	h := gost34311.New()
	_, _ = h.Write(c.SubjectPublicKeyBytes)
	return h.Sum(nil)
}

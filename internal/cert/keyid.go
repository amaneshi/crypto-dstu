package cert

import (
	"encoding/asn1"

	"github.com/amaneshi/crypto-dstu/internal/oid"
)

// KeyID returns the certificate's SubjectKeyIdentifier extension value (the
// contents of its OCTET STRING). It returns nil when the extension is absent,
// duplicated, malformed or empty. It is shared by every certificate issued for
// the same key only if the issuer derived it from that key.
func (c *Certificate) KeyID() []byte {
	var ski []byte
	found := false
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oid.OIDExtSubjectKeyID) {
			continue
		}
		if found {
			return nil
		}
		found = true
		if rest, err := asn1.Unmarshal(ext.Value, &ski); err != nil || len(rest) != 0 {
			return nil
		}
	}
	if !found || len(ski) == 0 {
		return nil
	}
	return ski
}

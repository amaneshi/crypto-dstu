package cert

import (
	"encoding/asn1"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

// KeyID returns the certificate's key identifier: its SubjectKeyIdentifier
// value when the extension is present and well-formed, otherwise, only when
// the extension is absent, the Kupyna-256 hash of the subjectPublicKey
// contents. Current CZO certificates derive their SKI the same way. A
// duplicated, malformed or empty extension yields nil, never a substitute.
// CMS identifier matching must use SubjectKeyID, which never falls back.
func (c *Certificate) KeyID() []byte {
	if ski, present := c.subjectKeyID(); present {
		return ski
	}
	if len(c.SubjectPublicKeyBytes) == 0 {
		return nil
	}
	h := kupyna.New256()
	_, _ = h.Write(c.SubjectPublicKeyBytes)
	return h.Sum(nil)
}

// SubjectKeyID returns only the SubjectKeyIdentifier extension value, or nil
// when the extension is absent, duplicated, malformed or empty.
func (c *Certificate) SubjectKeyID() []byte {
	ski, _ := c.subjectKeyID()
	return ski
}

// subjectKeyID reports the extension value and whether the extension exists at
// all (even if unusable), so callers can tell absence from corruption.
func (c *Certificate) subjectKeyID() (ski []byte, present bool) {
	found := false
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oid.OIDExtSubjectKeyID) {
			continue
		}
		if found {
			return nil, true
		}
		found = true
		if rest, err := asn1.Unmarshal(ext.Value, &ski); err != nil || len(rest) != 0 {
			return nil, true
		}
	}
	if !found {
		return nil, false
	}
	if len(ski) == 0 {
		return nil, true
	}
	return ski, true
}

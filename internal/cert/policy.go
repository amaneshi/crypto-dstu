package cert

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/oid"
)

func dnBytes(n asn1.RawValue) []byte {
	if len(n.FullBytes) > 0 {
		return n.FullBytes
	}
	return n.Bytes
}

// CheckSigningUsage rejects certificates explicitly restricted to other uses.
func CheckSigningUsage(c *Certificate) error {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oid.OIDExtKeyUsage) {
			var usage asn1.BitString
			rest, err := asn1.Unmarshal(ext.Value, &usage)
			if err != nil || len(rest) > 0 || usage.At(0) == 0 && usage.At(1) == 0 {
				return errors.New("cert: key usage does not permit signatures")
			}
		}
	}
	return nil
}

// CheckEncryptionUsage checks the agreement capability used by this library.
func CheckEncryptionUsage(c *Certificate) error {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oid.OIDExtKeyUsage) {
			var usage asn1.BitString
			rest, err := asn1.Unmarshal(ext.Value, &usage)
			if err != nil || len(rest) > 0 || usage.At(4) == 0 {
				return errors.New("cert: key usage does not permit key agreement")
			}
		}
	}
	return nil
}

func issuerPolicy(c *Certificate, below int) error {
	found := false
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oid.OIDExtBasicConstraints) {
			var bc struct {
				CA      bool `asn1:"optional"`
				MaxPath int  `asn1:"optional,default:-1"`
			}
			rest, err := asn1.Unmarshal(ext.Value, &bc)
			if err != nil || len(rest) > 0 || !bc.CA || bc.MaxPath >= 0 && below > bc.MaxPath {
				return errors.New("cert: invalid CA basic constraints or path length")
			}
			found = true
		}
		if ext.Id.Equal(oid.OIDExtKeyUsage) {
			var ku asn1.BitString
			rest, err := asn1.Unmarshal(ext.Value, &ku)
			if err != nil || len(rest) > 0 || ku.At(5) == 0 {
				return errors.New("cert: issuer cannot sign certificates")
			}
		}
	}
	if !found {
		return errors.New("cert: issuer is not a CA")
	}
	return nil
}

func checkCritical(c *Certificate) error { return checkCriticalForUsage(c, nil) }

func checkCriticalForUsage(c *Certificate, usage asn1.ObjectIdentifier) error {
	seen := map[string]bool{}
	for _, ext := range c.Extensions {
		if seen[ext.Id.String()] {
			return errors.New("cert: duplicate extension")
		}
		seen[ext.Id.String()] = true
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) && len(usage) > 0 {
			var purposes []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(ext.Value, &purposes); err != nil || len(rest) != 0 {
				return errors.New("cert: malformed extended key usage")
			}
			found := false
			for _, p := range purposes {
				found = found || p.Equal(usage)
			}
			if !found {
				return errors.New("cert: extended key usage excludes required purpose")
			}
			continue
		}
		if !ext.Critical {
			continue
		}
		if !ext.Id.Equal(oid.OIDExtKeyUsage) && !ext.Id.Equal(oid.OIDExtBasicConstraints) {
			return errors.New("cert: unsupported critical extension " + ext.Id.String())
		}
	}
	return nil
}

// VerifyCertChainWithIntermediates validates a bounded issuer path to an
// explicitly trusted certificate. Discovery certificates never become roots.
// This validates supported constraints; it does not perform online revocation.
func VerifyCertChainWithIntermediates(leaf *Certificate, roots, intermediates []*Certificate) error {
	_, err := BuildCertChain(leaf, roots, intermediates)
	return err
}

// BuildCertChain returns a validated leaf-to-anchor path. Its final certificate
// is an explicit trust anchor, never a certificate promoted from discovery.
func BuildCertChain(leaf *Certificate, roots, intermediates []*Certificate) ([]*Certificate, error) {
	return buildCertChain(leaf, roots, intermediates, time.Now(), nil)
}

// BuildCertChainForUsageAt validates a path with an explicit extended key purpose.
func BuildCertChainForUsageAt(leaf *Certificate, roots, intermediates []*Certificate, now time.Time, usage asn1.ObjectIdentifier) ([]*Certificate, error) {
	if len(usage) == 0 {
		return nil, errors.New("cert: required key purpose is missing")
	}
	return buildCertChain(leaf, roots, intermediates, now, usage)
}

func buildCertChain(leaf *Certificate, roots, intermediates []*Certificate, now time.Time, usage asn1.ObjectIdentifier) ([]*Certificate, error) {
	if leaf == nil || len(roots) == 0 {
		return nil, errors.New("cert: no trusted root configured")
	}
	candidates := append(append([]*Certificate(nil), intermediates...), roots...)
	var walk func(*Certificate, map[*Certificate]bool, int) ([]*Certificate, error)
	walk = func(c *Certificate, seen map[*Certificate]bool, below int) ([]*Certificate, error) {
		if c == nil || seen[c] || len(seen) >= 16 {
			return nil, errors.New("cert: certificate path cycle or depth exceeded")
		}
		if err := checkValidity(c, now); err != nil {
			return nil, err
		}
		if err := checkCriticalForUsage(c, usage); err != nil {
			return nil, err
		}
		for _, root := range roots {
			if root != nil && len(c.Raw) > 0 && bytes.Equal(c.Raw, root.Raw) && samePublicKey(c, root) {
				return []*Certificate{c}, nil
			}
		}
		seen[c] = true
		defer delete(seen, c)
		for _, issuer := range candidates {
			if issuer == nil || issuer == c || !bytes.Equal(dnBytes(c.Issuer), dnBytes(issuer.Subject)) {
				continue
			}
			nextBelow := below
			if parseBasicConstraintsFromCert(c) {
				nextBelow++
			}
			if err := issuerPolicy(issuer, nextBelow); err != nil {
				continue
			}
			if err := verifySignature(c, issuer.PublicKey); err != nil {
				continue
			}
			if path, err := walk(issuer, seen, nextBelow); err == nil {
				return append([]*Certificate{c}, path...), nil
			}
		}
		return nil, errors.New("cert: no valid path to a trusted root")
	}
	return walk(leaf, map[*Certificate]bool{}, 0)
}

func parseBasicConstraintsFromCert(c *Certificate) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid.OIDExtBasicConstraints) {
			return parseBasicConstraintsIsCA(e.Value)
		}
	}
	return false
}
func samePublicKey(a, b *Certificate) bool {
	return a.PublicKey != nil && b.PublicKey != nil && a.PublicKey.Curve != nil && b.PublicKey.Curve != nil && a.PublicKey.Curve.M == b.PublicKey.Curve.M && a.PublicKey.Q != nil && b.PublicKey.Q != nil && a.PublicKey.Q.X.Equal(b.PublicKey.Q.X) && a.PublicKey.Q.Y.Equal(b.PublicKey.Q.Y)
}

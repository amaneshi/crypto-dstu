package ocsp

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/oid"
)

var errUnrelatedCRL = errors.New("ocsp: unrelated responder CRL")

type crlAlgorithm struct {
	OID        asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// checkResponderCRL accepts only a complete, direct, issuer-signed v2 CRL.
// Delta and scoped/indirect CRLs cannot establish absence from this list.
func checkResponderCRL(der []byte, responder, issuer *cert.Certificate, now time.Time, maxAge, skew time.Duration) error {
	if len(der) == 0 || len(der) > 16<<20 || maxAge <= 0 || skew < 0 {
		return errors.New("ocsp: invalid responder CRL or freshness policy")
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm crlAlgorithm
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 || outer.Signature.BitLength != len(outer.Signature.Bytes)*8 {
		return errors.New("ocsp: malformed responder CRL")
	}
	var tbs struct {
		Version    int `asn1:"optional,default:0"`
		Algorithm  crlAlgorithm
		Issuer     asn1.RawValue
		ThisUpdate time.Time
		NextUpdate time.Time                 `asn1:"optional"`
		Revoked    []pkix.RevokedCertificate `asn1:"optional"`
		Extensions []pkix.Extension          `asn1:"optional,explicit,tag:0"`
	}
	if rest, err := asn1.Unmarshal(outer.TBS.FullBytes, &tbs); err != nil || len(rest) != 0 || tbs.Version != 1 {
		return errors.New("ocsp: malformed or unrelated responder CRL")
	}
	canonical, err := asn1.Marshal(tbs)
	if err != nil || !bytes.Equal(canonical, outer.TBS.FullBytes) {
		return errors.New("ocsp: noncanonical responder CRL fields")
	}
	canonical, err = asn1.Marshal(outer)
	if err != nil || !bytes.Equal(canonical, der) {
		return errors.New("ocsp: noncanonical responder CRL envelope")
	}
	if !bytes.Equal(tbs.Issuer.FullBytes, issuer.Subject.FullBytes) {
		return errUnrelatedCRL
	}
	innerAlg, _ := asn1.Marshal(tbs.Algorithm)
	outerAlg, _ := asn1.Marshal(outer.Algorithm)
	if !bytes.Equal(innerAlg, outerAlg) {
		return errors.New("ocsp: CRL signature algorithms differ")
	}
	for _, ext := range issuer.Extensions {
		if ext.Id.Equal(oid.OIDExtKeyUsage) {
			var usage asn1.BitString
			if rest, err := asn1.Unmarshal(ext.Value, &usage); err != nil || len(rest) != 0 || usage.At(6) != 1 {
				return errors.New("ocsp: issuer cannot sign CRLs")
			}
		}
	}
	seen := map[string]bool{}
	for _, ext := range tbs.Extensions {
		id := ext.Id.String()
		if seen[id] || id == "2.5.29.27" || id == "2.5.29.28" || ext.Critical {
			return errors.New("ocsp: unsupported responder CRL extension")
		}
		seen[id] = true
	}
	if tbs.ThisUpdate.IsZero() || tbs.NextUpdate.IsZero() || tbs.ThisUpdate.After(now.Add(skew)) || tbs.NextUpdate.Before(tbs.ThisUpdate) || now.After(tbs.NextUpdate.Add(skew)) || now.Sub(tbs.ThisUpdate) > maxAge+skew {
		return errors.New("ocsp: stale or future responder CRL")
	}
	if err := cert.VerifyDataSignature(outer.TBS.FullBytes, outer.Signature.Bytes, outer.Algorithm.OID, issuer.PublicKey); err != nil {
		return err
	}
	for _, entry := range tbs.Revoked {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 {
			return errors.New("ocsp: invalid CRL entry")
		}
		seen = map[string]bool{}
		for _, ext := range entry.Extensions {
			id := ext.Id.String()
			if seen[id] || ext.Critical || id == "2.5.29.29" {
				return errors.New("ocsp: unsupported CRL entry extension")
			}
			seen[id] = true
			if id == "2.5.29.21" {
				var reason asn1.Enumerated
				if rest, err := asn1.Unmarshal(ext.Value, &reason); err != nil || len(rest) != 0 || reason < 0 || reason > 10 || reason == 7 {
					return errors.New("ocsp: invalid full CRL reason")
				}
			}
		}
		// Treat every listed serial as revoked, including duplicate entries and
		// removeFromCRL reasons observed in public full CRLs. Never clear a revocation.
		if entry.SerialNumber.Cmp(responder.SerialNumber) == 0 {
			return errors.New("ocsp: responder certificate is revoked")
		}
	}
	return nil
}

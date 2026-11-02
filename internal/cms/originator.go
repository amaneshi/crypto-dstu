package cms

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math/big"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/oid"
	"crypto-dstu/pkg/dstu4145"
)

type originatorIdentifier struct {
	Issuer       asn1.RawValue
	Serial       *big.Int
	SubjectKeyID []byte
}

// parseOriginator reads the EXPLICIT originator choice: a public key,
// IssuerAndSerialNumber, or an IMPLICIT subjectKeyIdentifier.
func parseOriginator(raw asn1.RawValue) ([]byte, *originatorIdentifier, error) {
	if raw.Class != 2 || raw.Tag != 0 || !raw.IsCompound {
		return nil, nil, errors.New("cms: malformed originator wrapper")
	}
	var choice asn1.RawValue
	if rest, err := asn1.Unmarshal(raw.Bytes, &choice); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("cms: malformed originator choice")
	}
	switch {
	case choice.Class == 0 && choice.Tag == asn1.TagSequence && choice.IsCompound:
		var fields []asn1.RawValue
		if rest, err := asn1.Unmarshal(choice.FullBytes, &fields); err != nil || len(rest) != 0 || len(fields) != 2 || fields[0].Class != 0 || fields[0].Tag != asn1.TagSequence || !fields[0].IsCompound {
			return nil, nil, errors.New("cms: malformed originator issuer and serial")
		}
		var serial *big.Int
		if rest, err := asn1.Unmarshal(fields[1].FullBytes, &serial); err != nil || len(rest) != 0 || serial == nil || serial.Sign() <= 0 {
			return nil, nil, errors.New("cms: malformed originator serial")
		}
		return nil, &originatorIdentifier{Issuer: fields[0], Serial: serial}, nil
	case choice.Class == 2 && choice.Tag == 0 && !choice.IsCompound:
		if len(choice.Bytes) == 0 {
			return nil, nil, errors.New("cms: empty originator subject key identifier")
		}
		return nil, &originatorIdentifier{SubjectKeyID: choice.Bytes}, nil
	case choice.Class == 2 && choice.Tag == 1 && choice.IsCompound:
		var algorithm AlgorithmIdentifier
		fields, err := asn1.Unmarshal(choice.Bytes, &algorithm)
		if err != nil || !algorithm.Algorithm.Equal(dstu4145.OIDDstu4145WithGost34311) && !algorithm.Algorithm.Equal(dstu4145.OIDDstu4145WithKupyna256) {
			return nil, nil, errors.New("cms: unsupported originator algorithm")
		}
		if len(algorithm.Parameters.FullBytes) != 0 && !bytes.Equal(algorithm.Parameters.FullBytes, []byte{0x05, 0x00}) {
			return nil, nil, errors.New("cms: unsupported originator curve parameters")
		}
		var publicKey asn1.BitString
		if rest, err := asn1.Unmarshal(fields, &publicKey); err != nil || len(rest) != 0 || publicKey.BitLength != len(publicKey.Bytes)*8 || len(publicKey.Bytes) == 0 {
			return nil, nil, errors.New("cms: malformed originator public key")
		}
		return publicKey.Bytes, nil, nil
	default:
		return nil, nil, errors.New("cms: unsupported originator identifier")
	}
}

func (id *originatorIdentifier) matches(c *cert.Certificate) bool {
	if id == nil || c == nil {
		return false
	}
	if id.Serial != nil {
		return c.SerialNumber != nil && id.Serial.Cmp(c.SerialNumber) == 0 && bytes.Equal(id.Issuer.FullBytes, c.Issuer.FullBytes)
	}
	var ski []byte
	found := false
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oid.OIDExtSubjectKeyID) {
			continue
		}
		if found {
			return false
		}
		found = true
		if rest, err := asn1.Unmarshal(ext.Value, &ski); err != nil || len(rest) != 0 {
			return false
		}
	}
	return found && len(id.SubjectKeyID) != 0 && bytes.Equal(id.SubjectKeyID, ski)
}

// Resolving an agreement key does not trust the certificate or authenticate the
// plaintext. Signed content must be verified separately against explicit roots.
func resolveOriginator(id *originatorIdentifier, candidates []*cert.Certificate) (*dstu4145.PublicKey, error) {
	var selected *cert.Certificate
	for _, c := range candidates {
		if !id.matches(c) {
			continue
		}
		if c.PublicKey == nil || c.PublicKey.Q == nil || c.PublicKey.Curve == nil {
			return nil, errors.New("cms: originator certificate has no supported public key")
		}
		if err := cert.CheckEncryptionUsage(c); err != nil {
			return nil, err
		}
		if selected != nil {
			if c == selected || len(c.Raw) != 0 && bytes.Equal(c.Raw, selected.Raw) && c.PublicKey.Q.X.Equal(selected.PublicKey.Q.X) && c.PublicKey.Q.Y.Equal(selected.PublicKey.Q.Y) {
				continue
			}
			return nil, errors.New("cms: ambiguous originator certificate")
		}
		selected = c
	}
	if selected == nil {
		return nil, errors.New("cms: originator certificate not found")
	}
	return selected.PublicKey, nil
}

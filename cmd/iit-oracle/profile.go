package main

import (
	"encoding/asn1"
	"errors"
)

type nativeAlgorithm struct {
	OID        asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// checkNativeSigningProfile checks native CMS metadata independently of the
// library under test. A successful SDK call must not silently select another
// digest or signature profile. Cryptographic checks remain separate tests.
func checkNativeSigningProfile(der []byte, digest string, detached bool) error {
	var digestOID, signatureOID string
	switch digest {
	case "gost34311":
		digestOID, signatureOID = "1.2.804.2.1.1.1.1.2.1", "1.2.804.2.1.1.1.1.3.1.1"
	case "kupyna256":
		digestOID, signatureOID = "1.2.804.2.1.1.1.1.2.2.1", "1.2.804.2.1.1.1.1.3.6.1.1"
	case "kupyna512":
		digestOID, signatureOID = "1.2.804.2.1.1.1.1.2.2.3", "1.2.804.2.1.1.1.1.3.6.3.1"
	default:
		return errors.New("unknown native signing profile")
	}
	var document struct {
		Type    asn1.ObjectIdentifier
		Content struct {
			Version       int
			Digests       []nativeAlgorithm `asn1:"set"`
			Encapsulation asn1.RawValue
			Certificates  asn1.RawValue `asn1:"optional,tag:0"`
			CRLs          asn1.RawValue `asn1:"optional,tag:1"`
			Signers       []struct {
				Version    int
				SID        asn1.RawValue
				Digest     nativeAlgorithm
				Attributes asn1.RawValue `asn1:"optional,tag:0"`
				Signature  nativeAlgorithm
				Value      []byte
				Unsigned   asn1.RawValue `asn1:"optional,tag:1"`
			} `asn1:"set"`
		} `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(der, &document)
	if err != nil || len(rest) != 0 || document.Type.String() != "1.2.840.113549.1.7.2" {
		return errors.New("native output is not CMS SignedData")
	}
	content := document.Content
	var encapsulation struct {
		Type    asn1.ObjectIdentifier
		Payload asn1.RawValue `asn1:"optional,tag:0"`
	}
	rest, err = asn1.Unmarshal(content.Encapsulation.FullBytes, &encapsulation)
	if err != nil || len(rest) != 0 || encapsulation.Type.String() != "1.2.840.113549.1.7.1" || (len(encapsulation.Payload.FullBytes) != 0) == detached {
		return errors.New("native CMS content mode differs from request")
	}
	if len(content.Digests) != 1 || len(content.Signers) != 1 {
		return errors.New("native output must contain one digest and one signer")
	}
	signer := content.Signers[0]
	if content.Digests[0].OID.String() != digestOID || signer.Digest.OID.String() != digestOID || signer.Signature.OID.String() != signatureOID {
		return errors.New("native CMS algorithms differ from requested profile")
	}
	return nil
}
